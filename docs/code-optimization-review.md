# 当前实现的代码优化评估（2026-10-05）

本轮只做源码审查、读取 16 节点既有结果和离线微测量，没有修改协议生产代码，也没有将局部操作耗时当作整币延迟。

## 优先顺序

| 优先级 | 方向 | 收益对象 | 范围/风险 |
| --- | --- | --- | --- |
| P1 | 合并本地恢复和终止证据的重复完整验证 | CPU、延迟 | 本项目；保留完整 AX 检查及对 header root 的绑定 |
| P1 | 短语义证明直接验证必要字段，避免 sparse 全 bulk 对象 | 内存、分配、CPU | 本项目；验证所有必要字段和分支条件 |
| P1 | 固定长度 hash 写入栈数组、减少序列化/clone 和 gate 小 Vec | 分配、CPU、峰值内存 | 本项目；保持输出字节和域分离格式完全相同 |
| P2 | 按 dealer/事件推进，缓存输入 token 验证、有效权重及重复无效证据 | CPU，特别是恶意输入和大 n | 本项目；保留迟到触发和每发送者独立 allowance |
| P2 | 有界 CPU 工作队列接入 WHCC Context | 网络响应、STOP 响应、延迟波动 | 本项目；并发、事件顺序和本地 CPU 过量竞争需测试 |
| 独立实验 | 只增大 bulk WAVID 编码块到 64/128 B | 通信、stripe 数量和哈希/树处理 | 已有上游接口支持；改变公开布局及承诺，控制 WRBC 保持 32 B |
| 后续上游 | 一次编码同时得到 header root、private openings 和 compact packets | dealer CPU、复制 | 需要 SDC 新增可复用准备结果接口；不能退回 eager Prepared |

## 1. 本地成功恢复存在重复完整工作

调用链为 whcc/protocol/recovery.rs -> terminal::recover_bounded -> ax::verify_opening；这一步已经生成一次完整 AX 并和解码 Public 比较。随后外层对本地产生的 Certificate 调用 certified::verify，Success 再次执行 ax::generate + Codec::commit_file。因此同一成功候选经历两次 AX 生成，并在已绑定根的 ValidatedFile 上额外做一次编码/承诺计算。

可将本地恢复结果与已核验的 ValidatedFile、header、context 绑定，复用完整验证结论，避免第二遍。来自网络的 Success/RootFault 必须继续独立验证；不能把“本地有一个候选”直接视为验证通过。RootFault、范围失败和输入/门故障分别需要保留对应检查，不宜直接删除外层 ensure 而不重构验证结果流。

Release 微测量：16 节点，等权 659 门、bulk 64648 B；Aptos 1013 门、bulk 98632 B。每操作预热，5 批 × 30 次，以下为每批平均耗时的中位数：

| 操作 | 等权 ms | Aptos ms |
| --- | ---: | ---: |
| AX generate | 1.673 | 2.548 |
| 序列化 Public + commit_file | 1.668 | 2.661 |
| certified::verify_opening | 3.319 | 5.138 |
| recover_bounded（含第一遍 AX 验证） | 2.996 | 4.498 |
| 当前本地成功恢复+外层证据验证 | 6.322 | 9.724 |

这些数字确认重复阶段占该局部路径很大比例；不表示完整 coin 可以直接减半。微测量没有网络、竞争和其他协议阶段，也没有实现优化后的路径。

## 2. 短证明仍触发 bulk 大小的临时分配

certified.rs:317 的 sparse() 先创建 Public::encoded_len(s) 大小的零数组，填入少数字段，再 Public::decode 成 inputs/wires/gates 等完整向量。TrueFault/InputFault/GateFault 只需几个局部字段，却承担 O(L) 临时内存和解码；大权重电路时尤其不划算。

可引入认证字段读取器或小型结构，直接执行本地谓词。RootFault 也可直接读 output digest、encrypted key、两个 AX ciphertext；之后必须保留其完整重新生成检查。因此可去掉它的 sparse 临时对象，但不能宣称 RootFault 总计算从 O(L) 降为 O(1)。

terminal::recover_bounded 在确认有效输入权重达到 T 之前，就分配 circuit.nodes() 个 32 B token 和 known 数组。应先验证 true/input 条目及授权权重，再分配门求值空间；或按 dealer 缓存已验输入。提前发现 TrueFault/InputFault 的行为必须保留。

## 3. 明确的小分配和复制

- crypto/src/lib.rs:24 的 hash() 通过 expand(...,32) 创建 Vec 再转 [u8;32]。可以直接把 SHAKE 输出写入栈数组，保留全部长度前缀/域字节。
- wcss/protocol/sharing.rs:76 的 transcript_tag 克隆整个 Public、清零 tag、再编码。可对同一规范字节流计算 hash，虚拟写入零 tag，避免完整 clone。
- Public::encode 可按已知长度预分配，或写入调用者提供的缓冲区，减少嵌套 Public 编码的临时 Vec。
- terminal.rs 的逐门 choices Vec 可用固定数组或分支迭代替换。
- 恢复调用每次将 tokens.values() 克隆为 Vec，可改借用迭代器。
- 收到 ValidatedFile 后又完整解析成 Public，长期保留两份 bulk 表示。可考虑借用视图；已有 verified terminal 后可释放恢复专用的 Public/tokens 等 scratch，但不能删除 holder 的 stored_packet、私有 receipt 或迟到服务所需状态。上游自己也保留 ValidatedFile result，不能仅删一个 Arc 就声称释放了所有源数据。

这些点由源码确定；本轮没有做分配器计数或完整 CPU 火焰图，因此未给出它们各自的加速百分比。

## 4. 避免每次事件重新扫描和重复恶意验证

State::advance 每次调用 receipts/recovery；后者循环所有 dealer，再扫描所有 recipient 查 served/authorized。虽然 recovery_dirty 已避免无变化时重新计算电路，外围 O(n²) 扫描仍在。

可用待处理 dealer 集合、按 dealer 保存的 authorized/unserved 集合，以及按名单发送者索引的待处理证据。Freeze 触发一次全面激活，之后只处理受事件影响的状态。聚合也可等所有正系数对应值就绪再做一次，避免重复克隆值向量和大整数转换。

目前 terminal_seen 只按发送者去重。同一 dealer 下多个恶意 sender 可以发送完全相同的假 opening，引发重复 AX/root 计算。现有 16 节点 stress 结果中，每轮诚实节点合计平均拒绝约 587 份（等权）或 497 份（Aptos）terminal。可做每 dealer、有界、绑定 header/context 的原始证据或规范证据结果缓存。每个 sender 仍独立记录槽/授权；缓存命中不可让无效证据固定 dealer 值。攻击者改变证据即可避开相同内容缓存，所以该优化改善重复负载，不改变最坏安全界。已有 dealer.value 时会跳过后续验证，该现有优化应保留。

## 5. WHCC 上层同步 CPU 工作仍在异步事件循环内

SDC 已把 WAVID/WRBC 的重工作搬到有界 blocking worker；WHCC Context.run 仍同步调用 State 处理。一次事件可以进行多个完整 AX 生成、语义验证和聚合，期间该状态机不能及时消费其他事件。

建议将耗时的纯计算作为有界作业提交，保留单一状态提交点；完成事件必须重新匹配 session/dealer/header 和 freeze/complete 前提。不能给每条恶意消息无限 spawn_blocking；本地 16/64 进程各自开很多 worker 也可能增加 CPU 竞争。先消除重复计算，再测是否需要这一步。

## 6. 编码块是当前最有证据的通信优化候选

上次优化后的 16 节点诚实结果中，WAVID 占总 TCP payload 的 81.9%（等权）和 88.1%（Aptos）。改变其他小服务很难获得相同数量级的全局节省。

本轮通过当前 Codec::bundle_bytes 精确计算每个 dealer 向所有 owner 发出的存储包总字节数，保持 n、权重、bulk 字节完全相同：

| bulk 块长 | 等权 B | Aptos B |
| --- | ---: | ---: |
| 32 B | 678960 | 1118128 |
| 64 B | 440592 | 732816 |
| 128 B | 318736 | 542800 |
| 256 B | 257808 | 453072 |

32->128 B，存储包分别减少 53.1% 和 51.5%，主要因为 stripe 数从 127/193 降至 32/49，目录及 multiproof 重复量下降。这里是存储包大小，不包含 TCP framing、重传、token、terminal 或 STOP 截断。

如果保持服务边/发送完成量近似不变，按现有服务占比投影，仅此项可能让两类诚实场景总通信减少约 43%/45%；这只是布局投影，尚未做分布式验证，不能作为性能结论。

应拆分 bulk_coding 与 control_coding。小 header/名单使用 WRBC 时通常只有一条 stripe，块长变大不会减少 stripe，反而增加 padding 和片段大小；不应把当前共用的 Parameters::CODING 一并改大。更大的 bulk 块也增大 coding-fault witness 的片段数据，需比较 honest/stress 两类总成本并重新绑定上下文。b 应仍保持论文允许的安全参数尺度，不建议直接追求最大 4096 B。

## 7. dealer 端双重编码需要上游接口协作

当前 start_material 先 commit_file 获取 root 和 private source openings；然后 Disperse 把相同 raw bulk 交给上游 prepare_packets 再做一次 RS/树处理。这仍有重复。

理想接口一次准备就返回 compact packets 与 ValidatedFile/根/证明 provider，供本地应用认证 header 后启动分散；或者由 WAVID 返回准备事件供应用构造 header/receipt。复用结果必须绑定 codec context 和公开几何。不建议改回现有 eager Prepared + disperse_prepared，因为它会保留全部树/展开证明且复验 bundles，可能抵消收益。

## 实施建议

先做本项目的验证结果复用、局部字段读取、栈 hash/编码缓冲和早期授权检查；以相同 policy 重新跑 16 节点，验证输出一致、故障拒绝、迟到服务与冻结屏障。再单独做 bulk 64/128 B 的 A/B 实验，记录布局元数据并隔离旧 results。事件驱动和 CPU 作业化依据新的测量决定。不要通过降低安全参数、减少必要 BinAA 轮次、改变采样 quota 或删除重编码验证来取得表面性能提升。

离线测量源代码与日志位于 .reference/optimization-probe/ 和 .reference/optimization-probe.log；该工具未加入正式 workspace。
