# SDC 依赖升级（2026-10-05）

从 79e905a8bcd6d3fc0a5423f8cfcb383ad33a919e 更新到 731e0b81166125ea756c5a047ab813ccb8af7111。本次检查了本地 /root/Secure-Distributed-Computing-Protocols 的提交差异和说明，且确认其 HEAD 与 GitHub HEAD 一致；未修改该项目。所有共享原语及 config/types/util 固定到同一提交，Cargo.lock 已同步。

## 上游变化及接入

| 上游变化 | 本项目处理 |
| --- | --- |
| WAVID Descriptor、WRBC Register 增加 CodingParams | 显式传入 Parameters::CODING，固定 block_bytes=32；编码几何加入 WHCC 上下文绑定 |
| Fragment.data 改为 Vec<u8>；编码域和存储包升级 v3 | 适配证明读取与测试，所有节点统一升级，重新生成承诺 |
| WAVID/WRBC 输出 ValidatedFile | 读取共享字节，验证 root、coding_context、parameters，保留句柄生成局部证明 |
| commit_file / open_source 按需证明 | dealer 不再用 prepare 构造全部存储包；恢复后不再重复 prepare；成功/RootFault 验证使用逐 stripe 承诺重建 |
| 紧凑 multiproof、GF8/GF16 自动选择、增量恢复、有界 CPU worker | 经上游 Context 自动接入；保留独立子协议服务和多 dealer 实例 |
| TCP 发送窗口、共享缓冲、批量序列化、队列溢出落盘 | 删除旧 vendor/sdc-util 与 Cargo patch，直接使用上游 util |
| WBinAA/WRA/WGather 批量发送 | 保留现有 channel 调用；BinAA 数学状态机、精确 Dyadic 表示及精度选择未因本次升级改变 |

WHCC 的公开编码块仍为 32 字节，与 32 KiB TCP bulk chunk 无关。证明辅助函数按 codec 的块长计算字段覆盖，测试额外覆盖 64/128/256 字节；本轮没有增加可配置块长的 benchmark 参数。WHCC context 域更新为 whcc/striped-context/v4，header 仍为 112 字节。旧会话中的根、存储包及证据不可复用。

生产路径仅按需保存共享文件、目录和局部 proof cache。Prepared 仅保留在诊断/恶意编码测试，以及兼容的 ProofSource 接口中。上游 ValidatedFile 只保证编码和 padding 正确，AX 语义依然由本项目验证；不能把有效存储文件直接当作有效共享。

## 保留的协议条件

- WRBC 仅广播 header 与 recovery sampling 名单；bulk 通过独立 WAVID。
- header 认证后 Pin；本地 Stored 与私有 receipt 同时满足才向 WRA 输入 true。
- WRA true 才标记 Shared、通知 Gather，并向 WAVID 发送 External Complete。全局完成不额外要求本节点已有 receipt/storage。
- 只有名单授权方取回 bulk；整向量冻结后才能释放恢复 token/处理最终贡献。
- coin 输出后继续服务迟到方，直至同步器 STOP；缺失消息不转化为公开拒绝证据。

## 验证

以下检查均通过：

- cargo test --workspace --locked：64 项。
- cargo test -p util -p wavid -p wrbc --lib --tests --locked：34 项。
- cargo clippy --workspace --all-targets --locked -- -D warnings。
- Python unittest：61 项，包括两代 striped 结果的七服务校验、混合实现版本拒绝。
- 新增按需/预生成 receipt 与语义证据逐字节一致性测试，覆盖跨 block/stripe 字段、不同编码块长、错误实例、五类恶意 AX 数据；从实际 Codec::recover 输出的 ValidatedFile 生成证据。

四节点本地独立进程回归使用 policies/striped-smoke.json：权重 [3,3,3,3]，T=4，128 位输出，每个场景 1 次。

| 场景 | 同步器延迟 | 总发送 TCP payload | 活跃节点平均发送 |
| --- | ---: | ---: | ---: |
| honest | 40.180 ms | 1,473,877 B | 368,469.25 B |
| recovery-stress，节点 3 腐化，B=3 | 50.053 ms | 1,046,632 B | 261,658.00 B |

两组均满足同值 FINISH 权重 > T 后 STOP，所有进程正常退出，抓包 dropped_packets=0。stress 的诚实节点平均发送为 323,334.67 B；STOP 前两个诚实节点记录了恶意 dealer 的可验证拒绝。本次进程测试未观察到伪造终止包发送，该路径另由 Rust 对抗测试覆盖。

这是功能回归：每组仅一次，且同机运行期间存在回归检查负载，不能据此估计稳定加速倍数。quorum STOP 会截断后续服务，发送量也不是全部服务义务完成后的通信上界。

结果位置：

- [honest](../benchmark/results/whcc-striped-smoke-honest-n4-w12-t4-l128-20261005-104611Z-d0ec3dfc/whcc-0-4.json)
- [recovery-stress](../benchmark/results/whcc-striped-smoke-stress-n4-w12-t4-l128-20261005-104619Z-ea8ca0f0/whcc-0-4.json)

新 result 标识 compact-header-striped-wavid-v2，包含准确的上游 revision、Cargo.lock、binary、benchmark 和 transport 源码指纹。历史结果不改写，绘图继续严格隔离不同实现版本。
