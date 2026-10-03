# 完整 common coin 组合

## 入口和文件组织

consensus/commoncoin/src/context.rs 是协议运行入口。Context::spawn 接收外部 config::Node、Parameters、tokio 请求接收端和事件发送端，启动六个服务并返回 Handle。节点配置类型通过本地 config crate 重导出，实际类型就是外部 sdc_config::Node，不是转换副本或另造的节点配置格式。

src 根目录保留 lib.rs、context.rs、msg.rs 和 process.rs：context.rs 负责服务启动及异步等待，msg.rs 定义请求、动作和事件，process.rs 将动作分发到子协议 channel 并记录公开事件。具体逻辑放在 protocol/：state.rs 管理单次调用状态，parameters.rs 定义协议参数，sharing.rs 处理 WRBC/WRA 事件和私有回执，recovery.rs 管理候选方授权、token 投递、证据及迟到义务，aggregate.rs 做精确聚合。单元测试位于 protocol/tests/。consensus 之外的 recovery crate 负责纯本地采样和名单校验。

使用方式：

~~~rust
let (requests, input) = tokio::sync::mpsc::channel(8);
let (events, mut output) = tokio::sync::mpsc::channel(1024);
let handle = commoncoin::Context::spawn(
    node, commoncoin::Parameters::default(), input, events,
)?;
requests.send(commoncoin::Request::Start).await?;

// 持续接收 Shared / Gathered / Frozen / Terminal / Coin / Failed。
// 收到 Coin 后保留 handle，使迟到方仍能取得服务。
// 全局实验结束后再显式调用 handle.shutdown().await。
~~~

一次 Context 对应一个固定 epoch 和一次 coin，只接受一次 Start，不允许隐式重新抽样。关闭请求 channel 不会停止服务；显式 shutdown 或释放 Handle 才取消服务。所有原语在启动时预登记实例，处理不同启动顺序；WRA 使用 Expect，在共享记录到达前缓存限定数量的消息。

对应用层事件的交付使用内部有界数量的待发队列，并在 select 中等待发送许可。应用层读取慢或停止读取事件不会阻塞网络处理、迟到服务或显式停止。事件总量由实例规模限制，不周期性产生无界状态更新。

## 流程与约束

设总权重 W、秘密共享门限 T，静态腐化权重 B < T <= W/3。dealer universe 固定为 0..n-1。

1. **Assign**：每个参与方独立抽取固定配额的 dealer 子集，向 WRBC 提交一次排序后的稀疏名单。不根据完成情况或观察到的贡献重新选择。
2. **Share**：每方均作为 dealer，独立均匀抽取 M，再用独立 OS 随机数 R 生成 AX 分享。通过 WRBC 固定完整 Public，通过私有通道投递各方输入 token。
3. **Complete**：持有固定公开记录和通过 input/wire 双承诺认证的私有 token 后，才向 WRA 输入 true。WRA 输出 true 标记本地 Shared，并向 WGather 提交 Add(dealer)。
4. **Gather**：WGather 从本地完成实例中产生集合；以该集合的指示向量启动一次向量 WBinAA。
5. **Freeze**：只接受 WBinAA 的完整 DeliverVector。将整组系数冻结后才释放任意私有 token 或处理 token 相关终止证据。这个屏障是本地的，不要求检测全网同时冻结。
6. **Recover**：对每个已完成的 dealer，持有者向每个已由 RBC 名单授权的恢复方发送自己的 token 一次。恢复方验证 token、恢复 M/R 或构造拒绝证据，向各方发送一个终止包。
7. **Verify**：接收方检查本地完成、冻结、发送方名单授权和终止证据。成功时通过重生成完整 Public 验证；拒绝必须有可验证的具体证据，未经证明的裸 ⊥ 不进入聚合。
8. **Aggregate**：等待每个正系数对应的终止值；零系数不需要等待其值。每方只输出一次。

本地系数为零不取消恢复服务。名单和消息可以在冻结、完成甚至 coin 输出之后到达，仍能激活未履行的服务义务。每个 dealer/接收方的 token 仅投递一次；每个已授权恢复方对某 dealer 仅使用一次全网终止发送额度。无效终止包只占用其认证发送者的槽位，不能覆盖另一方。

## 独立采样

基本配额为 d_i = min(n, ceil(a n w_i / W))，其中 a 取满足覆盖分析的公开整数：

a >= 3/2 * (coverage_bits * ln 2 + ln n)。

实现通过任意精度有理数求对数的显式上界，再向上取整，不使用浮点数决定配额。对数使用 atanh 级数及正的尾项上界；与 Python 使用高精度 Decimal 的目的相同，均不允许把安全上界向下舍入。

等权场景采用论文更紧的整数判据，选择最小 d，使：

n * (n-d)^(n-t) * 2^coverage_bits <= n^(n-t),

其中 t = floor((T-1)/w)。测试复现 n=150、T=50、w=1 时 coverage_bits=40 得 d=42，coverage_bits=64 得 d=58。

本地采样采用拒绝法生成无偏有界整数，再部分洗牌、排序，得到恰好 d_i 个不同索引。只有 RBC-delivered 名单才能授权工作，每方至多接纳一个；非法交付同样不可被后续名单替换。收齐全部名单不是任何步骤的前置条件。

覆盖失败时允许协议保持 pending，绝不以超时输出 0、扩大恢复委员会、全网恢复或重新抽样。这是显式的覆盖错误事件，概率界至多 2^coverage_bits 的倒数。

## 精确聚合

设 nu = rounding_bits，Delta = 2^(nu+1)，D = 2Delta。消息 M 均匀分布于 [0,D)，WBinAA 精度为 eta = 1/(nD)。当前使用规范 p25519 编码，要求 1 <= nu <= 252；coverage_bits 范围为 1..=256。

系数使用外部原语的 Dyadic（整数 numerator / 2^exponent）。聚合全过程使用 BigUint：

Y = sum(alpha_d * v_d)
Z = ceil(Y) mod D
coin = floor(Z / Delta)

不能用 f64 替代：小于浮点分辨率的正数也可能改变 ceil 的结果。测试覆盖这一边界、模 D 回绕、零系数和等待中的正系数。

成功 AX opening 若揭示 dealer 的 M 不在 [0,D) 中，本身就是可核验的范围违规证据，贡献按 0 处理。任何合法拒绝也按 0 处理。覆盖失败与舍入分歧是分开的统计错误；测试中的同币输出不等同于无条件、零错误的一致性证明。

## 可验证终止

本阶段所有接收方已经拥有相同完整 Public，因此终止证据直接引用 Public 中的字段，不需要额外附 Merkle 字段路径。

- Success：M、R，必须重生成并比对整个记录。
- TrueFault：公开 true token 与对应 wire commitment 不匹配。
- InputFault：token 打开原 input commitment，但不能打开对应 wire commitment。
- GateFault：一个 OR 分支或两个 AND 分支的来源 token 已通过承诺认证，而解出的输出 token 不匹配目标 commitment。
- RootFault：经 output-wire commitment 认证的 token；验证者自行解出候选 M/R，完整重生成不匹配。候选值不是由证明者任意指定。

证据绑定固定 Public 的 digest，按种类精确限定编码长度，最大 106 字节。未知选择器、无效 token、错误上下文、额外字段或伪造拒绝都不能固定值。份额不足产生 pending，不能变成缺乏证据的拒绝。

这组证据对应论文 enhanced-sharing 的局部语义检查。论文最终方案的 storage-fault 证明依赖分条存储；当前完整 Public 已由 WRBC 正确交付，尚未把该存储方案替换进来。

## 配置、端口与私密信道

每方的基础地址来自 Node.net_map。步长 s 默认 n，也可以在参数文件明确指定 port_stride。六个独立端口范围的偏移依次为 0、s、2s、3s、4s、5s，分别用于 WRBC、WRA、WGather、WBinAA、私有回执、恢复。

端口通过上游 Node::with_protocol_port_offset 派生，启动前检查全部已知节点与服务的地址冲突、端口零值和溢出。远程主机 IP 不同，同一个子协议使用相同端口是允许的。上游 TCP 实现绑定 IPv4 wildcard，所以不接受 IPv6 或 unspecified peer 地址；本机回环别名视为相同主机。Node 中的额外同步器地址保持原样，本实现不启动同步器或 client_port 服务。

同一 WRBC 服务用 slot=0 表示 Public、slot=1 表示采样名单，每个 dealer 各两个实例。这是同一个子协议的多实例，不是用一个总端口路由所有协议。WGather 和 WBinAA 各有一个全局向量实例。

session_id、epoch、setup_id、coverage_bits 和 rounding_bits 一起绑定所有组件的调用上下文。Node 的成员、密钥和端口字段仍直接交给外部组件。应用不得为一次新实验复用旧会话配置。

上游 transport 提供 MAC 认证与可靠 TCP，但不加密。因此 network 模块在两个 token 相关服务上增加 AES-256-GCM，利用现有 Node.sk_map 的成对密钥进行组件、方向与会话域分离，并使用 OS 随机 nonce；不引入公钥基础设施。

## 资源、退出与验证范围

上游每服务限制 1024 个实例，本实现每方两个 WRBC 实例，因此单次调用最多 512 方。其他上游存储尺寸约束、WCSS 电路预算和可用端口范围仍适用，超限返回错误。需要扩容时应显式调整上游能力，而不是默默丢实例。

coin 输出不会触发自动垃圾回收。调用方在实验结束后显式停止；若要连续安全运行多个异步调用，需要另外设计完成/回收规则。

Rust 测试使用两种方式：直接组合原语状态机进行可控调度，以及单进程中启动真正的 tokio Context、channel 和 loopback TCP。后者包含六个活动节点和一个静默节点。测试中的超时仅用于检测测试失败，不参与协议决策。

当前未进行 Python 调度、多进程 benchmark、带宽/延迟测量或论文图表生成。完整公开记录广播的基线通信成本不能冒充附件 systematic-striped-storage 优化的复杂度。
