# hashwc-rs

加权 hash-based 随机币的 Rust 实现。当前完成第一阶段：**WCSS + AX + hash commitment 的 wiAwVSS**。

项目使用 Rust stable（本次验证为 1.99.0）和 Rust 2024 edition。旧版 Narwhal/Tusk、beacon、Rubato、DPSS、DAGRider、存储、网络实现和 Python benchmark 已移除，Cargo.lock 已重新生成并应纳入版本控制。协议通过配置或命令行选择，不再使用协议 feature 开关。

## 目录

| 目录 | 职责 |
| --- | --- |
| types | 任意精度整数权重、访问策略、实例标识及错误语义 |
| crypto | SHAKE256、带域分离的 input/wire commitments、加密掩码 |
| config | JSON 配置及运行时协议选择 |
| consensus/wcss | 按二进制权重构造单调电路、token 共享和重构 |
| consensus/wiawvss | AX 全份额恢复、完整记录核验、WRBC/WRA 组合状态机 |
| node | main.rs 命令入口、毫秒时间戳日志 |

外部 WRBC、WRA 来自 [Secure-Distributed-Computing-Protocols](https://github.com/linghe-yang/Secure-Distributed-Computing-Protocols/tree/79e905a8bcd6d3fc0a5423f8cfcb383ad33a919e)，固定提交为 79e905a8bcd6d3fc0a5423f8cfcb383ad33a919e。它们使用的 WAVID 及传递依赖由 Cargo 引入。本项目未重写这些原语；外部库自身的旧版传递依赖仍由它维护，已验证可与当前 stable 共同构建。

## 使用

在项目目录中执行（WSL/Linux）：

~~~sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo run --locked -p hashwc-node -- check-config --config config/examples/local.json --protocol wiawvss
~~~

check-config 会读取配置、检查异步模型约束、构造公开电路，并输出参数统计；它不是分布式运行或性能测试。JSON 的 protocol 也可选择协议。目前只有 wiawvss 一种；未知协议会被拒绝。

日志沿用 log + env_logger，总是启用毫秒时间戳，支持 RUST_LOG 和 -v。状态机记录 shared、reconstructed 和 bottom 事件及 party/dealer/epoch，不记录秘密、token 或 AX 随机数。

## 当前实现边界

- 使用公开正整数权重，不展开成虚拟节点。WCSS 支持任意合法门限；异步 wiAwVSS 额外要求 0 < T <= W/3，实际腐化权重必须满足 B < T。
- WCSS 使用参考实现中的 binary-carry + Batcher odd-even 排序网络，并做常量折叠、公共门复用和不可达门裁剪。规模依赖参与方数量和权重位长。
- 采用 256 位 token、SHAKE256 域分离哈希、规范的 32 字节大端 p25519 消息编码。AX 内层共享完整 256 位密钥，不对密钥取模。
- 重构有效份额不足返回 InsufficientShares，继续等待；授权集合发现不一致返回 InvalidCommitment，对应本地 ⊥。成功恢复消息、随机数及所有参与方的份额。
- 本阶段的 wiAwVSS 使用 WRBC 固定**完整公开记录**，在持有公开记录和有效私有 token 后向 WRA 输入 true。其额外通信成本不能用于声称已达到附件新版 striped-storage 的复杂度。
- State 是可接入异步网络的独立参与方状态机。模块测试真实调用外部原语的状态机，通过队列模拟私密认证信道、乱序、重复和静默故障；尚未实现 TCP 驱动或执行多进程测试。
- begin_reconstruction() 是显式释放接口。后续随机币必须在整个 BinAA 系数向量冻结后调用，不能因共享完成就提前调用。此阶段没有实现外层随机币、WGather/BinAA 编排、恢复委员会、systematic striped 存储和终止证书。
- Python local benchmark、result 数据、带宽/延迟统计及 plot 留待后续阶段。当前未输出随机币性能数据。

接口、状态语义、编码与论文对应关系见 [阶段一协议说明](docs/phase1.md)。

当前工作目录没有 Git 元数据。清理前的项目已存放于本地 .reference/legacy-project.tar.gz，仅供回溯，不参与构建；附件的参考源码也放在被忽略的 .reference/ 中。
