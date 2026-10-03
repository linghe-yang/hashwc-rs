# hashwc-rs

基于 AX、WCSS 和 hash commitment 的加权 common coin。Rust stable / 2024 edition，已在 Rust 1.99.0 上验证。程序从 main.rs 启动，运行方式由命令行和参数文件决定，不使用协议 feature 分支。

## 组成

| 目录 | 职责 |
| --- | --- |
| consensus/wcss | 不展开虚拟参与方的加权电路秘密共享 |
| consensus/wiawvss | AX、完整份额恢复、共享状态机、可验证终止证据 |
| consensus/commoncoin | context.rs 异步入口、共享完成、Gather、整向量 BinAA、恢复和聚合 |
| recovery | 每方本地独立采样、配额计算、一次性 RBC 名单接纳 |
| network | 私有份额及恢复消息的加密通信封装 |
| config | 直接重导出外部 Node，读取节点文件，检查子协议端口 |
| types / crypto | 公开策略、实例标识、哈希及承诺 |
| node | main.rs，配置检查和单次随机币运行 |

consensus 各 crate 的具体算法和状态机统一放在 src/protocol/。src/lib.rs 负责模块声明与公开接口重导出；异步入口、消息定义及动作分发分别放在 context.rs、msg.rs、process.rs（按需提供）。WCSS 是同步原语，不额外设置异步入口。

为方便科研测试，本项目自有结构体的字段统一使用 pub，便于直接构造、查看和修改状态；外部依赖保持原样。

WRBC、WRA、WGather、WBinAA 直接使用 [Secure-Distributed-Computing-Protocols](https://github.com/linghe-yang/Secure-Distributed-Computing-Protocols/tree/79e905a8bcd6d3fc0a5423f8cfcb383ad33a919e)，固定提交为 79e905a8bcd6d3fc0a5423f8cfcb383ad33a919e。本项目未重新实现这些原语。运行时调用它们的 Context，通过 tokio channels 交互，各自拥有独立网络服务。

## 验证与入口

~~~sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
cargo run --locked -p node -- check-config --config config/examples/local.json --parameters config/examples/coin.json
~~~

每个节点的配置文件是外部 crate 的 config::Node，包含 net_map、weights、weight_threshold、session_id、sk_map 等原有字段。没有自建替代 Node 的结构体。节点的公开成员顺序、权重、门限和 session_id 必须一致；sk_map 中成对共享的 32 字节密钥须在对应两方一致。

config/examples/local.json 是节点 0 的格式示例，含演示密钥，只用于配置检查。运行实验时需要生成完整的各节点配置和新会话标识；不能只复制该文件修改 id。

独立的 common coin 参数文件仅包含：

~~~json
{
  "epoch": 0,
  "coverage_bits": 40,
  "rounding_bits": 64,
  "port_stride": null
}
~~~

参数的含义及接口见 [完整随机币说明](docs/commoncoin.md)。准备好各方 Node 配置后，每方入口是：

~~~sh
cargo run --release --locked -p node -- run --config path/to/node0.json --parameters config/examples/coin.json
~~~

run 输出一次随机币后继续服务迟到的参与方，直到显式中断。这里只提供 Rust 运行入口；未创建或修改 Python benchmark，也未执行多进程性能实验。

## 独立端口

设节点 i 的 net_map 基础端口为 b_i，步长 s 默认等于参与方数 n：

| 服务 | 端口 |
| --- | --- |
| WRBC：公开共享记录与采样名单 | b_i |
| WRA：共享完成 | b_i + s |
| WGather | b_i + 2s |
| WBinAA | b_i + 3s |
| 私有份额 | b_i + 4s |
| 恢复 token 与终止证据 | b_i + 5s |

本地用相同 IP 和不同基础端口，例如 20000+i；远程用不同 IP 和相同基础端口，例如各主机均为 20000。端口通过 Node::with_protocol_port_offset() 派生。启动前检查跨节点、跨服务冲突及 u16 溢出。因上游监听器使用 IPv4 wildcard，要求显式 IPv4 peer 地址，loopback 别名按同一主机处理。

私有份额和恢复通道在上游 MAC 认证 TCP 之上增加 AES-256-GCM 加密；密钥绑定组件、会话、发送方和接收方。没有要求公钥、证书或额外可信设置。

## 协议范围

当前已经实现完整的单次随机币控制流程：独立采样并 RBC 声明 → wiAwVSS 共享完成 → WGather → 整向量 WBinAA 冻结 → 定向恢复和可验证终止 → 精确整数聚合。条件为静态腐化、私密认证可靠异步信道、实际腐化权重 B < T <= W/3。

当前继续使用阶段一的**完整公开记录 WRBC**。这实现了随机币的恢复和终止语义，但不是附件最终的 compact-header / systematic-striped-storage 优化。上游 WRBC 内部虽使用 WAVID，也不能据此声称已实现论文该优化的通信复杂度。

Rust 测试包括确定性消息调度、静默故障、恶意 dealer、伪造拒绝、迟到名单和冻结屏障；另有单进程 tokio + loopback TCP 测试，实际启动每方六个独立服务。它们不是多进程 benchmark，没有输出带宽或延迟实验数据。

日志沿用 log + env_logger，毫秒时间戳；共享完成、Gather、冻结、终止和 coin 输出均记录公开事件，不记录私有 token、AX 随机数或尚未公开的贡献。

历史阶段一说明见 [phase1.md](docs/phase1.md)。清理前的旧项目和附件参考代码保存在被忽略的 .reference/ 中，不参与构建。
