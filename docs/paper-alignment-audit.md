# 论文与 Rust 实现一致性审查（2026-10-05）

结论：在论文的静态腐化、B<T<=W/3、私密认证可靠异步信道和适用资源范围内，当前 WHCC 的协议层主流程与草稿一致。本轮未发现原先“完整 bulk 经外层 WRBC 广播”“仅凭存储完成共享”“局部 BinAA 完成就提前释放 token”“固定关闭恢复名单”等结构性偏差。这个结论是源码对照与回归检查的结果，不是完整安全性证明或所有异步执行的形式化验证。

审查使用本项目 .reference/doc/source/ 中的 model、election、protocol、striped_avid、enhanced_sharing、complexity、security，以及当前工作区。依赖固定为 SDC 731e0b81166125ea756c5a047ab813ccb8af7111；本地 Secure-Distributed-Computing-Protocols HEAD 相同且工作区干净。本文没有修改协议实现。

## 逐阶段核查

| 论文要求 | 实现及结论 |
| --- | --- |
| 固定 n 个 dealer，一次独立采样，RBC 宣告不可变名单 | recovery/src/lib.rs 的 Parameters::new/sample_with/Assignments::deliver。一般权重采用带严格余项上界的有理数 ln 计算保守 a；等权采用论文更紧的整数检验。不放回采样用拒绝采样消除模偏差。样本独立于 AX 的 M、R，无 reroll。 |
| d_i 上限与全局边预算，不等所有名单 | 只接受精确长度、严格递增、范围正确且 context 匹配的首份 RBC 名单。Authorize 只增加边；无全名单屏障，也不按本地 coefficient=0 取消服务。 |
| 小 header 走 WRBC，bulk 走 WAVID | whcc State::rbc_manifest 注册 112 B header 与 32+4d_i B 名单；avid_manifest 对每个 dealer 注册单独 bulk 实例。start_material 将 Public::encode() 交给 WAVID，没有将 bulk 填进 WRBC。 |
| 不带 content tree 的 systematic striped 编码 | SDC Codec::with_params 使用 k=n、q=max(1,ceil(L/(nb)))，storage_counts 为 ceil(3nw_i/W)，连续分配坐标。只补末尾 stripe 零字节；源数据不追加 Merkle 节点。GF8/GF16 系统码保留前 k 坐标为源块，取 field size 严格大于 m。 |
| 先固定 header，再认证收据 | WRBC Deliver 后 Pin WAVID root、Register WRA header_id。提前到达的 bulk 包由 WAVID 保存，在 Pin 前不会产生可用 Stored。Receipt 证明认证上下文、输入 digest 和输入 wire digest，并同时检查 token。 |
| 同一层联合完成，不按 stripe 重复 quorum | bulk WAVID 用 CompletionMode::External，不发送自己的 storage ACK/READY。只有 receipt 有效且 Stored root 匹配才向 WRA Input(true)。WRA 的 ECHO > W-T、READY >= T 中继、READY > W-T 完成，和论文完全相同。 |
| READY 中继者不必持有本地全部材料 | ra_event 在 WRA true 时直接 Shared、Gather Add、WAVID Complete；不会附加“本节点已收到私有收据”的条件。迟到材料仍能触发后续服务。 |
| Gather 具有本地有效性及固定公共核心 | Add 仅由 WRA true 驱动。上游 Inform/Prepare 的 bitmap 必须包含于本地 validated 后才响应/计数；三个控制阶段按权重。输出后仍处理 ACK/PREPARE。公共核心的源码级理由见下。 |
| BinAA 精确近似一致，不逐坐标提前打开 | 上游输入 Vec<bool>，内部精确整数格点，输出 Dyadic=numerator/2^rounds；网络传 coordinate+紧凑 code。只有 finished.len()==n 才 DeliverVector。本项目仅接收完整向量后设置 coefficients。 |
| 授权恢复及一次服务 | Retrieve 在本地名单授权且 header 已固定后登记 want，真正 Request/响应等待 sharing Complete。持有者的 served 集合限制每条边一次响应；token 的 served 和 terminal_sent 分别限制一次发送。 |
| 开放屏障适用于 token 和 terminal | recovery() 首先检查 coefficients 已冻结，再检查 dealer.complete。早到 token/terminal 在每发送者有限槽内保留；未授权 terminal 不产生值，失败证据不锁定值。 |
| 所有 stripe 验证完成才使用 bulk | SDC 每个 stripe 收 k 个不同的已认证坐标，解码后重新编码全部 m 坐标并比 root；检查源 padding。File 只在所有 stripe 成功后发布。编码失败证据使用原始收到的路径，不是错误候选树的路径。 |
| 语义拒绝必须公开可验证 | certified.rs 将 True/Input/Gate/RootFault 所需的常数个字段用 systematic opening 认证。无效 token 不能诬告；AND 必须两输入；RootFault 从认证 output token 推导候选，再检查完整 AX 重新生成和 WAVID root。 |
| 成功只广播短 opening，非恢复者不下载 bulk | Success(M,R) 在本地重建全部 sharing 与 root。正式恢复保存 ValidatedFile，按需开证明；不重新广播整个 Public。其他方验证成功或拒绝无需下载 bulk。 |
| 缺失消息不等于 rejection | 存储片段、header、收据或 token 不足都保持 pending；不生成超时拒绝、替换委员会或全网恢复 fallback。 |
| 本地输出后继续服务 | WHCC Context 的循环不以 coin 已输出为退出条件；上游 WAVID 保留 stored_packet/authorized/served，WRA/Gather/BinAA 也继续服务旧状态。退出由显式 shutdown/benchmark STOP 触发。 |

WRBC 内部使用 WAVID Storage 模式，只是该控制原语自己的实现。它传送的是短 header/名单，不能因此把它误认作 bulk 又进行了一次全网广播。bulk 本身只使用一次 External 联合完成层。

## Gather 公共核心的源码级理由

取最早发送 PREPARE 的诚实节点 p，其先前 INFORM 集合 S 权重 > W-T。p 收到的 ACK 集合 A 权重也 > W-T。A 中诚实 ACK 者在首次诚实 PREPARE 之前就验证了 S，因此它们之后发出的 PREPARE 集合都包含 S。

任一诚实输出收集 PREPARE 的发送者集合 Q 权重 > W-T。A 与 Q 的诚实交集权重严格大于 W-2T-B，因 B<T 和 W>=3T 而为正。因此该输出的 PREPARE 并集中包含 S。S 在首次诚实输出前已固定、权重 > W-T，且每个输出由本地已验证 dealer 组成。这符合论文要求的公共核心；不要求每个节点输出完全相同的 G_i。

## BinAA 阈值和表示

WRA/Gather 使用严格 >W-T；BinAA 的 ECHO1 认证、ECHO2 决定阶段使用 >=W-T，弱中继使用 >=T。不能因为符号不同就统一替换：BinAA 在 B<T 下的 quorum 诚实交集仍满足 W-2T-B>0，其规则不同于 WRA 的联合完成接口。

round_count 为 ceil(log2(1/eta))。紧凑 code 是相对格点差值编码，不是浮点截断或更低精度输出。旧轮状态仍可处理中继、提前未来轮消息有独立 sender 槽。本项目等待整向量，并以精确大整数实现 dyadic 求和、ceil、取模；未把有序数值运算替换为有限域运算。

## 必须在论文/结果说明中明确的差异

### 1. 多比特输出是对草稿的扩展

草稿 protocol.tex 写单比特，Delta=2^(nu+1)、D=2Delta。代码令 q=output_bits，使用同一 Delta 和 D=2^q Delta，eta=1/(nD)，输出 floor((ceil(sum alpha_d v_d) mod D)/Delta)。q=1 时退化为草稿公式。

在参考 residue 均匀且共享值固定等组合前提成立时，仍有 |Y_i-Y_j|<1；多比特输出有 2^q 个边界，坏区域比例至多 2*2^q/D=2/Delta。这个代数对应关系并不替代草稿所缺的联合隐私/提取证明。论文需要补写该扩展，并将 q（输出位数）与 lambda（hash/token 安全参数）分开。当前 hash/token 是 32 B，q 通常为 128；AX 要求 q+nu+1<=254，默认 nu=64 时 q<=189，不能声称当前配置可任意输出 256 位。

### 2. benchmark 的 STOP 不是论文的安全垃圾回收

node/synchronizer/state.rs 在相同值 FINISH 权重 >T 时记录结果。这个条件保证其中至少一方诚实，不保证所有诚实节点已完成，更不保证所有授权边已服务完毕。随后 STOP 会终止未完成的节点。

这是用户指定的 benchmark 完成口径，不能据此宣称完整异步服务义务已经完成。核心 Context 在不 STOP 的情况下会继续服务，且有迟到名单/收据测试。要测论文 all-prescribed-honest-sends 的通信量，应另有统计口径或单独的完成/服务收尾方案；不能用固定等待秒数冒充异步模型中的安全回收。

### 3. 实际 TCP 重传不受论文的逻辑消息次数上界直接约束

SDC util/src/weighted_sender.rs 的 STALL=5 秒，重连时重发所有未确认帧，并持续 retry。一个腐化接收者可以接收帧后不给有效应用 ACK、反复断开，让诚实发送者不断重发；这是有限协议 send action 之外的真实字节开销。去重保证协议消息不会重复生效，但不抹去已发送字节。

因此，一次每 edge 的应用发送预算和 tilde-O(n^3) 的理想信道通信分析仍可对应；当前抓包包含重传，不能给出任意恶意 TCP 行为下相同的有限 wire-byte 上界。宜将“协议逻辑序列化字节/发送次数”和“实际 TCP payload/重传”分列。本次审查没有改变重传机制，因为简单限次会损害无已知时延界时的可靠交付。

### 4. 草稿本身保留安全组合义务

security.tex 明确没有完成 enhanced sharing 的 joint ROM 或 UC 证明，尤其是首个诚实 token 释放前的联合隐私、恶意 contribution 的前缀提取，以及 Gather/BinAA 在同一模型中的组合。源码状态机和测试可以检查必要屏障与谓词，不能把这些义务升级为“完整证明已成立”。

此外，固定 32 B hash/编码块、最多 512 个参与方（每方需要两个 WRBC 实例）、编码文件/电路门数资源上限都是有限实现配置，不表示支持理论参数的任意增长。

## 本轮验证与定位

本轮未修改 Rust/Python 协议代码。执行 cargo test --workspace --locked（64 项）以及 cargo test -p wgather -p wbinaa -p wra --lib --tests --locked（12 项），全部通过。相关测试覆盖共享收据与 Stored 的合取、严格阈值、低权重的拜占庭物理多数、BinAA 所有二元输入模式/未来轮/恶意不一致投票/迟启动、完整向量屏障、恶意编码与语义拒绝、输出后迟到名单及收据、coverage failure 持续 pending。源码审查另覆盖本次升级的 WAVID 增量恢复、proof provider 和 transport 窗口。

关键代码定位：

- 本项目 consensus/whcc/src/protocol/state.rs:144、162、196、242、269：实例、启动、Gather、BinAA。
- 本项目 consensus/whcc/src/protocol/sharing.rs:12、57、85、179：header、WRA completion、WAVID event、联合收据。
- 本项目 consensus/whcc/src/protocol/recovery.rs:14、56：有限槽、屏障、授权发送和验证。
- 本项目 consensus/wiawvss/src/protocol/certified.rs：systematic source 字段认证和 VOpen。
- 上游 dissemination/wavid/src/protocol/{state,ready,retrieve,codec,stream,file}.rs：两种完成模式、一次服务、编码验证及 lazy proofs。
- 上游 consensus/wgather/src/protocol/gather.rs:3；consensus/wra/src/protocol/ready.rs；consensus/wbinaa/src/protocol/{state,binaa}.rs。
- 上游 util/src/weighted_sender.rs:5、76、145：无时限重试与重放；本项目 node/src/synchronizer/state.rs:56：benchmark 完成阈值。

源码版本变化后需要重新对照这些条件；本次结论不覆盖后续未审查改动。
