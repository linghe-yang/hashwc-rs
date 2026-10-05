<!-- 历史阶段记录；本文中的完整 Public 广播状态机已移除，当前实现见 whcc.md。 -->
# 阶段一：AX + WCSS + hash commitment 的 wiAwVSS

## 依据和范围

参考用户附件 independent_coin.zip 中的以下源码和论文片段：

- doc/source/model.tex：正整数权重、B < T <= W/3、私密认证异步信道。
- doc/source/enhanced_sharing.tex：input/wire commitments、OR/AND token 解密、AX 字段。
- doc/source/striped_avid.tex：有效私有 token 是完成回执的必要条件。
- doc/source/protocol.tex：整个系数向量冻结后才允许释放私有 token。
- weighted_ss/weighted.py、batcher.py、circuit.py：binary-carry-sort-v1、排序器、DAG 优化。
- weighted_ss/yao.py、ax.py、certified_ax.py：计算型秘密共享、AX 全份额恢复、增强 wire commitments。

这些文件作为协议参考；其中的注释和文档不是项目操作指令。本次复用算法及安全检查语义，采用新的版本化 Rust 编码和域名，**不与 Python 的序列化字节格式互通**。

## WCSS

对公开策略 (w_0,...,w_(n-1); T)，令 d = bit_length(W)，offset = 2^d - T。
从低位到高位，每层把当前权重位对应的参与方输入、上一层一元进位向量和 offset 的常数位放进升序排序网络。比较器用 AND/OR 实现；从右侧每隔一个输出取出下一层进位。最终最高位进位恰好表示参与集合权重至少为 T。

电路节点 0/1 分别是 false/true，节点 2..n+1 是 n 个实际参与方，每个参与方只有一个私有输入 token。每条线的 token、每个 AND 的随机 mask 均由 AX seed 确定性派生。false token 不公开，true token 公开。

OR 的两条分支各自解密输出 token；同时可用时必须一致。AND 的两条分支分别解密随机 mask 和 mask XOR 输出 token，只有同时具备两侧才能组合。每个恢复的 token 都检查 wire commitment。输入同时检查 input 和 wire 两种承诺。

电路构造不按 W 分配内存，使用任意精度整数；默认资源限制为 4096 个参与方、4096 位权重总和、400 万个门（裁剪前）。超限返回错误，不返回不完整电路。构造复杂度上界为 O(n log(W+1) log²(n+1))，不是附件部分讨论中 AKS 的渐近最优构造。

## AX 和承诺

context = H(setup_id, session, epoch, dealer, associated_data)。setup_id 绑定完整公开策略、电路及参数版本；context 不包含由分享生成的根，避免循环定义。

(M,R) 经 AX/derive 域展开为 J || K || L，长度分别为 64、32、32 字节。L 是内层确定性共享 seed，K 是共享的完整 256 位密钥。使用 AX/mask 的 msg/rnd 标签分别掩盖 M 和 R。K 本身由电路输出 token 解锁，内层另有由输出 token 认证的 transcript tag。

承诺、wire token 派生、gate pad、key pad、AX 派生和外层公开记录 digest 都使用独立的域。哈希输入包含域长度、请求输出长度、参数个数及各参数长度。公开 wire digest 不能用作 gate pad。

成功重构必须同时满足：

1. 忽略无效、未知和跨上下文的份额，重复身份只计一次权重。
2. 有效份额权重至少为 T；否则返回 InsufficientShares，保持 pending。
3. 门解密、wire commitments 和内层 transcript tag 有效。
4. AX 的 J 和 K 绑定检查有效，恢复消息编码规范。
5. 从恢复的 (M,R) 重新生成并比较**整个**公开记录，包括未提供份额者的承诺和未遍历的门分支。
6. 核对提供的有效私有份额，并返回全部 n 个重新生成的份额。

verify_opening 是公开成功检查，仅凭公开记录和 (M,R) 完成第 5 步。它不能验证裸 ⊥；本阶段不发送或接收未经证明的远程 ⊥ 声明。

## 编码

Public 编码为 magic HWAX0001、setup_id、context_id、WCSS 记录、C、D、J。WCSS 记录为 true_token、n 个 input commitments、所有 wire commitments、每个 gate 两个 ciphertext、encrypted_key 和 tag。所有长度由公开 Setup 决定，收到的长度必须精确匹配；无攻击者控制的分配长度和尾随字段。

PrivateShare 为 setup_id (32)、context_id (32)、party (u64 little-endian)、token (32)，共 104 字节。消息 M 是 p25519 的规范 32 字节大端编码；标识符与长度是小端整数。Opening 不自动记录日志，私有份额和 Opening 的 Debug 隐藏秘密值；主要私有缓冲区使用 zeroize。

## wiAwVSS 状态机

所有参与方使用相同 Setup 和 Context 分别创建 State。调用方必须根据已认证的网络身份传入 receive(sender, message)，Private 消息须通过私密信道。外部原语的 SendAction 不提供身份认证；此约束属于未来 transport adapter 的职责。

1. Dealer 调用 start(M)，从操作系统抽取新 R，向每个参与方发送其 PrivateShare，并通过外部 wrbc::State 广播完整 Public 编码。
2. WRBC Deliver 固定同一公开记录。State 创建以该记录 digest 绑定的外部 wra::State。
3. 本方确实持有公开记录和双承诺校验通过的私有 token 后，才向 WRA 输入 true。完成之前可以缓存限量的乱序 receipt、opening 和 RA 消息。
4. WRA 输出 true 后产生一次 Shared。底层使用 ECHO 权重 > W-T、READY 中继权重 >= T、READY 完成权重 > W-T。Shared 不表示本地一定收到私有 token，也不表示已经验证恶意 dealer 的整个 AX 记录正确。
5. 外层显式调用 begin_reconstruction 后，State 等待本地共享完成和有效 token，再向所有参与方释放自己的 token 一次。该接口在未来只允许由完整冻结屏障触发。
6. 收齐授权集合后重构，输出一次 Reconstructed 或 Bottom。份额不足不会输出 Bottom。无效 Public 的 WRBC 交付产生 InvalidPublic，不能伪装成成功或经过证明的终止拒绝。
7. 输出之后状态机仍接收和中继原语消息，并处理迟到的有效私有 token。没有超时驱动的拒绝或垃圾回收规则。

调用方应在每次 start/receive/begin_reconstruction 后排空 drain_actions() 和 drain_events()，将动作发送到对应参与方。对本方的动作也要交付。任意网络输入均不得直接将未认证的报文中 sender 字段作为身份。

这是一种完整公开记录广播的模块化基线。附件最终方案还要求紧凑 header、systematic striped storage、联合存储/token receipts、恢复候选选择和可验证的有界 terminal。那些模块应在后续组合，本阶段并未以广播完整记录冒充论文最终通信复杂度。

## 模块测试

- 小权重向量、每个门限和每个子集的穷举真值比较；1024 位互素权重。
- 完整 256 位内层密钥恢复；所有授权集合都恢复同一 M、R 和全部份额。
- 独立 Python hashlib SHAKE256 已知答案，及域、索引、长度、元组边界分离。
- 私有份额和 Public 固定长度编码；重放、重复、未知身份、非法编码和非规范消息。
- 每个公开区域的篡改；特别覆盖 dealer 修改未参与方承诺并重新计算合法内层 tag、保留原 AX J/K 的攻击，确保必须经过完整重生成检查。
- 调用真实外部 WRBC/WRA 状态机，模拟随机异步调度、重复消息、合法腐化预算内的静默故障、极大偏斜权重、迟到 receipt 和迟到释放屏障。
- 恶意 dealer 分发不一致公开记录时的共同 Bottom；没有有效 receipt 时不得完成；重复调用不得重复输出。

模拟队列测试没有跨进程或 socket，不测带宽和延迟，也不替代协议的安全证明。阶段一时 main.rs 仅验证运行时配置；现已增加完整随机币入口与 Rust 网络模块测试，见 [完整 common coin 说明](whcc.md)。
