# 按实际电路门数搜索的大权重 policy

本实验固定 n∈{4,16,31,46,64}、W=n^n、T=floor(W/3)，优化当前生产 Rust 电路在常量化简、同门复用和输出裁剪之后的门数。所有权重均为正整数。未改变协议、电路构造器或安全参数；尚未运行这些配置的分布式 benchmark。

这不是“最坏性能必须满足 W=O(n^n)”的证明。O(n^n) 是渐近上界写法，不给出具体最大值；这里将 W=n^n 作为明确的实验约束。没有搜索所有 W≤n^n，也没有证明最优门数必定出现在该范围的边界。大整数的位模式会影响门的复用和裁剪，所以 W 与门数不必单调。

## 搜索方法

- 评分器为 [count_gates.rs](../consensus/wcss/examples/count_gates.rs)，直接调用生产环境的 Circuit::build，评分就是 circuit.gates().len()。没有另写一套近似门数模型，也没有为了增大统计数字关闭化简。
- 每个 n 先评估上一轮 uniform-npow、dense-npow、aptos-npow 三个基线，保证保留的最佳值不差于这些基线。
- 生成 480 个二进制列候选，尝试 25/40/50/60/70/80/85/90/93/95/97/99% 的目标置位密度。这些百分比指导随机列的数量，最终数值由总权重约束修正，不表示最终权重精确服从某个密度。
- 若低位处理后剩余目标为 R，当前列选 c 个 party 置位，要求 c 与 R 同奇偶、0≤c≤min(n,R)，下一列剩余目标为 (R−c)/2。由此直接保证权重和为 n^n，避免归一化破坏精心构造的位模式。
- 然后进行 4096 次变异提案：调换 party 顺序、交换不同 party 的二进制位、保持总量的权重转移。保留门数最高的 12 个候选，既改进当前最佳，也从其他候选出发。
- 零权重及重复候选不计作实际评分。因此每个 n 的 evaluated 可以小于 480+4096+3。
- 固定总 seed=20261005，每个 n 使用 seed+n×1009。并行只用于不同 n，不影响各自的候选顺序或选择结果。

这些数值衡量当前构造器产生的门数，不是该访问结构所有等价布尔电路中的最小门数。以后若加入新的电路化简或等价权重约简，需要重新搜索和测量。

启发式算法输出的是 best found，不声称全局最优。本工作也未证明这个特定“生产电路门数最大化”问题是 NP-hard；采用启发式是为了在可控的搜索量内获得更大的实例。

## 结果与 policy

最终门数、与旧基线的比较、实际评分次数和 public record 大小见本文末尾的实测表。

- [policies/weights-gate-search.json](policies/weights-gate-search.json)：五种节点规模的合并策略。
- [policies/gate-search/](policies/gate-search/)：n4.json、n16.json、n31.json、n46.json、n64.json，便于分别运行。
- 每个规模包含 honest 和 recovery-stress，两种配置使用完全相同的权重与门限。共 10 个 case，每个 runs=3，完整运行会生成 30 次 coin。
- 输出 128 位、rounding_bits=64、coverage_bits=40。权重位长和 coin 输出位长是独立参数。
- F=T−1；stress 名单沿用 max-count-one-swap-v1：精确最大化预算内可腐化节点数，再做增重的单次替换，实际 B≤F。它不是全局最大腐化权重或全局最坏敌手的证明。
- 权重以十进制字符串保存，生成 upstream Node 配置时用十六进制，无浮点截断。
- 维持独立子协议端口和 synchronizer 端口；case 顺序运行。

[data/gate-search/report.json](data/gate-search/report.json) 保存最终权重、最佳来源、提升过程、随机种子、搜索量、三个旧基线的实测值，以及源码和评分器哈希。每个 n 的 JSONL 文件记录所有实际评分的候选摘要和门数；n*-best.json 保存单独报告。最终权重顺序也属于配置，不能在使用前再次排序。

[data/gate-search/verification.json](data/gate-search/verification.json) 使用真实 node check-config 和 upstream Node JSON 重新检查最终配置，交叉核对搜索门数、实际 setup 门数、权重和、门限、故障预算及 trace 哈希。这些检查不启动网络服务。

## 复现与后续 benchmark

在仓库根目录编译评分器：

~~~sh
cargo build --release --locked -p wcss --example count_gates
~~~

在 benchmark/ 中重新搜索：

~~~sh
python3 -m benchmark.gate_search
~~~

默认 480 次初始提案、4096 次变异提案、3 个独立搜索 worker。可使用 --samples、--steps、--workers 调整；固定代码、种子和预算时，权重和门数可复现。elapsed_seconds 仅是离线搜索耗时，不是 coin 延迟。改变预算得到的策略应作为新实验保存，避免与旧结果混淆。

后续启动分布式测试时可使用：

~~~sh
# 先独立运行某个规模；此次没有执行以下任务。
fab local --policy=policies/gate-search/n4.json --output=file
# 或顺序运行全部 10 个 case。
fab local --policy=policies/weights-gate-search.json --output=file

# 所有规模结果齐备后绘图。
fab plot --config=plot-configs/weights-gate-search.json
~~~

新绘图配置显式使用 n_pow_n 模式：它表示节点数和权重同时增长的压力测试，不能替代固定平均权重的节点扩展性曲线。门数是本次优化目标；真实延迟还受并行度、WRBC 编码、恢复路径、主机竞争等影响，不能将门数倍数直接当作延迟倍数。public_bytes 是单个 dealer 的 public record 编码大小，不是全协议总通信量。

## 本次搜索实测

| n | W 位数 | 旧三种分布中的最高门数 | 本次门数 | 倍数 | 实际评分候选数 | 单 dealer public_bytes |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 9 | 47 | 111 | 2.362× | 2444 | 11272 |
| 16 | 65 | 7761 | 17520 | 2.257× | 4239 | 1683304 |
| 31 | 154 | 58199 | 124246 | 2.135× | 4568 | 11929960 |
| 46 | 255 | 170001 | 396242 | 2.331× | 4576 | 38042536 |
| 64 | 385 | 441052 | 885186 | 2.007× | 4579 | 84982312 |

总计评估 20406 个不同候选。4 节点最终有序权重为 [15,59,63,119]，W=256，T=85；其余完整大整数权重见各 policy。

最终 10 个 case 全部通过真实 node check-config，搜索评分与 setup 门数一致。47 项 Python 测试、4 项 WCSS 模块测试及 Rust clippy 静态检查通过。未运行分布式 coin，也未声称上述门数倍数就是延迟或通信量倍数。
