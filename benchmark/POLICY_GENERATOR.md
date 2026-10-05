# 命令行 policy 生成任务

在 benchmark/ 目录使用 fab policy。任务只生成配置；只有第 4 类需要自动编译并调用 Rust 门数评估器，不启动分布式节点或采集性能数据。

~~~sh
fab --help policy
~~~

## 四种枚举

| --distribution | 含义 | 约束 |
|---:|---|---|
| 1 | 完全等权 | W 必须整除 n；否则明确报错 |
| 2 | 大致等权但不可约 | gcd(w_0,…,w_{n-1})=1，总和精确等于 W |
| 3 | 少数极大权重 | 所有 party 的权重都不超过 F，重节点权重严格大于轻节点 |
| 4 | W=n^n 下尽量增大门数 | 调用实际 Circuit::build 评分，保留启发式搜索中的最佳实例 |

这里的“不可约”按已约定的含义，仅指全部权重的最大公因数为 1，不表示加权访问结构不存在更小的等价权重表示。

例子：

~~~sh
# 1. 完全等权，每节点 1000。
fab policy --nodes=16 --total-weight=16000 --distribution=1 --output=policies/equal16.json

# 2. 近似等权、gcd=1；该例生成 999、1001 以及十四个 1000。
fab policy --nodes=16 --total-weight=16000 --distribution=2 --output=policies/coprime16.json

# 3. 三个重节点，目标合计占 80%；默认 T=floor(W/3)，F=T-1。
fab policy --nodes=16 --total-weight=16000 --distribution=3 --heavy-count=3 --heavy-share=0.8 --output=policies/heavy16.json

# 4. 固定 W=16^16，使用默认搜索预算。
fab policy --nodes=16 --distribution=4 --output=policies/max-gates16.json

# 小规模快速试用；仍按真实门数评分。
fab policy --nodes=4 --total-weight=n^n --distribution=4 --samples=24 --steps=64 --output=policies/max-gates4.json
~~~

第 2 类先尽量平均分配。W 不能整除 n 时采用相邻整数；能整除且 gcd>1 时做保持总量的小调整。n≥3 时最大最小权重之差不超过 2；n=2 的特殊整除情形可能需要差 4。W=n 时全为 1，已经满足 gcd=1，不强行生成不可行的非等权分布。

第 3 类默认 heavy_count=min(3,(n−1)//2)，重节点位于前几个 party ID，其余权重在轻节点内尽量平均。--heavy-share 是目标比例，可用十进制或有理数，例如 0.8、4/5。当目标超出 F 或正整数分配的可行范围时，会调整到可行边界，并在控制台和 report 中保存 requested_share、achieved_share、capped。若仍无法让重节点严格大于轻节点，则报错，不静默退化为等权。

例如 n=4、W=400、F=132 时，一个重节点最多占 33%，无法占 80%；生成器会明确报告这一限制。n×F<W 时，无论采用什么分布都无法使全部单节点权重≤F，直接拒绝。

第 4 类的 --total-weight 可省略，或写 n^n、与 n^n 相等的十进制/十六进制整数；不能填写其他总权重。默认 samples=480、steps=4096、seed=20261005。会自动编译 count_gates 示例程序，以等权以及本地已有的同 n、同 W、同 T 配置作为起点；已有配置的门数会重新计算。它也支持指定较低的合法 T，搜索时不会偷偷改回 W/3。门数是当前构造器化简、复用、裁剪后的结果，不保证全局最优或最大实际延迟。

## 权重池输入

--pool 与 --distribution 必须二选一。权重池不是额外作用在枚举上的过滤器。支持：

- JSON 权重数组，例如 [100,300,900]。
- 仅包含 weights 字段的对象，例如 {"weights":["100","300","900"]}。
- Aptos 的 0x1::stake::ValidatorSet 原始 JSON。
- 本项目已有的固定账本快照目录，含 snapshot.json、validator-set.json、ledger-info.json、reconfiguration.json。

大整数建议写成字符串；整数、小数、指数数字的处理不会混淆：浮点权重会被拒绝，不会截断成整数。

~~~sh
# 使用带账本版本及哈希的 Aptos 快照；推荐这种输入。
fab policy --nodes=31 --total-weight=93000000 --pool=data/aptos-mainnet-v7479751174 --output=policies/aptos31.json

# 也可读取原始 ValidatorSet；没有附带账本版本时不会编造版本信息。
fab policy --nodes=16 --total-weight=48000000 --pool=data/aptos-mainnet-v7479751174/validator-set.json --output=policies/aptos16.json

# 用户自行准备的 JSON 权重池。
fab policy --nodes=4 --total-weight=40000 --pool=data/my-weights.json --output=policies/pool4.json
~~~

映射使用排序后经验分位函数的等区间积分，再按目标 W 用最大余数法整数化；既可减少也可增加 party 数量。生成后的 party ID 表示映射后的排序位置，不对应原链验证者身份。要求权重为正整数且精确求和为 W；若目标 W 太小而产生零权重，会拒绝并提示增大总量。

Aptos 当前集合取 active_validators+pending_inactive，不包含 pending_active。快照目录会校验资源哈希、网络、账本版本、epoch、地址唯一性及总权重。原始资源单文件只能校验其内容，不能据此推断账本版本。源文件会复制进生成记录，整个过程不访问链上最新数据，也不修改输入文件。

权重池与其他枚举不受第 3 类的“每个 party≤F”约束，以免擅自改变真实分布；实际选出的拜占庭集合仍必须满足 B≤F。

## 共用选项与输出

- --nodes：2..512，并受协议及 4096 位总权重限制。比如某些较大 n 的 n^n 会超过该限制，明确拒绝。
- --total-weight：精确正整数，至少为 n；也接受十六进制和符号 n^n。除第 4 类之外必须填写。
- --threshold：协议门限 T，默认 floor(W/3)；要求 0<T≤W/3。
- --fault-weight-threshold：实际故障预算 F，默认 T−1；要求 0≤F<T。第 3 类也把 F 用作单节点权重上限。
- --fault-case：honest（默认）、stress、both。stress 使用已有 recovery-stress 行为与 max-count-one-swap-v1 选择器，不声称全局最大腐化权重；没有可容纳的拜占庭节点时拒绝生成 stress。
- --runs：默认 1。both 生成两个 case，每个分别运行 runs 次。
- --output-bits：默认 128，rounding_bits=64、coverage_bits=40。
- --experiment-id：可显式指定实验组名；默认 generated-weights-v1。不要将不同搜索预算或不同权重实例误并为一个统计点。
- --output：输出 policy 路径，所有相对路径都相对于当前命令目录。省略时生成到 policies/，文件名包括分布、节点数和请求摘要。
- --overwrite：明确替换已有 policy 及其配套生成记录；默认遇到已有输出会报错。校验失败不会发布半成品或破坏原 policy。

~~~sh
# 同时生成诚实和压力配置，每个 case 运行三次；指定容错参数。
fab policy --nodes=16 --total-weight=16000 --distribution=3 --threshold=5000 --fault-weight-threshold=4999 --fault-case=both --runs=3 --experiment-id=heavy-study-v1 --output=policies/heavy-study.json

# 后续真正开始实验时再运行：
fab local --policy=policies/heavy-study.json --output=file
~~~

生成 example.json 时，同目录生成 example.generation/：

- report.json：请求参数、精确权重、W/T/F、gcd、分布统计、算法详情、源码哈希及 policy 哈希。
- source/：权重池原始文件副本（若使用）。
- n*.jsonl、n*-best.json、search-baselines.json：第 4 类的实际评分记录、最佳结果及本次使用的初始候选。

policy 自身的 metadata 包含分布参数、算法、源快照信息、生成详情和每个 case 的真实腐化权重 B，可由现有 fab local 直接读取。生成时会校验现有配置解析器和各子协议端口。

本次已通过实际 Fabric 命令验证四种枚举及 Aptos 快照输入，共生成并检查 10 个 honest/stress case；均通过 node check-config。Python 回归测试共 56 项通过。验证没有运行分布式协议。
