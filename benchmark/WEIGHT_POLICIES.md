# Aptos 真实分布与 W=n^n 权重实验

本次只制定 policy、保存原始数据并离线检查电路；没有运行这些 policy 的分布式实验，也没有产生性能结果。

## 数据来源与快照

直接读取 Aptos 官方主网 REST 接口的 0x1::stake::ValidatorSet，使用 voting_power 作为权重。固定 ledger_version=7479751174，epoch=17519，chain_id=1。账本时间为 2026-10-04 21:11:56.596（Asia/Shanghai）。

- 当前集合：active_validators + pending_inactive。待退出者在本 epoch 仍有投票权。
- 不包含 pending_active；它们尚未在本 epoch 加入。
- 这次 active=85、pending_inactive=0、pending_active=0。
- 总权重：75479730360415546 octa，即 754797303.60415546 APT。
- 原始分布 Gini=0.3592128844，最大单节点份额约 3.4748%。
- 原始 JSON 的 SHA-256：5c4ac58a336824d953d0aa215401f9a88ca1ef5cd62010e1ff7f305a45e67b41。

原始响应、账本信息、同版本 epoch 资源及来源信息保存在 [data/aptos-mainnet-v7479751174](data/aptos-mainnet-v7479751174)。生成器只读这个快照，不会在不同节点规模的实验中自动获取不同时间的数据。接口响应头里的 x-aptos-ledger-version 是服务节点的最新高度，不能覆盖请求 URL 中的历史版本。

官方依据：

- [固定账本版本的 ValidatorSet 请求](https://fullnode.mainnet.aptoslabs.com/v1/accounts/0x1/resource/0x1::stake::ValidatorSet?ledger_version=7479751174)
- [stake.move：ValidatorSet 与当前 epoch 投票权语义](https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-framework/sources/stake.move)
- [APT 单位：1 APT = 10^8 octa](https://aptos.dev/build/guides/application-integration)

## 从 85 个验证者映射到指定 n

n 固定为 4、16、31、46、64。方法是排序后的经验分位函数积分，不取 top-n，也不随机抽取一部分验证者：

1. 按 (voting_power, address) 升序排序全部当前验证者。
2. 将验证者排名区间 [0,1] 等分为 n 段，计算每段内权重的平均值。跨段边界的原验证者按区间交叠比例计入。
3. 对得到的 n 个正数按目标总权重归一化，使用 Hamilton 最大余数法整数化；余数相同按 party ID。
4. 全程使用 Python 任意精度整数/有理数，输入文件中的大权重保存为十进制字符串。生成 upstream Node 配置时转换为十六进制字符串。

设排序后的原权重为 v_j，原节点数为 m=85，使用整数网格计算：

    a_i = sum_j overlap([i*m,(i+1)*m], [j*n,(j+1)*n]) * v_j
    w_i = Hamilton(W * a_i / sum_j(a_j))

这里 sum_i(a_i)=n*sum_j(v_j)，因此所有源权重都得到保留。整数化前，在新排名分界点 i/n 处保留源分布的 Lorenz 曲线值；整数化使单个权重与目标分数的差小于 1。这不表示有限 n 能完整保留原来的 85 个个体及尾部分布。

例如，映射后的 Gini 在 n=4 时约 0.33053，在 n=64 时约 0.35910。n=4 的最大 party 约占 47.13%，已超过腐化预算，不能把该 party 指定为拜占庭节点。这是低节点数近似带来的限制，不能据此声称四节点实验复现了 Aptos 的去中心化程度。

## 已生成的三个 policy

| 文件 | 分布与总权重 | 配置数量 |
|---|---|---:|
| [weights-aptos-native.json](policies/weights-aptos-native.json) | Aptos 分位映射；W=n×887996827769592 | 10 |
| [weights-aptos-normalized.json](policies/weights-aptos-normalized.json) | 同一 Aptos 分布；W=n×3000000 | 10 |
| [weights-npow.json](policies/weights-npow.json) | W=n^n；等权、确定性稠密权重、Aptos 分布三种 | 30 |

每种分布/节点数都包含 honest 和 recovery-stress。共 50 个配置，每个 runs=3；全部实际执行时会产生 150 次 coin。可通过 fab local 的 --runs 覆盖。

Aptos native 使用 mu=3*floor(W_source/(3*m))，比原始平均投票权少不到 3 octa，保留实际权重的整数数量级。固定平均权重使随 n 的曲线主要测量节点扩展性，而不是让 n 增加时每个节点的权重自动减小。它是从真实数据构造的合成委员会，不是链上 85 个验证者的原样执行。

normalized 使用固定均值 3000000，对比同一分布在较小整数表示下的成本。它与 native 分别整数化，因此不是逐个权重完全相同倍数的缩放：不能混入现有要求精确同比缩放的 weight_scale 图。两套 policy 使用不同 experiment_id 和不同分布参数，分别绘制 party 曲线。

共同参数：

- output_bits=128、rounding_bits=64、coverage_bits=40。
- T=floor(W/3)，F=T−1，始终断言实际腐化权重 B≤F<T。
- silent faults=0；stress 节点仍启动，执行已有 recovery-stress。
- duration=1800 秒、startup_timeout=600 秒，是实验超时预算，不是性能预测。
- 继续使用六组子协议端口和单独的 synchronizer 端口。默认 n=64 时为 20000..20383，控制端口 20384；不同 case 顺序运行。

## W=n^n 的含义及分布选择

W=n^n 是约定的超大权重压力族，不是实现允许的绝对最大 W，也不是已经证明的最坏电路输入。当前电路按二进制位层构造、消除常量、复用同门并裁去不影响输出的门；最终成本也取决于权重的位模式。

三种分布都严格满足同一个 W=n^n：

- uniform-npow：w_i=n^(n−1)，保留等权对照。n 为 2 的幂时权重极稀疏，可能大幅化简。
- dense-npow：SHAKE256 根据固定 seed=20261004、n、party ID 生成 512 位正分数，再按 W 最大余数分配。分数在 [2^511,2^512) 内，避免单个节点支配；如所有整数有公因子，作保持总量的微小调整使 gcd=1。它提供可复现的稠密位模式，不宣称找到了最大门数。
- aptos-npow：用同一 Aptos 分位分布分配 W，观察真实分布形状与超大整数的结合。

在当前 Rust 电路上离线测得：

| n | W 的位数 | uniform 门数 | dense 门数 | Aptos 门数 |
|---:|---:|---:|---:|---:|
| 4 | 9 | 9 | 43 | 47 |
| 16 | 65 | 171 | 7761 | 7205 |
| 31 | 154 | 52742 | 53039 | 58199 |
| 46 | 255 | 157951 | 169100 | 170001 |
| 64 | 385 | 1689 | 441052 | 430926 |

因此只用等权测试会严重低估 n=64 的大权重成本；也不能预设电路规模随 n 或 W 单调增长。385 位权重由 BigUint 处理，与 128 位 coin 输出是独立参数，不需要降低权重精度。

n^n 图明确称为 joint party/weight stress：n 与 log(W) 同时增长，不能当作固定平均权重下的纯节点扩展性。绘图配置使用 weight_control=n_pow_n，逐点验证 W=n^n、T=floor(W/3)、weight_scale=1。原有 fixed_mean 检查仍是默认值，不能用此选项绕过任意数据的可比性检查。

## 拜占庭选择

n=64 且权重可达数百位，不继续使用旧的小规模精确子集枚举。新规则 max-count-one-swap-v1：

1. 选择权重最小的可容纳前缀，得到预算内最大可腐化节点数。若最轻的 k+1 个节点之和都超预算，任何 k+1 节点集合都超预算，所以此数量是精确最优。
2. 保持此数量，反复选择预算内增重最大的单次内外节点替换，直到无法进一步增重；平局按 old/new party ID。

第二步只保证单次替换局部最优，不保证全局最大腐化权重。最大腐化身份数有利于产生更多恶意终止消息，但也不能由此推导全协议的最坏延迟。图例使用 Recovery stress，区别于旧矩阵经精确求解的 Max-weight stress。

Aptos native 的腐化身份数量为 2、9、18、26、37；B/W 分别约为 24.36%、33.31%、33.327%、33.322%、33.326%。n=4 的离散权重限制使预算不能接近填满。每个 case 保存明确名单、T、F、B、选择算法；报告另外保存预算缺口，不将预算 F 当成实际 B。

## 复现与运行

在 benchmark/ 中执行：

~~~sh
# 离线重建所有 policy、plot config 和分布报告。
python3 -m benchmark.weight_policies

# 如已有编译后的 node，同时构造 upstream Node 配置并检查 Rust 电路。
# 不开启监听端口，不启动分布式 coin。
python3 -m benchmark.weight_policies --check-rust ../target/release/node

# 之后需要实际测量时运行；此次未执行这些任务。
fab local --policy=policies/weights-aptos-normalized.json --output=file
fab local --policy=policies/weights-aptos-native.json --output=file
fab local --policy=policies/weights-npow.json --output=file

# 完整实验结果存在后，各生成延迟、诚实方平均通信量两张图。
fab plot --config=plot-configs/weights-aptos-normalized.json
fab plot --config=plot-configs/weights-aptos-native.json
fab plot --config=plot-configs/weights-npow.json
~~~

[weight-study-report.json](data/weight-study-report.json) 保存源分布和各 case 的 W/T/F/B、位数、Gini、最大份额、公因子、二进制置位总数、腐化名单、预算差；使用 --check-rust 时还保存实际门数、public_bytes、检查二进制和电路源文件的 SHA-256。仅重新生成而不传 --check-rust 时报告不会伪称执行了 Rust 检查。

本次 50 个 case 均通过 Python policy/端口/预算检查；25 个不同的权重与门限组合通过现有 Rust check-config 并成功生成电路。Python 回归测试共 43 项通过。

n=64 dense 的单 dealer public record 为 42345448 字节（约 40.4 MiB）。上游 WAVID 已使用 32 KiB 分块，不能把整个 public record 大于 1 MiB 等同于超出 TCP 单帧上限；其原始文件上限为 512 MiB。这些离线检查不验证全部节点同时运行的内存峰值、抓包容量或活性时间。后续本地大规模实验应先检查主机资源，保留真实失败和超时记录，不将其填为性能数据。
