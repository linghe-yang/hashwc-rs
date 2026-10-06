# WHCC 本地 benchmark

沿用旧版 Fabric local/logs 任务，以及 LocalBench、CommandMaker、BenchParameters、NodeParameters、LocalCommittee、LogParser、PathMaker 的组织方式。当前提供 local、logs、plot 任务；plot 读取已有 result，不重新运行实验。remote 暂未实现。

## 运行

在 Linux / WSL 中，需要当前项目 Rust 工具链、Python 3.8+、Fabric、Matplotlib，以及用于流量采集的 root 或 CAP_NET_RAW（大规模测试推荐系统 tcpdump/libpcap）：

~~~sh
cd benchmark
python3 -m pip install -r requirements.txt
fab local --policy=policies/local-4.json --output=console
fab local --policy=policies/local-4.json --output=file
fab local --policy=policies/local-4-128.json --output=file
fab local --policy=policies/local-4-128.json --runs=3 --output=file
~~~

每个 case 自动编译同一个 release node、生成上游 config::Node 配置，启动一个 synchronizer 进程及各 party 进程，解析日志并输出 result。每轮使用新会话和成对密钥，不使用 feature 切换协议。正式构建直接使用固定提交的上游优化传输，不再使用 vendor/sdc-util 补丁。结果记录 sdc_revision、上游 transport 源码指纹、实际 coding_block_bytes 及 control_coding_block_bytes=32；WAVID 使用 `vendor/wavid` 中固定上游版本的本地 CPU 复用补丁（记录 `wavid_source_sha256`），其网络格式与完成条件不变；当前实现标识为 compact-header-striped-wavid-v5-reuse，绘图不会与旧版本混合。

## 同步流程与门限

同步器代码在 node/src/synchronizer/。通过同一个 main 的独立子命令启动，控制端口独立于六类协议端口：

~~~sh
node synchronizer --config .synchronizer.json --parameters .parameters.json
node run --synchronize --config .node-0.json --parameters .parameters.json
~~~

1. Party 连接同步器并发送携带 output_bits 的认证 HELLO；位数不匹配会拒绝连接。同步器对每个已连接的 party 发送 PREPARE，迟到连接会收到当前阶段的指令。
2. Party 收到 PREPARE 后构建电路、恢复采样参数、协议状态并绑定六个子协议服务。完成后发送 PREPAREOK。
3. 同步器按身份去重，累计 PREPAREOK 权重严格大于 W−T 时记录开始时刻并广播 START。它不等待所有物理节点准备完成。
4. 已准备方收到 START 立即启动 coin；仍在准备的方暂存 START，准备好后启动。收到 STOP 时不会等待准备结束。
5. Party 输出 coin 后发送 FINISH(coin)，继续处理协议消息，直到 STOP。
6. 同步器保留 party→coin 映射，重复身份不重复计权，也不能改变第一次投票。某个相同 coin 的累计权重严格大于 T 时，记录终止时刻、结果和 FINISH 集合，广播 STOP。
7. Party 收到 STOP 后记录停止事件，立即退出整个进程，不等待电路构建、恢复或其他工作完成。同步器保持控制端口开放以便向迟到连接发送 STOP；Python 确认活动 party 已退出后关闭同步器。

控制消息绑定会话、epoch、身份和方向；每个 party 与同步器使用独立共享密钥。节点文件仍然直接使用上游 Node：net_map[num_nodes] 是同步器地址，party 的 sk_map[num_nodes] 是控制密钥。.synchronizer.json 同样是 Node 格式，其 sk_map[i] 存放与 party i 的控制密钥。协议端口派生不会修改同步器地址。

这是可信 benchmark 控制器，不属于 common coin 共识协议。W、T 都是权重，两个门限均为严格大于；FINISH 不按物理节点数量计数。在 B<T 假设下，超过 T 的同结果集合必然包含诚实方，但不表示所有节点都已输出。STOP 有意截断剩余工作，因此这个指标是指定权重的结果完成时间，而非全体终止时间。遇到已观察到的 coin 分歧，脚本如实报错，不重跑掩盖失败。

## policy

~~~json
{
  "metadata": {
    "experiment_id": "uniform-smoke-v1",
    "experiment_axis": "smoke"
  },
  "bench_params": {
    "protocol": "whcc",
    "faults": 0,
    "duration": 60,
    "runs": 1,
    "base_port": 20000,
    "sync_port": null,
    "startup_timeout": 30
  },
  "node_params": {
    "epoch": 0,
    "coverage_bits": 40,
    "rounding_bits": 64,
    "output_bits": 1,
    "port_stride": null
  },
  "cases": [
    {
      "name": "uniform-4",
      "nodes": 4,
      "weights": {"distribution": "uniform", "weight": 1},
      "threshold": 1
    }
  ]
}
~~~

- nodes 是物理参与方数；weights 可用显式整数数组（支持十进制/0x 字符串）、uniform 分布，或 linear 分布，后者权重为 (start+i*step)*scale，三项默认均为 1。
- threshold 是正整数 T，或 auto（floor(W/3)）；要求 B<T<=W/3。
- faults 表示不启动的静默节点数，默认最后 faults 个，也可在 case 中指定 faulty_nodes。case 可覆盖全局 faults。故障合法性按静默节点与活动拜占庭节点的联合权重检查。
- node_params.output_bits 指定输出位数，默认 1；128 位示例见 local-4-128.json。要求 output_bits + rounding_bits + 1 <= 254。默认 rounding_bits=64 时最多 189 位；扩大输出宽度会提高 WBinAA 精度需求，实验比较应固定这个参数。
- runs 默认 1，为顺序执行次数，每轮一个 coin。优先级为命令行 --runs > case.runs > bench_params.runs > 默认值。每个 case 只编译一次；各轮权重、门限、安全参数、故障集合和运行配置相同，重新生成 session、密钥与协议随机数，并递增 epoch。每轮都重新启动进程及同步器，不复用上一轮协议状态。命令行覆盖后的有效次数保存在 resolved-policy.json，原 policy.json 保持原样。
- startup_timeout 为等待同步器就绪、PREPARE 达标及 STOP 退出的外部失败检测时间；duration 为等待同步器结果的最大秒数。超时不会产生替代 coin。
- 旧字段 settle_time 仍可读取，但会提示忽略：STOP 后不再保留额外运行时间。

节点 i、服务 j 的端口为 base_port+i+j*port_stride，j=0..5 分别是 WRBC、WRA、WGather、WBinAA、私有份额和恢复。port_stride 默认 nodes。sync_port 默认 base_port+6*port_stride，也可显式设置。启动前同时检查协议和同步器端口的冲突、溢出及可用性。4 方默认使用 20000..20023，同步器使用 20024。

提供 local-4.json、local-4-128.json、party-scalability.json 和 weight-scalability.json，分别用于单比特基本测试、128 位基本测试、固定权重风格改变节点数、固定节点数改变权重。

weight-scalability.json 是示例合集，包含不同分布与数值缩放；不能将全部 case 无条件连成同一条“权重大小”曲线。纯数值缩放需要权重和门限同步乘以 scale，例如 [1,2,3,4], T=3 放大 100 倍后 T=300，不能重新用 auto 得到 333。

每个进程默认两个 Tokio worker 线程，可用 TOKIO_WORKER_THREADS 覆盖并记录。--debug 开启详细日志，比较性能时应保持一致。

## 延迟与带宽

**单次 coin 延迟直接取 synchronizer.log 的 latency_us / 1000。** 开始点是 PREPAREOK 权重达标、发送 START 前；终止点是同一 coin 的 FINISH 权重达标。两点使用同一进程的 Instant 单调时钟，也记录墙钟时间供查看。该延迟包含 START 传播和 FINISH 返回通信，不包含编译与 PREPARE。不再用各方延迟的平均值替代它；重复运行时可对这些独立的同步器测量汇总均值、最小值、最大值和标准差。

带宽从每个 primary-i.log 的 bandwidth 记录提取 total_sent_bytes，再对本轮全部活动节点求算术平均；包括尚未输出就被 STOP 的节点。也保留各方、各子协议及全局总字节数。静默未启动节点不进入活动节点平均值。

原语网络层没有计数接口，因此计数仍由 Linux 回环被动采集产生，并明确标记 source=linux-af-packet-collector。采集器通过首个上游认证 Frame 的 sender/recipient 字段识别发送进程，将发送的 TCP 数据和应用层 ACK 分别计入实际发送方；支持分段、乱序和重传。实验停止后采集器把对应计数写入各方日志，并与全局计数交叉校验。不会用收到的数据量冒充发出量。

Python 后备采集器只计 PACKET_OUTGOING；原生 libpcap 采集器只取一个 incoming loopback twin，因为部分 libpcap 版本会主动屏蔽 outgoing twin。两者都对每次实际发送计数一次，并按发送端口/Frame sender 归属，绝不按接收节点冒充发送量。计入 TCP payload，包括协议编码、认证封装、加密份额、应用层 ACK 和重传数据；不包括 TCP/IP/Ethernet 头、纯 TCP ACK、RST、本方内存投递。同步器独立端口上的 HELLO/PREPARE/PREPAREOK/START/FINISH/STOP 不计入协议开销。

采集区间从 PREPARE 服务启动之前到所有活动 party 收到 STOP 并退出，因而包含 STOP 传播期间各方尚在发送的协议数据。它不等于所有节点完整完成一次 coin 的通信成本。Python 后备采集 socket 请求 128 MiB 缓冲区；拥有 CAP_NET_ADMIN 时使用 SO_RCVBUFFORCE 绕过较小的系统默认上限，只影响本次 socket，不修改全局 sysctl，实际分配量记录在 receive_buffer_bytes。若捕获丢包、身份无法归属或各方与总数不一致，实验拒绝产生有效 result。被动采集会消耗本地 CPU，比较时应保持相同条件。

## result 与文件

--output=console 仅在控制台输出总结，原始配置和日志保存在 logs/ 下；不写总结 JSON/txt。--output=file 同时打印并在 results/ 新建独立 case 目录，--results=/path/to/results 可以更改父目录。目录名含协议、case、节点数、总权重、门限、输出位数、UTC 时间及随机后缀。

~~~text
whcc-uniform-4-n4-w4-t1-l1-<UTC时间>-<后缀>/
  policy.json                  # 完整原始 policy
  resolved-policy.json         # 当前 case 展开的权重、门限及默认值
  build.log
  whcc-0-4.txt
  whcc-0-4.json
  run-001/
    resolved-policy.json
    .parameters.json
    .synchronizer.json
    .node-0.json ... .node-3.json
    run.json                   # 会话、epoch、配置标识、电路规模、构建与运行环境
    bandwidth.json
    logs/synchronizer.log
    logs/primary-0.log ... primary-3.log
~~~

协议名称统一为 whcc，新目录及结果文件使用 whcc 前缀。旧 commoncoin policy 输入仍接受；fab logs 可以读取旧日志并产生规范的 whcc 结果，source_protocol 记录原始名称。历史文件不会自动迁移或覆盖。

JSON 现在使用 schema_version=5，顶层、配置和每轮结果均记录 output_bits。1 位 coin 仍用整数 0/1；多比特 coin 用补齐 ceil(output_bits/4) 位的 0x 前缀小写十六进制字符串，FINISH map 和各方结果使用相同完整值，避免大整数精度丢失。解析器仍兼容省略 output_bits 的旧单比特同步日志。runs[].latency_ms 来自同步器；synchronizer 包含开始/结束时间、FINISH map 和达标权重；avg_sent_bytes 为逐节点日志字节数平均值，total_sent_bytes 为总量。parties 中 coin=null 表示收到 STOP 时尚未输出，不等于 coin=0，也不是失败。summary.latency_ms 仅汇总不同运行的同步器延迟，summary.avg_sent_bytes_per_active_party 汇总各运行的带宽均值。

旧版无 synchronizer.log 的实验无法用新口径重新测量，解析器会报错，不回退到旧的各方延迟平均值，也不改写历史结果。

~~~sh
fab logs --directory=results/<实验目录>
fab logs --directory=logs/<实验目录> --output=file
~~~

失败保留日志及 failure.json，不生成成功总结。只清理自己启动的进程，不终止其他实验。root/CAP_NET_RAW 权限不足会明确报错，不把不可测流量当作零。

当前 coin 使用小 header 的 WRBC 与条带化 WAVID bulk 分发；公开记录不再通过 WRBC 广播。带宽统计包括其余子协议及可靠传输封装，不能仅凭单份 bulk 大小推算整币通信量。

## 实验元数据

policy 顶层 metadata 可提供全局默认值；case.metadata 按字段覆盖它（weight_profile、generation 等对象整体替换，不进行深层合并）。旧 policy 不需要增加字段即可运行。元数据不会进入上游 config::Node，也不改变协议。

- experiment_id：实验批次名称，例如 party-scaling-v1。省略为 null，不从文件名推断。
- experiment_axis：nodes、weight_scale、weight_skew 或 smoke；省略为 null。
- weight_profile：包含 id 和 parameters，例如 {"id":"linear","parameters":{"start":1,"step":1}}。builtin uniform/linear 自动生成；linear 的 scale 独立保存，不混入分布形状参数。显式数组默认标记 explicit，不推断分布来源。
- weight_scale：正整数缩放倍数。linear 从输入 scale 读取并检查声明一致性；uniform 默认为 1；显式数组省略时为 null。它是相对某个基础权重的数值缩放，不代表集中度。
- generation：method、version，以及可选 input、seed、snapshot。内置生成方式自动保存原始生成参数。外部采样需要用户声明方法/版本；snapshot 可记录 network、epoch、ledger_version、timestamp、sha256、source。这里保存来源标识，不自动下载或复制快照；实际使用的完整权重始终随 resolved-policy 保存。

每个 result 的 metadata 自动补充：

- policy：精确十进制权重、W/T、权重位数、平均权重的精确分子分母、实际 T/W 与故障权重 B/W、最大权重占比、变异系数和 Gini 系数，以及安全参数。十进制字符串避免其他绘图语言丢失大整数精度；比率等描述统计使用浮点数。
- weight_instance_id：有序权重和门限的 SHA-256；configuration_id 进一步包含故障集合与安全参数。它们不包含 runs/session/epoch，可用于识别相同实验条件；不单独代表完整的运行环境兼容性。
- circuit：从真实 Rust check-config 输出采集 gates、public_bytes，表示电路门数和单份公开记录的编码长度，后者不是网络流量估算。采集在计时和流量统计之前进行。
- build：二进制与 Cargo.lock 哈希、Rust 版本、Git revision/dirty、实现标识、传输层及 benchmark 源码哈希。
- environment：CPU、可用 CPU affinity、内存、OS/kernel、Python 版本、本地回环网络、Tokio 线程数、debug 设置等。

每轮 run.json 保存 configuration_id、构建、环境和电路规模。解析时拒绝把不同构建、环境、电路或配置混入同一个成功汇总。旧日志缺失的来源和环境保留 null，provenance_status 为 legacy-partial；不根据当前机器或源码为旧实验补造元数据。

现有 party-scalability 示例仍使用单位权重和 auto 门限，因此 T/W 会随取整变化；结果会如实保存该比率。需要严格固定 T/W 时，应在实验 policy 中选择合适的权重和门限。

## 重复运行统计与误差条

result.runs 保留每次测量，不只保存平均值。summary 的三个指标分别为 latency_ms、avg_sent_bytes_per_active_party、total_sent_bytes；每个指标包含：

- count、mean、median、min、max。
- stdev：各次运行之间的样本标准差（分母 runs−1），standard_error 为 stdev/sqrt(runs)。
- error_bar：method=min_max、lower=min、upper=max，以及相对均值的 minus=mean−min、plus=max−mean。后续折线图可以直接使用这两个非对称误差长度。
- variability_estimated：runs>1 时为 true；只有一次时 stdev 和 standard_error 为 null，上下限重合。此时不能估计重复运行的波动。

上下限表示已经观测到的最小/最大值，**不是 95% 置信区间**。控制台和 txt 同样打印均值、范围和样本标准差。若以后绘图选择其他误差定义，仍可从逐次测量重新计算。

通信指标先在每轮对全部活动节点求平均，再在各轮之间求均值和偏差；不把同一轮的多个节点当作独立重复样本。延迟始终先取每轮 synchronizer 的测量，再跨 runs 统计。故障或丢包造成任意一轮不完整时，不静默跳过该轮生成成功均值。

## 活动拜占庭节点与容错预算

保留 faults/faulty_nodes 表示不启动的静默节点；新增 byzantine_nodes 指定实际启动的恶意节点，二者不可重叠或重复。byzantine_behavior 当前支持 recovery-stress。三个新字段均可放在 bench_params 中，或由 case 覆盖。

threshold=T 仍是原协议门限；fault_weight_threshold=F 是用户指定的**包含端点的腐化权重预算**，默认 T−1。脚本检查：B≤F<T≤W/3，其中 B 是静默与活动拜占庭节点的权重之和。这里不能直接把原协议 B<T 改成 B≤T。整数权重允许 F=0；所有预算和权重比较使用精确整数。

例如 case：

~~~json
{
  "name": "byzantine-4",
  "nodes": 4,
  "weights": [3, 3, 3, 3],
  "threshold": 4,
  "fault_weight_threshold": 3,
  "byzantine_nodes": [3],
  "byzantine_behavior": "recovery-stress"
}
~~~

此时 W=12、T=4、F=3、B=3。4 方单位权重与 T=1 的旧基础例子不允许一个权重为 1 的故障，不能直接在其中添加 byzantine_nodes=[3]。

~~~sh
fab local --policy=policies/byzantine-4-128.json --runs=3 --output=file
~~~

该 policy 包含相同权重、安全参数和门限的诚实对照与一个拜占庭节点的 case。节点仍直接读取上游 config::Node，实验角色只通过命令行传入，不向 Node 增加自定义字段。Rust 单独启动示例：

~~~sh
node run --config .node-3.json --parameters .parameters.json --synchronize --behavior recovery-stress
~~~

默认 --behavior honest。recovery-stress 的具体行为：

1. 正常生成 AX/WCSS 份额，篡改公开 AX commitment 的一个比特。份额的 input/wire 承诺不变，能够通过收据检查并进入 WRA/WGather；错误到恢复及完整重生成时才暴露。
2. 正常使用六个子协议端口，发布符合配额的采样名单，并参与 WRBC/WRA/WGather/WBinAA；不是另一个静默节点。
3. 扣留全部恢复 token 和有效终止证据。一旦得到某个 dealer 的 Public 且自己获名单授权，就在冻结之前向其他节点预先发送一个带正确 Public digest、语法合法但 opening 错误的 Success。诚实接收者必须等到本地完成与冻结后处理该结果，并通过完整 AX 重生成判错。
4. 不输出 coin、不发送 FINISH，继续接收消息直到可信实验控制器发送 STOP。它配合 PREPARE/STOP 是为了可控测量，并不代表协议假设敌手愿意配合控制器。

这是有界、可重复的恢复压力策略，不声称穷尽所有敌手或达到全协议理论最坏值。逻辑伪造发送数最多为 (n−1)×该节点恢复配额；网络实际字节还包括封装、ACK 与可能的重传。名单授权、每 sender/dealer 一个 terminal 槽位等诚实验证逻辑保持启用。它不伪造诚实身份，不注入无界洪泛，也不修改上游原语内部来实现 WBinAA 等的逐轮矛盾消息。

result.fault_model（也在 metadata 内保存）包含 total_weight、protocol_threshold、fault_weight_threshold、corrupted_weight、silent_weight、byzantine_weight、角色名单与攻击名称，权重用十进制字符串精确保存。控制台打印 W/T/F/B。run.json 的 schema_version=2 保存角色，解析器交叉检查配置、manifest 和进程实际行为日志。

原 avg_sent_bytes_per_active_party 仍包括拜占庭发送方；新增 avg_sent_bytes_per_honest_party、honest_sent_bytes、byzantine_sent_bytes，防止敌手不发消息时拉低平均值而掩盖诚实方成本。总流量继续包含全部实际发送。不同 case、不同腐化权重和名单不能自动混成同一统计点。

每轮 work 及 summary.work 保存诚实方终止验证次数、已解码的终止验证次数、拒绝次数、拒绝 dealer 的观察次数和拜占庭伪造发送数。节点 work 日志由主进程在 STOP 时输出，计数代表 STOP 前已消费的协议事件，是诊断数据；排队但尚未消费的事件可能未计入，不能当作精确 CPU 指令数或严格全程验证次数。被动采集的字节数仍是独立的实际流量测量。成功 result 不要求拜占庭节点输出，也不把其缺失输出当作诚实方失败。

## 绘图

~~~sh
# 只读已有结果，生成 PDF、SVG、PNG 和浏览页；不编译、不启动节点。
fab plot --config=plot-configs/scalability.json
~~~

输出默认放在 plots/scalability/，打开 index.html 可浏览全部图；论文插图使用 PDF/SVG，PNG 用于预览。保留旧版 Ploter.plot(plot_params) 风格，实现在 benchmark/plot.py。原始 results 保持不变。

配置的相对路径统一相对于 benchmark/（配置文件自身的读取路径相对于当前命令目录）。results 可指定目录或具体 result JSON，目录递归扫描。示例：

~~~json
{
  "results": ["results"],
  "filters": {
    "experiment_id": ["scalability-20261004-v1"],
    "protocol": ["whcc"],
    "weight_profile": ["uniform", "bimodal"],
    "fault_case": ["honest", "recovery-stress"],
    "output_bits": [128],
    "rounding_bits": [64],
    "coverage_bits": [40]
  },
  "series": ["weight_profile", "fault_case"],
  "metrics": ["latency_ms", "avg_sent_bytes_per_honest_party"],
  "error_bar": "min_max",
  "min_runs": 3,
  "formats": ["pdf", "svg", "png"],
  "output": "plots/scalability",
  "charts": [
    {"name": "party-scalability", "x": "nodes", "values": [4, 10, 16], "filters": {"weight_scale": [1]}},
    {"name": "weight-scalability-n10", "x": "weight_scale", "values": [1, 10, 100], "filters": {"nodes": [10]}, "xscale": "log"}
  ]
}
~~~

- filters 可使用 protocol、experiment_id、nodes、weight_profile、weight_scale、fault_case、output_bits、rounding_bits、coverage_bits、case_name，值均为允许值列表。chart.filters 与全局筛选同时生效。只看一种分布或拜占庭曲线时缩小对应列表即可。
- series 指定曲线分组字段。横轴 x 为 nodes 或 weight_scale。values 明确要求哪些横坐标，缺失时直接报错，不补零、不跨缺口画完整曲线；显式筛选的 series 组合若整条缺失也报错。
- metrics 支持 latency_ms、avg_sent_bytes_per_honest_party、avg_sent_bytes_per_active_party、total_sent_bytes。延迟单位 ms，通信量绘成 MiB/coin；后两项分别是全部活动方平均值和系统总量。当前主要图使用诚实方平均发送量，避免敌手扣留消息拉低均值。
- error_bar 支持 min_max（观测范围）、stdev（均值±样本标准差）、none。均值始终从逐 run 测量重算；不是对目录里的 summary.mean 再平均。min_runs 是每个点去重后的最少运行次数，默认 1。一次测量的波动不可估计。
- xscale/yscale 支持 linear 或 log；对数纵轴要求整个误差范围为正。output 必须位于 benchmark/plots 下。

绘图会拒绝混用不同二进制、benchmark 版本、运行环境、安全参数、采集后端或测量口径。同一条节点数曲线要求分布参数、平均权重、门限比例与权重缩放固定；同一条权重缩放曲线要求基础有序权重、基础门限、节点数和腐化名单固定。同一个点不允许混入不同权重实例。不同版本的历史实验应通过 results 路径另行选择，不能直接混到新曲线里。

重复拷贝的 session/epoch 只计一次；同一 session/epoch 出现矛盾数值则报错。缺少来源信息的旧结果不自动猜测分布或机器配置。失败实验及筛选之外的结果写入 manifest.json；未成功的运行不会静默加入均值。

每个 chart 生成 <name>-points.json，包含逐 run 指标、均值/上下限、原始 result 路径、session/epoch、W/T/F/B、腐化名单、电路规模及配置标识；manifest.json 记录所有入选/排除文件和图表清单，config.json 保存实际绘图参数。图像与来源数据可以一一核对。

## 已提供的扩展性实验矩阵

~~~sh
# 重新生成受控实验与绘图配置；不运行协议。
python3 -m benchmark.experiments
# 36 个配置，每个配置 3 次。也可使用 --runs 覆盖。
fab local --policy=policies/scalability.json --output=file
fab plot --config=plot-configs/scalability.json
~~~

矩阵覆盖 n=4/10/16、scale=1/10/100、uniform/bimodal 两种分布、honest/recovery-stress 两类运行，共 36 个配置、108 次 coin。

- uniform 基础权重全为 6；bimodal 为一半 3、一半 9。各 n 的平均基础权重精确为 6，分布形状固定；不是把线性权重列表延长后称作相同分布。
- W=6n×scale，T=2n×scale，始终 T/W=1/3。F=(2n−1)×scale，使权重与授权门限一起缩放。固定 n 时所有 scale 的基础权重、基础门限与腐化名单相同。
- 拜占庭子集用精确子集和选择：先最大化预算内实际腐化权重，再最大化腐化节点数，再按身份字典序打破平局。选择器限制 n≤20，以免把任意大权重子集和问题伪装成廉价操作。所选规则记录在 metadata.fault_selection；绘图遇到该规则声明时会重新核对选择结果。
- “Max-weight stress” 表示最大可行腐化权重下执行当前有界 recovery-stress；不表示已证明对所有敌手策略达到全局最坏。因权重离散，B 不一定等于 F。基础 scale=1 时 uniform 的 B 为 6/18/30，bimodal 的 B 为 6/18/30；对应腐化数量分别为 1/3/5 和 2/4/8。精确名单和缩放后的值随每个点保存。
- 输出 128 位、rounding_bits=64、coverage_bits=40、默认每进程 2 个 Tokio worker。所有节点运行于同一台机器，16 节点曲线也包含本机 CPU 竞争，不能直接解释为多机部署的网络表现。

默认配置生成 8 张图：节点数的延迟/通信量两张，以及固定 n=4、10、16 时权重大小的延迟/通信量各两张。每张包含两个分布的诚实/拜占庭曲线，实线/虚线区分；均输出 PDF、SVG、PNG。

## Aptos 真实分布与超大权重

新增 n=4/16/31/46/64 的真实分布与 W=n^n 测试策略，见 [WEIGHT_POLICIES.md](WEIGHT_POLICIES.md)。原始主网快照、可复现生成方法、三套 policy、三套 plot config 和离线电路检查报告均已保存；这些策略的分布式实验尚未执行。

chart 可指定 weight_control="n_pow_n"，只用于 nodes 横轴，严格验证 W=n^n、T=floor(W/3)、weight_scale=1，并将图标题标注为节点数与权重共同增长的压力测试。默认 fixed_mean 仍要求节点曲线的平均权重与门限比例固定。新策略的拜占庭选择侧重最大身份数与预算内单次替换局部最优，不冒充旧策略的全局最大腐化权重。

## 大规模流量采集

系统存在 tcpdump 时，优先使用原生 libpcap/mmap 抓包，将指定协议端口的 SYN 与带数据报文截取到 256 字节，保存为每轮 .traffic.pcap；协议停止后，Python 再进行发送者归属和字节汇总。完整 TCP 数据字节数从原始 IP/TCP 长度计算，不把截取后的长度当作通信量。capture.log 保存原生采集统计，丢包非零、记录不完整或身份归属不完整都会使实验失败。

抓包启动就绪后才启动协议节点。STOP 后短暂排空抓包队列不计入 synchronizer 延迟；此时 party 已退出。原始抓包文件只保留每包开头，支持复核统计。无 tcpdump 时仍可使用 Python AF_PACKET 后备采集器，内核 BPF 同样过滤无关报文并截取包头；高流量下可能不足，发生丢包时会明确失败。

128 MiB 是请求的捕获缓冲区；后备 socket 若无 CAP_NET_ADMIN 会受系统 rmem_max 限制。脚本不修改系统网络参数。采集方式和过滤版本写入 bandwidth 元数据，绘图禁止混用不同采集后端。

## 检查

~~~sh
python3 -m unittest discover -s tests -v
~~~

Rust 测试覆盖严格加权门限、去重、分歧结果分别计权、大整数、控制消息绑定、分段读取、独立端口及迟到 STOP。Python 测试覆盖配置、原始 TCP 计数与发送方归属、静默节点零负载控制包、同步器门限校验、停止前未输出节点以及日志与流量异常。

## 按电路门数搜索的压力策略

已为 n=4/16/31/46/64 固定 W=n^n 搜索较大电路实例，提供合并 policy 与各规模独立 policy。方法、门数、复现入口及保证范围见 [GATE_SEARCH.md](GATE_SEARCH.md)。搜索和配置检查均为离线操作，不代表已完成分布式性能测试。

## 命令行生成 policy

使用 `fab policy --nodes=16 --total-weight=16000 --distribution=2 --output=policies/custom.json` 生成配置，随后交给原有 `fab local` 运行。分布枚举为 1 等权、2 近似等权且 gcd=1、3 少数重节点且各自不超过 F、4 固定 W=n^n 的门数搜索；也可使用与枚举互斥的 `--pool` 读取 Aptos 或自定义 JSON 权重池。默认 runs=1，仅生成 honest case。完整命令、故障参数与输出记录见 [POLICY_GENERATOR.md](POLICY_GENERATOR.md)。

31 节点 CPU 优化对照策略见 `policies/cpu-optimization-n31.json`，实现说明见 `../docs/cpu-optimization.md`。这轮保持 32 B 编码块和原有安全参数，结果版本隔离。

## Python 静态选择 bulk 编码块

保持原有默认值 32 B。可以在 policy 的 node_params 中设置 "bulk_block_bytes": "auto"；local 会为每个 case 在 Python 中独立求解，再把整数写入 .parameters.json。case 的 bulk_block_bytes 可以覆盖全局设置（整数或 auto）。Rust 只读取、验证和使用该值，不搜索最优参数。仍然直接使用上游 config::Node；不要修改 Node.block_size，这个字段属于旧协议。

也可以先生成选定整数的 policy，完全不编译或运行 Rust：

~~~sh
cd benchmark
fab coding --policy=policies/coding-static-input.json --output=policies/my-selected.json
# 等价的纯 Python 入口，不依赖 Fabric：
python3 -m benchmark.coding --policy policies/coding-static-input.json --output policies/my-selected.json
# 之后按原方式运行（大规模策略请按需自行运行）：
fab local --policy=policies/my-selected.json --output=file
# 本轮实际小规模验证策略，仅 4 个节点：
fab local --policy=policies/coding-local4.json --output=file
~~~

任务同时写出 .coding.json，记录模型版本、候选集、门数、bulk 长度、存储几何、采样配额、最优值、32 B 基线及逐项成本。自动 local 另保存 coding-selection.json。预生成 policy 的情况下，选择报告位于原 policy 同目录；每次实验仍保存原 policy、解析后的参数及实际块大小。Python 与 Rust 在启动前交叉检查门数、bulk 长度、采样配额和每个 owner 的存储包字节数。

优化模型 honest-full-service-sdc731e-v1 假定所有节点诚实，全部 n 个 dealer 完成，所有采样授权恢复关系均服务到底，各授权恢复者最终广播一次 Success。模型包含远程 WAVID 分散和恢复包、32 KiB 分片的协议头、可靠信道 framing/MAC/应用 ACK、加密私有收据、恢复请求、token 和 Success 消息；排除本地投递、重传、TCP/IP 头和 synchronizer。不随 bulk 参数变化的 WRBC/WRA/WGather/WBinAA 成本不进入目标，不能把 modeled_bytes 称为整币实际抓包总量。模型的百分比仅针对这些被计入的服务。

对 owner i，设包（含分片 framing/ACK）大小为 P_i，采样配额为 d_i，总配额 D=sum(d_i)。所有 dealer 的长度相同，因此总分散成本为 (n-1)*sum(P_i)，总恢复成本为 sum((D-d_i)*P_i)。这些完整服务成本无需抽样模拟；具体名单不改变总和。每个 receipt 的源开口按实际块位置去重，并按 bincode 的真实长度计费。Success 大小不随块长变化；诚实模型不计故障证据，但合法候选必须能安全传送最坏形状的故障证据。

枚举偶数 32..4096，并剔除故障证据可能超出 SDC 1 MiB 帧限制的尺寸；相同目标值选择更小的块。公开块参数绑定到 WHCC v5 context 和 WAVID root。控制 WRBC 仍固定 32 B，不与 bulk 一起变大。该选择保证上述有限成本模型中的最优，不保证 STOP 截断或不同调度下实际 TCP 流量最优，也不替代论文中块大小与安全参数尺度的渐近约束。

静态样例 coding-static-selected.json 覆盖 4/16/31/46/64 节点、四种分布、1/100 倍权重，另含 100 节点小权重和 64 节点 W=n^n 的稠密权重分布，共 42 个配置。它们仅运行 Python 计算，没有启动对应大规模协议测试。

## 2026-10-06 全诚实评估

本批次策略在 `policies/evaluation-20261006.json`：单位权重的 n=4/10/16/31/46/64/100，以及 n=31 的 Aptos 映射、W=31^31 最大门数搜索实例；各配置 3 次，输出 128 位，rounding_bits=64、coverage_bits=40，bulk 块长在 Python 中自动选择。Aptos 使用已保存快照的分位质量映射和原始平均权重尺度；最大门数实例沿用保存的候选并由实际电路重新计数，不声称全局最优。

~~~sh
cd benchmark
fab local --policy=policies/evaluation-20261006.json --output=file --results=results/evaluation-20261006
fab plot --config=plot-configs/evaluation-20261006.json
~~~

节点曲线显式使用 `threshold_control="floor_third"`，逐点检查 T=floor(W/3)，保留整数门限的取整差异；默认 `fixed_ratio` 检查不变。固定 n 的三种配置使用 `kind="comparison"`、`x="weight_profile"`，绘制分类柱图，因为权重分布和总权重同时改变，不应连接成一条只改变权重大小的曲线。分类比较仍校验节点数、构建、环境、安全参数及重复次数。

100 节点的首次尝试因采集缓冲区丢包而作废。`tools/retry_evaluation_capture.py` 是本批次的可追溯重试入口，只提升外部 tcpdump 的调度优先级，保持协议进程优先级与通信参数不变；每轮保存 capture-tuning.json。它要求已完成的 evaluation-status.json，不能替代一般 local 入口。抓包的内核缓冲区丢包与接口级丢包计数不同，原始 capture.log 与汇总均保留后者；接口计数覆盖整个接口，并不只对应协议过滤器。
