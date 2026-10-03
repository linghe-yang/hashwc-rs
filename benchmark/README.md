# 加权 common coin 本地 benchmark

沿用旧版 Fabric local/logs 任务，以及 LocalBench、CommandMaker、BenchParameters、NodeParameters、LocalCommittee、LogParser、PathMaker 的组织方式。当前只提供 local 与 result，不包含 remote 或 plot。

## 运行

在 Linux / WSL 中，需要当前项目 Rust 工具链、Python 3.8+、Fabric，以及用于流量采集的 root 或 CAP_NET_RAW：

~~~sh
cd benchmark
python3 -m pip install -r requirements.txt
fab local --policy=policies/local-4.json --output=console
fab local --policy=policies/local-4.json --output=file
fab local --policy=policies/local-4-128.json --output=file
~~~

每个 case 自动编译同一个 release node、生成上游 config::Node 配置，启动一个 synchronizer 进程及各 party 进程，解析日志并输出 result。每轮使用新会话和成对密钥，不使用 feature 切换协议。正式构建自动包含 vendor/sdc-util 的低延迟 TCP 补丁，不需要临时注入或修改 Python 启动方式；原语轮数、参数和统计口径不变。

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
  "bench_params": {
    "protocol": "commoncoin",
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
- faults 表示不启动的静默节点数，默认最后 faults 个，也可在 case 中指定 faulty_nodes。case 可覆盖全局 faults。故障合法性按实际权重检查。
- node_params.output_bits 指定输出位数，默认 1；128 位示例见 local-4-128.json。要求 output_bits + rounding_bits + 1 <= 254。默认 rounding_bits=64 时最多 189 位；扩大输出宽度会提高 WBinAA 精度需求，实验比较应固定这个参数。
- runs 为顺序执行次数，每轮一个 coin。每轮重新生成会话和密钥，并递增 epoch。
- startup_timeout 为等待同步器就绪、PREPARE 达标及 STOP 退出的外部失败检测时间；duration 为等待同步器结果的最大秒数。超时不会产生替代 coin。
- 旧字段 settle_time 仍可读取，但会提示忽略：STOP 后不再保留额外运行时间。

节点 i、服务 j 的端口为 base_port+i+j*port_stride，j=0..5 分别是 WRBC、WRA、WGather、WBinAA、私有份额和恢复。port_stride 默认 nodes。sync_port 默认 base_port+6*port_stride，也可显式设置。启动前同时检查协议和同步器端口的冲突、溢出及可用性。4 方默认使用 20000..20023，同步器使用 20024。

提供 local-4.json、local-4-128.json、party-scalability.json 和 weight-scalability.json，分别用于单比特基本测试、128 位基本测试、固定权重风格改变节点数、固定节点数改变权重。

每个进程默认两个 Tokio worker 线程，可用 TOKIO_WORKER_THREADS 覆盖并记录。--debug 开启详细日志，比较性能时应保持一致。

## 延迟与带宽

**单次 coin 延迟直接取 synchronizer.log 的 latency_us / 1000。** 开始点是 PREPAREOK 权重达标、发送 START 前；终止点是同一 coin 的 FINISH 权重达标。两点使用同一进程的 Instant 单调时钟，也记录墙钟时间供查看。该延迟包含 START 传播和 FINISH 返回通信，不包含编译与 PREPARE。不再用各方延迟的平均值替代它；重复运行时可对这些独立的同步器测量汇总均值、最小值、最大值和标准差。

带宽从每个 primary-i.log 的 bandwidth 记录提取 total_sent_bytes，再对本轮全部活动节点求算术平均；包括尚未输出就被 STOP 的节点。也保留各方、各子协议及全局总字节数。静默未启动节点不进入活动节点平均值。

原语网络层没有计数接口，因此计数仍由 Linux 回环被动采集产生，并明确标记 source=linux-af-packet-collector。采集器通过首个上游认证 Frame 的 sender/recipient 字段识别发送进程，将发送的 TCP 数据和应用层 ACK 分别计入实际发送方；支持分段、乱序和重传。实验停止后采集器把对应计数写入各方日志，并与全局计数交叉校验。不会用收到的数据量冒充发出量。

只计 PACKET_OUTGOING，避免回环副本重复计算。计入 TCP payload，包括协议编码、认证封装、加密份额、应用层 ACK 和重传数据；不包括 TCP/IP/Ethernet 头、纯 TCP ACK、RST、本方内存投递。同步器独立端口上的 HELLO/PREPARE/PREPAREOK/START/FINISH/STOP 不计入协议开销。

采集区间从 PREPARE 服务启动之前到所有活动 party 收到 STOP 并退出，因而包含 STOP 传播期间各方尚在发送的协议数据。它不等于所有节点完整完成一次 coin 的通信成本。采集 socket 请求 16 MiB 缓冲区；拥有 CAP_NET_ADMIN 时使用 SO_RCVBUFFORCE 绕过较小的系统默认上限，只影响本次 socket，不修改全局 sysctl，实际分配量记录在 receive_buffer_bytes。若捕获丢包、身份无法归属或各方与总数不一致，实验拒绝产生有效 result。被动采集会消耗本地 CPU，比较时应保持相同条件。

## result 与文件

--output=console 仅在控制台输出总结，原始配置和日志保存在 logs/ 下；不写总结 JSON/txt。--output=file 同时打印并在 results/ 新建独立 case 目录，--results=/path/to/results 可以更改父目录。目录名含协议、case、节点数、总权重、门限、输出位数、UTC 时间及随机后缀。

~~~text
commoncoin-uniform-4-n4-w4-t1-l1-<UTC时间>-<后缀>/
  policy.json                  # 完整原始 policy
  resolved-policy.json         # 当前 case 展开的权重、门限及默认值
  build.log
  commoncoin-0-4.txt
  commoncoin-0-4.json
  run-001/
    resolved-policy.json
    .parameters.json
    .synchronizer.json
    .node-0.json ... .node-3.json
    run.json                   # 会话、epoch、活动节点、编译/二进制信息
    bandwidth.json
    logs/synchronizer.log
    logs/primary-0.log ... primary-3.log
~~~

JSON 现在使用 schema_version=3，顶层、配置和每轮结果均记录 output_bits。1 位 coin 仍用整数 0/1；多比特 coin 用补齐 ceil(output_bits/4) 位的 0x 前缀小写十六进制字符串，FINISH map 和各方结果使用相同完整值，避免大整数精度丢失。解析器仍兼容省略 output_bits 的旧单比特同步日志。runs[].latency_ms 来自同步器；synchronizer 包含开始/结束时间、FINISH map 和达标权重；avg_sent_bytes 为逐节点日志字节数平均值，total_sent_bytes 为总量。parties 中 coin=null 表示收到 STOP 时尚未输出，不等于 coin=0，也不是失败。summary.latency_ms 仅汇总不同运行的同步器延迟，summary.avg_sent_bytes_per_active_party 汇总各运行的带宽均值。

旧版无 synchronizer.log 的实验无法用新口径重新测量，解析器会报错，不回退到旧的各方延迟平均值，也不改写历史结果。

~~~sh
fab logs --directory=results/<实验目录>
fab logs --directory=logs/<实验目录> --output=file
~~~

失败保留日志及 failure.json，不生成成功总结。只清理自己启动的进程，不终止其他实验。root/CAP_NET_RAW 权限不足会明确报错，不把不可测流量当作零。

当前 coin 仍是完整公开记录 WRBC 基线，尚非论文的条带化存储优化；这些数据不能代表后者的通信复杂度。

## 检查

~~~sh
python3 -m unittest discover -s tests -v
~~~

Rust 测试覆盖严格加权门限、去重、分歧结果分别计权、大整数、控制消息绑定、分段读取、独立端口及迟到 STOP。Python 测试覆盖配置、原始 TCP 计数与发送方归属、静默节点零负载控制包、同步器门限校验、停止前未输出节点以及日志与流量异常。
