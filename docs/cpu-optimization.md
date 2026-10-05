# WHCC 本地验证与分配优化

本轮保持协议、阈值、采样、安全参数、SDC 提交及编码块大小不变。实现标识为 compact-header-striped-wavid-v3-cpu；旧版 compact-header-striped-wavid-v2 仍可解析，并与新版结果隔离。

## 验证结果复用

certified::RecoverySource::recover 把本地恢复结果绑定到 header 的 setup/context/root/file_bytes、ValidatedFile 的编码上下文与参数，以及 Public 的完整规范编码。recover_bounded_iter 仍检查全部必要 token、求值门并执行完整 AX 重新生成。只有该检查通过且 Public 与已验证源文件逐字节相同时，才直接采用生成的本地终止证明，不再对同一个本地结果重复执行 AX 生成与 RS/Merkle 承诺。

输入不足时返回 None；不能将其当成 bottom。Public 与文件的完整比较在产生终止结果后进行，避免每条不足权重的输入触发一次 bulk 扫描。远程 Success/RootFault 仍走完整验证。存储故障继续独立验证。

## 短证明验证

移除 sparse() 的整 bulk 零填充、解码及大向量。先按 Layout::ranges 验证所有源开口和格式，再通过 AuthenticatedFields 读取必要字段。TrueFault/InputFault/GateFault 与完整 Public 共用 terminal::verify_local_fault 谓词。AND 仍需要两条分支，OR 仍只能指定一条分支，未使用 token 必须为零。RootFault 直接读取输出承诺、加密 key 和两个 ciphertext，继续要求有效输出 token 与完整重新生成失败（或范围失败）。

## 内存与复制

- hash()/AX derive 使用调用者提供的固定数组；保留域分离、输出长度及各 part 的长度前缀。
- WCSS transcript 和 Public digest 按规范字节流哈希，不克隆完整 Public 或创建序列化中间副本。
- Public 编码预留精确容量；完整比较直接遍历全部字段，以非短路方式比较内容。
- 恢复借用 token，仅在有效权重足够后分配电路求值空间；仍在权重判断前检查 TrueFault/InputFault。逐门分支使用固定数组。
- 聚合借用各 dealer 的 BigUint；pending terminal 通过移动缓冲区避免额外复制。
- 保留所有迟到恢复服务所需状态。本轮没有调整持有者服务、冻结屏障、WRA/WRBC/WAVID 启动与终止条件。

## 验证与对照实验

测试覆盖旧版固定 AX digest、WCSS tag、WAVID root；规范哈希分块等价；本地来源错绑、跨实例与上下文；重复 token 不增加权重；输入不足时提前故障；gate 分支伪造；多种编码块长度的认证字段；迟到服务与乱序消息。

策略：benchmark/policies/cpu-optimization-n31.json。31 节点，四种分布（uniform、near-uniform、heavy-tail、Aptos），W = 9300 × {1,10,100}，T = W/3，F = 3099 × scale；相同基础权重与门限统一缩放。每种配置 honest/recovery-stress，各 3 runs，两版共 144 runs。输出 128 bits、rounding 64 bits、coverage 40 bits、每进程 2 个 Tokio worker、编码块 32 B、固定 SDC 731e0b8。

未优化基线是本轮修改前的实际工作目录快照（包含此前 SDC 更新），不是旧 Git HEAD。快照及逐文件 SHA256 位于 .reference/cpu-baseline-20261005/。两版使用独立 release 构建，按 case 交替前后顺序，在同一机器顺序运行。运行器 .reference/run-cpu-n31.py 支持从 manifest 恢复。

统计使用 synchronizer 延迟及无丢包的 TCP payload 采集，结果保存每次运行、均值、样本标准差和 min/max。STOP 会截断其他节点的未完成工作，因此通信量可能随执行顺序变化；本轮不缩减报文格式或理论通信复杂度。3 次运行只能展示本机观测波动，不构成远程性能或显著性保证。

## 用户停止时的结果

已按用户要求停止后续测试。23 个单版本 case 已完整完成（各 3 次，共 69 次），其中 11 组前后配对（66 次）。近似等权 100 倍 stress 的优化版完成，基线在第 2 次运行期间被中断，该配置不纳入配对统计。少数重节点和 Aptos 尚未开始。未执行计划中的后续独立 CPU/分配微测量。

已完成的 11 组中有 9 组延迟均值下降；各配置前后延迟比的几何平均下降约 3.44%。首组等权诚实实验存在 14.295 秒慢运行，已保留在均值与标准差中。完整表见 benchmark/results/cpu-optimization-n31-comparison.md 和 JSON。69 项 Rust 测试、Clippy 与 61 项 Python 测试通过。
