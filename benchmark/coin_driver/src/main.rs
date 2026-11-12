//! Uniform measurement wrapper. It does not change any protocol transition.
use anyhow::{Result, ensure};
use clap::Parser;
use serde_json::{Value, json};
use std::{io::Write, path::PathBuf, time::Instant};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::mpsc,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    protocol: String,
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    parameters: PathBuf,
    #[arg(long)]
    describe: bool,
}

fn resources() -> Value {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage writes a complete rusage to a valid aligned pointer.
    let code = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    assert_eq!(code, 0);
    let usage = unsafe { usage.assume_init() };
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let rss = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let hwm = status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    json!({"user_us":usage.ru_utime.tv_sec*1_000_000+usage.ru_utime.tv_usec,
        "system_us":usage.ru_stime.tv_sec*1_000_000+usage.ru_stime.tv_usec,
        "max_rss_kib":hwm,"rusage_maxrss_kib":usage.ru_maxrss,"rss_kib":rss,
        "minor_faults":usage.ru_minflt,"major_faults":usage.ru_majflt,
        "voluntary_switches":usage.ru_nvcsw,"involuntary_switches":usage.ru_nivcsw,
        "network":sdc_util::weighted::metrics::snapshot(),
        "profile_enabled":sdc_util::profile::enabled(),
        "compute_profile":sdc_util::profile::snapshot()})
}
fn emit(v: Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &v)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn describe(args: &Args, node: &config::Node, raw: &[u8]) -> Result<Value> {
    let result = match args.protocol.as_str() {
        "whcc" => {
            let p: whcc::Parameters = serde_json::from_slice(raw)?;
            let (s, p, selection) = p.prepare(node)?;
            let plan = p.group_plan(&s)?;
            let quotas = p.sampling(&s)?.quotas;
            let list_blocks = if plan.is_none()
                && p.list_broadcast == whcc::protocol::parameters::ListBroadcast::FixedChunksV1
            {
                Some(
                    quotas
                        .iter()
                        .map(|&d| {
                            recovery::ranked::Codec::new(node.num_nodes, d).map(|c| c.blocks())
                        })
                        .collect::<Result<Vec<_>>>()?,
                )
            } else {
                None
            };
            let recovery = plan
                .as_ref()
                .map(|g| {
                    json!({
                        "kind":format!("{:?}",g.kind),"table_digest":g.digest(),"groups":g.groups,
                        "terminal_edges":g.edges,"max_load":g.max_load,"self_edges":g.self_edges,
                        "remote_edges":g.edges-if p.reuse_local_dealer {g.self_edges} else {0},
                        "baseline_edges":g.baseline_edges,"baseline_max_load":g.baseline_max_load,
                        "passes_bounds":g.within_bounds(),"reuse_local_dealer":p.reuse_local_dealer
                    })
                })
                .unwrap_or_else(|| {
                    let edges=quotas.iter().sum::<usize>();
                    let certain=if p.reuse_local_dealer {quotas.iter().filter(|&&d|d==node.num_nodes).count()}else{0};
                    json!({"kind":"Sampled","reuse_local_dealer":p.reuse_local_dealer,
                        "terminal_edges":edges,"certain_self_edges":certain,
                        "remote_edges_upper_bound":edges-certain,
                        "expected_self_edges":if p.reuse_local_dealer {edges as f64 / node.num_nodes as f64}else{0.0},
                        "budget_basis":"public-full-service-upper-bound"})
                });
            json!({"gates":s.circuit().gates().len(),"wires":s.circuit().nodes(),
                "public_bytes":wiawvss::Public::encoded_len(&s),"parameters":p,"block_selection":selection,
                "setup_id":s.id(),"circuit_mode":p.circuit_mode,
                "css_backend":s.backend().name(),"correction_blocks":s.correction_blocks(),
                "pvr_wire_digests":s.pvr_wire_count(),
                "pvr_module_columns":s.boundary().map(|_| wcss::boundary::COLUMNS_PER_MODULE),
                "pvr_modules":s.boundary().map(|p| p.modules().len()),
                "reuse_verified_material":p.reuse_verified_material,
                "sampling_mode":p.sampling_mode,"sampling_quotas":quotas,"list_broadcast":p.list_broadcast,"list_blocks":list_blocks,"recovery":recovery,"header_rbc":if p.short_root_rbc {"bracha-32-byte-root"} else {"coded-112-byte-header"}})
        }
        "csshashcoin" => {
            let p: csshashcoin::Parameters = serde_json::from_slice(raw)?;
            let (s, p, selection) = p.prepare(node)?;
            json!({"gates":s.circuit().gates().len(),"wires":s.circuit().nodes(),
                "setup_id":s.id(),"circuit_mode":p.circuit_mode,
                "css_backend":s.backend().name(),"correction_blocks":s.correction_blocks(),
                "public_bytes":wiawvss::compact::Public::encoded_len(&s),"parameters":p,"block_selection":selection})
        }
        "hashrand" => {
            let p: hashrand::Parameters = serde_json::from_slice(raw)?;
            p.validate(node)?;
            let l = p.layout(node)?;
            json!({"virtual_shares":l.total,"parameters":p,"batch_size":p.batch_size,"batches":p.batches})
        }
        _ => anyhow::bail!("unknown protocol"),
    };
    Ok(result)
}

async fn whcc_progress(input: &mpsc::Sender<whcc::Request>) -> Result<Value> {
    let (reply, mut rx) = mpsc::unbounded_channel();
    input.send(whcc::Request::Inspect { reply }).await?;
    let progress = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("inspection channel ended"))?;
    Ok(serde_json::to_value(progress)?)
}
async fn csshashcoin_progress(input: &mpsc::Sender<csshashcoin::Request>) -> Result<Value> {
    let (reply, mut rx) = mpsc::unbounded_channel();
    input.send(csshashcoin::Request::Inspect { reply }).await?;
    let progress = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("inspection channel ended"))?;
    Ok(serde_json::to_value(progress)?)
}
async fn hashrand_progress(input: &mpsc::Sender<hashrand::Request>) -> Result<Value> {
    let (reply, mut rx) = mpsc::unbounded_channel();
    input.send(hashrand::Request::Inspect { reply }).await?;
    let progress = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("inspection channel ended"))?;
    Ok(serde_json::to_value(progress)?)
}

macro_rules! run_protocol {
    ($module:ident,$node:expr,$raw:expr,$inspect:ident)=>{{
        use $module as protocol;
        let node=$node;
        let p:protocol::Parameters=serde_json::from_slice($raw)?;
        let id=node.id;
        emit(json!({"kind":"preparing","party":id,"driver_schema_version":2,"resources":resources()}))?;
        let preparation=Instant::now();
        let (input,rx)=mpsc::channel(16);
        let (tx,mut output)=mpsc::channel(4096);
        let handle=protocol::Context::spawn(node,p,rx,tx)?;
        // All processes reach this barrier before START is sent by the controller.
        emit(json!({"kind":"ready","party":id,"prepare_us":preparation.elapsed().as_micros(),"resources":resources(),"execution":sdc_util::execution::Settings::from_env()?}))?;
        let mut lines=BufReader::new(tokio::io::stdin()).lines();
        ensure!(lines.next_line().await?.as_deref()==Some("start"),"expected start");
        let started=Instant::now();
        emit(json!({"kind":"started","party":id,"resources":resources()}))?;
        input.send(protocol::Request::Start).await?;
        let audit = sdc_util::observation::bulk_audit::enabled();
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(5));
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _=heartbeat.tick(), if audit => {
                    emit(json!({"kind":"resource_tick","party":id,"elapsed_us":started.elapsed().as_micros(),"resources":resources()}))?;
                }
                line=lines.next_line()=>match line?.as_deref(){
                    Some("stop")|None=>break,
                    Some("sample")=>{
                        let progress=$inspect(&input).await?;
                        emit(json!({"kind":"sample","party":id,"elapsed_us":started.elapsed().as_micros(),"resources":resources(),"service_progress":progress}))?;
                    },
                    _=>anyhow::bail!("unknown controller command"),
                },
                event=output.recv()=>{
                    let event=event.ok_or_else(||anyhow::anyhow!("protocol event stream ended"))?;
                    let value=serde_json::to_value(&event)?;
                    let kind=value["kind"].as_str().unwrap_or("");
                    if !matches!(kind,"token_released"|"terminal_checked"|"adversarial_terminal") {
                        let r=if matches!(kind,"coin"|"beacon"|"complete"){resources()}else{Value::Null};
                        emit(json!({"kind":"event","party":id,"elapsed_us":started.elapsed().as_micros(),"resources":r,"event":value}))?;
                    }
                    if let protocol::Event::Failed{reason}=event{anyhow::bail!(reason);}
                },
                signal=tokio::signal::ctrl_c()=>{signal?;break;}
            }
        }
        emit(json!({"kind":"stopping","party":id,"elapsed_us":started.elapsed().as_micros(),"resources":resources()}))?;
        handle.shutdown().await?;
        if audit {
            emit(json!({"kind":"bulk_audit","party":id,"counters":sdc_util::observation::bulk_audit::snapshot()}))?;
        }
        emit(json!({"kind":"stopped","party":id,"elapsed_us":started.elapsed().as_micros(),"resources":resources()}))?;
    }};
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let args = Args::parse();
    let node = config::load(&args.config)?;
    let raw = std::fs::read(&args.parameters)?;
    if args.describe {
        return emit(describe(&args, &node, &raw)?);
    }
    match args.protocol.as_str() {
        "whcc" => run_protocol!(whcc, node, &raw, whcc_progress),
        "csshashcoin" => run_protocol!(csshashcoin, node, &raw, csshashcoin_progress),
        "hashrand" => run_protocol!(hashrand, node, &raw, hashrand_progress),
        _ => anyhow::bail!("unknown protocol"),
    }
    Ok(())
}
