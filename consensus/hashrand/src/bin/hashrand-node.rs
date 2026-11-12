//! Independent process entry point; completion keeps peer services alive until STOP.
use anyhow::{Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use hashrand::{Behavior, Context, Event, Parameters, Request};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::mpsc,
};
#[derive(Parser)]
#[command(about = "Weighted HashRand baseline with virtual Shamir shares")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum Role {
    Honest,
    InvalidPolynomial,
    WithholdRecovery,
}
impl From<Role> for Behavior {
    fn from(role: Role) -> Self {
        match role {
            Role::Honest => Self::Honest,
            Role::InvalidPolynomial => Self::InvalidPolynomial,
            Role::WithholdRecovery => Self::WithholdRecovery,
        }
    }
}
#[derive(Subcommand)]
enum Command {
    GenerateLocal {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        weights: String,
        #[arg(long)]
        threshold: String,
        #[arg(long)]
        base_port: u16,
    },
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        parameters: PathBuf,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        parameters: PathBuf,
        /// Wait for "start" on stdin; continue serving after Complete until "stop".
        #[arg(long)]
        controlled: bool,
        #[arg(long, value_enum, default_value = "honest")]
        behavior: Role,
    },
}
fn emit(value: serde_json::Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
fn load(config: PathBuf, parameters: PathBuf) -> Result<(config::Node, Parameters)> {
    let node = config::load(config)?;
    let p: Parameters = serde_json::from_slice(&std::fs::read(parameters)?)?;
    p.validate(&node)?;
    Ok((node, p))
}
fn write_config(path: &Path, node: &config::Node) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    serde_json::to_writer_pretty(&mut f, node)?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    match Args::parse().command {
        Command::GenerateLocal {
            directory,
            weights,
            threshold,
            base_port,
        } => {
            let weights = weights
                .split(',')
                .map(str::parse::<sdc_types::Weight>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(anyhow::Error::msg)?;
            let threshold: sdc_types::Weight = threshold.parse().map_err(anyhow::Error::msg)?;
            ensure!((2..=512).contains(&weights.len()), "physical party limit");
            ensure!(
                base_port as usize + config::SERVICE_COUNT * weights.len() < 65536,
                "port overflow"
            );
            std::fs::create_dir_all(&directory)?;
            let session = crypto::random().map_err(|e| anyhow::anyhow!("{e}"))?;
            let key_seed = crypto::random().map_err(|e| anyhow::anyhow!("{e}"))?;
            for id in 0..weights.len() {
                let mut node = config::Node::new();
                node.id = id;
                node.num_nodes = weights.len();
                node.weights = weights.clone();
                node.weight_threshold = Some(threshold.clone());
                node.session_id = session;
                for peer in 0..weights.len() {
                    node.net_map
                        .insert(peer, format!("127.0.0.1:{}", base_port + peer as u16));
                    node.sk_map.insert(
                        peer,
                        crypto::hash(
                            b"local-experiment/key",
                            &[
                                &key_seed,
                                &(id.min(peer) as u64).to_le_bytes(),
                                &(id.max(peer) as u64).to_le_bytes(),
                            ],
                        )
                        .to_vec(),
                    );
                }
                node.validate_weighted()?;
                write_config(&directory.join(format!("node-{id}.json")), &node)?;
            }
        }
        Command::CheckConfig { config, parameters } => {
            let (node, p) = load(config, parameters)?;
            let layout = p.layout(&node)?;
            emit(
                serde_json::json!({"kind":"configuration","protocol":"hashrand-virtual",
                "parties":node.num_nodes,"total_tickets":layout.total,"sharing_threshold":layout.threshold,
                "tickets_per_party":layout.ranges.iter().map(|r|r.len()).collect::<Vec<_>>(),
                "parameters":p,"public_root_bytes_per_dealer":(0..p.batches).map(|b|32*p.slots(b,node.num_nodes)).collect::<Vec<_>>(),
                "reserved_seed_slots":(0..p.batches).map(|b|p.reserved(b,node.num_nodes)).collect::<Vec<_>>() }),
            )?;
        }
        Command::Run {
            config,
            parameters,
            controlled,
            behavior,
        } => {
            let (node, p) = load(config, parameters)?;
            let id = node.id;
            let (input, rx) = mpsc::channel(1);
            let (tx, mut output) = mpsc::channel(4096);
            let handle = Context::spawn_with_behavior(node, p, behavior.into(), rx, tx)?;
            emit(serde_json::json!({"kind":"ready","party":id}))?;
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            if controlled {
                ensure!(
                    lines.next_line().await?.as_deref() == Some("start"),
                    "expected start"
                );
            }
            let started = Instant::now();
            input.send(Request::Start).await?;
            loop {
                tokio::select! {
                    line=lines.next_line(),if controlled=>{
                        match line?.as_deref(){Some("stop")|None=>break,Some(other)=>anyhow::bail!("unknown control: {other}")}
                    },
                    signal=tokio::signal::ctrl_c()=>{signal?;break;},
                    event=output.recv()=>match event {
                        Some(event)=>{
                            emit(serde_json::json!({"kind":"protocol_event","party":id,
                                "elapsed_us":started.elapsed().as_micros(),
                                "unix_us":SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),"event":event}))?;
                            if let Event::Failed {reason}=event{anyhow::bail!(reason);}
                        },
                        None=>anyhow::bail!("protocol event channel ended"),
                    }
                }
            }
            handle.shutdown().await?;
        }
    }
    Ok(())
}
