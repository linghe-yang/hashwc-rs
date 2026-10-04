mod synchronizer;
use clap::{Parser, Subcommand, ValueEnum};
use config::Ports;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use whcc::{Context, Event, Parameters, Request};
#[derive(Parser)]
#[command(name = "node", version, about = "Weighted hash-based common coin")]
struct Args {
    #[arg(short,long,action=clap::ArgAction::Count)]
    pub verbose: u8,
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum Protocol {
    #[value(alias = "commoncoin")]
    Whcc,
    Wiawvss,
}
#[derive(Clone, Copy, ValueEnum)]
enum BehaviorArg {
    Honest,
    RecoveryStress,
}
impl From<BehaviorArg> for whcc::Behavior {
    fn from(value: BehaviorArg) -> Self {
        match value {
            BehaviorArg::Honest => Self::Honest,
            BehaviorArg::RecoveryStress => Self::RecoveryStress,
        }
    }
}
#[derive(Subcommand)]
enum Command {
    /// Validate an upstream Node configuration and all protocol ports.
    CheckConfig {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        parameters: Option<std::path::PathBuf>,
        #[arg(long, default_value = "whcc")]
        protocol: Protocol,
    },
    /// Run one invocation; keep serving slow peers after output until interrupted.
    Run {
        /// Follow PREPARE/START/STOP from the independent benchmark synchronizer.
        #[arg(long)]
        synchronize: bool,
        /// Bounded adversarial workload for research benchmarks.
        #[arg(long, value_enum, default_value = "honest")]
        behavior: BehaviorArg,
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        parameters: Option<std::path::PathBuf>,
    },
    /// Run the independent benchmark synchronizer using an upstream Node config.
    Synchronizer {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        parameters: Option<std::path::PathBuf>,
    },
}
fn parameters(path: Option<std::path::PathBuf>) -> anyhow::Result<Parameters> {
    Ok(match path {
        Some(p) => serde_json::from_slice(&std::fs::read(p)?)?,
        None => Parameters::default(),
    })
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if args.verbose > 0 {
            "debug"
        } else {
            "info"
        }),
    )
    .format_timestamp_millis()
    .init();
    match args.command {
        Command::Synchronizer {
            config,
            parameters: path,
        } => {
            synchronizer::run(config::load(config)?, parameters(path)?).await?;
        }
        Command::CheckConfig {
            config,
            parameters: path,
            protocol,
        } => {
            let node = config::load(config)?;
            let p = parameters(path)?;
            let setup = p.setup(&node)?;
            let ports = Ports::new(&node, p.port_stride)?;
            let protocol = match protocol {
                Protocol::Whcc => "whcc",
                Protocol::Wiawvss => "wiawvss",
            };
            println!(
                "{}",
                serde_json::json!({"protocol":protocol,"party":node.id,"parties":node.num_nodes,"gates":setup.circuit().gates().len(),"public_bytes":wiawvss::Public::encoded_len(&setup),"port_stride":ports.stride(),"status":"valid","output_bits":p.output_bits})
            );
        }
        Command::Run {
            synchronize,
            behavior,
            config,
            parameters: path,
        } => {
            let node = config::load(config)?;
            if synchronize {
                synchronizer::party::run(node, parameters(path)?, behavior.into()).await?;
                // STOP is an experiment-wide abort, including any spawn_blocking preparation.
                std::process::exit(0);
            }
            let party = node.id;
            let session = node
                .session_id
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let p = parameters(path)?;
            let epoch = p.epoch;
            let output_bits = p.output_bits;
            let (input, rx) = mpsc::channel(1);
            let (tx, mut output) = mpsc::channel(1024);
            let service = Context::spawn_with_behavior(node, p, behavior.into(), rx, tx)?;
            let started_us = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
            let started = Instant::now();
            log::info!("WHCC request for epoch {epoch} sent at {started_us}");
            println!(
                "{}",
                serde_json::json!({"kind":"start","protocol":"whcc","output_bits":output_bits,"party":party,"epoch":epoch,"session":session,"started_us":started_us})
            );
            input.send(Request::Start).await?;
            loop {
                tokio::select! {
                    result=tokio::signal::ctrl_c()=>{result?;break;},
                    event=output.recv()=>match event {
                        Some(Event::Coin{epoch,value})=>{
                            let latency_us = started.elapsed().as_micros();
                            let completed_us = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
                            log::info!("WHCC result for epoch {epoch} is {value} received at {completed_us}; latency_us={latency_us}");
                            println!("{}",serde_json::json!({"kind":"coin","protocol":"whcc","output_bits":output_bits,"party":party,"epoch":epoch,"session":session,"coin":synchronizer::coin_json(value),"started_us":started_us,"completed_us":completed_us,"latency_us":latency_us}));
                        },
                        Some(Event::Failed{reason})=>anyhow::bail!(reason),Some(_)=>{},None=>anyhow::bail!("common coin service stopped"),
                    }
                }
            }
            service.shutdown().await?;
        }
    }
    Ok(())
}
