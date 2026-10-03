use clap::{Parser, Subcommand, ValueEnum};
use commoncoin::{Context, Event, Parameters, Request};
use config::Ports;
use tokio::sync::mpsc;
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
    Commoncoin,
    Wiawvss,
}
#[derive(Subcommand)]
enum Command {
    /// Validate an upstream Node configuration and all protocol ports.
    CheckConfig {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        parameters: Option<std::path::PathBuf>,
        #[arg(long, default_value = "commoncoin")]
        protocol: Protocol,
    },
    /// Run one invocation; keep serving slow peers after output until interrupted.
    Run {
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
                Protocol::Commoncoin => "commoncoin",
                Protocol::Wiawvss => "wiawvss",
            };
            println!(
                "{}",
                serde_json::json!({"protocol":protocol,"party":node.id,"parties":node.num_nodes,"gates":setup.circuit().gates().len(),"public_bytes":wiawvss::Public::encoded_len(&setup),"port_stride":ports.stride(),"status":"valid"})
            );
        }
        Command::Run {
            config,
            parameters: path,
        } => {
            let node = config::load(config)?;
            let party = node.id;
            let p = parameters(path)?;
            let (input, rx) = mpsc::channel(1);
            let (tx, mut output) = mpsc::channel(1024);
            let service = Context::spawn(node, p, rx, tx)?;
            input.send(Request::Start).await?;
            loop {
                tokio::select! {
                    result=tokio::signal::ctrl_c()=>{result?;break;},
                    event=output.recv()=>match event {
                        Some(Event::Coin{epoch,bit})=>println!("{}",serde_json::json!({"protocol":"commoncoin","party":party,"epoch":epoch,"coin":bit})),
                        Some(Event::Failed{reason})=>anyhow::bail!(reason),Some(_)=>{},None=>anyhow::bail!("common coin service stopped"),
                    }
                }
            }
            service.shutdown().await?;
        }
    }
    Ok(())
}
