use clap::{Parser, Subcommand, ValueEnum};
use config::{Config, Protocol};
use wcss::{Limits, Setup};
#[derive(Parser)]
#[command(
    name = "node",
    version,
    about = "Weighted hash-based coin research: wiAwVSS stage"
)]
struct Args {
    #[arg(short,long,action=clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum Selection {
    Wiawvss,
}
#[derive(Subcommand)]
enum Command {
    /// Validate runtime configuration and compile the public weighted circuit.
    CheckConfig {
        #[arg(long)]
        config: std::path::PathBuf,
        #[arg(long)]
        protocol: Option<Selection>,
    },
}
fn main() -> anyhow::Result<()> {
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
        Command::CheckConfig { config, protocol } => {
            let mut config = Config::load(config)?;
            if let Some(Selection::Wiawvss) = protocol {
                config.protocol = Protocol::Wiawvss;
            }
            match config.protocol {
                Protocol::Wiawvss => {
                    let setup = Setup::new(config.policy()?, Limits::default())?;
                    log::info!(
                        "wiAwVSS configuration parties={} gates={} public_bytes={}",
                        setup.circuit().policy().n(),
                        setup.circuit().gates().len(),
                        wiawvss::Public::encoded_len(&setup)
                    );
                    println!(
                        "{}",
                        serde_json::json!({"protocol":"wiawvss","parties":setup.circuit().policy().n(),"gates":setup.circuit().gates().len(),"public_bytes":wiawvss::Public::encoded_len(&setup),"status":"valid"})
                    );
                }
            }
        }
    }
    Ok(())
}
