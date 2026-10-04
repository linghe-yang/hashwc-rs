use super::{
    address, emit,
    msg::Message,
    timestamp_us,
    transport::{self, Channel},
};
use anyhow::{Result, anyhow, ensure};
use config::Node;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::{net::TcpStream, sync::mpsc};
use whcc::{Context, Event, Parameters, Request};

/// Returns only on STOP. main exits the process without waiting for CPU-bound preparation.
pub async fn run(node: Node, parameters: Parameters, behavior: whcc::Behavior) -> Result<()> {
    Parameters::validate_widths(parameters.rounding_bits, parameters.output_bits)?;
    let output_bits = parameters.output_bits;
    let addr = address(&node, parameters.port_stride)?;
    let key = node
        .sk_map
        .get(&node.num_nodes)
        .ok_or_else(|| anyhow!("missing synchronizer key sk_map[num_nodes]"))?
        .clone();
    let stream = loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => break stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    };
    stream.set_nodelay(true)?;
    let epoch = parameters.epoch;
    let party = node.id;
    let mut stream = stream;
    let hello = super::msg::Payload {
        session: node.session_id,
        epoch,
        party,
        message: Message::Hello { output_bits },
    };
    transport::write(&mut stream, &transport::seal(hello, &key, false)?).await?;
    let mut channel = Channel::new(stream, node.clone(), epoch, party, key, false);
    let (requests, input) = mpsc::channel(1);
    let (events, mut output) = mpsc::channel(1024);
    let mut prepare_input = Some((input, events));
    let mut preparation = None;
    let mut service = None;
    let mut start_requested = false;
    let mut started = None::<Instant>;
    let mut started_us = 0;
    let mut coin = None;
    let mut terminal_checks = 0u64;
    let mut decoded_terminal_checks = 0u64;
    let mut rejected_terminals = 0u64;
    let mut forged_terminal_sends = 0usize;
    let mut rejected_dealers = std::collections::BTreeSet::new();
    emit(
        &node,
        epoch,
        output_bits,
        "behavior",
        json!({"party":party,"behavior":behavior.name()}),
    );
    loop {
        tokio::select! {
            biased;
            control=channel.recv()=>match control? {
                Message::Stop=>{
                    // No synchronous shutdown/join here: main terminates every worker immediately.
                    emit(&node, epoch, output_bits, "work", json!({"party":party,"terminal_checks":terminal_checks,"decoded_terminal_checks":decoded_terminal_checks,"rejected_terminals":rejected_terminals,"forged_terminal_sends":forged_terminal_sends,"rejected_dealers":rejected_dealers,"corrupted_public":behavior == whcc::Behavior::RecoveryStress && started.is_some()}));
                    emit(&node, epoch, output_bits, "stopped", json!({"party":party,"coin":coin.map(super::coin_json),"started":started.is_some()}));
                    return Ok(());
                },
                Message::Prepare=>{
                    if let Some((input, events))=prepare_input.take() {
                        let config = node.clone(); let params = parameters.clone();
                        emit(&node, epoch, output_bits, "prepare", json!({"party":party}));
                        preparation=Some(tokio::task::spawn_blocking(move || Context::spawn_with_behavior(config, params, behavior, input, events)));
                    }
                },
                Message::Start=>start_requested=true,
                _=>return Err(anyhow!("unexpected synchronizer directive")),
            },
            prepared=async { preparation.as_mut().expect("guarded").await }, if preparation.is_some()=>{
                service=Some(prepared??);
                preparation=None;
                emit(&node, epoch, output_bits, "ready", json!({"party":party}));
                channel.send(Message::PrepareOk)?;
            },
            event=output.recv(), if service.is_some()=>match event {
                Some(Event::Coin { epoch: output_epoch, value })=>{
                    ensure!(output_epoch == epoch && coin.is_none(), "unexpected/duplicate coin output");
                    let latency_us = started.ok_or_else(|| anyhow!("coin before START"))?.elapsed().as_micros();
                    coin=Some(value);
                    channel.send(Message::Finish { coin: value })?;
                    emit(&node, epoch, output_bits, "coin", json!({"party":party,"coin":super::coin_json(value),"started_us":started_us,"completed_us":timestamp_us()?,"latency_us":latency_us}));
                },
                Some(Event::AdversarialTerminal { recipients, .. })=>forged_terminal_sends += recipients,
                Some(Event::TerminalChecked { decoded, accepted, .. })=>{
                    terminal_checks += 1;
                    decoded_terminal_checks += u64::from(decoded);
                    rejected_terminals += u64::from(!accepted);
                },
                Some(Event::Terminal { dealer, rejected: true })=>{ rejected_dealers.insert(dealer); },
                Some(Event::Failed { reason })=>return Err(anyhow!(reason)),
                Some(_)=>{},
                None=>return Err(anyhow!("coin service stopped before STOP")),
            },
        }
        // START may reach a slow party during PREPARE; it starts as soon as preparation completes.
        if start_requested && service.is_some() && started.is_none() {
            started_us = timestamp_us()?;
            started = Some(Instant::now());
            requests.send(Request::Start).await?;
            emit(
                &node,
                epoch,
                output_bits,
                "start",
                json!({"party":party,"started_us":started_us}),
            );
        }
    }
}
