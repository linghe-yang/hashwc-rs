//! Trusted benchmark coordinator, separate from the asynchronous coin protocol.
pub mod msg;
pub mod party;
pub mod state;
#[cfg(test)]
mod tests;
pub mod transport;

use anyhow::{Result, ensure};
use config::{Node, Ports, Service};
use msg::Message;
use serde_json::json;
use state::State;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinSet,
};
use transport::Channel;

pub fn timestamp_us() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())
}
pub fn session(node: &Node) -> String {
    node.session_id.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn emit(node: &Node, epoch: u64, output_bits: u32, kind: &str, mut value: serde_json::Value) {
    value["output_bits"] = json!(output_bits);
    value["protocol"] = json!("whcc");
    value["kind"] = json!(kind);
    value["session"] = json!(session(node));
    value["epoch"] = json!(epoch);
    println!("{value}");
}
pub fn address(node: &Node, stride: Option<u16>) -> Result<SocketAddr> {
    let ports = Ports::new(node, stride)?;
    let addr: SocketAddr = node
        .net_map
        .get(&node.num_nodes)
        .ok_or_else(|| anyhow::anyhow!("missing synchronizer net_map[num_nodes]"))?
        .parse()?;
    ensure!(
        addr.is_ipv4() && !addr.ip().is_unspecified() && addr.port() != 0,
        "synchronizer needs an explicit IPv4 endpoint"
    );
    for service in Service::ALL {
        for i in 0..node.num_nodes {
            let peer: SocketAddr = ports.node(node, service)?.net_map[&i].parse()?;
            let same_host =
                peer.ip() == addr.ip() || (peer.ip().is_loopback() && addr.ip().is_loopback());
            ensure!(
                !same_host || peer.port() != addr.port(),
                "synchronizer port collides with protocol service"
            );
        }
    }
    Ok(addr)
}
enum Event {
    Connected {
        party: usize,
        connection: usize,
        output: mpsc::UnboundedSender<Message>,
    },
    Received {
        party: usize,
        connection: usize,
        message: Message,
    },
    Disconnected {
        party: usize,
        connection: usize,
    },
}
async fn connection(
    mut stream: TcpStream,
    node: Node,
    epoch: u64,
    output_bits: u32,
    connection: usize,
    events: mpsc::UnboundedSender<Event>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let wire =
        tokio::time::timeout(Duration::from_secs(10), transport::read(&mut stream)).await??;
    let party = wire.payload.party;
    ensure!(party < node.num_nodes, "unknown control party");
    let key = node.sk_map[&party].clone();
    let hello = transport::verify(wire, &node, epoch, party, &key, false)?;
    ensure!(
        hello.message == Message::Hello { output_bits },
        "expected HELLO with matching output_bits"
    );
    let mut channel = Channel::new(stream, node, epoch, party, key, true);
    events.send(Event::Connected {
        party,
        connection,
        output: channel.output.clone(),
    })?;
    while let Ok(message) = channel.recv().await {
        if events
            .send(Event::Received {
                party,
                connection,
                message,
            })
            .is_err()
        {
            break;
        }
    }
    let _ = events.send(Event::Disconnected { party, connection });
    Ok(())
}
pub async fn run(node: Node, parameters: whcc::Parameters) -> Result<()> {
    parameters.validate(&node)?;
    let output_bits = parameters.output_bits;
    let addr = address(&node, parameters.port_stride)?;
    let policy = config::policy(&node)?;
    let mut state = State::new(
        policy.weights().to_vec(),
        policy.threshold().clone(),
        output_bits,
    )?;
    let listener = TcpListener::bind(addr).await?;
    let epoch = parameters.epoch;
    emit(
        &node,
        epoch,
        output_bits,
        "sync_ready",
        json!({"address":addr.to_string()}),
    );
    let (events, mut input) = mpsc::unbounded_channel();
    let mut tasks = JoinSet::new();
    let mut peers = BTreeMap::<usize, (usize, mpsc::UnboundedSender<Message>)>::new();
    let mut next_connection = 0;
    let mut started = None::<Instant>;
    let mut started_us = 0;
    loop {
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            accepted=listener.accept()=>{
                let (stream, _) = accepted?;
                tasks.spawn(connection(stream, node.clone(), epoch, output_bits, next_connection, events.clone()));
                next_connection += 1;
            },
            Some(event)=input.recv()=>match event {
                Event::Connected { party, connection, output }=>{
                    if peers.contains_key(&party) { let _=output.send(Message::Stop); continue; }
                    // Catch up late connections. STOP always wins over PREPARE/START.
                    if state.result.is_some() { let _=output.send(Message::Stop); }
                    else {
                        let _=output.send(Message::Prepare);
                        if state.started { let _=output.send(Message::Start); }
                    }
                    peers.insert(party, (connection, output));
                },
                Event::Disconnected { party, connection }=>{
                    if peers.get(&party).is_some_and(|(id,_)| *id == connection) { peers.remove(&party); }
                },
                Event::Received { party, connection, message }=>{
                    if !peers.get(&party).is_some_and(|(id,_)| *id == connection) { continue; }
                    match message {
                        Message::PrepareOk if state.result.is_none()=>{
                            if state.prepare(party)? {
                                started = Some(Instant::now());
                                started_us = timestamp_us()?;
                                for (_,output) in peers.values() { let _=output.send(Message::Start); }
                                log::info!("Synchronizer START at {started_us}: prepared weight {} > W-T", state.prepared_weight);
                                emit(&node, epoch, output_bits, "sync_start", json!({"started_us":started_us,"prepared":state.prepared,"prepared_weight":state.prepared_weight.to_string()}));
                            }
                        },
                        Message::Finish { coin } if state.result.is_none()=>{
                            match state.finish(party, coin) {
                                Ok(true)=>{
                                    let latency_us = started.expect("START precedes FINISH").elapsed().as_micros();
                                    let completed_us = timestamp_us()?;
                                    log::info!("Synchronizer result {coin} at {completed_us}; latency_us={latency_us}");
                                    emit(&node, epoch, output_bits, "sync_result", json!({"coin":coin_json(coin),"started_us":started_us,"completed_us":completed_us,"latency_us":latency_us,
                                        "finishes":state.finishes.iter().map(|(&p,&c)|(p,coin_json(c))).collect::<BTreeMap<_,_>>(),"finish_weight":state.finish_weights[&coin].to_string()}));
                                    for (_,output) in peers.values() { let _=output.send(Message::Stop); }
                                },
                                Ok(false)=>{},
                                Err(e)=>log::warn!("Ignored FINISH from {party}: {e}"),
                            }
                        },
                        _=>{},
                    }
                },
            },
            Some(result)=tasks.join_next(), if !tasks.is_empty()=>{
                if let Ok(Err(e))=result { log::debug!("Control connection rejected: {e}"); }
            },
        }
    }
    ensure!(
        state.result.is_some(),
        "synchronizer stopped before reaching FINISH threshold"
    );
    Ok(())
}

/// Keep binary logs numeric; wider words use fixed-width hex to avoid JSON number truncation.
pub fn coin_json(coin: whcc::Coin) -> serde_json::Value {
    if coin.bits == 1 {
        json!(coin.bit(0).expect("validated coin"))
    } else {
        json!(coin.to_hex())
    }
}
