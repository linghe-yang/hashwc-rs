//! Authenticated reliable TCP transport for weighted services.
//! One outgoing queue per physical peer: a silent peer never stalls another peer.
//! Transport retry timers do not produce protocol decisions. Local state is not restart-persistent.
use anyhow::{anyhow, Result};
use bincode::Options;
use config::Node;
use crypto::hash::{mac_parts, serialized_mac, Hash};
#[cfg(test)]
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashMap,
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex},
    task::{JoinHandle, JoinSet},
};
use types::{Replica, SendAction};

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_INSTANCES: usize = 1024;
#[path = "weighted_ack_writer.rs"]
mod ack_writer;
#[path = "weighted_budget.rs"]
mod budget;
#[path = "weighted_frame.rs"]
mod frame;
#[path = "weighted_metrics.rs"]
pub mod metrics;
#[path = "weighted_payload.rs"]
mod payload;
#[path = "weighted_queue.rs"]
mod queue;
#[path = "weighted_reader.rs"]
mod reader;
#[path = "weighted_sender.rs"]
mod sender;
const WINDOW_FRAMES: usize = 32;
const WINDOW_BYTES: usize = 1024 * 1024;

// Both directions carry small latency-sensitive protocol frames or ACKs.
fn low_latency(stream: TcpStream) -> std::io::Result<TcpStream> {
    stream.set_nodelay(true)?;
    Ok(stream)
}

// Keep the existing wire format, but submit its prefix and body together.
#[cfg(test)]
fn encode_frame(frame: &Frame) -> Result<Vec<u8>> {
    encode_packet(
        frame.context,
        frame.sender,
        frame.recipient,
        frame.sequence,
        &frame.payload,
        frame.mac,
    )
}
fn encode_packet(
    context: Hash,
    sender: Replica,
    recipient: Replica,
    sequence: u64,
    payload: &[u8],
    mac: Hash,
) -> Result<Vec<u8>> {
    // Fixed-width bincode envelope: 32-byte context, four u64 fields, and 32-byte MAC.
    let size = 96 + payload.len();
    if size > MAX_FRAME_BYTES {
        return Err(anyhow!("weighted frame exceeds limit"));
    }
    let mut packet = Vec::with_capacity(size + 4);
    packet.extend_from_slice(&(size as u32).to_le_bytes());
    bincode::serialize_into(
        &mut packet,
        &(context, sender, recipient, sequence, payload.len() as u64),
    )?;
    packet.extend_from_slice(payload);
    packet.extend_from_slice(&mac);
    Ok(packet)
}

#[cfg(test)]
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Frame {
    context: Hash,
    sender: Replica,
    recipient: Replica,
    sequence: u64,
    payload: Vec<u8>,
    mac: Hash,
}
#[cfg(test)]
fn mac_prefix(f: &Frame) -> Vec<u8> {
    bincode::serialize(&(
        "weighted/frame/v1",
        f.context,
        f.sender,
        f.recipient,
        f.sequence,
        f.payload.len() as u64,
    ))
    .expect("frame prefix")
}
#[cfg(test)]
fn frame_mac(f: &Frame, key: &[u8]) -> Hash {
    mac_parts(&[&mac_prefix(f), &f.payload], key)
}
#[cfg(test)]
fn ack_mac(f: &Frame, key: &[u8]) -> Hash {
    serialized_mac(
        &(
            "weighted/ack/v1",
            f.context,
            f.sender,
            f.recipient,
            f.sequence,
        ),
        key,
    )
    .expect("ACK MAC")
}
fn decode<T: DeserializeOwned>(raw: &[u8]) -> Result<T> {
    let _profile = crate::profile::span("transport.payload.decode");
    decode_value(raw)
}
fn decode_value<T: DeserializeOwned>(raw: &[u8]) -> Result<T> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(raw)?)
}

/// Canonical fixed-width protocol payload, bounded before entering any send queue.
pub fn serialize_payload<T: Serialize>(message: &T) -> Result<Vec<u8>> {
    let _profile = crate::profile::span("transport.payload.encode");
    let mut raw = Vec::new();
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit((MAX_FRAME_BYTES - 256) as u64)
        .serialize_into(&mut raw, message)?;
    Ok(raw)
}

/// Opt-in for expensive custom serializers, such as compact BinAA.
/// Bounds are identical, but byte-at-a-time bulk serializers should use the default path.
pub fn serialize_payload_once<T: Serialize>(message: &T) -> Result<Vec<u8>> {
    let _profile = crate::profile::span("transport.payload.encode");
    Ok(payload::encode(message, MAX_FRAME_BYTES - 256)?)
}

/// Each protocol aliases this handler in handlers/handler.rs.
pub struct Handler<T> {
    id: Replica,
    context: Hash,
    keys: Arc<HashMap<Replica, Vec<u8>>>,
    received: Arc<HashMap<Replica, Mutex<u64>>>,
    tx: mpsc::Sender<(Replica, T)>,
    metrics: Arc<metrics::Counters>,
}
impl<T> Clone for Handler<T> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            context: self.context,
            keys: self.keys.clone(),
            received: self.received.clone(),
            tx: self.tx.clone(),
            metrics: self.metrics.clone(),
        }
    }
}
impl<T: DeserializeOwned + Send + 'static> Handler<T> {
    async fn dispatch(&self, stream: TcpStream) -> Result<()> {
        let mut stream = low_latency(stream)?;
        // TCP borrowed halves add no generic split mutex or extra task.
        let (read, write) = stream.split();
        let read = metrics::Counted::new(read, self.metrics.clone());
        let write = metrics::Counted::ack_writer(write, self.metrics.clone());
        self.receive_halves(read, write).await
    }
    #[cfg(test)]
    async fn receive_frames<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        stream: S,
    ) -> Result<()> {
        let (read, write) = tokio::io::split(stream);
        self.receive_halves(read, write).await
    }
    async fn receive_halves<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
        &self,
        read: R,
        write: W,
    ) -> Result<()> {
        let mut input = reader::FrameReader::new(read);
        let mut acks = ack_writer::ReadyAcks::new(write);
        let mut work = budget::ReceiveBudget::new(&self.metrics);
        loop {
            let next = work
                .track(acks.wait_ready(async {
                    let raw = input.next().await?;
                    let bytes = raw.len() + 4;
                    let ack = self.accept_frame(raw).await?;
                    Ok::<_, anyhow::Error>((ack, bytes))
                }))
                .await?;
            let (ack, bytes) = match next {
                Ok(value) => value,
                Err(error) => {
                    // EOF, an invalid later frame or a closed actor must not
                    // discard ACKs for previously accepted frames.
                    work.track(acks.drain()).await?;
                    return Err(error);
                }
            };
            acks.push(&ack);
            if acks.full() || work.yields_after(bytes) {
                work.track(acks.drain()).await?;
            }
            // Diagnostic accounting is at acceptance. Any optional explicit
            // yield is preceded by draining the current ACK; defaults are zero.
            work.complete(bytes).await;
        }
    }
    async fn accept_frame(&self, raw: &[u8]) -> Result<Hash> {
        let f = {
            let _profile = crate::profile::span("transport.frame.decode");
            frame::FrameRef::parse(raw)?
        };
        let key = self
            .keys
            .get(&f.sender)
            .ok_or_else(|| anyhow!("unknown sender"))?;
        let authentic = {
            let _profile = crate::profile::span("transport.frame.verify");
            *f.context == self.context && f.recipient == self.id && f.verify(key)
        };
        if !authentic {
            return Err(anyhow!("invalid message authentication/context"));
        }
        let mut received = self
            .received
            .get(&f.sender)
            .ok_or_else(|| anyhow!("unknown sender"))?
            .lock()
            .await;
        let last = &mut *received;
        if f.sequence == last.saturating_add(1) && f.sequence != 0 {
            let msg = decode(f.payload)?;
            let permit = match self.tx.try_reserve() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(anyhow!("protocol stopped"))
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let started = std::time::Instant::now();
                    let result = self.tx.reserve().await;
                    self.metrics.backpressure(started.elapsed());
                    result.map_err(|_| anyhow!("protocol stopped"))?
                }
            };
            permit.send((f.sender, msg));
            *last = f.sequence;
        } else if f.sequence == 0 || f.sequence > *last {
            return Err(anyhow!("out-of-order transport sequence"));
        }
        drop(received);
        let ack = {
            let _profile = crate::profile::span("transport.ack.compute");
            f.ack(key)
        };
        Ok(ack)
    }
}

/// Share identical queued wire payloads across recipients without retaining completed sends.
#[derive(Default)]
struct PayloadCache {
    entries: HashMap<Hash, Weak<Vec<u8>>>,
    insertions: usize,
}
impl PayloadCache {
    fn intern(&mut self, bytes: Vec<u8>) -> Arc<Vec<u8>> {
        let key = crypto::hash::do_hash(&bytes);
        if let Some(existing) = self.entries.get(&key).and_then(Weak::upgrade) {
            // Equality keeps this a storage optimization even in the event of a hash collision.
            if *existing == bytes {
                return existing;
            }
        }
        self.insertions += 1;
        if self.insertions % 1024 == 0 {
            self.entries.retain(|_, value| value.strong_count() != 0);
        }
        let shared = Arc::new(bytes);
        self.entries.insert(key, Arc::downgrade(&shared));
        shared
    }
}

pub struct Endpoint<T> {
    pub recv: mpsc::Receiver<(Replica, T)>,
    pub public_id: Hash,
    outbound: Outbound,
    tasks: Vec<JoinHandle<()>>,
}
impl<T: Clone + Debug + Serialize + DeserializeOwned + Send + Sync + 'static> Endpoint<T> {
    pub fn bind(config: &Node, component: &str) -> Result<Self> {
        Self::bind_with_wire_domain(config, component, component)
    }
    /// Keep the metric component stable while authenticating a distinct wire version.
    pub fn bind_with_wire_domain(
        config: &Node,
        component: &str,
        wire_domain: &str,
    ) -> Result<Self> {
        config.validate_weighted()?;
        let n = config.num_nodes;
        let id = config.id;
        let context = config.weighted_public_id(wire_domain);
        let metrics = metrics::counter(component);
        let execution = crate::execution::Settings::from_env()?;
        let (tx, recv) = mpsc::channel(execution.transport_receive_capacity);
        let keys: HashMap<_, _> = (0..n).map(|i| (i, config.sk_map[&i].clone())).collect();
        let handler = Handler {
            id,
            context,
            keys: Arc::new(keys),
            received: Arc::new((0..n).map(|i| (i, Mutex::new(0))).collect()),
            tx: tx.clone(),
            metrics: metrics.clone(),
        };
        let address: SocketAddr = config.net_map[&id].parse()?;
        let listener =
            std::net::TcpListener::bind(SocketAddr::new("0.0.0.0".parse()?, address.port()))?;
        listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(listener)?;
        let mut tasks = vec![tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>match accepted {
                        Ok((socket,_))=>{ let h=handler.clone(); connections.spawn(async move { let _=h.dispatch(socket).await; }); },
                        Err(e)=>{ log::error!("weighted listener: {}",e); break; }
                    },
                    _=connections.join_next(), if !connections.is_empty()=>{}
                }
            }
        })];
        let mut peers = Vec::with_capacity(n);
        for peer in 0..n {
            let queue = Arc::new(queue::Queue::default());
            peers.push(queue.clone());
            let tx = tx.clone();
            let key = config.sk_map[&peer].clone();
            let addr: SocketAddr = config.net_map[&peer].parse()?;
            let metrics = metrics.clone();
            tasks.push(tokio::spawn(async move {
                if peer == id {
                    // Local delivery still follows this peer's FIFO and backpressure.
                    while let Ok(Some(message)) = queue.pop().await {
                        let Ok(message) = decode::<T>(&message) else {
                            return;
                        };
                        if tx.send((id, message)).await.is_err() {
                            return;
                        }
                    }
                } else if let Err(e) =
                    sender::send_peer(queue, addr, context, id, peer, key, metrics).await
                {
                    log::error!("weighted sender peer {}: {}", peer, e);
                }
            }));
        }
        Ok(Self {
            recv,
            public_id: context,
            outbound: Outbound {
                peers: Arc::new(peers),
                local_id: id,
                metrics,
                payloads: Arc::new(StdMutex::new(PayloadCache::default())),
            },
            tasks,
        })
    }
    pub fn send(&self, action: SendAction<T>) -> Result<()> {
        self.outbound.send(action)
    }
    pub fn sender(&self) -> Outbound {
        self.outbound.clone()
    }
}
#[derive(Clone)]
pub struct Outbound {
    local_id: Replica,
    metrics: Arc<metrics::Counters>,
    peers: Arc<Vec<Arc<queue::Queue>>>,
    payloads: Arc<StdMutex<PayloadCache>>,
}
impl Outbound {
    pub fn send<T: Serialize>(&self, action: SendAction<T>) -> Result<()> {
        let raw = serialize_payload(&action.message)?;
        let peer = self
            .peers
            .get(action.recipient)
            .ok_or_else(|| anyhow!("unknown recipient"))?;
        let payload = self
            .payloads
            .lock()
            .map_err(|_| anyhow!("payload cache poisoned"))?
            .intern(raw);
        if action.recipient != self.local_id {
            self.metrics.queue();
        }
        let result = peer.push(payload);
        if result.is_err() && action.recipient != self.local_id {
            self.metrics.unqueue();
        }
        result.map_err(Into::into)
    }
    pub fn send_batch<T: Serialize + PartialEq>(&self, actions: Vec<SendAction<T>>) -> Result<()> {
        self.send_batch_using(actions, serialize_payload)
    }
    /// Avoid the size-preflight traversal for an expensive custom serializer.
    /// This does not wait for more messages or change the batching/queue semantics.
    pub fn send_batch_single_pass<T: Serialize + PartialEq>(
        &self,
        actions: Vec<SendAction<T>>,
    ) -> Result<()> {
        self.send_batch_using(actions, serialize_payload_once)
    }
    fn send_batch_using<T: Serialize + PartialEq>(
        &self,
        actions: Vec<SendAction<T>>,
        encode: impl Fn(&T) -> Result<Vec<u8>>,
    ) -> Result<()> {
        let mut previous: Option<(T, Arc<Vec<u8>>)> = None;
        for action in actions {
            let peer = self
                .peers
                .get(action.recipient)
                .ok_or_else(|| anyhow!("unknown recipient"))?;
            let payload = match &previous {
                Some((message, payload)) if message == &action.message => payload.clone(),
                _ => {
                    let raw = encode(&action.message)?;
                    self.payloads
                        .lock()
                        .map_err(|_| anyhow!("payload cache poisoned"))?
                        .intern(raw)
                }
            };
            if action.recipient != self.local_id {
                self.metrics.queue();
            }
            if let Err(e) = peer.push(payload.clone()) {
                if action.recipient != self.local_id {
                    self.metrics.unqueue();
                }
                return Err(e.into());
            }
            previous = Some((action.message, payload));
        }
        Ok(())
    }
}

impl<T> Drop for Endpoint<T> {
    fn drop(&mut self) {
        for queue in self.outbound.peers.iter() {
            queue.close();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn exchange(handler: Handler<u64>, raw: Vec<u8>) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            handler.dispatch(socket).await
        });
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket.write_u32_le(raw.len() as u32).await.unwrap();
        socket.write_all(&raw).await.unwrap();
        let mut ack = [0; 32];
        let accepted = socket.read_exact(&mut ack).await.is_ok();
        drop(socket);
        let _ = worker.await;
        accepted
    }
    #[tokio::test]
    async fn authenticated_context_sequence_and_duplicate_delivery() {
        let key = vec![7; crypto::SECRET_KEY_SIZE];
        let (tx, mut rx) = mpsc::channel(8);
        let handler = Handler {
            id: 1,
            context: [9; 32],
            keys: Arc::new(vec![(0, key.clone())].into_iter().collect()),
            received: Arc::new(vec![(0, Mutex::new(0))].into_iter().collect()),
            tx,
            metrics: metrics::counter("authentication-test"),
        };
        let mut f = Frame {
            context: [9; 32],
            sender: 0,
            recipient: 1,
            sequence: 1,
            payload: bincode::serialize(&42u64).unwrap(),
            mac: [0; 32],
        };
        f.mac = frame_mac(&f, &key);
        let mut bad = f.clone();
        bad.payload[0] ^= 1;
        assert!(!exchange(handler.clone(), bincode::serialize(&bad).unwrap()).await);
        bad = f.clone();
        bad.context = [8; 32];
        bad.mac = frame_mac(&bad, &key);
        assert!(!exchange(handler.clone(), bincode::serialize(&bad).unwrap()).await);
        bad = f.clone();
        bad.sequence = 2;
        bad.mac = frame_mac(&bad, &key);
        assert!(!exchange(handler.clone(), bincode::serialize(&bad).unwrap()).await);
        assert!(rx.try_recv().is_err());
        let raw = bincode::serialize(&f).unwrap();
        assert!(exchange(handler.clone(), raw.clone()).await);
        assert_eq!(rx.recv().await, Some((0, 42)));
        assert!(exchange(handler.clone(), raw).await);
        assert!(rx.try_recv().is_err());
        f.sequence = 2;
        f.mac = frame_mac(&f, &key);
        assert!(exchange(handler, bincode::serialize(&f).unwrap()).await);
        assert_eq!(rx.recv().await, Some((0, 42)));
    }
    #[test]
    fn identical_pending_payloads_share_storage_and_completed_ones_expire() {
        let mut cache = PayloadCache::default();
        let a = cache.intern(vec![1; 32768]);
        let b = cache.intern(vec![1; 32768]);
        assert!(Arc::ptr_eq(&a, &b));
        let weak = Arc::downgrade(&a);
        drop(a);
        drop(b);
        assert!(weak.upgrade().is_none());
        for i in 0u32..2048 {
            cache.intern(i.to_le_bytes().to_vec());
        }
        assert!(cache.entries.len() < 1024);
    }
    #[test]
    fn malformed_serialization_is_bounded() {
        let mut raw = bincode::serialize(&7u64).unwrap();
        raw.push(1);
        assert!(decode::<u64>(&raw).is_err());
        assert!(decode::<Vec<u8>>(&u64::MAX.to_le_bytes()).is_err());
    }
}

#[cfg(test)]
#[path = "weighted_tests.rs"]
mod transport_tests;

#[cfg(test)]
#[path = "weighted_receiver_tests.rs"]
mod receiver_tests;
