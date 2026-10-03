//! Authenticated reliable TCP transport for weighted services.
//! One outgoing queue per physical peer: a silent peer never stalls another peer.
//! Transport retry timers do not produce protocol decisions. Local state is not restart-persistent.
use anyhow::{Result, anyhow};
use bincode::Options;
use config::Node;
use crypto::hash::{Hash, do_mac, verf_mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::HashMap, fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
    task::{JoinHandle, JoinSet},
};
use types::{Replica, SendAction};

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_INSTANCES: usize = 1024;

// Both directions carry small latency-sensitive protocol frames or ACKs.
fn low_latency(stream: TcpStream) -> std::io::Result<TcpStream> {
    stream.set_nodelay(true)?;
    Ok(stream)
}

// Keep the existing wire format, but submit its prefix and body together.
fn encode_frame(frame: &Frame) -> Result<Vec<u8>> {
    let size = bincode::serialized_size(frame)?;
    if size > MAX_FRAME_BYTES as u64 {
        return Err(anyhow!("weighted frame exceeds limit"));
    }
    let mut packet = Vec::with_capacity(size as usize + 4);
    packet.extend_from_slice(&(size as u32).to_le_bytes());
    bincode::serialize_into(&mut packet, frame)?;
    Ok(packet)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Frame {
    context: Hash,
    sender: Replica,
    recipient: Replica,
    sequence: u64,
    payload: Vec<u8>,
    mac: Hash,
}
fn frame_mac(f: &Frame, key: &[u8]) -> Hash {
    do_mac(
        &bincode::serialize(&(
            "weighted/frame/v1",
            f.context,
            f.sender,
            f.recipient,
            f.sequence,
            &f.payload,
        ))
        .expect("frame encoding"),
        key,
    )
}
fn ack_mac(f: &Frame, key: &[u8]) -> Hash {
    do_mac(
        &bincode::serialize(&(
            "weighted/ack/v1",
            f.context,
            f.sender,
            f.recipient,
            f.sequence,
        ))
        .expect("ACK encoding"),
        key,
    )
}
fn decode<T: DeserializeOwned>(raw: &[u8]) -> Result<T> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
        .reject_trailing_bytes()
        .deserialize(raw)?)
}

/// Each protocol aliases this handler in handlers/handler.rs.
pub struct Handler<T> {
    id: Replica,
    context: Hash,
    keys: Arc<HashMap<Replica, Vec<u8>>>,
    received: Arc<Mutex<HashMap<Replica, u64>>>,
    tx: mpsc::Sender<(Replica, T)>,
}
impl<T> Clone for Handler<T> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            context: self.context,
            keys: self.keys.clone(),
            received: self.received.clone(),
            tx: self.tx.clone(),
        }
    }
}
impl<T: DeserializeOwned + Send + 'static> Handler<T> {
    async fn dispatch(&self, stream: TcpStream) -> Result<()> {
        let mut stream = low_latency(stream)?;
        loop {
            let size = stream.read_u32_le().await? as usize;
            if size == 0 || size > MAX_FRAME_BYTES {
                return Err(anyhow!("invalid frame size"));
            }
            let mut raw = vec![0; size];
            stream.read_exact(&mut raw).await?;
            let f: Frame = decode(&raw)?;
            let key = self
                .keys
                .get(&f.sender)
                .ok_or_else(|| anyhow!("unknown sender"))?;
            if f.context != self.context
                || f.recipient != self.id
                || !verf_mac(
                    &bincode::serialize(&(
                        "weighted/frame/v1",
                        f.context,
                        f.sender,
                        f.recipient,
                        f.sequence,
                        &f.payload,
                    ))?,
                    key,
                    &f.mac,
                )
            {
                return Err(anyhow!("invalid message authentication/context"));
            }
            let mut received = self.received.lock().await;
            let last = received.entry(f.sender).or_insert(0);
            if f.sequence == last.saturating_add(1) && f.sequence != 0 {
                let msg = decode(&f.payload)?;
                self.tx
                    .send((f.sender, msg))
                    .await
                    .map_err(|_| anyhow!("protocol stopped"))?;
                *last = f.sequence;
            } else if f.sequence == 0 || f.sequence > *last {
                return Err(anyhow!("out-of-order transport sequence"));
            }
            drop(received);
            stream.write_all(&ack_mac(&f, key)).await?;
        }
    }
}

pub struct Endpoint<T> {
    pub recv: mpsc::Receiver<(Replica, T)>,
    pub public_id: Hash,
    peers: Vec<mpsc::UnboundedSender<T>>,
    tasks: Vec<JoinHandle<()>>,
}
impl<T: Clone + Debug + Serialize + DeserializeOwned + Send + Sync + 'static> Endpoint<T> {
    pub fn bind(config: &Node, component: &str) -> Result<Self> {
        config.validate_weighted()?;
        let n = config.num_nodes;
        let id = config.id;
        let context = config.weighted_public_id(component);
        let (tx, recv) = mpsc::channel(1024);
        let keys: HashMap<_, _> = (0..n).map(|i| (i, config.sk_map[&i].clone())).collect();
        let handler = Handler {
            id,
            context,
            keys: Arc::new(keys),
            received: Arc::new(Mutex::new(HashMap::new())),
            tx: tx.clone(),
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
            let (out, mut queue) = mpsc::unbounded_channel::<T>();
            peers.push(out);
            let tx = tx.clone();
            let key = config.sk_map[&peer].clone();
            let addr: SocketAddr = config.net_map[&peer].parse()?;
            tasks.push(tokio::spawn(async move {
                let mut sequence = 0u64;
                let mut connection = None;
                while let Some(message) = queue.recv().await {
                    if peer == id {
                        if tx.send((id, message)).await.is_err() {
                            break;
                        }
                        continue;
                    }
                    sequence = match sequence.checked_add(1) {
                        Some(s) => s,
                        None => break,
                    };
                    let mut f = Frame {
                        context,
                        sender: id,
                        recipient: peer,
                        sequence,
                        payload: match bincode::serialize(&message) {
                            Ok(x) => x,
                            Err(_) => break,
                        },
                        mac: [0; 32],
                    };
                    f.mac = frame_mac(&f, &key);
                    let packet = match encode_frame(&f) {
                        Ok(x) => x,
                        _ => {
                            log::error!("weighted frame exceeds limit");
                            break;
                        }
                    };
                    loop {
                        let result = tokio::time::timeout(Duration::from_secs(5), async {
                            if connection.is_none() {
                                connection = Some(low_latency(TcpStream::connect(addr).await?)?);
                            }
                            let socket = connection.as_mut().unwrap();
                            socket.write_all(&packet).await?;
                            let mut ack = [0; 32];
                            socket.read_exact(&mut ack).await?;
                            if ack != ack_mac(&f, &key) {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    "invalid ACK",
                                ));
                            }
                            Ok::<_, std::io::Error>(())
                        })
                        .await;
                        if matches!(result, Ok(Ok(()))) {
                            break;
                        }
                        connection = None;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }));
        }
        Ok(Self {
            recv,
            public_id: context,
            peers,
            tasks,
        })
    }
    pub fn send(&self, action: SendAction<T>) -> Result<()> {
        // Reserve room for the fixed envelope before enqueueing. Bodies are protocol-bounded.
        if bincode::serialized_size(&action.message)? > (MAX_FRAME_BYTES - 256) as u64 {
            return Err(anyhow!("message exceeds frame limit"));
        }
        self.peers
            .get(action.recipient)
            .ok_or_else(|| anyhow!("unknown recipient"))?
            .send(action.message)
            .map_err(|_| anyhow!("peer sender stopped"))
    }
}
impl<T> Drop for Endpoint<T> {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[cfg(test)]
#[path = "weighted_tests.rs"]
mod transport_tests;

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
            received: Arc::new(Mutex::new(HashMap::new())),
            tx,
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
    fn malformed_serialization_is_bounded() {
        let mut raw = bincode::serialize(&7u64).unwrap();
        raw.push(1);
        assert!(decode::<u64>(&raw).is_err());
        assert!(decode::<Vec<u8>>(&u64::MAX.to_le_bytes()).is_err());
    }
}
