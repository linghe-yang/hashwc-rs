//! A continuously refilled, bounded window. Wire frames and ACKs are unchanged.
use super::*;
use std::{collections::VecDeque, io::IoSlice};
use tokio::{
    io::{AsyncRead, BufReader},
    time::{sleep_until, timeout, Instant},
};

// At most one send window of already-arrived ACK bytes; never wait to fill it.
const ACK_READ_AHEAD_BYTES: usize = WINDOW_FRAMES * std::mem::size_of::<Hash>();
fn ack_reader<R: AsyncRead>(reader: R) -> BufReader<R> {
    BufReader::with_capacity(ACK_READ_AHEAD_BYTES, reader)
}
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
struct Pending {
    packet: Vec<u8>,
    ack: Hash,
    payload_bytes: usize,
    written: usize,
}
fn enqueue(
    pending: &mut VecDeque<Pending>,
    bytes: &mut usize,
    sequence: &mut u64,
    message: &[u8],
    context: Hash,
    id: Replica,
    peer: Replica,
    key: &[u8],
    metrics: &metrics::Counters,
) -> Result<()> {
    let _profile = crate::profile::span("transport.send.prepare");
    *sequence = sequence
        .checked_add(1)
        .ok_or_else(|| anyhow!("sequence exhausted"))?;
    let prefix = bincode::serialize(&(
        "weighted/frame/v1",
        context,
        id,
        peer,
        *sequence,
        message.len() as u64,
    ))?;
    let mac = mac_parts(&[&prefix, message], key);
    pending.push_back(Pending {
        packet: encode_packet(context, id, peer, *sequence, message, mac)?,
        ack: serialized_mac(&("weighted/ack/v1", context, id, peer, *sequence), key)?,
        payload_bytes: message.len(),
        written: 0,
    });
    metrics.encoded(pending.back().expect("just enqueued").packet.len());
    *bytes += message.len();
    Ok(())
}
fn room(pending: &VecDeque<Pending>, bytes: usize) -> bool {
    // As before: a final frame may cross the byte target, but total stays < 2 MiB.
    pending.len() < WINDOW_FRAMES && bytes < WINDOW_BYTES
}

pub(super) async fn send_peer(
    queue: Arc<queue::Queue>,
    addr: SocketAddr,
    context: Hash,
    id: Replica,
    peer: Replica,
    key: Vec<u8>,
    metrics: Arc<metrics::Counters>,
) -> Result<()> {
    let stall = Duration::from_millis(crate::execution::Settings::from_env()?.transport_stall_ms);
    let mut pending = VecDeque::new();
    let mut bytes = 0;
    let mut sequence = 0;
    loop {
        if pending.is_empty() {
            let message = queue.pop().await?;
            enqueue(
                &mut pending,
                &mut bytes,
                &mut sequence,
                &message,
                context,
                id,
                peer,
                &key,
                &metrics,
            )?;
        }
        let connection = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await;
        if let Ok(Ok(socket)) = connection {
            let mut socket = low_latency(socket)?;
            metrics.connected();
            // Only unacknowledged frames survive reconnect. A partial frame or ACK
            // is replayed from its beginning, using exactly the same sequence/MAC.
            for frame in &mut pending {
                if frame.written > 0 {
                    metrics.replay();
                }
                frame.written = 0;
            }
            let (reader, writer) = socket.split();
            // Keep the partial ACK offset outside select!, exactly as before.
            // The buffer is connection-local and is discarded on reconnect.
            let mut reader = ack_reader(metrics::Counted::ack_reader(reader, metrics.clone()));
            let mut writer = metrics::Counted::new(writer, metrics.clone());
            let mut ack = [0; 32];
            let mut ack_bytes = 0;
            let mut deadline = Instant::now() + stall;
            loop {
                // Drain currently available work before yielding to I/O, but never
                // wait for the queue when there is an outstanding write or ACK.
                while room(&pending, bytes) {
                    let Some(message) = queue.try_pop()? else {
                        break;
                    };
                    enqueue(
                        &mut pending,
                        &mut bytes,
                        &mut sequence,
                        &message,
                        context,
                        id,
                        peer,
                        &key,
                        &metrics,
                    )?;
                }
                let writing = pending.iter().any(|f| f.written < f.packet.len());
                let reading = pending.front().is_some_and(|f| f.written == f.packet.len());
                let slices: Vec<_> = pending
                    .iter()
                    .filter(|f| f.written < f.packet.len())
                    .map(|f| IoSlice::new(&f.packet[f.written..]))
                    .collect();
                tokio::select! {
                    // read()/write_vectored() are cancellation-safe; offsets live
                    // outside these futures. Never select on read_exact/write_all.
                    result = reader.read(&mut ack[ack_bytes..]), if reading => {
                        let n = match result { Ok(0) | Err(_) => { metrics.io_disconnect(); break; }, Ok(n) => n };
                        ack_bytes += n;
                        deadline = Instant::now() + stall;
                        if ack_bytes == ack.len() {
                            if pending.front().unwrap().ack != ack { metrics.invalid_ack(); break; }
                            bytes -= pending.pop_front().unwrap().payload_bytes;
                            metrics.acknowledge();
                            ack_bytes = 0;
                            // The next iteration immediately refills the freed slot,
                            // without waiting for ACKs of the rest of the window.
                        }
                    },
                    result = writer.write_vectored(&slices), if writing => {
                        let mut n = match result { Ok(0) | Err(_) => { metrics.io_disconnect(); break; }, Ok(n) => n };
                        for frame in &mut pending {
                            let take = n.min(frame.packet.len() - frame.written);
                            frame.written += take;
                            n -= take;
                            if n == 0 { break; }
                        }
                        deadline = Instant::now() + stall;
                    },
                    message = queue.pop(), if room(&pending, bytes) => {
                        let was_idle = pending.is_empty();
                        let message = message?;
                        enqueue(&mut pending, &mut bytes, &mut sequence, &message, context, id, peer, &key, &metrics)?;
                        if was_idle { deadline = Instant::now() + stall; }
                    },
                    _ = sleep_until(deadline), if !pending.is_empty() => { metrics.stall_reconnect(); break; },
                }
            }
        } else {
            metrics.connect_failure();
        }
        // Connection failure is a transport retry only, never a protocol outcome.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
#[path = "weighted_ack_tests.rs"]
mod ack_tests;
