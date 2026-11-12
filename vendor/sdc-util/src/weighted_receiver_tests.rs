//! Exercise authenticated receiver behavior with controlled peer progress.
use super::*;
use std::{future::poll_fn, pin::Pin, task::Poll};
use tokio::io::{AsyncRead, ReadBuf};

pub(super) fn handler(capacity: usize) -> (Handler<u64>, mpsc::Receiver<(usize, u64)>) {
    let (tx, rx) = mpsc::channel(capacity);
    (
        Handler {
            id: 1,
            context: [9; 32],
            keys: Arc::new(HashMap::from([(0, vec![7; 32])])),
            received: Arc::new(HashMap::from([(0, Mutex::new(0))])),
            tx,
            metrics: metrics::counter("receiver-refinement-test"),
        },
        rx,
    )
}
pub(super) fn frame(sequence: u64, value: u64) -> Frame {
    let mut f = Frame {
        context: [9; 32],
        sender: 0,
        recipient: 1,
        sequence,
        payload: bincode::serialize(&value).unwrap(),
        mac: [0; 32],
    };
    f.mac = frame_mac(&f, &[7; 32]);
    f
}
#[tokio::test]
async fn ack_waits_for_delivery_but_never_waits_for_another_frame() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let (h, mut rx) = handler(1);
        let diagnostics = h.metrics.clone();
        let (mut peer, stream) = tokio::io::duplex(4096);
        let worker = tokio::spawn(async move { h.receive_frames(stream).await });
        let f1 = frame(1, 41);
        let f2 = frame(2, 42);
        let f3 = frame(3, 43);
        let mut bytes = encode_frame(&f1).unwrap();
        bytes.extend(encode_frame(&f2).unwrap());
        // Pipeline frames 1/2 but hold frame 3 until ACK 2. The queue holds only 1.
        peer.write_all(&bytes).await.unwrap();
        let mut ack = [0; 32];
        peer.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, ack_mac(&f1, &[7; 32]));
        poll_fn(|cx| {
            let mut raw = [0; 32];
            let mut read = ReadBuf::new(&mut raw);
            match Pin::new(&mut peer).poll_read(cx, &mut read) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("ACK sent before bounded actor queue accepted frame 2"),
            }
        })
        .await;
        assert_eq!(rx.recv().await.unwrap(), (0, 41));
        peer.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, ack_mac(&f2, &[7; 32]));
        assert_eq!(rx.recv().await.unwrap(), (0, 42));
        peer.write_all(&encode_frame(&f3).unwrap()).await.unwrap();
        peer.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, ack_mac(&f3, &[7; 32]));
        assert_eq!(rx.recv().await.unwrap(), (0, 43));
        drop(peer);
        assert!(worker.await.unwrap().is_err());
        assert!(diagnostics.current().receive_backpressure_waits >= 1);
    })
    .await
    .expect("ACK/backpressure test stalled");
}
#[tokio::test]
async fn rejected_prefetched_frame_never_delivers_later_bytes_or_advances_sequence() {
    tokio::time::timeout(Duration::from_secs(2), async {
        for kind in 0..7 {
            let (h, mut rx) = handler(4);
            let mut bad = frame(1, 41);
            match kind {
                0 => bad.mac[0] ^= 1,
                1 => {
                    bad.context[0] ^= 1;
                    bad.mac = frame_mac(&bad, &[7; 32]);
                }
                2 => {
                    bad.recipient = 0;
                    bad.mac = frame_mac(&bad, &[7; 32]);
                }
                3 => {
                    bad.sender = 2;
                    bad.mac = frame_mac(&bad, &[7; 32]);
                }
                4 => {
                    bad.sequence = 2;
                    bad.mac = frame_mac(&bad, &[7; 32]);
                }
                5 => {
                    bad.sequence = 0;
                    bad.mac = frame_mac(&bad, &[7; 32]);
                }
                _ => {
                    bad.payload.clear();
                    bad.mac = frame_mac(&bad, &[7; 32]);
                }
            }
            let mut bytes = encode_frame(&bad).unwrap();
            let good = frame(1, 42);
            bytes.extend(encode_frame(&good).unwrap());
            let (mut peer, stream) = tokio::io::duplex(4096);
            let copy = h.clone();
            let worker = tokio::spawn(async move { copy.receive_frames(stream).await });
            peer.write_all(&bytes).await.unwrap();
            assert!(worker.await.unwrap().is_err());
            assert!(rx.try_recv().is_err());
            assert_eq!(*h.received[&0].lock().await, 0);
            let mut byte = [0];
            assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
            // Reconnection still accepts the first valid sequence exactly once.
            assert_eq!(
                h.accept_frame(&bincode::serialize(&good).unwrap())
                    .await
                    .unwrap(),
                ack_mac(&good, &[7; 32])
            );
            assert_eq!(rx.recv().await.unwrap(), (0, 42));
            assert_eq!(
                h.accept_frame(&bincode::serialize(&good).unwrap())
                    .await
                    .unwrap(),
                ack_mac(&good, &[7; 32])
            );
            assert!(rx.try_recv().is_err());
        }
    })
    .await
    .expect("rejection/replay test stalled");
}
#[tokio::test]
async fn closed_actor_does_not_commit_or_ack_an_undelivered_frame() {
    let (h, rx) = handler(1);
    drop(rx);
    let f = frame(1, 42);
    assert!(h
        .accept_frame(&bincode::serialize(&f).unwrap())
        .await
        .is_err());
    assert_eq!(*h.received[&0].lock().await, 0);
}
