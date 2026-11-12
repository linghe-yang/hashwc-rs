use super::super::{
    ack_mac, encode_frame,
    receiver_tests::{frame, handler},
};
use super::*;
use std::{
    future::{pending, ready},
    sync::{Arc, Mutex},
    task::Waker,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct State {
    bytes: Vec<u8>,
    writes: Vec<usize>,
    limit: Option<usize>,
    fail: bool,
    zero: bool,
    waker: Option<Waker>,
}
#[derive(Clone, Default)]
struct Writer(Arc<Mutex<State>>);
impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut s = self.0.lock().unwrap();
        if s.zero {
            return Poll::Ready(Ok(0));
        }
        let room = s
            .limit
            .map_or(usize::MAX, |n| n.saturating_sub(s.bytes.len()));
        if room == 0 {
            if s.fail {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            s.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = bytes.len().min(room);
        s.bytes.extend_from_slice(&bytes[..n]);
        s.writes.push(n);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn ready_burst_has_identical_authenticated_acks_and_bounded_writes() {
    let (h, mut rx) = handler(128);
    let mut wire = Vec::new();
    let mut expected = Vec::new();
    for seq in 1..=128 {
        let f = frame(seq, seq + 100);
        wire.extend(encode_frame(&f).unwrap());
        expected.extend(ack_mac(&f, &[7; 32]));
    }
    let writer = Writer::default();
    // Suppress runtime-induced Pending only for this deterministic burst oracle.
    // Real TCP and cooperative scheduling are exercised separately.
    assert!(
        tokio::task::unconstrained(h.receive_halves(wire.as_slice(), writer.clone()))
            .await
            .is_err()
    );
    for seq in 1..=128 {
        assert_eq!(rx.try_recv().unwrap(), (0, seq + 100));
    }
    assert!(rx.try_recv().is_err());
    let state = writer.0.lock().unwrap();
    assert_eq!(state.bytes, expected);
    assert_eq!(state.writes.len(), 128 / ACK_BATCH_FRAMES);
    assert!(state.writes.iter().all(|n| *n == ACK_BATCH_BYTES));
    println!(
        "ACK_WRITES,128,128,{},{}",
        state.writes.len(),
        state.bytes.len()
    );
}
#[tokio::test]
async fn partial_next_frame_never_holds_the_previous_ack_or_loses_read_progress() {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        for cut in [1, 3, 4, 7, 31, 107] {
            let (h, mut rx) = handler(2);
            let (mut peer, stream) = tokio::io::duplex(256);
            let worker = tokio::spawn(async move { h.receive_frames(stream).await });
            let a = frame(1, 41);
            let b = frame(2, 42);
            let second = encode_frame(&b).unwrap();
            let mut first = encode_frame(&a).unwrap();
            first.extend_from_slice(&second[..cut]);
            peer.write_all(&first).await.unwrap();
            let mut ack = [0; 32];
            peer.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack, ack_mac(&a, &[7; 32]));
            assert_eq!(rx.try_recv().unwrap(), (0, 41));
            assert!(rx.try_recv().is_err());
            // Finish the frame only after ACK 1. It must resume at the saved
            // prefix/body offset instead of restarting or dropping a future.
            peer.write_all(&second[cut..]).await.unwrap();
            peer.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack, ack_mac(&b, &[7; 32]));
            assert_eq!(rx.recv().await.unwrap(), (0, 42));
            drop(peer);
            assert!(worker.await.unwrap().is_err());
        }
    })
    .await
    .expect("partial next frame blocked the preceding ACK");
}
#[test]
fn a_pending_receive_can_finish_but_waits_for_the_preceding_partial_ack() {
    let writer = Writer::default();
    writer.0.lock().unwrap().limit = Some(7);
    let mut output = ReadyAcks::new(writer.clone());
    output.push(&[9; 32]);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let polls = std::cell::Cell::new(0);
    {
        let next = poll_fn(|_| {
            polls.set(polls.get() + 1);
            if polls.get() == 1 {
                Poll::Pending
            } else {
                Poll::Ready(42)
            }
        });
        let mut f = std::pin::pin!(output.wait_ready(next));
        assert!(f.as_mut().poll(&mut cx).is_pending());
        assert_eq!(writer.0.lock().unwrap().bytes.len(), 7);
        assert!(f.as_mut().poll(&mut cx).is_pending());
        assert_eq!(
            polls.get(),
            2,
            "blocked write prevented the active receive from completing"
        );
        let wake = {
            let mut s = writer.0.lock().unwrap();
            s.limit = None;
            s.waker.take().unwrap()
        };
        wake.wake();
        assert!(matches!(f.as_mut().poll(&mut cx), Poll::Ready(Ok(42))));
        assert_eq!(polls.get(), 2);
    }
    assert_eq!(writer.0.lock().unwrap().bytes, vec![9; 32]);
    output.push(&[8; 32]);
    assert!(std::pin::pin!(output.drain())
        .as_mut()
        .poll(&mut cx)
        .is_ready());
    assert_eq!(
        writer.0.lock().unwrap().bytes,
        [vec![9; 32], vec![8; 32]].concat()
    );
}
#[tokio::test]
async fn invalid_or_truncated_later_frame_flushes_only_previously_accepted_acks() {
    for kind in 0..6 {
        let (h, mut rx) = handler(4);
        let first = frame(1, 41);
        let mut bad = frame(2, 42);
        let tail = match kind {
            0 => {
                bad.mac[0] ^= 1;
                encode_frame(&bad).unwrap()
            }
            1 => {
                bad.sequence = 3;
                bad.mac = super::super::frame_mac(&bad, &[7; 32]);
                encode_frame(&bad).unwrap()
            }
            2 => {
                bad.payload.clear();
                bad.mac = super::super::frame_mac(&bad, &[7; 32]);
                encode_frame(&bad).unwrap()
            }
            3 => u32::MAX.to_le_bytes().to_vec(),
            4 => vec![1, 0],
            _ => {
                let mut raw = encode_frame(&bad).unwrap();
                raw.truncate(raw.len() - 1);
                raw
            }
        };
        let mut wire = encode_frame(&first).unwrap();
        wire.extend(tail);
        if kind < 4 {
            wire.extend(encode_frame(&frame(2, 99)).unwrap());
        }
        let writer = Writer::default();
        assert!(h
            .receive_halves(wire.as_slice(), writer.clone())
            .await
            .is_err());
        assert_eq!(writer.0.lock().unwrap().bytes, ack_mac(&first, &[7; 32]));
        assert_eq!(rx.try_recv().unwrap(), (0, 41));
        assert!(rx.try_recv().is_err());
        assert_eq!(*h.received[&0].lock().await, 1);
        let second = frame(2, 99);
        let wire = [
            encode_frame(&first).unwrap(),
            encode_frame(&second).unwrap(),
        ]
        .concat();
        let retry = Writer::default();
        assert!(h
            .receive_halves(wire.as_slice(), retry.clone())
            .await
            .is_err());
        assert_eq!(
            retry.0.lock().unwrap().bytes,
            [ack_mac(&first, &[7; 32]), ack_mac(&second, &[7; 32])].concat()
        );
        assert_eq!(rx.try_recv().unwrap(), (0, 99));
        assert!(
            rx.try_recv().is_err(),
            "replay delivered the first frame twice"
        );
    }
}
#[tokio::test]
async fn write_failure_preserves_committed_sequences_for_reconnect_replay() {
    for zero in [false, true] {
        let (h, mut rx) = handler(4);
        let frames = [frame(1, 41), frame(2, 42)];
        let wire = frames
            .iter()
            .flat_map(|f| encode_frame(f).unwrap())
            .collect::<Vec<_>>();
        let writer = Writer::default();
        {
            let mut s = writer.0.lock().unwrap();
            s.limit = Some(7);
            s.fail = true;
            s.zero = zero;
        }
        assert!(h
            .receive_halves(wire.as_slice(), writer.clone())
            .await
            .is_err());
        assert_eq!(
            writer.0.lock().unwrap().bytes.len(),
            if zero { 0 } else { 7 }
        );
        assert_eq!(*h.received[&0].lock().await, 2);
        assert_eq!(rx.try_recv().unwrap(), (0, 41));
        assert_eq!(rx.try_recv().unwrap(), (0, 42));
        let retry = Writer::default();
        assert!(h
            .receive_halves(wire.as_slice(), retry.clone())
            .await
            .is_err());
        assert_eq!(
            retry.0.lock().unwrap().bytes,
            frames
                .iter()
                .flat_map(|f| ack_mac(f, &[7; 32]))
                .collect::<Vec<_>>()
        );
        assert!(rx.try_recv().is_err());
    }
}
#[tokio::test]
async fn actor_shutdown_after_backpressure_keeps_the_earlier_ack() {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let (h, rx) = handler(1);
        let inspect = h.clone();
        let (mut peer, stream) = tokio::io::duplex(256);
        let worker = tokio::spawn(async move { h.receive_frames(stream).await });
        let first = frame(1, 41);
        let wire = [
            encode_frame(&first).unwrap(),
            encode_frame(&frame(2, 42)).unwrap(),
        ]
        .concat();
        peer.write_all(&wire).await.unwrap();
        let mut ack = [0; 32];
        peer.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, ack_mac(&first, &[7; 32]));
        drop(rx);
        assert!(worker.await.unwrap().is_err());
        assert_eq!(*inspect.received[&0].lock().await, 1);
        assert_eq!(peer.read(&mut ack).await.unwrap(), 0);
    })
    .await
    .expect("actor shutdown lost an earlier ACK");
}
#[test]
fn an_idle_receive_flushes_one_ack_without_a_timer_or_extra_input() {
    let writer = Writer::default();
    let mut output = ReadyAcks::new(writer.clone());
    output.push(&[7; 32]);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    {
        let mut f = std::pin::pin!(output.wait_ready(pending::<()>()));
        assert!(f.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(writer.0.lock().unwrap().bytes, vec![7; 32]);
    // Zero pending ACKs add no write when a ready operation completes.
    assert!(matches!(
        std::pin::pin!(output.wait_ready(ready(5)))
            .as_mut()
            .poll(&mut cx),
        Poll::Ready(Ok(5))
    ));
    assert_eq!(writer.0.lock().unwrap().writes, vec![32]);
}

#[tokio::test]
async fn blocked_ack_write_does_not_hold_an_available_actor_permit_or_sequence_lock() {
    let (h, mut rx) = handler(1);
    let first = frame(1, 41);
    let second = frame(2, 42);
    let wire = [
        encode_frame(&first).unwrap(),
        encode_frame(&second).unwrap(),
    ]
    .concat();
    let writer = Writer::default();
    writer.0.lock().unwrap().limit = Some(7);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut receiver = std::pin::pin!(h.receive_halves(wire.as_slice(), writer.clone()));
    assert!(receiver.as_mut().poll(&mut cx).is_pending());
    assert_eq!(writer.0.lock().unwrap().bytes.len(), 7);
    assert_eq!(rx.try_recv().unwrap(), (0, 41)); // Makes the queued send permit available.
    assert!(receiver.as_mut().poll(&mut cx).is_pending());
    assert_eq!(writer.0.lock().unwrap().bytes.len(), 7); // ACK is STILL blocked.
    assert_eq!(
        rx.try_recv().unwrap(),
        (0, 42),
        "available actor permit was held behind ACK backpressure"
    );
    assert_eq!(
        *h.received[&0]
            .try_lock()
            .expect("sequence lock held behind ACK write"),
        2
    );
    {
        let mut s = writer.0.lock().unwrap();
        s.limit = None;
        s.waker.take().unwrap().wake();
    }
    assert!(matches!(
        receiver.as_mut().poll(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert_eq!(
        writer.0.lock().unwrap().bytes,
        [ack_mac(&first, &[7; 32]), ack_mac(&second, &[7; 32])].concat()
    );
}

#[tokio::test]
async fn write_failure_cancels_a_blocked_delivery_without_committing_it() {
    let (h, mut rx) = handler(1);
    let first = frame(1, 41);
    let second = frame(2, 42);
    let wire = [
        encode_frame(&first).unwrap(),
        encode_frame(&second).unwrap(),
    ]
    .concat();
    let writer = Writer::default();
    {
        let mut s = writer.0.lock().unwrap();
        s.limit = Some(7);
        s.fail = true;
    }
    assert!(h
        .receive_halves(wire.as_slice(), writer.clone())
        .await
        .is_err());
    assert_eq!(
        *h.received[&0]
            .try_lock()
            .expect("cancelled delivery retained its lock"),
        1
    );
    assert_eq!(rx.try_recv().unwrap(), (0, 41));
    assert!(rx.try_recv().is_err());
    let retry = Writer::default();
    assert!(h
        .receive_halves(wire.as_slice(), retry.clone())
        .await
        .is_err());
    assert_eq!(rx.try_recv().unwrap(), (0, 42));
    assert!(rx.try_recv().is_err());
    assert_eq!(
        retry.0.lock().unwrap().bytes,
        [ack_mac(&first, &[7; 32]), ack_mac(&second, &[7; 32])].concat()
    );
}
