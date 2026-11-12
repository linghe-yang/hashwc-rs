//! Regression tests for framing, authenticated retries, and independent peer queues.
use super::*;
use types::Weight;

fn frame(sequence: u64, value: u64) -> Frame {
    let mut frame = Frame {
        context: [9; 32],
        sender: 0,
        recipient: 1,
        sequence,
        payload: bincode::serialize(&value).unwrap(),
        mac: [0; 32],
    };
    frame.mac = frame_mac(&frame, &[7; 32]);
    frame
}

#[test]
fn combined_packet_preserves_wire_bytes_and_rejects_oversized_frames() {
    let f = frame(1, 42);
    let raw = bincode::serialize(&f).unwrap();
    let mut legacy = (raw.len() as u32).to_le_bytes().to_vec();
    legacy.extend_from_slice(&raw);
    assert_eq!(encode_frame(&f).unwrap(), legacy);
    let mut too_big = f;
    too_big.payload.resize(MAX_FRAME_BYTES, 0);
    assert!(encode_frame(&too_big).is_err());
}

#[tokio::test]
async fn receiver_handles_fragmented_and_coalesced_frames_and_deduplicates_replays() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (tx, mut rx) = mpsc::channel(8);
        let handler = Handler::<u64> {
            id: 1,
            context: [9; 32],
            keys: Arc::new(vec![(0, vec![7; 32])].into_iter().collect()),
            received: Arc::new(vec![(0, Mutex::new(0))].into_iter().collect()),
            tx,
            metrics: metrics::counter("fragment-test"),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut socket = low_latency(
            TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap(),
        )
        .unwrap();
        let worker = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handler.dispatch(stream).await
        });
        let first = frame(1, 42);
        let second = frame(2, 43);
        let packet = encode_frame(&first).unwrap();
        // Split both the length prefix and body. No partial message may be delivered.
        socket.write_all(&packet[..2]).await.unwrap();
        socket.write_all(&packet[2..9]).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(10), rx.recv())
            .await
            .is_err());
        // Coalesce the remainder, a duplicate, and the next complete frame in one write.
        let mut rest = packet[9..].to_vec();
        rest.extend_from_slice(&packet);
        rest.extend_from_slice(&encode_frame(&second).unwrap());
        socket.write_all(&rest).await.unwrap();
        let mut acks = [0; 96];
        socket.read_exact(&mut acks).await.unwrap();
        assert_eq!(&acks[..32], &ack_mac(&first, &[7; 32]));
        assert_eq!(&acks[32..64], &ack_mac(&first, &[7; 32]));
        assert_eq!(&acks[64..], &ack_mac(&second, &[7; 32]));
        assert_eq!(rx.recv().await.unwrap(), (0, 42));
        assert_eq!(rx.recv().await.unwrap(), (0, 43));
        assert!(rx.try_recv().is_err());
        drop(socket);
        let _ = worker.await;
    })
    .await
    .expect("fragmented stream stalled");
}

async fn read_frame(socket: &mut TcpStream) -> Frame {
    let len = socket.read_u32_le().await.unwrap() as usize;
    assert!(len <= MAX_FRAME_BYTES);
    let mut bytes = vec![0; len];
    socket.read_exact(&mut bytes).await.unwrap();
    decode(&bytes).unwrap()
}

#[tokio::test]
async fn sender_retries_same_frame_after_bad_and_partial_acks_without_stalling_other_peers() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut node = Node::new();
        node.id = 0;
        node.num_nodes = 4;
        node.session_id = [9; 32];
        node.weights = vec![Weight::from(1u64); 4];
        node.weight_threshold = Some(Weight::from(1u64));
        for (id, addr) in vec![
            local.local_addr().unwrap(),
            peer.local_addr().unwrap(),
            silent.local_addr().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
        ]
        .into_iter()
        .enumerate()
        {
            node.net_map.insert(id, addr.to_string());
            node.sk_map.insert(id, vec![7; 32]);
        }
        drop(local);
        let mut endpoint = Endpoint::<u64>::bind(&node, "transport-test").unwrap();
        // This peer establishes TCP but never reads or ACKs. It must not stall peer 1.
        endpoint
            .send(SendAction {
                recipient: 2,
                message: 99,
            })
            .unwrap();
        endpoint
            .send(SendAction {
                recipient: 1,
                message: 42,
            })
            .unwrap();
        endpoint
            .send(SendAction {
                recipient: 1,
                message: 43,
            })
            .unwrap();
        let (mut socket, _) = peer.accept().await.unwrap();
        let original = read_frame(&mut socket).await;
        assert_eq!(original.context, endpoint.public_id);
        assert_eq!(original.mac, frame_mac(&original, &[7; 32]));
        assert_eq!(original.sequence, 1);
        assert_eq!(decode::<u64>(&original.payload).unwrap(), 42);
        socket.write_all(&[0; 32]).await.unwrap(); // invalid authenticated ACK
        drop(socket);

        let (mut socket, _) = peer.accept().await.unwrap();
        let retried = read_frame(&mut socket).await;
        assert_eq!(
            encode_frame(&retried).unwrap(),
            encode_frame(&original).unwrap()
        );
        let ack = ack_mac(&retried, &[7; 32]);
        socket.write_all(&ack[..16]).await.unwrap(); // connection drops mid-ACK
        drop(socket);

        let (mut socket, _) = peer.accept().await.unwrap();
        let retried = read_frame(&mut socket).await;
        assert_eq!(
            encode_frame(&retried).unwrap(),
            encode_frame(&original).unwrap()
        );
        socket.write_all(&ack).await.unwrap();
        let next = read_frame(&mut socket).await;
        assert_eq!(next.sequence, 2);
        assert_eq!(decode::<u64>(&next.payload).unwrap(), 43);
        assert_eq!(next.mac, frame_mac(&next, &[7; 32]));
        socket.write_all(&ack_mac(&next, &[7; 32])).await.unwrap();
        endpoint
            .send(SendAction {
                recipient: 0,
                message: 44,
            })
            .unwrap();
        assert_eq!(endpoint.recv.recv().await.unwrap(), (0, 44));
    })
    .await
    .expect("retry or independent peer queue stalled");
}

#[tokio::test]
async fn bounded_window_is_sent_before_acks_and_silent_peer_spills() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut node = Node::new();
        node.id = 0;
        node.num_nodes = 4;
        node.session_id = [9; 32];
        node.weights = vec![Weight::from(1); 4];
        node.weight_threshold = Some(Weight::from(1));
        for (i, addr) in vec![
            local.local_addr().unwrap(),
            peer.local_addr().unwrap(),
            silent.local_addr().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
        ]
        .into_iter()
        .enumerate()
        {
            node.net_map.insert(i, addr.to_string());
            node.sk_map.insert(i, vec![7; 32]);
        }
        drop(local);
        let endpoint = Endpoint::<Vec<u8>>::bind(&node, "window-test").unwrap();
        for i in 0..96 {
            let mut data = vec![0; 32768];
            data[0] = i;
            endpoint
                .send(SendAction {
                    recipient: 2,
                    message: data,
                })
                .unwrap();
        }
        for i in 0..64 {
            endpoint
                .send(SendAction {
                    recipient: 1,
                    message: vec![i; 32768],
                })
                .unwrap();
        }
        let (mut socket, _) = peer.accept().await.unwrap();
        let mut acks = Vec::new();
        // A stop-and-wait implementation cannot read a whole window here.
        for i in 1..=32 {
            let f = read_frame(&mut socket).await;
            assert_eq!(f.sequence, i);
            acks.extend(ack_mac(&f, &[7; 32]));
        }
        socket.write_all(&acks).await.unwrap();
        acks.clear();
        for i in 33..=64 {
            let f = read_frame(&mut socket).await;
            assert_eq!(f.sequence, i);
            acks.extend(ack_mac(&f, &[7; 32]));
        }
        socket.write_all(&acks).await.unwrap();
    })
    .await
    .expect("pipeline or silent-peer isolation stalled");
}
#[test]
fn streamed_frame_authentication_matches_legacy() {
    let f = frame(1, 42);
    let old = crypto::hash::do_mac(
        &bincode::serialize(&(
            "weighted/frame/v1",
            f.context,
            f.sender,
            f.recipient,
            f.sequence,
            &f.payload,
        ))
        .unwrap(),
        &[7; 32],
    );
    assert_eq!(f.mac, old);
}

#[tokio::test]
async fn closing_queue_releases_storage_and_rejects_late_send() {
    let q = queue::Queue::default();
    q.push(Arc::new(vec![1; 32])).unwrap();
    q.close();
    assert!(q.push(Arc::new(vec![2; 32])).is_err());
    assert!(q.pop().await.is_err());
}

#[tokio::test]
async fn sliding_window_refills_after_one_ack_and_replays_only_unacknowledged_frames() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let queue = Arc::new(queue::Queue::default());
        for value in 1u64..=64 {
            queue
                .push(Arc::new(bincode::serialize(&value).unwrap()))
                .unwrap();
        }
        let task = tokio::spawn(sender::send_peer(
            queue.clone(),
            listener.local_addr().unwrap(),
            [9; 32],
            0,
            1,
            vec![7; 32],
            metrics::counter("sender-replay-test"),
        ));
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        for sequence in 1..=32 {
            let f = read_frame(&mut socket).await;
            assert_eq!(f.sequence, sequence);
            received.push(f);
        }
        // A full window cannot send frame 33 without an authenticated ACK.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), socket.read_u8())
                .await
                .is_err()
        );
        let ack = ack_mac(&received[0], &[7; 32]);
        socket.write_all(&ack[..7]).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), socket.read_u8())
                .await
                .is_err()
        );
        socket.write_all(&ack[7..]).await.unwrap();
        // The old batch barrier deadlocks here: ACKs 2..32 have not been sent.
        let f33 = read_frame(&mut socket).await;
        assert_eq!(f33.sequence, 33);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), socket.read_u8())
                .await
                .is_err()
        );
        let ack2 = ack_mac(&received[1], &[7; 32]);
        socket.write_all(&ack2[..13]).await.unwrap();
        drop(socket);
        let (mut socket, _) = listener.accept().await.unwrap();
        // ACK 1 was committed; the partial ACK 2 must be discarded on reconnect.
        for sequence in 2..=33 {
            let f = read_frame(&mut socket).await;
            assert_eq!(f.sequence, sequence);
            let expected = if sequence == 33 {
                &f33
            } else {
                &received[sequence as usize - 1]
            };
            assert_eq!(encode_frame(&f).unwrap(), encode_frame(expected).unwrap());
            socket.write_all(&ack_mac(&f, &[7; 32])).await.unwrap();
        }
        for sequence in 34..=64 {
            let f = read_frame(&mut socket).await;
            assert_eq!(f.sequence, sequence);
            socket.write_all(&ack_mac(&f, &[7; 32])).await.unwrap();
        }
        queue.close();
        let _ = task.await;
        let snapshot = metrics::snapshot();
        let counts = &snapshot["sender-replay-test"];
        assert_eq!(counts.logical_frames, 64);
        assert_eq!(
            counts.logical_frame_bytes,
            64 * encode_frame(&f33).unwrap().len() as u64
        );
        assert_eq!(counts.connected_streams, 2);
        assert_eq!(counts.replayed_frames, 32);
        assert!(counts.io_disconnects >= 1);
        assert_eq!(counts.stall_reconnects, 0);
        assert!(counts.sent_bytes > counts.logical_frame_bytes);
    })
    .await
    .expect("sliding window failed to refill or reconnect");
}

#[tokio::test]
async fn partial_ack_survives_new_queue_work_and_partial_large_writes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let queue = Arc::new(queue::Queue::default());
        queue
            .push(Arc::new(vec![1; MAX_FRAME_BYTES - 256]))
            .unwrap();
        let task = tokio::spawn(sender::send_peer(
            queue.clone(),
            listener.local_addr().unwrap(),
            [9; 32],
            0,
            1,
            vec![7; 32],
            metrics::counter("sender-test"),
        ));
        let (mut socket, _) = listener.accept().await.unwrap();
        let first = read_frame(&mut socket).await;
        let ack = ack_mac(&first, &[7; 32]);
        socket.write_all(&ack[..11]).await.unwrap();
        // Queue wakeup and writes compete with the outstanding partial ACK read.
        queue
            .push(Arc::new(vec![2; MAX_FRAME_BYTES - 256]))
            .unwrap();
        let second = read_frame(&mut socket).await;
        assert_eq!(second.sequence, 2);
        assert_eq!(second.mac, frame_mac(&second, &[7; 32]));
        let mut rest = ack[11..].to_vec();
        rest.extend(ack_mac(&second, &[7; 32]));
        socket.write_all(&rest).await.unwrap();
        queue
            .push(Arc::new(vec![3; MAX_FRAME_BYTES - 256]))
            .unwrap();
        let third = read_frame(&mut socket).await;
        assert_eq!(third.sequence, 3);
        socket.write_all(&ack_mac(&third, &[7; 32])).await.unwrap();
        queue.close();
        let _ = task.await;
    })
    .await
    .expect("partial I/O lost progress during window refill");
}

#[tokio::test]
async fn invalid_prefetched_ack_discards_later_acks_and_replays_from_first_unacked() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let queue = Arc::new(queue::Queue::default());
        let counts = Arc::new(metrics::Counters::default());
        for value in 1u64..=64 {
            queue
                .push(Arc::new(bincode::serialize(&value).unwrap()))
                .unwrap();
        }
        let task = tokio::spawn(sender::send_peer(
            queue.clone(),
            listener.local_addr().unwrap(),
            [9; 32],
            0,
            1,
            vec![7; 32],
            counts.clone(),
        ));
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut frames = Vec::new();
        for sequence in 1..=32 {
            let f = read_frame(&mut socket).await;
            assert_eq!(f.sequence, sequence);
            frames.push(f);
        }
        let mut acks = ack_mac(&frames[0], &[7; 32]).to_vec();
        let mut bad = ack_mac(&frames[1], &[7; 32]);
        bad[0] ^= 1;
        acks.extend_from_slice(&bad);
        acks.extend_from_slice(&ack_mac(&frames[2], &[7; 32]));
        socket.write_all(&acks).await.unwrap();
        // Keep the old socket alive: authentication failure, not peer EOF,
        // must trigger reconnect. Valid ACK 3 must not bypass invalid ACK 2.
        let (mut reconnected, _) = listener.accept().await.unwrap();
        assert_eq!(counts.current().acknowledged_frames, 1);
        for sequence in 2..=33 {
            let f = read_frame(&mut reconnected).await;
            assert_eq!(f.sequence, sequence);
            if sequence <= 32 {
                assert_eq!(
                    encode_frame(&f).unwrap(),
                    encode_frame(&frames[sequence as usize - 1]).unwrap()
                );
            }
            reconnected.write_all(&ack_mac(&f, &[7; 32])).await.unwrap();
        }
        for sequence in 34..=64 {
            let f = read_frame(&mut reconnected).await;
            assert_eq!(f.sequence, sequence);
            reconnected.write_all(&ack_mac(&f, &[7; 32])).await.unwrap();
        }
        queue.close();
        let _ = task.await;
    })
    .await
    .expect("invalid buffered ACK did not recover");
}
