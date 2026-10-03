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
            keys: Arc::new([(0, vec![7; 32])].into_iter().collect()),
            received: Arc::new(Mutex::new(HashMap::new())),
            tx,
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
        assert!(
            tokio::time::timeout(Duration::from_millis(10), rx.recv())
                .await
                .is_err()
        );
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
        for (id, addr) in [
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
