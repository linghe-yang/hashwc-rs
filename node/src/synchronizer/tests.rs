use super::{
    msg::{Message, Payload},
    state::State,
    transport,
};
use num_bigint::BigUint;

fn state(weights: &[u64], t: u64) -> State {
    State::new(
        weights.iter().copied().map(BigUint::from).collect(),
        t.into(),
        1,
    )
    .unwrap()
}
#[test]
fn strict_weighted_thresholds_deduplicate_and_freeze_first_finish() {
    let mut s = state(&[1, 2, 3, 4], 3);
    assert!(!s.prepare(3).unwrap());
    assert!(!s.prepare(3).unwrap());
    assert!(!s.prepare(2).unwrap()); // weight 7 == W-T is insufficient
    assert!(s.prepare(0).unwrap()); // weight 8 > 7
    assert!(!s.finish(2, bit(0)).unwrap()); // weight 3 == T is insufficient
    assert!(!s.finish(2, bit(1)).unwrap()); // cannot change first vote
    assert_eq!(s.finishes.len(), 1);
    assert!(s.finish(0, bit(0)).unwrap()); // weight 4 > 3
    assert_eq!(s.result, Some(bit(0)));
    assert!(!s.finish(3, bit(1)).unwrap());
    assert_eq!(s.finishes.len(), 2);
}
#[test]
fn silent_weight_budget_and_split_results() {
    let mut s = state(&[1; 7], 2);
    for i in 0..5 {
        assert!(!s.prepare(i).unwrap());
    }
    assert!(s.prepare(5).unwrap()); // sixth starts; seventh need not respond
    assert!(!s.finish(0, bit(0)).unwrap());
    assert!(!s.finish(1, bit(1)).unwrap());
    assert!(!s.finish(2, bit(0)).unwrap());
    assert!(!s.finish(3, bit(1)).unwrap());
    assert!(s.finish(4, bit(0)).unwrap());
    assert_eq!(s.finish_weights[&bit(0)], BigUint::from(3u8));
    assert_eq!(s.finish_weights[&bit(1)], BigUint::from(2u8));
}
#[test]
fn invalid_early_messages_and_arbitrary_precision_weights() {
    let mut s = state(&[1; 4], 1);
    assert!(s.finish(0, bit(0)).is_err());
    assert!(s.prepare(4).is_err());
    for i in 0..4 {
        s.prepare(i).unwrap();
    }
    assert!(
        s.finish(0, whcc::Coin::from_hex(2, "0x2").unwrap())
            .is_err()
    );
    let huge = BigUint::from(1u8) << 512usize;
    let mut s = State::new(vec![huge.clone(); 4], huge.clone(), 1).unwrap();
    for i in 0..3 {
        assert!(!s.prepare(i).unwrap());
    }
    assert!(s.prepare(3).unwrap());
    assert!(!s.finish(0, bit(1)).unwrap());
    assert!(s.finish(1, bit(1)).unwrap());
}
#[test]
fn control_messages_bind_session_party_epoch_and_direction() {
    let mut node = config::Node::new();
    node.session_id = [7; 32];
    let payload = Payload {
        session: node.session_id,
        epoch: 9,
        party: 2,
        message: Message::PrepareOk,
    };
    let key = [8; 32];
    assert!(
        transport::verify(
            transport::seal(payload.clone(), &key, false).unwrap(),
            &node,
            9,
            2,
            &key,
            false
        )
        .is_ok()
    );
    for (epoch, party, server) in [(8, 2, false), (9, 1, false), (9, 2, true)] {
        assert!(
            transport::verify(
                transport::seal(payload.clone(), &key, false).unwrap(),
                &node,
                epoch,
                party,
                &key,
                server
            )
            .is_err()
        );
    }
    node.session_id = [1; 32];
    assert!(
        transport::verify(
            transport::seal(payload, &key, false).unwrap(),
            &node,
            9,
            2,
            &key,
            false
        )
        .is_err()
    );
}
#[tokio::test]
async fn fragmented_control_reads_survive_other_ready_events() {
    use tokio::io::AsyncWriteExt;
    let mut node = config::Node::new();
    node.session_id = [7; 32];
    let key = vec![8; 32];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut sender = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (receiver, _) = listener.accept().await.unwrap();
    let mut channel = transport::Channel::new(receiver, node.clone(), 9, 2, key.clone(), false);
    let wire = transport::seal(
        Payload {
            session: node.session_id,
            epoch: 9,
            party: 2,
            message: Message::Stop,
        },
        &key,
        true,
    )
    .unwrap();
    let data = serde_json::to_vec(&wire).unwrap();
    sender.write_u32_le(data.len() as u32).await.unwrap();
    sender.write_all(&data[..3]).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), channel.recv())
            .await
            .is_err()
    );
    sender.write_all(&data[3..]).await.unwrap();
    assert_eq!(channel.recv().await.unwrap(), Message::Stop);
}

#[test]
fn synchronizer_port_is_separate_including_loopback_aliases() {
    let mut node: config::Node =
        serde_json::from_str(include_str!("../../../config/examples/local.json")).unwrap();
    node.net_map
        .insert(node.num_nodes, "127.0.0.2:20000".into());
    assert!(super::address(&node, None).is_err());
    node.net_map
        .insert(node.num_nodes, "127.0.0.1:20049".into());
    assert_eq!(super::address(&node, None).unwrap().port(), 20049);
}
#[tokio::test]
async fn late_party_accepts_stop_before_prepare() {
    use super::party;
    let mut node: config::Node =
        serde_json::from_str(include_str!("../../../config/examples/local.json")).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    node.net_map
        .insert(node.num_nodes, listener.local_addr().unwrap().to_string());
    let key = vec![77; 32];
    node.sk_map.insert(node.num_nodes, key.clone());
    let server_node = node.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let hello = transport::read(&mut stream).await.unwrap();
        assert_eq!(
            transport::verify(hello, &server_node, 0, 0, &key, false)
                .unwrap()
                .message,
            Message::Hello { output_bits: 1 }
        );
        let stop = transport::seal(
            Payload {
                session: server_node.session_id,
                epoch: 0,
                party: 0,
                message: Message::Stop,
            },
            &key,
            true,
        )
        .unwrap();
        transport::write(&mut stream, &stop).await.unwrap();
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        party::run(node, whcc::Parameters::default(), whcc::Behavior::Honest),
    )
    .await
    .unwrap()
    .unwrap();
    server.await.unwrap();
}

fn bit(bit: u8) -> whcc::Coin {
    whcc::Coin::from_hex(1, &format!("0x{bit:x}")).unwrap()
}

#[test]
fn multibit_finish_votes_compare_entire_word_and_enforce_width() {
    let mut s = State::new(vec![1u8.into(); 4], 1u8.into(), 128).unwrap();
    for i in 0..4 {
        s.prepare(i).unwrap();
    }
    let a = whcc::Coin::from_hex(128, "0x80000000000000000000000000000001").unwrap();
    let b = whcc::Coin::from_hex(128, "0x90000000000000000000000000000001").unwrap();
    assert_eq!(a.bit(0).unwrap(), b.bit(0).unwrap());
    assert!(s.finish(0, bit(1)).is_err());
    assert!(!s.finish(0, a).unwrap());
    assert!(!s.finish(1, b).unwrap());
    assert!(!s.finish(1, a).unwrap()); // first complete word is immutable
    assert!(s.finish(2, a).unwrap());
    assert_eq!(s.result, Some(a));
    assert_eq!(s.finish_weights.len(), 2);
    assert_eq!(s.finish_weights[&a], 2u8.into());
    let message = Message::Finish { coin: a };
    assert_eq!(
        serde_json::from_slice::<Message>(&serde_json::to_vec(&message).unwrap()).unwrap(),
        message
    );
}
