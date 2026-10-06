use crate::{
    Parameters,
    msg::{Action, Event},
    state::State,
};
use network::Packet;
use sdc_types::InstanceId;
use std::collections::BTreeMap;
use wiawvss::{Opening, ax};
#[derive(Clone, Debug)]
enum Message {
    Rbc(wrbc::ProtMsg),
    Avid(wavid::ProtMsg),
    Ra(wra::ProtMsg),
    Gather(wgather::ProtMsg),
    BinAa(wbinaa::ProtMsg),
    Private(Packet),
    Recovery(Packet),
}
struct Party {
    pub app: State,
    pub rbc: BTreeMap<InstanceId, wrbc::State>,
    pub avid: BTreeMap<InstanceId, wavid::State>,
    pub ra: BTreeMap<InstanceId, wra::State>,
    pub pending_ra: BTreeMap<(InstanceId, usize, u8), wra::ProtMsg>,
    pub gather: wgather::State,
    pub binaa: wbinaa::State,
    pub node: config::Node,
}
struct Sim {
    pub parties: Vec<Party>,
    pub queue: Vec<(usize, usize, Message)>,
    pub silent: Option<usize>,
    pub seed: u64,
    pub outputs: Vec<Option<types::Coin>>,
    pub frozen: Vec<bool>,
    pub token_sends: usize,
    pub terminal_sends: usize,
    pub hold_freeze: Option<usize>,
    pub held_freeze: Vec<(usize, wbinaa::Event)>,
    pub hold_list: Option<usize>,
    pub held_lists: Vec<(usize, wrbc::Event)>,
    pub rejected: Vec<Vec<usize>>,
}
impl Sim {
    fn new(weights: &[u64], threshold: u64, silent: Option<usize>, seed: u64) -> Self {
        let nodes = super::nodes(weights, threshold, 20000);
        let params = Parameters {
            coverage_bits: 8,
            rounding_bits: 8,
            ..Parameters::default()
        };
        let parties = nodes
            .into_iter()
            .map(|node| {
                let app = State::new(&node, params.clone()).unwrap();
                let m = node.weighted_membership().unwrap();
                let bound = params.bound_node(&node, app.setup());
                let rbc = app
                    .rbc_manifest()
                    .into_iter()
                    .map(|r| match r {
                        wrbc::Request::Register {
                            instance,
                            file_bytes,
                            coding,
                        } => (
                            instance,
                            wrbc::State::with_params(
                                m.clone(),
                                node.id,
                                instance,
                                bound.weighted_public_id("wrbc"),
                                file_bytes,
                                coding,
                            )
                            .unwrap(),
                        ),
                        _ => unreachable!(),
                    })
                    .collect();
                let avid = app
                    .avid_manifest()
                    .into_iter()
                    .map(|r| match r {
                        wavid::Request::Register {
                            instance,
                            descriptor,
                        } => (
                            instance,
                            wavid::State::new(
                                m.clone(),
                                node.id,
                                instance,
                                bound.weighted_public_id("wavid"),
                                descriptor,
                            )
                            .unwrap(),
                        ),
                        _ => unreachable!(),
                    })
                    .collect();
                let gather = wgather::State::new(m.clone(), node.id, app.global()).unwrap();
                let binaa =
                    wbinaa::State::new(m, node.id, app.global(), params.precision(node.num_nodes))
                        .unwrap();
                Party {
                    app,
                    rbc,
                    avid,
                    ra: BTreeMap::new(),
                    pending_ra: BTreeMap::new(),
                    gather,
                    binaa,
                    node,
                }
            })
            .collect();
        let n = weights.len();
        Self {
            parties,
            queue: vec![],
            silent,
            seed,
            outputs: vec![None; n],
            frozen: vec![false; n],
            token_sends: 0,
            terminal_sends: 0,
            hold_freeze: None,
            held_freeze: vec![],
            hold_list: None,
            held_lists: vec![],
            rejected: vec![vec![]; n],
        }
    }
    fn start(&mut self, fault: Option<usize>) {
        for (id, p) in self.parties.iter_mut().enumerate() {
            if self.silent == Some(id) {
                continue;
            }
            let mut bytes = [0; 32];
            bytes[31] = (id as u8 + 1) * 7;
            let opening = Opening {
                message: bytes,
                randomness: [id as u8 + 1; 32],
            };
            let (mut public, shares) =
                ax::generate(&p.app.setup, &p.app.dealers[id].context, &opening).unwrap();
            if fault == Some(id) {
                public.base.tag[0] ^= 1;
            }
            let n = p.app.n;
            let d = p.app.sampling.quotas[id];
            let mut list = (0..d).map(|j| (id + j) % n).collect::<Vec<_>>();
            list.sort_unstable();
            p.app.start_material(list, public, shares).unwrap();
        }
    }
    fn pump(&mut self) {
        loop {
            let mut progress = false;
            for (id, p) in self.parties.iter_mut().enumerate() {
                for action in p.app.drain_actions() {
                    progress = true;
                    match action {
                        Action::Rbc(wrbc::Request::Broadcast { instance, data }) => {
                            p.rbc.get_mut(&instance).unwrap().broadcast(&data).unwrap()
                        }
                        Action::Avid(request) => {
                            let instance = request.instance();
                            let st = p.avid.get_mut(&instance).unwrap();
                            match request {
                                wavid::Request::DisperseCached { prepared, .. } => {
                                    st.disperse_cached(prepared).unwrap()
                                }
                                wavid::Request::Disperse { data, .. } => {
                                    st.disperse(&data).unwrap()
                                }
                                wavid::Request::Pin { root, .. } => st.pin_root(root).unwrap(),
                                wavid::Request::Authorize { retrievers, .. } => {
                                    st.authorize(retrievers).unwrap()
                                }
                                wavid::Request::Retrieve { .. } => st.retrieve().unwrap(),
                                wavid::Request::Complete { root, .. } => {
                                    st.accept_completion(root).unwrap()
                                }
                                _ => unreachable!(),
                            }
                        }
                        Action::Ra(wra::Request::Register {
                            instance,
                            header_id,
                        }) => {
                            assert!(!p.ra.contains_key(&instance));
                            let mut state = wra::State::new(
                                p.node.weighted_membership().unwrap(),
                                id,
                                instance,
                                header_id,
                            )
                            .unwrap();
                            let keys = p
                                .pending_ra
                                .keys()
                                .copied()
                                .filter(|k| k.0 == instance)
                                .collect::<Vec<_>>();
                            for key in keys {
                                state.receive(key.1, p.pending_ra.remove(&key).unwrap());
                            }
                            p.ra.insert(instance, state);
                        }
                        Action::Ra(wra::Request::Input { instance, value }) => {
                            p.ra.get_mut(&instance).unwrap().input(value).unwrap()
                        }
                        Action::Gather(wgather::Request::Start { .. }) => p.gather.start().unwrap(),
                        Action::Gather(wgather::Request::Add { dealer, .. }) => {
                            p.gather.add(dealer).unwrap()
                        }
                        Action::BinAa(wbinaa::Request::Start { inputs, .. }) => {
                            p.binaa.start(inputs).unwrap()
                        }
                        Action::Private { recipient, packet } => {
                            self.queue.push((id, recipient, Message::Private(packet)))
                        }
                        Action::Recovery { recipient, packet } => {
                            assert!(p.app.is_frozen(), "early token/terminal release");
                            assert!(p.app.dealers[packet.dealer].complete);
                            if packet.kind == crate::msg::RECOVERY_TOKEN {
                                assert!(p.app.assignments.authorized(recipient, packet.dealer));
                                self.token_sends += 1;
                            } else {
                                assert!(p.app.assignments.authorized(id, packet.dealer));
                                self.terminal_sends += 1;
                            }
                            self.queue.push((id, recipient, Message::Recovery(packet)));
                        }
                        other => panic!("unexpected action {other:?}"),
                    }
                }
                for state in p.rbc.values_mut() {
                    for a in std::mem::take(&mut state.outgoing) {
                        self.queue.push((id, a.recipient, Message::Rbc(a.message)));
                    }
                    for e in std::mem::take(&mut state.events) {
                        progress = true;
                        if matches!(&e,wrbc::Event::Deliver{instance,..} if instance.slot==1 && instance.dealer==self.hold_list)
                        {
                            self.held_lists.push((id, e));
                        } else {
                            p.app.rbc_event(e).unwrap();
                        }
                    }
                }
                for state in p.avid.values_mut() {
                    for a in std::mem::take(&mut state.outgoing) {
                        self.queue.push((id, a.recipient, Message::Avid(a.message)));
                    }
                    for e in std::mem::take(&mut state.events) {
                        progress = true;
                        p.app.avid_event(e).unwrap();
                    }
                }
                for state in p.ra.values_mut() {
                    for a in std::mem::take(&mut state.outgoing) {
                        self.queue.push((id, a.recipient, Message::Ra(a.message)));
                    }
                    for e in std::mem::take(&mut state.events) {
                        progress = true;
                        p.app.ra_event(e).unwrap();
                    }
                }
                for a in std::mem::take(&mut p.gather.outgoing) {
                    self.queue
                        .push((id, a.recipient, Message::Gather(a.message)));
                }
                for e in std::mem::take(&mut p.gather.events) {
                    progress = true;
                    p.app.gather_event(e).unwrap();
                }
                for a in std::mem::take(&mut p.binaa.outgoing) {
                    self.queue
                        .push((id, a.recipient, Message::BinAa(a.message)));
                }
                for e in std::mem::take(&mut p.binaa.events) {
                    progress = true;
                    if self.hold_freeze == Some(id) {
                        self.held_freeze.push((id, e));
                    } else {
                        p.app.binaa_event(e).unwrap();
                    }
                }
                for e in p.app.drain_events() {
                    match e {
                        Event::Frozen { .. } => {
                            assert!(!self.frozen[id]);
                            self.frozen[id] = true;
                        }
                        Event::Coin { value, .. } => {
                            assert!(self.outputs[id].is_none());
                            assert!(self.frozen[id]);
                            self.outputs[id] = Some(value);
                        }
                        Event::Terminal {
                            dealer,
                            rejected: true,
                        } => self.rejected[id].push(dealer),
                        Event::Failed { reason } => panic!("{reason}"),
                        _ => {}
                    }
                }
            }
            if !progress {
                break;
            }
        }
    }
    fn receive(&mut self, sender: usize, to: usize, message: Message) {
        let p = &mut self.parties[to];
        match message {
            Message::Avid(msg) => p.avid.get_mut(&msg.instance).unwrap().receive(sender, msg),
            Message::Rbc(msg) => p.rbc.get_mut(&msg.instance).unwrap().receive(sender, msg),
            Message::Ra(msg) => {
                if let Some(ra) = p.ra.get_mut(&msg.instance) {
                    ra.receive(sender, msg);
                } else {
                    let role = matches!(msg.kind, wra::Kind::Ready(_)) as u8;
                    p.pending_ra
                        .entry((msg.instance, sender, role))
                        .or_insert(msg);
                }
            }
            Message::Gather(msg) => p.gather.receive(sender, msg),
            Message::BinAa(msg) => p.binaa.receive(sender, msg),
            Message::Private(msg) => p.app.private_packet(sender, msg).unwrap(),
            Message::Recovery(msg) => p.app.recovery_packet(sender, msg).unwrap(),
        }
    }
    fn settle(&mut self) {
        self.pump();
        let mut steps = 0;
        while !self.queue.is_empty() {
            self.seed ^= self.seed << 13;
            self.seed ^= self.seed >> 7;
            self.seed ^= self.seed << 17;
            let k = self.seed as usize % self.queue.len();
            let (sender, to, msg) = self.queue.swap_remove(k);
            if Some(sender) != self.silent && Some(to) != self.silent {
                if self.seed.is_multiple_of(11) {
                    self.receive(sender, to, msg.clone());
                }
                self.receive(sender, to, msg);
            }
            self.pump();
            steps += 1;
            assert!(steps < 1_000_000, "protocol did not quiesce");
        }
    }
    fn assert_complete(&self) {
        let values = self
            .outputs
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != self.silent)
            .map(|(_, v)| v.expect("honest party pending"))
            .collect::<Vec<_>>();
        assert!(values.windows(2).all(|w| w[0] == w[1]));
        let edges = self.parties[0].app.sampling.edge_bound();
        let n = self.parties.len();
        assert!(self.token_sends <= n * edges);
        assert!(self.terminal_sends <= n * edges);
    }
}
#[test]
fn composed_coin_with_reordered_duplicates_and_silent_byzantine_party() {
    for seed in [17, 31, 53] {
        let mut s = Sim::new(&[1; 7], 2, Some(6), seed);
        s.start(None);
        s.settle();
        s.assert_complete();
    }
}
#[test]
fn malicious_dealer_has_publicly_verified_common_rejection() {
    let mut s = Sim::new(&[1; 7], 2, None, 61);
    s.start(Some(0));
    s.settle();
    s.assert_complete();
    for rejected in &s.rejected {
        assert!(rejected.contains(&0));
    }
}
#[test]
fn late_lists_activate_new_recovery_service_after_coin_output() {
    let mut s = Sim::new(&[1; 7], 2, None, 71);
    s.hold_list = Some(6);
    s.start(None);
    s.settle();
    s.assert_complete();
    let before = s.token_sends;
    s.hold_list = None;
    for (id, e) in std::mem::take(&mut s.held_lists) {
        s.parties[id].app.rbc_event(e).unwrap();
    }
    s.settle();
    assert!(s.token_sends > before);
    s.assert_complete();
}
#[test]
fn entire_vector_barrier_holds_early_packets_until_late_freeze() {
    let mut s = Sim::new(&[1; 7], 2, None, 79);
    s.hold_freeze = Some(6);
    s.start(None);
    s.settle();
    assert!(!s.frozen[6]);
    assert_eq!(s.outputs[6], None);
    assert!(!s.held_freeze.is_empty());
    s.hold_freeze = None;
    for (id, e) in std::mem::take(&mut s.held_freeze) {
        s.parties[id].app.binaa_event(e).unwrap();
    }
    s.settle();
    s.assert_complete();
}
#[test]
fn skewed_weights_preserve_progress_under_weight_bounded_silence() {
    let mut s = Sim::new(&[3, 4, 5, 6], 6, Some(2), 83);
    s.start(None);
    s.settle();
    s.assert_complete();
}

#[test]
fn coverage_failure_stays_pending_without_reroll_or_all_party_fallback() {
    let mut s = Sim::new(&[1; 7], 2, None, 97);
    s.start(None);
    // This rare but valid draw leaves dealers 5 and 6 with no recoverer.
    for p in &mut s.parties {
        let d = p.app.sampling.quotas[p.app.id];
        assert!(d < 7);
        let raw = p
            .app
            .sampling
            .encode(p.app.context_id, p.app.id, &(0..d).collect::<Vec<_>>())
            .unwrap();
        for a in &mut p.app.actions {
            if let Action::Rbc(wrbc::Request::Broadcast { instance, data }) = a
                && instance.slot == 1
            {
                *data = raw.clone();
            }
        }
    }
    s.settle();
    assert!(s.frozen.iter().all(|v| *v));
    assert!(s.outputs.iter().all(Option::is_none));
    for p in &s.parties {
        assert!(p.app.dealers[6].value.is_none());
    }
}
#[test]
fn invalid_remote_rejection_cannot_fix_an_honest_dealer_value() {
    let mut s = Sim::new(&[1; 7], 2, Some(6), 103);
    s.start(None);
    s.pump();
    // Sender 6 has no RBC-authorized list; an arbitrary claimed bottom is inert.
    for to in 0..6 {
        s.parties[to]
            .app
            .recovery_packet(
                6,
                Packet {
                    epoch: 0,
                    dealer: 0,
                    kind: crate::msg::TERMINAL,
                    payload: vec![0; 65],
                },
            )
            .unwrap();
    }
    s.settle();
    s.assert_complete();
    assert!(s.rejected.iter().all(Vec::is_empty));
}

#[test]
fn valid_ax_opening_outside_coin_range_is_certified_as_zero() {
    let mut s = Sim::new(&[1; 7], 2, None, 109);
    s.start(None);
    let p = &mut s.parties[0];
    let mut message = [0; 32];
    message[30] = 4; // 1024 equals D for nu=8.
    let (public, shares) = ax::generate(
        &p.app.setup,
        &p.app.dealers[0].context,
        &Opening {
            message,
            randomness: [91; 32],
        },
    )
    .unwrap();
    let list = (0..p.app.sampling.quotas[0]).collect();
    p.app.actions.clear();
    p.app.started = false;
    p.app.start_material(list, public, shares).unwrap();
    s.settle();
    s.assert_complete();
    for p in &s.parties {
        assert_eq!(p.app.dealers[0].value, Some(0u8.into()));
    }
    for rejected in &s.rejected {
        assert!(rejected.contains(&0));
    }
}
#[test]
fn even_an_authorized_recoverer_cannot_forge_a_rejection() {
    let mut s = Sim::new(&[1; 7], 2, None, 113);
    s.start(None);
    let p = &s.parties[0];
    let raw = p
        .app
        .actions
        .iter()
        .find_map(|a| match a {
            Action::Rbc(wrbc::Request::Broadcast { instance, data }) if instance.slot == 0 => {
                Some(data)
            }
            _ => None,
        })
        .unwrap();
    let header =
        wiawvss::certified::Header::decode(&p.app.setup, &p.app.dealers[0].context, raw).unwrap();
    let raw = wiawvss::certified::Certificate {
        header_id: header.id(),
        evidence: wiawvss::certified::Evidence::Semantic {
            fault: wiawvss::terminal::Terminal::RootFault { token: [0; 32] },
            fields: vec![],
        },
    }
    .encode();
    for to in 0..7 {
        s.parties[to]
            .app
            .recovery_packet(
                6,
                Packet {
                    epoch: 0,
                    dealer: 0,
                    kind: crate::msg::TERMINAL,
                    payload: raw.clone(),
                },
            )
            .unwrap();
    }
    s.settle();
    s.assert_complete();
    assert!(s.parties.iter().all(|p| p.app.assignments.authorized(6, 0)));
    assert!(s.rejected.iter().all(Vec::is_empty));
}

#[test]
fn sharing_needs_both_storage_and_authenticated_private_receipts() {
    for drop_storage in [false, true] {
        let mut s = Sim::new(&[1; 7], 2, None, 127);
        s.start(None);
        s.pump();
        s.queue.retain(|(_, _, msg)| match msg {
            Message::Private(p) if !drop_storage && p.dealer == 0 => false,
            Message::Avid(m)
                if drop_storage
                    && m.instance.dealer == Some(0)
                    && matches!(m.kind, wavid::Kind::Init { .. }) =>
            {
                false
            }
            _ => true,
        });
        s.settle();
        for p in &s.parties {
            assert!(p.app.dealers[0].header.is_some());
            assert!(!p.app.dealers[0].echoed);
            assert!(!p.app.dealers[0].complete);
            assert!(p.app.dealers[0].value.is_none());
        }
    }
}
#[test]
fn global_completion_does_not_require_local_receipt_and_late_receipt_still_serves() {
    let mut s = Sim::new(&[1; 7], 2, None, 131);
    s.start(None);
    s.pump();
    let k = s
        .queue
        .iter()
        .position(|(_, to, m)| *to == 6 && matches!(m,Message::Private(p) if p.dealer==0))
        .unwrap();
    let late = s.queue.swap_remove(k);
    s.settle();
    s.assert_complete();
    assert!(s.parties[6].app.dealers[0].complete);
    assert!(!s.parties[6].app.dealers[0].echoed);
    let before = s.token_sends;
    s.receive(late.0, late.1, late.2);
    s.settle();
    assert!(s.parties[6].app.dealers[0].echoed);
    assert!(s.token_sends > before);
    s.assert_complete();
}
#[test]
fn nonrecoverers_verify_outputs_without_downloading_public_bulk() {
    let mut s = Sim::new(&[1; 7], 2, None, 137);
    s.start(None);
    s.settle();
    s.assert_complete();
    let mut nonmembers = 0;
    for p in &s.parties {
        for d in 0..7 {
            if !p.app.assignments.authorized(p.app.id, d) {
                nonmembers += 1;
                assert!(!p.app.dealers[d].retrieving);
                assert!(p.app.dealers[d].recovery_cache.is_none());
                assert!(p.app.dealers[d].value.is_some());
            }
        }
    }
    assert!(nonmembers > 0);
}
#[test]
fn committed_bad_codeword_completes_storage_but_yields_public_coding_rejection() {
    use wiawvss::certified::{Header, Receipt};
    let mut s = Sim::new(&[1; 7], 2, None, 139);
    s.start(None);
    let p = &mut s.parties[0];
    let public = p
        .app
        .actions
        .iter()
        .find_map(|a| {
            if let Action::Avid(wavid::Request::DisperseCached { prepared, .. }) = a {
                Some(prepared.file().to_vec())
            } else {
                None
            }
        })
        .unwrap();
    let codec = &p.app.dealers[0].codec;
    let mut rows = codec.prepare(&public).unwrap().rows;
    rows[0][codec.k][0] ^= 1;
    let prepared = codec.commit_rows(rows).unwrap();
    let header = Header::new(&p.app.setup, &p.app.dealers[0].context, prepared.root);
    for a in &mut p.app.actions {
        match a {
            Action::Rbc(wrbc::Request::Broadcast { instance, data }) if instance.slot == 0 => {
                *data = header.encode()
            }
            Action::Private { packet, .. } => {
                let old = Receipt::decode(codec, &packet.payload).unwrap();
                let share = wiawvss::PrivateShare::decode(&old.share).unwrap();
                packet.payload = Receipt::new(&p.app.setup, codec, &prepared, &share)
                    .unwrap()
                    .encode();
            }
            _ => {}
        }
    }
    p.app
        .actions
        .retain(|a| !matches!(a, Action::Avid(wavid::Request::DisperseCached { .. })));
    p.avid
        .get_mut(&p.app.instance(0, 0))
        .unwrap()
        .disperse_prepared(prepared)
        .unwrap();
    s.settle();
    s.assert_complete();
    assert!(
        s.parties
            .iter()
            .all(|p| p.app.dealers[0].complete && p.app.dealers[0].value == Some(0u8.into()))
    );
    assert!(s.rejected.iter().all(|r| r.contains(&0)));
}

#[test]
fn malformed_private_tokens_cannot_obtain_honest_echoes() {
    let mut s = Sim::new(&[1; 7], 2, None, 149);
    s.start(None);
    let codec = s.parties[0].app.dealers[0].codec.clone();
    for a in &mut s.parties[0].app.actions {
        if let Action::Private { packet, .. } = a {
            let mut receipt = wiawvss::certified::Receipt::decode(&codec, &packet.payload).unwrap();
            receipt.share[103] ^= 1;
            packet.payload = receipt.encode();
        }
    }
    s.settle();
    for p in &s.parties {
        assert!(!p.app.dealers[0].echoed);
        assert!(!p.app.dealers[0].complete);
    }
}
