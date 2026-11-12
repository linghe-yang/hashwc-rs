//! Bounded per-recipient stripe retrieval, sharing the ordinary WAVID dispersal.
use super::codec::{Coordinate, StoredFragment};
use crate::{Codec, Event, Fragment, Kind, SourceOpening, State, StorageFault, StripeWitness};
use anyhow::{ensure, Result};
use crypto::{
    aes_hash::Proof,
    hash::Hash,
    weighted_merkle::{verify, IndexedTree},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};
pub const MAX_STRIPES_PER_REQUEST: usize = 256;

#[derive(Clone)]
pub struct ValidatedStripe(Arc<StripeData>);
struct StripeData {
    codec: Arc<Codec>,
    header: Hash,
    stripe: usize,
    source: Vec<u8>,
    stripe_root: Hash,
    tree: OnceLock<IndexedTree>,
    directory_proof: Proof,
}
impl std::fmt::Debug for ValidatedStripe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedStripe")
            .field("stripe", &self.index())
            .finish()
    }
}
impl ValidatedStripe {
    pub fn index(&self) -> usize {
        self.0.stripe
    }
    pub fn root(&self) -> Hash {
        self.0.header
    }
    pub fn coding_context(&self) -> Hash {
        self.0.codec.context
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0.source
    }
    pub(crate) fn matching_source_root(
        &self,
        codec: &Codec,
        header: Hash,
        z: usize,
        source: &[u8],
    ) -> Option<Hash> {
        (self.root() == header
            && self.coding_context() == codec.context
            && self.index() == z
            && self.bytes() == source)
            .then_some(self.0.stripe_root)
    }
    pub fn open_source(&self, block: usize) -> Result<SourceOpening> {
        let c = &self.0.codec;
        ensure!(
            block / c.k == self.index(),
            "block outside recovered stripe"
        );
        let index = block % c.k;
        let b = c.parameters().block_bytes;
        // As with WHCC's ValidatedFile, successful recovery retains source bytes,
        // not every Merkle tree. Only actual evidence requests rebuild a tree.
        if self.0.tree.get().is_none() {
            let row = c.encode_stripe(&self.0.source)?;
            let _ = self.0.tree.set(c.stripe_tree(self.index(), &row));
        }
        let tree = self.0.tree.get().unwrap();
        Ok(SourceOpening {
            stripe: self.index(),
            root: self.0.stripe_root,
            directory_proof: self.0.directory_proof.clone(),
            fragment: Fragment {
                index,
                data: self.0.source[index * b..(index + 1) * b].to_vec(),
                proof: tree.proof(index),
            },
        })
    }
}
impl Codec {
    /// Authenticate exactly k coordinates, decode, re-encode, and check padding.
    /// ValidatedStripe retains enough evidence to open every systematic block.
    pub fn recover_selected(
        &self,
        header: Hash,
        w: &StripeWitness,
    ) -> Result<Result<ValidatedStripe, StorageFault>> {
        ensure!(
            w.stripe < self.q
                && w.fragments.len() == self.k
                && verify(
                    self.directory_context,
                    header,
                    self.q,
                    w.stripe,
                    &w.root,
                    &w.directory_proof
                ),
            "invalid selected stripe directory proof"
        );
        ensure!(
            w.fragments.iter().all(|f| f.index < self.m
                && f.data.len() == self.parameters().block_bytes
                && verify(
                    self.stripe_context(w.stripe),
                    w.root,
                    self.m,
                    f.index,
                    &f.data,
                    &f.proof
                )),
            "invalid selected stripe coordinate"
        );
        Arc::new(self.clone()).recover_authenticated_selected(
            header,
            w.stripe,
            w.root,
            &w.directory_proof,
            &w.fragments,
        )
    }
    /// Internal path: callers have authenticated the directory and owner-range
    /// multiproofs. Keep shared proofs; expand paths only on an actual coding fault.
    pub(super) fn recover_authenticated_selected<F: Coordinate>(
        self: &Arc<Self>,
        header: Hash,
        z: usize,
        root: Hash,
        directory_proof: &Proof,
        fragments: &[F],
    ) -> Result<Result<ValidatedStripe, StorageFault>> {
        let row = self.decode_stripe(fragments)?;
        let tree = self.stripe_tree(z, &row);
        if tree.root() != root {
            return Ok(Err(StorageFault::Coding(StripeWitness {
                stripe: z,
                root,
                directory_proof: directory_proof.clone(),
                fragments: fragments.iter().map(Coordinate::export).collect(),
            })));
        }
        let b = self.parameters().block_bytes;
        let stripe = ValidatedStripe(Arc::new(StripeData {
            codec: self.clone(),
            header,
            stripe: z,
            source: row[..self.k * b].to_vec(),
            stripe_root: root,
            tree: OnceLock::new(),
            directory_proof: directory_proof.clone(),
        }));
        for (j, block) in stripe.bytes().chunks_exact(b).enumerate() {
            if block
                .iter()
                .enumerate()
                .any(|(o, &v)| (z * self.k + j) * b + o >= self.file_bytes && v != 0)
            {
                let _ = stripe.0.tree.set(tree);
                return Ok(Err(StorageFault::Padding(
                    stripe.open_source(z * self.k + j)?,
                )));
            }
        }
        Ok(Ok(stripe))
    }
}

pub(crate) struct Selective {
    codec: Arc<Codec>,
    budget: usize,
    // Bounded even before authorization, completion, or storage; retained across output.
    requests: BTreeMap<usize, BTreeMap<usize, Hash>>,
    served: BTreeSet<(usize, usize)>,
    directory: Option<IndexedTree>,
    selected: Option<BTreeSet<usize>>,
    asked: bool,
    done: BTreeSet<usize>,
    seen: BTreeSet<(usize, usize)>,
    witnesses: BTreeMap<usize, VerifiedSelection>,
}
struct VerifiedSelection {
    root: Hash,
    directory_proof: Proof,
    fragments: Vec<StoredFragment>,
}
impl State {
    pub(crate) fn with_selection_budget(mut self, budget: Option<usize>) -> Result<Self> {
        if let Some(budget) = budget {
            ensure!(
                budget > 0 && budget <= self.codec.q,
                "invalid selective stripe budget"
            );
            self.selective = Some(Selective {
                codec: Arc::new(self.codec.clone()),
                budget,
                requests: BTreeMap::new(),
                served: BTreeSet::new(),
                directory: None,
                selected: None,
                asked: false,
                done: BTreeSet::new(),
                seen: BTreeSet::new(),
                witnesses: BTreeMap::new(),
            });
            // Full-file recovery allocates a slot for every stripe. Selective
            // recovery stores only requested stripes in witnesses/done.
            self.rows = Vec::new();
        }
        Ok(self)
    }
    pub fn retrieve_selected(&mut self, stripes: Vec<usize>) -> Result<()> {
        ensure!(
            self.retrievers.contains(&self.id),
            "unauthorized selected retrieval"
        );
        let s = self
            .selective
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("not a selective instance"))?;
        ensure!(s.selected.is_none(), "selection already frozen");
        ensure!(
            !stripes.is_empty()
                && stripes.len() <= s.budget
                && stripes.iter().all(|&z| z < self.codec.q)
                && stripes.windows(2).all(|w| w[0] < w[1]),
            "noncanonical selection or request budget exceeded"
        );
        s.selected = Some(stripes.into_iter().collect());
        self.advance();
        Ok(())
    }
    pub(crate) fn request_stripe(&mut self, sender: usize, root: Hash, stripe: usize) {
        let Some(s) = &mut self.selective else {
            return;
        };
        if stripe >= self.codec.q || self.descriptor.root.is_some_and(|r| r != root) {
            return;
        }
        let requested = s.requests.entry(sender).or_default();
        if requested.len() < s.budget {
            requested.entry(stripe).or_insert(root);
        }
    }
    pub(crate) fn request_stripes(&mut self, sender: usize, root: Hash, stripes: &[usize]) {
        if stripes.is_empty()
            || stripes.len() > MAX_STRIPES_PER_REQUEST
            || stripes.windows(2).any(|w| w[0] >= w[1])
            || stripes.iter().any(|&z| z >= self.codec.q)
        {
            return;
        }
        for &stripe in stripes {
            self.request_stripe(sender, root, stripe);
        }
    }
    pub(crate) fn advance_selective(&mut self) {
        let Some(root) = self.completed_root else {
            return;
        };
        let s = self.selective.as_mut().unwrap();
        let ask = if !s.asked {
            s.selected
                .as_ref()
                .map(|selected| {
                    s.asked = true;
                    selected.iter().copied().collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            vec![]
        };
        for stripes in ask.chunks(MAX_STRIPES_PER_REQUEST) {
            self.broadcast(Kind::RequestStripes {
                root,
                stripes: stripes.to_vec(),
            });
        }
        if self.stored_root != Some(root) {
            return;
        }
        let s = self.selective.as_mut().unwrap();
        let raw = self.stored_packet.as_ref().unwrap();
        if s.directory.is_none() {
            let roots = self
                .codec
                .decode_directory(&raw[..self.codec.directory_bytes()])
                .unwrap();
            s.directory = Some(IndexedTree::new(self.codec.directory_context, &roots));
        }
        let directory = s.directory.as_ref().unwrap();
        let mut replies = Vec::new();
        for (&peer, requested) in &s.requests {
            if !self.retrievers.contains(&peer) {
                continue;
            }
            for (&stripe, &requested_root) in requested {
                if requested_root != root || !s.served.insert((peer, stripe)) {
                    continue;
                }
                let len = self.codec.stripe_bytes(self.id);
                let start = self.codec.directory_bytes() + stripe * len;
                // Read the stripe root from the already validated fixed directory prefix.
                let stripe_root = raw[9 + stripe * 32..9 + (stripe + 1) * 32]
                    .try_into()
                    .unwrap();
                replies.push((
                    peer,
                    Kind::Stripe {
                        stripe,
                        root: stripe_root,
                        directory_proof: directory.proof(stripe),
                        bytes: raw[start..start + len].to_vec(),
                    },
                ));
            }
        }
        for (peer, reply) in replies {
            self.send(peer, reply);
        }
    }
    pub(crate) fn receive_stripe(
        &mut self,
        sender: usize,
        stripe: usize,
        root: Hash,
        directory_proof: Proof,
        bytes: Vec<u8>,
    ) {
        let Some(header) = self.completed_root else {
            return;
        };
        let Some(s) = &mut self.selective else {
            return;
        };
        if !s.asked
            || self.result.is_some()
            || s.done.contains(&stripe)
            || !s.selected.as_ref().is_some_and(|zs| zs.contains(&stripe))
            || !s.seen.insert((sender, stripe))
        {
            return;
        }
        if !verify(
            self.codec.directory_context,
            header,
            self.codec.q,
            stripe,
            &root,
            &directory_proof,
        ) {
            return;
        }
        let Some(fragments) = self
            .codec
            .decode_stripe_packet(sender, stripe, bytes, root)
        else {
            return;
        };
        let w = s
            .witnesses
            .entry(stripe)
            .or_insert_with(|| VerifiedSelection {
                root,
                directory_proof,
                fragments: vec![],
            });
        if w.root != root {
            return;
        }
        // Owner coordinate ranges are disjoint; each sender is consumed once.
        w.fragments
            .extend(fragments.into_iter().take(self.codec.k - w.fragments.len()));
        if w.fragments.len() == self.codec.k {
            let w = s.witnesses.remove(&stripe).unwrap();
            match s.codec.recover_authenticated_selected(
                header,
                stripe,
                w.root,
                &w.directory_proof,
                &w.fragments,
            ) {
                Ok(Ok(validated)) => {
                    s.done.insert(stripe);
                    self.events.push(Event::Stripe {
                        instance: self.instance,
                        stripe: validated,
                    });
                }
                Ok(Err(fault)) => {
                    let result = crate::Retrieval::Invalid(fault);
                    self.result = Some(result.clone());
                    self.events.push(Event::Result {
                        instance: self.instance,
                        result,
                    });
                    s.witnesses.clear();
                }
                Err(e) => log::error!("selected WAVID decoding: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompletionMode, Descriptor, ProtMsg};
    use types::{InstanceId, Weight, WeightedMembership};
    fn state() -> State {
        let membership =
            WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
        State::new(
            membership,
            0,
            InstanceId::new(0, Some(0), 0),
            [21; 32],
            Descriptor {
                coding: crate::CodingParams::default(),
                file_bytes: 32 * 4 * 40,
                root: None,
                retrievers: vec![],
                completion: CompletionMode::External,
            },
        )
        .unwrap()
        .with_selection_budget(Some(2))
        .unwrap()
    }
    fn deliver(s: &mut State, sender: usize, kind: Kind) {
        s.receive(
            sender,
            ProtMsg {
                instance: s.instance,
                kind,
            },
        );
    }
    #[test]
    fn budget_is_per_recipient_persistent_and_cannot_be_bypassed_by_full_requests() {
        let mut s = state();
        let prepared = s.codec.prepare(&vec![7; s.codec.file_bytes]).unwrap();
        let root = prepared.root;
        // Requests may beat authorization, storage and header delivery.
        for stripe in [0, 1, 0, 2, 3] {
            deliver(&mut s, 1, Kind::RequestStripe { root, stripe });
        }
        assert!(s.outgoing.is_empty());
        let packet = s.codec.encode_bundle(0, &prepared.bundles[0]).unwrap();
        for (index, bytes) in packet.chunks(crate::CHUNK_BYTES).enumerate() {
            deliver(
                &mut s,
                0,
                Kind::Init {
                    index: index as u32,
                    bytes: bytes.to_vec(),
                },
            );
        }
        assert!(s.stored_root.is_none());
        s.pin_root(root).unwrap();
        s.accept_completion(root).unwrap();
        assert!(s.outgoing.is_empty());
        s.authorize(vec![1]).unwrap();
        let sent: Vec<_> = std::mem::take(&mut s.outgoing)
            .into_iter()
            .filter_map(|a| match a.message.kind {
                Kind::Stripe { stripe, .. } => Some((a.recipient, stripe)),
                _ => None,
            })
            .collect();
        assert_eq!(sent, vec![(1, 0), (1, 1)]);
        // None of these operations resets spent slots, including a new requested root.
        s.authorize(vec![1]).unwrap();
        s.pin_root(root).unwrap();
        s.accept_completion(root).unwrap();
        for stripe in [0, 1, 2, 39] {
            deliver(&mut s, 1, Kind::RequestStripe { root, stripe });
        }
        deliver(
            &mut s,
            1,
            Kind::RequestStripe {
                root: [0; 32],
                stripe: 4,
            },
        );
        deliver(&mut s, 1, Kind::Request(root));
        assert!(s.outgoing.is_empty());
        // A second authorized recipient has its own budget, not a global reset.
        s.authorize(vec![2]).unwrap();
        for stripe in [4, 5, 6] {
            deliver(&mut s, 2, Kind::RequestStripe { root, stripe });
        }
        assert_eq!(s.outgoing.len(), 2);
        assert!(s.outgoing.iter().all(|a| a.recipient == 2));
        assert!(s.retrieve().is_err());
    }
    #[test]
    fn local_selection_is_immutable_and_oversized_selections_are_rejected() {
        let mut s = state();
        assert!(s.retrieve_selected(vec![0]).is_err());
        s.authorize(vec![0]).unwrap();
        assert!(s.retrieve_selected(vec![0, 1, 2]).is_err());
        assert!(s.retrieve_selected(vec![0, 0]).is_err());
        assert!(s.retrieve_selected(vec![40]).is_err());
        s.retrieve_selected(vec![1, 3]).unwrap();
        assert!(s.retrieve_selected(vec![2, 4]).is_err());
    }
    #[test]
    fn batched_requests_share_the_same_persistent_distinct_stripe_budget() {
        let mut s = state();
        let root = [3; 32];
        for stripes in [
            vec![],
            vec![1, 1],
            vec![2, 1],
            vec![40],
            vec![0; MAX_STRIPES_PER_REQUEST + 1],
        ] {
            deliver(&mut s, 1, Kind::RequestStripes { root, stripes });
        }
        assert!(s.selective.as_ref().unwrap().requests.is_empty());
        deliver(
            &mut s,
            1,
            Kind::RequestStripes {
                root,
                stripes: vec![1, 3, 5],
            },
        );
        deliver(&mut s, 1, Kind::RequestStripe { root, stripe: 7 });
        deliver(
            &mut s,
            1,
            Kind::RequestStripes {
                root,
                stripes: vec![9, 11],
            },
        );
        let requested = &s.selective.as_ref().unwrap().requests[&1];
        assert_eq!(requested.keys().copied().collect::<Vec<_>>(), vec![1, 3]);
        s.authorize(vec![0]).unwrap();
        s.pin_root(root).unwrap();
        s.accept_completion(root).unwrap();
        s.retrieve_selected(vec![1, 3]).unwrap();
        assert_eq!(s.outgoing.len(), 4);
        assert!(s.outgoing.iter().all(
            |a| matches!(&a.message.kind,Kind::RequestStripes{stripes,..} if stripes == &[1,3])
        ));
    }
    #[test]
    fn verified_range_fast_path_keeps_public_coding_faults_and_rejects_bad_packets() {
        for bad_codeword in [false, true] {
            let mut s = state();
            let mut prepared = s.codec.prepare(&vec![7; s.codec.file_bytes]).unwrap();
            if bad_codeword {
                prepared.rows[0][s.codec.m - 1][0] ^= 1;
                prepared = s.codec.commit_rows(prepared.rows).unwrap();
            }
            s.authorize(vec![0]).unwrap();
            s.pin_root(prepared.root).unwrap();
            s.accept_completion(prepared.root).unwrap();
            s.retrieve_selected(vec![0]).unwrap();
            s.events.clear();
            let reply = |owner: usize| {
                let packet = s
                    .codec
                    .encode_bundle(owner, &prepared.bundles[owner])
                    .unwrap();
                let offset = s.codec.directory_bytes();
                Kind::Stripe {
                    stripe: 0,
                    root: prepared.stripes[0].root(),
                    directory_proof: prepared.directory.proof(0),
                    bytes: packet[offset..offset + s.codec.stripe_bytes(owner)].to_vec(),
                }
            };
            let good = reply(0);
            let good_second = reply(2);
            let mut invalid = reply(1);
            if let Kind::Stripe { ref mut bytes, .. } = invalid {
                bytes[0] ^= 1;
            }
            deliver(&mut s, 1, invalid);
            assert!(s.events.is_empty());
            deliver(&mut s, 0, good.clone());
            deliver(&mut s, 2, good_second);
            if bad_codeword {
                assert!(s.events.iter().any(
                    |e| matches!(e,Event::Result{result:crate::Retrieval::Invalid(fault),..}
                    if s.codec.verify_fault(prepared.root,fault))
                ));
            } else {
                let stripe = s
                    .events
                    .iter()
                    .find_map(|e| match e {
                        Event::Stripe { stripe, .. } => Some(stripe),
                        _ => None,
                    })
                    .unwrap();
                assert!(
                    stripe.0.tree.get().is_none(),
                    "honest recovery should retain no proof tree"
                );
                assert_eq!(
                    stripe.bytes(),
                    vec![7; s.codec.k * s.codec.parameters().block_bytes]
                );
                for i in 0..s.codec.k {
                    assert!(s
                        .codec
                        .verify_source(prepared.root, &stripe.open_source(i).unwrap()));
                }
            }
            s.events.clear();
            deliver(&mut s, 0, good);
            assert!(s.events.is_empty());
        }
    }
    #[test]
    fn nonzero_padding_in_a_valid_codeword_is_publicly_refutable() {
        let membership =
            WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
        let codec = Codec::new(&membership, InstanceId::new(0, Some(0), 0), [3; 32], 33).unwrap();
        let mut source = vec![0; 128];
        source[40] = 1;
        let row = codec.encode_stripe(&source).unwrap();
        let bad = codec
            .commit_rows(vec![row.chunks(32).map(|b| b.to_vec()).collect()])
            .unwrap();
        let w = StripeWitness {
            stripe: 0,
            root: bad.stripes[0].root(),
            directory_proof: bad.directory.proof(0),
            fragments: (0..4)
                .map(|i| {
                    bad.bundles
                        .iter()
                        .flat_map(|b| b.stripes[0].iter())
                        .find(|f| f.index == i)
                        .unwrap()
                        .clone()
                })
                .collect(),
        };
        let fault = codec.recover_selected(bad.root, &w).unwrap().unwrap_err();
        assert!(matches!(fault, StorageFault::Padding(_)));
        assert!(codec.verify_fault(bad.root, &fault));
    }
    #[test]
    fn reusing_validated_stripes_still_commits_every_candidate_byte() {
        let codec = state().codec;
        let data: Vec<_> = (0..codec.file_bytes).map(|i| (i % 251) as u8).collect();
        let prepared = codec.prepare(&data).unwrap();
        let mut known = BTreeMap::new();
        for z in [0, 2, codec.q - 1] {
            let witness = StripeWitness {
                stripe: z,
                root: prepared.stripes[z].root(),
                directory_proof: prepared.directory.proof(z),
                fragments: (0..codec.k)
                    .map(|i| Fragment {
                        index: i,
                        data: prepared.rows[z][i].clone(),
                        proof: prepared.stripes[z].proof(i),
                    })
                    .collect(),
            };
            known.insert(
                z,
                codec
                    .recover_selected(prepared.root, &witness)
                    .unwrap()
                    .unwrap(),
            );
        }
        let source = &data[..codec.k * codec.parameters().block_bytes];
        assert!(known[&0]
            .matching_source_root(&codec, prepared.root, 0, source)
            .is_some());
        assert!(known[&0]
            .matching_source_root(&codec, [0; 32], 0, source)
            .is_none());
        assert!(known[&0]
            .matching_source_root(&codec, prepared.root, 1, source)
            .is_none());
        assert_eq!(
            codec
                .commit_parts_reusing(data.chunks(17), prepared.root, &known)
                .unwrap(),
            prepared.root
        );
        // Both downloaded and undownloaded changed fields must affect the result.
        for offset in [
            0,
            codec.k * codec.parameters().block_bytes + 3,
            data.len() - 1,
        ] {
            let mut changed = data.clone();
            changed[offset] ^= 1;
            let root = codec.commit_file(changed.clone()).unwrap().root();
            assert_ne!(root, prepared.root);
            assert_eq!(
                codec
                    .commit_parts_reusing(changed.chunks(31), prepared.root, &known)
                    .unwrap(),
                root
            );
        }
        let mut swapped = known.clone();
        swapped.insert(2, known[&0].clone());
        assert_eq!(
            codec
                .commit_parts_reusing(data.chunks(13), prepared.root, &swapped)
                .unwrap(),
            prepared.root
        );
        let membership =
            WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
        let other = Codec::new(
            &membership,
            InstanceId::new(1, Some(0), 0),
            [21; 32],
            data.len(),
        )
        .unwrap();
        assert_eq!(
            other
                .commit_parts_reusing(data.chunks(19), prepared.root, &known)
                .unwrap(),
            other.commit_file(data).unwrap().root()
        );
    }
}
