//! Compact source openings: one directory path per stripe and a multiproof per
//! contiguous source range. Uses the same indexed Merkle trees as storage.
use crate::{Codec, SourceOpening};
use anyhow::{ensure, Result};
use crypto::{
    aes_hash::Proof,
    hash::Hash,
    weighted_merkle::{pack_range, verify, verify_range},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactOpenings {
    stripes: Vec<StripeOpenings>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StripeOpenings {
    stripe: usize,
    root: Hash,
    directory_proof: Proof,
    ranges: Vec<SourceRange>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SourceRange {
    start: usize,
    data: Vec<u8>,
    siblings: Vec<Hash>,
}
/// Borrowed data whose complete, canonical set of blocks has been authenticated.
pub struct AuthenticatedOpenings<'a> {
    block_bytes: usize,
    blocks: Vec<(usize, &'a [u8])>,
}
impl AuthenticatedOpenings<'_> {
    pub fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        offset.checked_add(N)?;
        let mut out = [0; N];
        let mut copied = 0;
        while copied < N {
            let position = offset + copied;
            let i = self
                .blocks
                .binary_search_by_key(&(position / self.block_bytes), |b| b.0)
                .ok()?;
            let within = position % self.block_bytes;
            let len = (N - copied).min(self.block_bytes - within);
            out[copied..copied + len].copy_from_slice(&self.blocks[i].1[within..within + len]);
            copied += len;
        }
        Some(out)
    }
}
impl CompactOpenings {
    /// Input paths are produced locally. Authentication takes place in verify;
    /// packing alone never produces an AuthenticatedOpenings value.
    pub fn pack(codec: &Codec, fields: &[SourceOpening]) -> Result<Self> {
        ensure!(
            fields
                .windows(2)
                .all(|w| (w[0].stripe, w[0].fragment.index) < (w[1].stripe, w[1].fragment.index)),
            "unordered source openings"
        );
        let mut stripes = vec![];
        let mut p = 0;
        while p < fields.len() {
            let first = &fields[p];
            ensure!(first.stripe < codec.q, "unknown stripe");
            let mut stripe = StripeOpenings {
                stripe: first.stripe,
                root: first.root,
                directory_proof: first.directory_proof.clone(),
                ranges: vec![],
            };
            while p < fields.len() && fields[p].stripe == first.stripe {
                let start = fields[p].fragment.index;
                let mut data = vec![];
                let mut proofs = vec![];
                loop {
                    let f = &fields[p];
                    ensure!(
                        f.root == first.root
                            && f.directory_proof == first.directory_proof
                            && f.fragment.index < codec.k
                            && f.fragment.data.len() == codec.parameters().block_bytes,
                        "inconsistent source opening"
                    );
                    data.extend_from_slice(&f.fragment.data);
                    proofs.push(f.fragment.proof.clone());
                    p += 1;
                    if p == fields.len()
                        || fields[p].stripe != first.stripe
                        || fields[p].fragment.index != start + proofs.len()
                    {
                        break;
                    }
                }
                let siblings = pack_range(codec.m, start, &proofs)
                    .ok_or_else(|| anyhow::anyhow!("malformed source path"))?;
                stripe.ranges.push(SourceRange {
                    start,
                    data,
                    siblings,
                });
            }
            stripes.push(stripe);
        }
        Ok(Self { stripes })
    }
    pub fn verify<'a>(
        &'a self,
        codec: &Codec,
        root: Hash,
        expected: &[usize],
    ) -> Option<AuthenticatedOpenings<'a>> {
        if expected.windows(2).any(|w| w[0] >= w[1]) {
            return None;
        }
        let b = codec.parameters().block_bytes;
        let mut blocks = Vec::with_capacity(expected.len());
        let mut previous_stripe = None;
        for s in &self.stripes {
            if s.stripe >= codec.q
                || previous_stripe.is_some_and(|z| z >= s.stripe)
                || s.ranges.is_empty()
                || !verify(
                    codec.directory_context,
                    root,
                    codec.q,
                    s.stripe,
                    &s.root,
                    &s.directory_proof,
                )
            {
                return None;
            }
            previous_stripe = Some(s.stripe);
            let mut previous_end = None;
            for r in &s.ranges {
                let len = r.data.len() / b;
                if len == 0
                    || r.data.len() % b != 0
                    || r.start.checked_add(len)? > codec.k
                    || previous_end.is_some_and(|end| end >= r.start)
                {
                    return None;
                }
                previous_end = Some(r.start + len);
                let values: Vec<_> = r.data.chunks_exact(b).collect();
                // Check exact requested blocks before hashing; extra blocks cannot
                // change an input set or enlarge the verifier's admitted work.
                for (j, &value) in values.iter().enumerate() {
                    let index = s.stripe * codec.k + r.start + j;
                    if expected.get(blocks.len()) != Some(&index) {
                        return None;
                    }
                    blocks.push((index, value));
                }
                verify_range(
                    codec.stripe_context(s.stripe),
                    s.root,
                    codec.m,
                    r.start,
                    &values,
                    &r.siblings,
                )?;
            }
        }
        (blocks.len() == expected.len()).then_some(AuthenticatedOpenings {
            block_bytes: b,
            blocks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{InstanceId, Weight, WeightedMembership};

    #[test]
    fn compact_paths_preserve_binding_and_exact_field_selection() {
        for n in [4, 16] {
            for block_bytes in [32, 34, 64, 128] {
                let m = WeightedMembership::new(vec![Weight::from(3); n], Weight::from(n as u64))
                    .unwrap();
                let c = Codec::with_params(
                    &m,
                    InstanceId::new(2, Some(0), 0),
                    [19; 32],
                    n * block_bytes * 3 + 19,
                    crate::CodingParams { block_bytes },
                )
                .unwrap();
                let data: Vec<_> = (0..c.file_bytes).map(|i| (i % 251) as u8).collect();
                let file = c.commit_file(data.clone()).unwrap();
                let indices: Vec<_> = (0..data.len().div_ceil(block_bytes))
                    .filter(|i| i % 3 != 1)
                    .collect();
                let fields: Vec<_> = indices
                    .iter()
                    .map(|&i| file.open_source(i).unwrap())
                    .collect();
                let packed = CompactOpenings::pack(&c, &fields).unwrap();
                assert!(
                    bincode::serialized_size(&packed).unwrap()
                        < bincode::serialized_size(&fields).unwrap()
                );
                let raw = bincode::serialize(&packed).unwrap();
                let packed: CompactOpenings = bincode::deserialize(&raw).unwrap();
                let view = packed.verify(&c, file.root(), &indices).unwrap();
                for &i in &indices {
                    let got = view.read::<16>(i * block_bytes).unwrap();
                    for (j, &v) in got.iter().enumerate() {
                        assert_eq!(v, data.get(i * block_bytes + j).copied().unwrap_or(0));
                    }
                }
                assert!(view.read::<32>(block_bytes).is_none());
                assert!(packed.verify(&c, [0; 32], &indices).is_none());
                assert!(packed.verify(&c, file.root(), &indices[1..]).is_none());
                let mut bad = packed.clone();
                bad.stripes[0].ranges[0].data[0] ^= 1;
                assert!(bad.verify(&c, file.root(), &indices).is_none());
                let mut bad = packed.clone();
                bad.stripes[0].ranges[0].siblings[0][0] ^= 1;
                assert!(bad.verify(&c, file.root(), &indices).is_none());
                let mut bad = packed.clone();
                bad.stripes[0].ranges[0].start = usize::MAX;
                assert!(bad.verify(&c, file.root(), &indices).is_none());
                let mut bad = packed.clone();
                bad.stripes.reverse();
                assert!(bad.verify(&c, file.root(), &indices).is_none());
                let mut bad = packed.clone();
                bad.stripes[0].ranges[0].data.push(0);
                assert!(bad.verify(&c, file.root(), &indices).is_none());
            }
        }
    }
    #[test]
    fn streaming_commitment_is_independent_of_part_boundaries() {
        let m = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
        for len in [0, 1, 31, 32, 127, 128, 129, 1023] {
            let c = Codec::new(&m, InstanceId::new(0, Some(0), 0), [9; 32], len).unwrap();
            let data: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            let root = c.commit_file(data.clone()).unwrap().root();
            for chunk in [1, 7, 32, 33, 127, 256] {
                assert_eq!(c.commit_parts(data.chunks(chunk)).unwrap(), root);
            }
            assert!(c.commit_parts([data.as_slice(), &[0]]).is_err());
            if len > 0 {
                assert!(c.commit_parts([&data[..len - 1]]).is_err());
            }
        }
    }
}
