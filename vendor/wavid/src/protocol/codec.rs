use crate::{
    Bundle, CodingParams, Fragment, Retrieval, SourceOpening, StorageFault, StripeWitness,
    ValidatedFile,
};
use anyhow::{ensure, Result};
use bincode::Options;
use crypto::{
    hash::{do_hash, Hash},
    weighted_merkle::{
        pack_range, range_frontier, verify, verify_range, IndexedTree, VerifiedRange,
    },
};
use reed_solomon_erasure::galois_16::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, OnceLock, Weak},
};
use types::{InstanceId, Replica, WeightedMembership};

/// Default source-block size. Use Codec::parameters() for an instance's actual size.
pub const BLOCK_BYTES: usize = 32;
// For n <= 64 and W <= n^n, the reference 256-bit certified AX bulk
// is bounded by 126.90 MiB (odd-even) or 157.99 MiB (bitonic).
// Keep more than 3x headroom; this caps raw file bytes, not encoded storage.
pub const MAX_FILE_BYTES: usize = 512 * 1024 * 1024;
pub const CHUNK_BYTES: usize = 32 * 1024;
/// One shared directory and completion instance; stripes never run separate quorums.
#[derive(Clone)]
pub struct Codec {
    pub(super) parameters: CodingParams,
    pub k: usize,
    pub m: usize,
    pub q: usize,
    pub file_bytes: usize,
    pub counts: Vec<usize>,
    pub positions: Vec<std::ops::Range<usize>>,
    pub context: Hash,
    pub directory_context: Hash,
    code: Arc<Coding>,
}
enum Coding {
    Gf8(reed_solomon_erasure::galois_8::ReedSolomon),
    Gf16(ReedSolomon),
}
fn coding(k: usize, m: usize) -> Result<Arc<Coding>> {
    type Cache = Mutex<HashMap<(usize, usize), Weak<Coding>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    if let Some(c) = cache.get(&(k, m)).and_then(Weak::upgrade) {
        return Ok(c);
    }
    cache.retain(|_, v| v.strong_count() > 0);
    let c = Arc::new(if m < 256 {
        Coding::Gf8(reed_solomon_erasure::galois_8::ReedSolomon::new(k, m - k)?)
    } else {
        Coding::Gf16(ReedSolomon::new(k, m - k)?)
    });
    cache.insert((k, m), Arc::downgrade(&c));
    Ok(c)
}
#[derive(Serialize, Deserialize)]
struct PackedStripe {
    // Fixed geometry determines boundaries; a flat buffer avoids per-block lengths.
    data: Vec<u8>,
    siblings: Vec<Hash>,
}
#[derive(Serialize, Deserialize)]
struct PackedBundle {
    version: u8,
    directory: Vec<Hash>,
    stripes: Vec<PackedStripe>,
}
/// Only the verified decoder constructs this wrapper; caller mutation cannot bypass checks.
pub(crate) struct VerifiedBundle {
    pub(crate) directory: Vec<Hash>,
    pub(crate) stripes: Vec<Vec<StoredFragment>>,
    pub(crate) root: Hash,
}
/// A received coordinate shares its authenticated tree with other coordinates
/// in the same owner range. Expand paths only for a public certificate.
#[derive(Clone)]
pub(crate) struct StoredFragment {
    index: usize,
    data: Arc<Vec<u8>>,
    offset: usize,
    block_bytes: usize,
    proof: Arc<VerifiedRange>,
}
trait Coordinate {
    fn index(&self) -> usize;
    fn data(&self) -> &[u8];
    fn export(&self) -> Fragment;
}
impl Coordinate for Fragment {
    fn index(&self) -> usize {
        self.index
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn export(&self) -> Fragment {
        self.clone()
    }
}
impl Coordinate for StoredFragment {
    fn index(&self) -> usize {
        self.index
    }
    fn data(&self) -> &[u8] {
        &self.data[self.offset..self.offset + self.block_bytes]
    }
    fn export(&self) -> Fragment {
        Fragment {
            index: self.index,
            data: self.data().to_vec(),
            proof: self
                .proof
                .proof(self.index)
                .expect("verified range contains coordinate"),
        }
    }
}
impl StoredFragment {
    pub(crate) fn index(&self) -> usize {
        self.index
    }
}
/// Eager diagnostic representation. Prefer ValidatedFile for upper-layer source
/// openings: Prepared deliberately retains all rows, trees, and expanded bundles.
pub struct Prepared {
    pub root: Hash,
    pub bundles: Vec<Bundle>,
    pub stripes: Vec<IndexedTree>,
    pub directory: IndexedTree,
    pub rows: Vec<Vec<Vec<u8>>>,
}
impl Codec {
    pub fn new(
        membership: &WeightedMembership,
        instance: InstanceId,
        public_id: Hash,
        file_bytes: usize,
    ) -> Result<Self> {
        Self::with_params(
            membership,
            instance,
            public_id,
            file_bytes,
            CodingParams::default(),
        )
    }
    /// Construct a deterministic systematic codec. All parties must use the same
    /// membership, instance, public_id, file length, and coding parameters. The
    /// public_id is Node::weighted_public_id("wavid") ("wrbc" for WRBC); the
    /// instance must name its dealer. Do not put the resulting root in public_id.
    pub fn with_params(
        membership: &WeightedMembership,
        instance: InstanceId,
        public_id: Hash,
        file_bytes: usize,
        parameters: CodingParams,
    ) -> Result<Self> {
        parameters.validate()?;
        let k = membership.n();
        ensure!(
            k <= 4096 && instance.valid(k) && instance.dealer.is_some(),
            "WAVID requires a registered dealer and at most 4096 physical parties"
        );
        ensure!(
            file_bytes <= MAX_FILE_BYTES,
            "file length exceeds resource limit"
        );
        let counts = membership.storage_counts();
        let m: usize = counts.iter().sum();
        let q = file_bytes.max(1).div_ceil(k * parameters.block_bytes);
        let code = coding(k, m)?;
        let mut offset = 0;
        let positions = counts
            .iter()
            .map(|count| {
                let r = offset..offset + count;
                offset += count;
                r
            })
            .collect();
        let context = do_hash(&bincode::serialize(&(
            "wavid/systematic-adaptive/multiproof/v3",
            parameters.block_bytes as u64,
            public_id,
            instance,
            file_bytes as u64,
            k as u64,
            m as u64,
            &counts,
        ))?);
        let directory_context = do_hash(&bincode::serialize(&("wavid/directory/v1", context))?);
        Ok(Self {
            parameters,
            k,
            m,
            q,
            file_bytes,
            counts,
            positions,
            context,
            directory_context,
            code,
        })
    }
    pub fn parameters(&self) -> CodingParams {
        self.parameters
    }
    pub fn stripe_context(&self, z: usize) -> Hash {
        do_hash(&bincode::serialize(&("wavid/stripe/v1", self.context, z as u64)).unwrap())
    }
    pub(super) fn stripe_tree(&self, z: usize, row: &[u8]) -> IndexedTree {
        let blocks: Vec<_> = row.chunks_exact(self.parameters.block_bytes).collect();
        IndexedTree::new(self.stripe_context(z), &blocks)
    }
    /// Flat scratch buffers avoid one heap allocation per coding coordinate.
    pub(super) fn encode_stripe(&self, data: &[u8]) -> Result<Vec<u8>> {
        let b = self.parameters.block_bytes;
        ensure!(data.len() == self.k * b, "source stripe size");
        if let Coding::Gf8(code) = self.code.as_ref() {
            let mut row = vec![0; self.m * b];
            row[..data.len()].copy_from_slice(data);
            let mut shards: Vec<_> = row.chunks_exact_mut(b).collect();
            code.encode(&mut shards)?;
            return Ok(row);
        }
        let mut symbols = vec![[0; 2]; self.m * b / 2];
        for (symbol, bytes) in symbols.iter_mut().zip(data.chunks_exact(2)) {
            *symbol = [bytes[0], bytes[1]];
        }
        let mut shards: Vec<_> = symbols.chunks_exact_mut(b / 2).collect();
        match self.code.as_ref() {
            Coding::Gf16(code) => code.encode(&mut shards)?,
            Coding::Gf8(_) => unreachable!(),
        }
        Ok(symbols.into_iter().flatten().collect())
    }
    /// Construct one contiguous source stripe; only the last stripe is padded.
    pub(super) fn source_stripe(&self, data: &[u8], z: usize) -> Vec<u8> {
        let size = self.k * self.parameters.block_bytes;
        let mut stripe = vec![0; size];
        let start = z * size;
        if start < data.len() {
            let len = size.min(data.len() - start);
            stripe[..len].copy_from_slice(&data[start..start + len]);
        }
        stripe
    }
    /// Serialize stripes directly into final owner packets. Only one encoded
    /// stripe and tree exist at a time; no intermediate Vec<PackedBundle> or
    /// individual paths are retained. The directory prefix is filled in last.
    pub(crate) fn prepare_packets(&self, data: &[u8]) -> Result<(Hash, Vec<Vec<u8>>)> {
        let (directory, packets, _) = self.prepare_selected(data, &Default::default())?;
        Ok((directory.root(), packets))
    }
    /// Encode once for the header, owner packets and selected systematic proofs.
    /// Retains final packets and requested proofs, never all stripe trees.
    pub fn prepare_dispersal(
        &self,
        data: Vec<u8>,
        blocks: &std::collections::BTreeSet<usize>,
    ) -> Result<super::Dispersal> {
        let (directory, packets, openings) = self.prepare_selected(&data, blocks)?;
        Ok(super::Dispersal::new(
            super::ValidatedFile::from_verified(self.clone(), data, directory),
            packets,
            openings,
        ))
    }
    fn prepare_selected(
        &self,
        data: &[u8],
        blocks: &std::collections::BTreeSet<usize>,
    ) -> Result<(
        IndexedTree,
        Vec<Vec<u8>>,
        std::collections::BTreeMap<usize, crate::SourceOpening>,
    )> {
        ensure!(
            data.len() == self.file_bytes,
            "fixed file length differs from descriptor"
        );
        ensure!(
            blocks.iter().all(|&i| i < self.q * self.k),
            "source block index"
        );
        let mut openings = std::collections::BTreeMap::new();
        let prefix_bytes = 1 + 8 + 32 * self.q + 8;
        let mut packets: Vec<_> = (0..self.k)
            .map(|owner| {
                let mut raw = Vec::with_capacity(self.bundle_bytes(owner));
                raw.resize(prefix_bytes, 0);
                raw
            })
            .collect();
        let mut roots = Vec::with_capacity(self.q);
        for z in 0..self.q {
            let row = self.encode_stripe(&self.source_stripe(data, z))?;
            let tree = self.stripe_tree(z, &row);
            roots.push(tree.root());
            for &block in blocks.range(z * self.k..(z + 1) * self.k) {
                let index = block % self.k;
                let b = self.parameters.block_bytes;
                openings.insert(
                    block,
                    (
                        tree.root(),
                        crate::Fragment {
                            index,
                            data: row[index * b..(index + 1) * b].to_vec(),
                            proof: tree.proof(index),
                        },
                    ),
                );
            }
            for (owner, raw) in packets.iter_mut().enumerate() {
                let positions = self.positions[owner].clone();
                // PackedStripe's flat Vec has one byte length, followed by blocks
                // and the canonical sibling vector. No block copies or lengths.
                bincode::serialize_into(
                    &mut *raw,
                    &((positions.len() * self.parameters.block_bytes) as u64),
                )?;
                let b = self.parameters.block_bytes;
                raw.extend_from_slice(&row[positions.start * b..positions.end * b]);
                bincode::serialize_into(
                    raw,
                    &tree.range_proof(positions.start, positions.len()).unwrap(),
                )?;
            }
        }
        let directory = IndexedTree::new(self.directory_context, &roots);
        let openings = openings
            .into_iter()
            .map(|(block, (root, fragment))| {
                let stripe = block / self.k;
                (
                    block,
                    crate::SourceOpening {
                        stripe,
                        root,
                        directory_proof: directory.proof(stripe),
                        fragment,
                    },
                )
            })
            .collect();
        let prefix = bincode::serialize(&(3u8, &roots, self.q as u64))?;
        for raw in &mut packets {
            raw[..prefix_bytes].copy_from_slice(&prefix);
        }
        Ok((directory, packets, openings))
    }
    pub fn prepare(&self, data: &[u8]) -> Result<Prepared> {
        ensure!(
            data.len() == self.file_bytes,
            "fixed file length differs from descriptor"
        );
        let rows = (0..self.q)
            .map(|z| {
                self.encode_stripe(&self.source_stripe(data, z)).map(|row| {
                    row.chunks_exact(self.parameters.block_bytes)
                        .map(|b| b.to_vec())
                        .collect()
                })
            })
            .collect::<Result<_>>()?;
        self.commit_rows(rows)
    }
    /// Low-level commitment; callers may use this to exercise malformed-dealer certificates.
    pub fn commit_rows(&self, rows: Vec<Vec<Vec<u8>>>) -> Result<Prepared> {
        ensure!(
            rows.len() == self.q
                && rows.iter().all(|s| s.len() == self.m
                    && s.iter().all(|b| b.len() == self.parameters.block_bytes)),
            "invalid coordinate geometry"
        );
        let stripes: Vec<_> = rows
            .iter()
            .enumerate()
            .map(|(z, r)| IndexedTree::new(self.stripe_context(z), r))
            .collect();
        let roots: Vec<_> = stripes.iter().map(|t| t.root()).collect();
        let directory = IndexedTree::new(self.directory_context, &roots);
        let root = directory.root();
        let bundles = (0..self.k)
            .map(|owner| Bundle {
                directory: stripes.iter().map(|t| t.root()).collect(),
                stripes: rows
                    .iter()
                    .enumerate()
                    .map(|(z, r)| {
                        self.positions[owner]
                            .clone()
                            .map(|index| Fragment {
                                index,
                                data: r[index].clone(),
                                proof: stripes[z].proof(index),
                            })
                            .collect()
                    })
                    .collect(),
            })
            .collect();
        Ok(Prepared {
            root,
            bundles,
            stripes,
            directory,
            rows,
        })
    }
    pub(crate) fn directory_bytes(&self) -> usize {
        1 + 8 + 32 * self.q + 8
    }
    pub(crate) fn stripe_bytes(&self, owner: Replica) -> usize {
        let frontier = range_frontier(self.m, self.positions[owner].start, self.counts[owner])
            .unwrap()
            .len();
        8 + self.parameters.block_bytes * self.counts[owner] + 8 + 32 * frontier
    }
    pub fn bundle_bytes(&self, owner: Replica) -> usize {
        self.directory_bytes() + self.q * self.stripe_bytes(owner)
    }
    /// Decode only the fixed v3 prefix. Geometry comes from registration, never
    /// from an untrusted length prefix. The caller authenticates the directory root.
    pub(crate) fn decode_directory(&self, raw: &[u8]) -> Option<Vec<Hash>> {
        if raw.len() != self.directory_bytes()
            || raw[0] != 3
            || u64::from_le_bytes(raw[1..9].try_into().ok()?) != self.q as u64
            || u64::from_le_bytes(raw[raw.len() - 8..].try_into().ok()?) != self.q as u64
        {
            return None;
        }
        Some(
            raw[9..raw.len() - 8]
                .chunks_exact(32)
                .map(|b| b.try_into().unwrap())
                .collect(),
        )
    }
    pub(crate) fn decode_stripe_packet(
        &self,
        owner: Replica,
        z: usize,
        raw: &[u8],
        root: Hash,
    ) -> Option<Vec<StoredFragment>> {
        if owner >= self.k || z >= self.q || raw.len() != self.stripe_bytes(owner) {
            return None;
        }
        let stripe: PackedStripe = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(raw.len() as u64)
            .reject_trailing_bytes()
            .deserialize(raw)
            .ok()?;
        self.verify_packed_stripe(owner, z, stripe, root)
    }
    fn verify_packed_stripe(
        &self,
        owner: Replica,
        z: usize,
        stripe: PackedStripe,
        root: Hash,
    ) -> Option<Vec<StoredFragment>> {
        if stripe.data.len() != self.counts[owner] * self.parameters.block_bytes {
            return None;
        }
        let blocks: Vec<_> = stripe
            .data
            .chunks_exact(self.parameters.block_bytes)
            .collect();
        let proof = Arc::new(verify_range(
            self.stripe_context(z),
            root,
            self.m,
            self.positions[owner].start,
            &blocks,
            &stripe.siblings,
        )?);
        let data = Arc::new(stripe.data);
        Some(
            self.positions[owner]
                .clone()
                .enumerate()
                .map(|(j, index)| StoredFragment {
                    index,
                    data: data.clone(),
                    offset: j * self.parameters.block_bytes,
                    block_bytes: self.parameters.block_bytes,
                    proof: proof.clone(),
                })
                .collect(),
        )
    }
    /// Versioned compact wire representation; public single-block openings remain available.
    pub fn encode_bundle(&self, owner: Replica, bundle: &Bundle) -> Result<Vec<u8>> {
        ensure!(
            owner < self.k && bundle.directory.len() == self.q && bundle.stripes.len() == self.q,
            "bundle geometry"
        );
        let mut stripes = Vec::with_capacity(self.q);
        for stripe in &bundle.stripes {
            ensure!(
                stripe.len() == self.counts[owner]
                    && stripe
                        .iter()
                        .zip(self.positions[owner].clone())
                        .all(|(f, i)| f.index == i && f.data.len() == self.parameters.block_bytes),
                "coordinate geometry"
            );
            let proofs: Vec<_> = stripe.iter().map(|f| f.proof.clone()).collect();
            let siblings = pack_range(self.m, self.positions[owner].start, &proofs)
                .ok_or_else(|| anyhow::anyhow!("malformed proof"))?;
            stripes.push(PackedStripe {
                data: stripe.iter().flat_map(|f| f.data.iter().copied()).collect(),
                siblings,
            });
        }
        let mut raw = Vec::with_capacity(self.bundle_bytes(owner));
        bincode::serialize_into(
            &mut raw,
            &PackedBundle {
                version: 3,
                directory: bundle.directory.clone(),
                stripes,
            },
        )?;
        Ok(raw)
    }
    pub fn decode_bundle(&self, owner: Replica, raw: &[u8]) -> Option<Bundle> {
        self.decode_verified_bundle(owner, raw, None, None)
            .map(|v| Bundle {
                directory: v.directory,
                stripes: v
                    .stripes
                    .into_iter()
                    .map(|s| s.into_iter().map(|f| f.export()).collect())
                    .collect(),
            })
    }
    pub(crate) fn decode_verified_bundle(
        &self,
        owner: Replica,
        raw: &[u8],
        expected: Option<Hash>,
        cached_directory: Option<&[Hash]>,
    ) -> Option<VerifiedBundle> {
        self.decode_packet(owner, raw, expected, cached_directory, true)
    }
    /// Storage acknowledgements need complete verification, but not retained paths.
    pub(crate) fn verify_packet(
        &self,
        owner: Replica,
        raw: &[u8],
        expected: Option<Hash>,
    ) -> Option<Hash> {
        self.decode_packet(owner, raw, expected, None, false)
            .map(|b| b.root)
    }
    fn decode_packet(
        &self,
        owner: Replica,
        raw: &[u8],
        expected: Option<Hash>,
        cached_directory: Option<&[Hash]>,
        retain: bool,
    ) -> Option<VerifiedBundle> {
        if owner >= self.k || raw.len() != self.bundle_bytes(owner) {
            return None;
        }
        let packed: PackedBundle = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(raw.len() as u64)
            .reject_trailing_bytes()
            .deserialize(raw)
            .ok()?;
        if packed.version != 3 || packed.directory.len() != self.q || packed.stripes.len() != self.q
        {
            return None;
        }
        let root = if let (Some(root), Some(directory)) = (expected, cached_directory) {
            if directory != packed.directory.as_slice() {
                return None;
            }
            root
        } else {
            IndexedTree::new(self.directory_context, &packed.directory).root()
        };
        if expected.is_some_and(|r| r != root) {
            return None;
        }
        let mut stripes = Vec::with_capacity(if retain { self.q } else { 0 });
        for (z, stripe) in packed.stripes.into_iter().enumerate() {
            let fragments = self.verify_packed_stripe(owner, z, stripe, packed.directory[z])?;
            if retain {
                stripes.push(fragments);
            }
        }
        Some(VerifiedBundle {
            root,
            directory: packed.directory,
            stripes,
        })
    }
    pub fn verify_bundle(
        &self,
        owner: Replica,
        bundle: &Bundle,
        expected: Option<Hash>,
    ) -> Option<Hash> {
        if owner >= self.k || bundle.directory.len() != self.q || bundle.stripes.len() != self.q {
            return None;
        }
        let root = IndexedTree::new(self.directory_context, &bundle.directory).root();
        if expected.is_some_and(|r| r != root) {
            return None;
        }
        for (z, stripe) in bundle.stripes.iter().enumerate() {
            if stripe.len() != self.counts[owner] {
                return None;
            }
            for (index, fragment) in self.positions[owner].clone().zip(stripe) {
                if fragment.index != index
                    || fragment.data.len() != self.parameters.block_bytes
                    || !verify(
                        self.stripe_context(z),
                        bundle.directory[z],
                        self.m,
                        index,
                        &fragment.data,
                        &fragment.proof,
                    )
                {
                    return None;
                }
            }
        }
        Some(root)
    }
    fn decode_stripe<F: Coordinate>(&self, fragments: &[F]) -> Result<Vec<u8>> {
        ensure!(
            fragments.len() == self.k
                && fragments
                    .iter()
                    .all(|f| f.data().len() == self.parameters.block_bytes),
            "exactly k correctly sized fragments needed"
        );
        if let Coding::Gf8(code) = self.code.as_ref() {
            let mut shards: Vec<Option<Vec<u8>>> = vec![None; self.m];
            for f in fragments {
                ensure!(
                    f.index() < self.m && shards[f.index()].is_none(),
                    "duplicate or unknown coordinate"
                );
                shards[f.index()] = Some(f.data().to_vec());
            }
            code.reconstruct_data(&mut shards)?;
            let source: Vec<u8> = shards[..self.k]
                .iter()
                .flat_map(|s| s.as_ref().unwrap().iter().copied())
                .collect();
            return self.encode_stripe(&source);
        }
        let mut shards: Vec<Option<Vec<[u8; 2]>>> = vec![None; self.m];
        for f in fragments {
            ensure!(
                f.index() < self.m && shards[f.index()].is_none(),
                "duplicate or unknown coordinate"
            );
            shards[f.index()] = Some(f.data().chunks_exact(2).map(|c| [c[0], c[1]]).collect());
        }
        match self.code.as_ref() {
            Coding::Gf16(code) => code.reconstruct_data(&mut shards)?,
            Coding::Gf8(_) => unreachable!(),
        };
        // Re-encode all coordinates, including supplied parity, before root comparison.
        let source: Vec<u8> = shards[..self.k]
            .iter()
            .flat_map(|s| s.as_ref().unwrap().iter().flat_map(|v| v.iter().copied()))
            .collect();
        self.encode_stripe(&source)
    }
    pub fn source_opening(&self, prepared: &Prepared, block: usize) -> Result<SourceOpening> {
        ensure!(block < self.q * self.k, "source block index");
        let z = block / self.k;
        let index = block % self.k;
        Ok(SourceOpening {
            stripe: z,
            root: prepared.stripes[z].root(),
            directory_proof: prepared.directory.proof(z),
            fragment: Fragment {
                index,
                data: prepared.rows[z][index].clone(),
                proof: prepared.stripes[z].proof(index),
            },
        })
    }
    pub fn verify_source(&self, root: Hash, p: &SourceOpening) -> bool {
        p.stripe < self.q
            && p.fragment.data.len() == self.parameters.block_bytes
            && p.fragment.index < self.k
            && verify(
                self.directory_context,
                root,
                self.q,
                p.stripe,
                &p.root,
                &p.directory_proof,
            )
            && verify(
                self.stripe_context(p.stripe),
                p.root,
                self.m,
                p.fragment.index,
                &p.fragment.data,
                &p.fragment.proof,
            )
    }
    pub fn verify_fault(&self, root: Hash, fault: &StorageFault) -> bool {
        match fault {
            StorageFault::Coding(w) => {
                if w.stripe >= self.q
                    || w.fragments.len() != self.k
                    || !verify(
                        self.directory_context,
                        root,
                        self.q,
                        w.stripe,
                        &w.root,
                        &w.directory_proof,
                    )
                {
                    return false;
                }
                if w.fragments.iter().any(|f| {
                    !verify(
                        self.stripe_context(w.stripe),
                        w.root,
                        self.m,
                        f.index,
                        &f.data,
                        &f.proof,
                    )
                }) {
                    return false;
                }
                match self.decode_stripe(&w.fragments) {
                    Ok(rows) => self.stripe_tree(w.stripe, &rows).root() != w.root,
                    Err(_) => false,
                }
            }
            StorageFault::Padding(p) => {
                self.verify_source(root, p)
                    && p.fragment.data.iter().enumerate().any(|(offset, b)| {
                        (p.stripe * self.k + p.fragment.index) * self.parameters.block_bytes
                            + offset
                            >= self.file_bytes
                            && *b != 0
                    })
            }
        }
    }
    pub fn recover(
        &self,
        root: Hash,
        directory: &[Hash],
        rows: &[BTreeMap<usize, Fragment>],
    ) -> Result<Option<Retrieval>> {
        if rows.len() != self.q || rows.iter().any(|r| r.len() < self.k) {
            return Ok(None);
        }
        ensure!(directory.len() == self.q, "directory size");
        let tree = IndexedTree::new(self.directory_context, directory);
        ensure!(tree.root() == root, "directory commitment");
        let mut data = Vec::with_capacity(self.file_bytes);
        for z in 0..self.q {
            let fragments: Vec<_> = rows[z].values().take(self.k).cloned().collect();
            match self.check_stripe(z, directory[z], &tree, &fragments, false)? {
                Ok(bytes) => data.extend(bytes),
                Err(fault) => return Ok(Some(Retrieval::Invalid(fault))),
            }
        }
        Ok(Some(Retrieval::File(ValidatedFile::from_verified(
            self.clone(),
            data,
            tree,
        ))))
    }
    /// Only internally authenticated coordinates may skip repeated path checking.
    pub(crate) fn recover_verified_stripe(
        &self,
        z: usize,
        root: Hash,
        directory: &IndexedTree,
        fragments: &[StoredFragment],
    ) -> Result<Result<Vec<u8>, StorageFault>> {
        self.check_stripe(z, root, directory, fragments, true)
    }
    fn check_stripe<F: Coordinate>(
        &self,
        z: usize,
        root: Hash,
        directory: &IndexedTree,
        fragments: &[F],
        verified: bool,
    ) -> Result<Result<Vec<u8>, StorageFault>> {
        ensure!(
            verified
                || fragments.iter().all(|f| verify(
                    self.stripe_context(z),
                    root,
                    self.m,
                    f.index(),
                    f.data(),
                    &f.export().proof
                )),
            "unauthenticated recovery coordinate"
        );
        let mut decoded = self.decode_stripe(fragments)?;
        let encoded_tree = self.stripe_tree(z, &decoded);
        if encoded_tree.root() != root {
            return Ok(Err(StorageFault::Coding(StripeWitness {
                stripe: z,
                root,
                directory_proof: directory.proof(z),
                // These are the received paths, not paths in the different candidate tree.
                fragments: fragments.iter().map(Coordinate::export).collect(),
            })));
        }
        for (index, block) in decoded
            .chunks_exact(self.parameters.block_bytes)
            .take(self.k)
            .enumerate()
        {
            if block.iter().enumerate().any(|(offset, b)| {
                (z * self.k + index) * self.parameters.block_bytes + offset >= self.file_bytes
                    && *b != 0
            }) {
                return Ok(Err(StorageFault::Padding(SourceOpening {
                    stripe: z,
                    root,
                    directory_proof: directory.proof(z),
                    fragment: Fragment {
                        index,
                        data: block.to_vec(),
                        proof: encoded_tree.proof(index),
                    },
                })));
            }
        }
        let source_bytes = self.k * self.parameters.block_bytes;
        decoded.truncate(source_bytes.min(self.file_bytes.saturating_sub(z * source_bytes)));
        Ok(Ok(decoded))
    }
}
