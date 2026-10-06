use super::{Codec, CodingParams};
use crate::{Fragment, SourceOpening};
use anyhow::{ensure, Result};
use crypto::{hash::Hash, weighted_merkle::IndexedTree};
use std::sync::{Arc, Mutex};

/// Immutable, locally validated source data and an on-demand proof provider.
/// Clones share the file, directory, and a one-stripe tree cache. Construction
/// verifies every stripe; this type does not certify upper-layer circuit semantics.
/// Keeping this handle is sufficient to open any source block, including one
/// assigned to a silent holder. No further network responses are needed.
#[derive(Clone)]
pub struct ValidatedFile(Arc<Inner>);
struct Inner {
    codec: Codec,
    data: Vec<u8>,
    directory: IndexedTree,
    // A local performance option only: one cached stripe, never all stripe trees.
    cached: Mutex<Option<(usize, IndexedTree)>>,
}
impl std::fmt::Debug for ValidatedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedFile")
            .field("bytes", &self.0.data.len())
            .field("root", &self.root())
            .field("parameters", &self.parameters())
            .finish()
    }
}
impl AsRef<[u8]> for ValidatedFile {
    fn as_ref(&self) -> &[u8] {
        &self.0.data
    }
}
impl std::ops::Deref for ValidatedFile {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}
impl PartialEq<Vec<u8>> for ValidatedFile {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_ref() == other
    }
}
impl PartialEq<ValidatedFile> for Vec<u8> {
    fn eq(&self, other: &ValidatedFile) -> bool {
        self.as_slice() == other.as_ref()
    }
}
impl ValidatedFile {
    pub(super) fn from_verified(codec: Codec, data: Vec<u8>, directory: IndexedTree) -> Self {
        Self(Arc::new(Inner {
            codec,
            data,
            directory,
            cached: Mutex::new(None),
        }))
    }
    pub fn root(&self) -> Hash {
        self.0.directory.root()
    }
    pub fn parameters(&self) -> CodingParams {
        self.0.codec.parameters
    }
    /// Binds session/protocol context, instance, geometry and file length.
    pub fn coding_context(&self) -> Hash {
        self.0.codec.context
    }
    /// Convert to an owned buffer. Moves if uniquely owned; otherwise copies.
    /// Prefer as_ref() when consuming data to retain cheap shared proof access.
    pub fn into_vec(self) -> Vec<u8> {
        match Arc::try_unwrap(self.0) {
            Ok(inner) => inner.data,
            Err(inner) => inner.data.clone(),
        }
    }
    /// Open a systematic source block by its global block index. Padding blocks
    /// are allowed for public padding witnesses. Parity coordinates are excluded.
    pub fn open_source(&self, block: usize) -> Result<SourceOpening> {
        let codec = &self.0.codec;
        ensure!(block < codec.q * codec.k, "source block index");
        let z = block / codec.k;
        let index = block % codec.k;
        let mut cached = self
            .0
            .cached
            .lock()
            .map_err(|_| anyhow::anyhow!("proof cache poisoned"))?;
        if cached.as_ref().is_none_or(|(stripe, _)| *stripe != z) {
            let row = codec.encode_stripe(&codec.source_stripe(&self.0.data, z))?;
            *cached = Some((z, codec.stripe_tree(z, &row)));
        }
        let tree = &cached.as_ref().unwrap().1;
        let b = codec.parameters.block_bytes;
        let start = block * b;
        let mut data = vec![0; b];
        if start < self.0.data.len() {
            let len = b.min(self.0.data.len() - start);
            data[..len].copy_from_slice(&self.0.data[start..start + len]);
        }
        Ok(SourceOpening {
            stripe: z,
            root: tree.root(),
            directory_proof: self.0.directory.proof(z),
            fragment: Fragment {
                index,
                data,
                proof: tree.proof(index),
            },
        })
    }
    /// Open all blocks covering an application field at [offset, offset+len).
    /// Crossing a block/stripe boundary is supported; empty ranges return no proofs.
    /// The caller remains responsible for canonical field offsets and interpretation.
    pub fn open_range(&self, offset: usize, len: usize) -> Result<Vec<SourceOpening>> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| anyhow::anyhow!("range overflow"))?;
        ensure!(end <= self.0.data.len(), "range outside source file");
        if len == 0 {
            return Ok(Vec::new());
        }
        let b = self.parameters().block_bytes;
        (offset / b..=(end - 1) / b)
            .map(|i| self.open_source(i))
            .collect()
    }
}
impl Codec {
    /// Validate an already available source file against a public root. Rebuilds
    /// one stripe at a time and keeps only the directory and the original file.
    /// Use this for dealer-side private-input openings or reopening saved data.
    pub fn validate_file(&self, root: Hash, data: Vec<u8>) -> Result<ValidatedFile> {
        let file = self.commit_file(data)?;
        ensure!(
            file.root() == root,
            "source file differs from public commitment"
        );
        Ok(file)
    }
    /// Dealer-side canonical commitment and private-input proof provider. Encodes
    /// stripe by stripe; unlike prepare(), retains no full coded bulk or bundles.
    /// The application must authenticate this root in its public header.
    pub fn commit_file(&self, data: Vec<u8>) -> Result<ValidatedFile> {
        ensure!(
            data.len() == self.file_bytes,
            "fixed file length differs from descriptor"
        );
        let mut roots = Vec::with_capacity(self.q);
        for z in 0..self.q {
            let row = self.encode_stripe(&self.source_stripe(&data, z))?;
            roots.push(self.stripe_tree(z, &row).root());
        }
        let directory = IndexedTree::new(self.directory_context, &roots);
        Ok(ValidatedFile::from_verified(self.clone(), data, directory))
    }
}
