//! Per-instance authenticated material shared by full retrieval and a local
//! source verifier. The mutex spans RS work and publication: a cache snapshot
//! alone would permit a concurrent decoder to redo the same stripe.
use super::codec::StoredFragment;
use super::{Codec, ValidatedFile, ValidatedStripe};
use anyhow::{ensure, Result};
use crypto::{hash::Hash, weighted_merkle::IndexedTree};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct VerifiedMaterial(Arc<Shared>);
struct Shared {
    codec: Arc<Codec>,
    root: Hash,
    cache: Mutex<Cache>,
}
#[derive(Default)]
struct Cache {
    stripes: BTreeMap<usize, ValidatedStripe>,
    file: Option<ValidatedFile>,
    stats: MaterialStats,
}
/// Counts successful and failed candidate work separately; no network semantics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MaterialStats {
    pub decoded_stripes: usize,
    pub encoded_stripes: usize,
    pub reused_stripes: usize,
    pub file_hits: usize,
    pub rejected_candidates: usize,
}
impl std::fmt::Debug for VerifiedMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedMaterial")
            .field("root", &self.0.root)
            .finish()
    }
}
pub(super) enum MaterialResult {
    Stripe,
    File(ValidatedFile),
    Invalid(crate::StorageFault),
}
impl VerifiedMaterial {
    /// The caller pins this root through the ordinary authenticated Header.
    /// Construction itself confers no validation on any source data.
    pub fn new(codec: Arc<Codec>, root: Hash) -> Self {
        Self(Arc::new(Shared {
            codec,
            root,
            cache: Mutex::new(Cache::default()),
        }))
    }
    pub fn matches(&self, codec: &Codec, root: Hash) -> bool {
        self.0.root == root
            && self.0.codec.context == codec.context
            && self.0.codec.file_bytes == codec.file_bytes
            && self.0.codec.parameters() == codec.parameters()
    }
    pub fn stats(&self) -> Result<MaterialStats> {
        Ok(self
            .0
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("material cache poisoned"))?
            .stats
            .clone())
    }
    pub fn file(&self) -> Result<Option<ValidatedFile>> {
        Ok(self
            .0
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("material cache poisoned"))?
            .file
            .clone())
    }
    /// Compare the entire canonical stream, reusing only fully checked source
    /// stripes with identical bytes including padding. A rejected candidate may
    /// update work counters but never publishes data, roots or file handles.
    pub fn verify_parts<'a>(
        &self,
        parts: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Option<ValidatedFile>> {
        let c = &self.0.codec;
        let mut cache = self
            .0
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("material cache poisoned"))?;
        if let Some(file) = cache.file.clone() {
            let _profile = util::profile::span("material.file_hit");
            cache.stats.file_hits += 1;
            let mut offset = 0usize;
            let mut equal = true;
            for part in parts {
                let end = offset
                    .checked_add(part.len())
                    .ok_or_else(|| anyhow::anyhow!("source length overflow"))?;
                equal &= file.get(offset..end).is_some_and(|bytes| bytes == part);
                offset = end;
            }
            if equal && offset == file.len() {
                return Ok(Some(file));
            }
            cache.stats.rejected_candidates += 1;
            return Ok(None);
        }
        let mut data = Vec::with_capacity(c.file_bytes);
        for part in parts {
            ensure!(
                part.len() <= c.file_bytes - data.len(),
                "source length exceeds descriptor"
            );
            data.extend_from_slice(part);
        }
        ensure!(
            data.len() == c.file_bytes,
            "source length differs from descriptor"
        );
        let mut roots = Vec::with_capacity(c.q);
        for z in 0..c.q {
            let source = c.source_stripe(&data, z);
            if let Some(root) = cache
                .stripes
                .get(&z)
                .and_then(|s| s.matching_source_root(c, self.0.root, z, &source))
            {
                let _profile = util::profile::span("material.reuse_stripe");
                cache.stats.reused_stripes += 1;
                roots.push(root);
            } else {
                let _profile = util::profile::span("material.encode_missing");
                cache.stats.encoded_stripes += 1;
                roots.push(c.stripe_tree(z, &c.encode_stripe(&source)?).root());
            }
        }
        let directory = IndexedTree::new(c.directory_context, &roots);
        if directory.root() != self.0.root {
            cache.stats.rejected_candidates += 1;
            return Ok(None);
        }
        let file = ValidatedFile::from_verified((**c).clone(), data, directory);
        cache.file = Some(file.clone());
        cache.stripes.clear();
        Ok(Some(file))
    }
    /// Called only after directory and owner-range proofs have authenticated the
    /// coordinates. Decode/re-encode, root and padding validation remain intact.
    pub(super) fn recover(
        &self,
        z: usize,
        root: Hash,
        directory: &IndexedTree,
        fragments: &[StoredFragment],
    ) -> Result<MaterialResult> {
        let c = &self.0.codec;
        ensure!(
            z < c.q && directory.root() == self.0.root,
            "material directory binding"
        );
        let mut cache = self
            .0
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("material cache poisoned"))?;
        if let Some(file) = &cache.file {
            return Ok(MaterialResult::File(file.clone()));
        }
        if cache.stripes.contains_key(&z) {
            return Ok(MaterialResult::Stripe);
        }
        let _profile = util::profile::span("material.decode_stripe");
        cache.stats.decoded_stripes += 1;
        let stripe = match c.recover_authenticated_selected(
            self.0.root,
            z,
            root,
            &directory.proof(z),
            fragments,
        )? {
            Ok(stripe) => stripe,
            Err(fault) => return Ok(MaterialResult::Invalid(fault)),
        };
        cache.stripes.insert(z, stripe);
        if cache.stripes.len() == c.q {
            let mut data = Vec::with_capacity(c.file_bytes);
            for stripe in cache.stripes.values() {
                let take = stripe.bytes().len().min(c.file_bytes - data.len());
                data.extend_from_slice(&stripe.bytes()[..take]);
            }
            ensure!(data.len() == c.file_bytes, "material file length");
            let roots: Vec<_> = cache
                .stripes
                .iter()
                .map(|(&i, s)| {
                    s.matching_source_root(c, self.0.root, i, s.bytes())
                        .expect("bound stripe")
                })
                .collect();
            let rebuilt = IndexedTree::new(c.directory_context, &roots);
            ensure!(rebuilt.root() == self.0.root, "material directory mismatch");
            let file = ValidatedFile::from_verified((**c).clone(), data, rebuilt);
            cache.file = Some(file.clone());
            cache.stripes.clear();
            Ok(MaterialResult::File(file))
        } else {
            Ok(MaterialResult::Stripe)
        }
    }
}
impl super::State {
    /// Local-only attachment; no new network message or peer-controlled handle.
    pub fn attach_material(&mut self, material: VerifiedMaterial) -> Result<()> {
        ensure!(
            self.selective.is_none() && !self.asked && self.material.is_none(),
            "material must be attached once before full retrieval"
        );
        ensure!(
            self.descriptor
                .root
                .is_some_and(|r| material.matches(&self.codec, r)),
            "material instance/root/geometry mismatch"
        );
        self.material = Some(material);
        Ok(())
    }
    /// Wake retrieval after a successful local verifier published a file. Does
    /// not grant authorization, mark storage complete, or change holder service.
    pub fn poll_material(&mut self) -> Result<()> {
        ensure!(self.material.is_some(), "no attached material");
        self.advance();
        Ok(())
    }
    pub(super) fn install_material_file(&mut self) {
        if self.result.is_some() || !self.want || !self.asked {
            return;
        }
        let Some(material) = &self.material else {
            return;
        };
        if self
            .completed_root
            .is_none_or(|root| !material.matches(&self.codec, root))
        {
            return;
        }
        match material.file() {
            Ok(Some(file)) => self.finish_retrieval(crate::Retrieval::File(file)),
            Ok(None) => {}
            Err(e) => log::error!("WAVID shared material: {e}"),
        }
    }
}

#[cfg(test)]
#[path = "material_tests.rs"]
mod tests;
