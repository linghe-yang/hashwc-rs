//! Incremental consumption of the existing v3 owner packet. No wire-format change.
use super::{Codec, ValidatedFile};
use crate::CHUNK_BYTES;
use anyhow::{ensure, Result};
use crypto::{hash::Hash, weighted_merkle::IndexedTree};
use std::collections::BTreeMap;

/// One bounded slot per sender. Out-of-order chunks are retained; consumed chunks
/// are released and ignored on replay. Record boundaries may cross TCP chunks.
pub(crate) struct DataStream {
    total: usize,
    consumed: usize,
    contiguous: usize,
    parts: BTreeMap<usize, Vec<u8>>,
    closed: bool,
    pub(crate) directory_checked: bool,
    pub(crate) stripe: usize,
}
impl DataStream {
    pub(crate) fn new(total: usize) -> Self {
        Self {
            total,
            consumed: 0,
            contiguous: 0,
            parts: BTreeMap::new(),
            closed: false,
            directory_checked: false,
            stripe: 0,
        }
    }
    pub(crate) fn close(&mut self) {
        self.closed = true;
        self.parts.clear();
    }
    pub(crate) fn add(&mut self, index: u32, bytes: Vec<u8>) {
        if self.closed {
            return;
        }
        let Some(start) = (index as usize).checked_mul(CHUNK_BYTES) else {
            self.close();
            return;
        };
        if start >= self.total || bytes.len() != CHUNK_BYTES.min(self.total - start) {
            self.close();
            return;
        }
        if start + bytes.len() <= self.consumed {
            return;
        }
        self.parts.entry(index as usize).or_insert(bytes);
        while self.contiguous < self.total {
            let Some(part) = self.parts.get(&(self.contiguous / CHUNK_BYTES)) else {
                break;
            };
            self.contiguous += part.len();
        }
    }
    pub(crate) fn take(&mut self, len: usize) -> Option<Vec<u8>> {
        let end = self.consumed.checked_add(len)?;
        if self.closed || end > self.contiguous {
            return None;
        }
        let mut raw = Vec::with_capacity(len);
        while self.consumed < end {
            let index = self.consumed / CHUNK_BYTES;
            let part = self.parts.get(&index)?;
            let offset = self.consumed % CHUNK_BYTES;
            let take = (end - self.consumed).min(part.len() - offset);
            raw.extend_from_slice(&part[offset..offset + take]);
            self.consumed += take;
            if offset + take == part.len() {
                self.parts.remove(&index);
            }
        }
        if self.consumed == self.total {
            self.close();
        }
        Some(raw)
    }
}

/// Validated directory plus partial file. Only completed, fully checked stripes
/// are written to data. Publication waits for all stripes, including padding.
pub(crate) struct Recovery {
    pub(crate) roots: Vec<Hash>,
    pub(crate) directory: IndexedTree,
    pub(crate) done: Vec<bool>,
    remaining: usize,
    data: Vec<u8>,
}
impl Recovery {
    pub(crate) fn new(codec: &Codec, root: Hash, roots: Vec<Hash>) -> Result<Self> {
        ensure!(roots.len() == codec.q, "directory size");
        let directory = IndexedTree::new(codec.directory_context, &roots);
        ensure!(directory.root() == root, "directory commitment");
        Ok(Self {
            roots,
            directory,
            done: vec![false; codec.q],
            remaining: codec.q,
            data: Vec::with_capacity(codec.file_bytes),
        })
    }
    pub(crate) fn store(&mut self, codec: &Codec, z: usize, bytes: &[u8]) {
        assert!(!self.done[z]);
        let start = (z * codec.k * codec.parameters().block_bytes).min(codec.file_bytes);
        let end = start + bytes.len();
        // Grow initialized data only as validated stripes arrive.
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[start..end].copy_from_slice(bytes);
        self.done[z] = true;
        self.remaining -= 1;
    }
    pub(crate) fn complete(&self) -> bool {
        self.remaining == 0
    }
    pub(crate) fn finish(self, codec: &Codec) -> ValidatedFile {
        assert!(self.complete());
        assert_eq!(self.data.len(), codec.file_bytes);
        ValidatedFile::from_verified(codec.clone(), self.data, self.directory)
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
