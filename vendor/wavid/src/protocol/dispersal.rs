use super::{Codec, ValidatedFile};
use crate::{SourceOpening, State};
use anyhow::{ensure, Result};
use std::{collections::BTreeMap, sync::Arc};

/// Immutable local result of one canonical encoding pass. Like ValidatedFile,
/// it cannot be manufactured from unauthenticated wire data.
#[derive(Clone, Debug)]
pub struct Dispersal(Arc<Inner>);
#[derive(Debug)]
struct Inner {
    file: ValidatedFile,
    packets: Vec<Vec<u8>>,
    openings: BTreeMap<usize, SourceOpening>,
}
impl Dispersal {
    pub(super) fn new(
        file: ValidatedFile,
        packets: Vec<Vec<u8>>,
        openings: BTreeMap<usize, SourceOpening>,
    ) -> Self {
        Self(Arc::new(Inner {
            file,
            packets,
            openings,
        }))
    }
    pub fn file(&self) -> &ValidatedFile {
        &self.0.file
    }
    pub fn open_source(&self, block: usize) -> Result<SourceOpening> {
        self.0
            .openings
            .get(&block)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("source proof not requested during preparation"))
    }
    pub fn matches(&self, codec: &Codec) -> bool {
        self.file().coding_context() == codec.context
            && self.file().parameters() == codec.parameters()
            && self.file().len() == codec.file_bytes
            && self.0.packets.len() == codec.k
    }
}
impl State {
    /// Consume canonical local preparation without repeating coding or Merkle work.
    /// Receivers still authenticate ordinary Init packets before Stored is emitted.
    pub fn disperse_cached(&mut self, prepared: Dispersal) -> Result<()> {
        ensure!(
            Some(self.id) == self.instance.dealer && !self.dispersed,
            "only dealer may disperse, once"
        );
        ensure!(
            prepared.matches(&self.codec),
            "prepared encoding context differs"
        );
        ensure!(
            self.descriptor
                .root
                .is_none_or(|r| r == prepared.file().root()),
            "encoding differs from pinned root"
        );
        self.dispersed = true;
        for (peer, raw) in prepared.0.packets.iter().enumerate() {
            self.packet(peer, false, raw);
        }
        Ok(())
    }
}
