//! Borrow the existing fixed-width bincode envelope; do not deserialize/copy its payload.
use super::MAX_FRAME_BYTES;
use anyhow::{anyhow, Result};
use crypto::hash::{mac_parts, verify_mac_parts, Hash};
use std::convert::{TryFrom, TryInto};

const HEADER: usize = 64;
const OVERHEAD: usize = HEADER + 32;
const FRAME_DOMAIN: &[u8] = b"weighted/frame/v1";
const ACK_DOMAIN: &[u8] = b"weighted/ack/v1";

pub(super) struct FrameRef<'a> {
    pub context: &'a Hash,
    pub sender: usize,
    pub recipient: usize,
    pub sequence: u64,
    pub payload: &'a [u8],
    pub mac: &'a Hash,
    header: &'a [u8],
}
impl<'a> FrameRef<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if !(OVERHEAD..=MAX_FRAME_BYTES).contains(&raw.len()) {
            return Err(anyhow!("invalid frame envelope size"));
        }
        let word = |start| u64::from_le_bytes(raw[start..start + 8].try_into().unwrap());
        // Check against the actual bounded slice before computing any payload offset.
        if word(56) != (raw.len() - OVERHEAD) as u64 {
            return Err(anyhow!("frame payload length or trailing bytes"));
        }
        let end = raw.len() - 32;
        Ok(Self {
            context: raw[..32].try_into().unwrap(),
            sender: usize::try_from(word(32))?,
            recipient: usize::try_from(word(40))?,
            sequence: word(48),
            payload: &raw[HEADER..end],
            mac: raw[end..].try_into().unwrap(),
            header: &raw[..HEADER],
        })
    }
    pub fn verify(&self, key: &[u8]) -> bool {
        // Exactly bincode(str domain) || fixed header || payload.
        verify_mac_parts(
            &[
                &(FRAME_DOMAIN.len() as u64).to_le_bytes(),
                FRAME_DOMAIN,
                self.header,
                self.payload,
            ],
            key,
            self.mac,
        )
    }
    pub fn ack(&self, key: &[u8]) -> Hash {
        // The ACK covers context/sender/recipient/sequence, excluding payload length.
        mac_parts(
            &[
                &(ACK_DOMAIN.len() as u64).to_le_bytes(),
                ACK_DOMAIN,
                &self.header[..56],
            ],
            key,
        )
    }
}

#[cfg(test)]
#[path = "weighted_frame_tests.rs"]
mod tests;
