//! Separate authenticated TCP service with payload confidentiality for private tokens.
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Result, ensure};
use bincode::Options;
use crypto::{Block, hash};
use sdc_config::Node;
use sdc_types::SendAction;
use sdc_util::weighted::{Endpoint, MAX_FRAME_BYTES};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Packet {
    pub epoch: u64,
    pub dealer: usize,
    pub kind: u8,
    pub payload: Vec<u8>,
}
impl std::fmt::Debug for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Packet")
            .field("epoch", &self.epoch)
            .field("dealer", &self.dealer)
            .field("kind", &self.kind)
            .field("bytes", &self.payload.len())
            .finish()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sealed {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}
/// Channel keys are derived from Node.sk_map, with component and direction separation.
pub struct Cipher {
    pub id: usize,
    pub context: Block,
    pub keys: Zeroizing<Vec<Block>>,
}
impl Cipher {
    pub fn new(node: &Node, component: &str) -> Result<Self> {
        node.validate_weighted()?;
        Ok(Self {
            id: node.id,
            context: node.weighted_public_id(component),
            keys: Zeroizing::new(
                (0..node.num_nodes)
                    .map(|i| node.sk_map[&i].as_slice().try_into().unwrap())
                    .collect(),
            ),
        })
    }
    fn aad(&self, sender: usize, recipient: usize) -> Vec<u8> {
        let mut b = self.context.to_vec();
        b.extend_from_slice(&(sender as u64).to_le_bytes());
        b.extend_from_slice(&(recipient as u64).to_le_bytes());
        b
    }
    fn key(&self, peer: usize, sender: usize, recipient: usize) -> Result<Zeroizing<Block>> {
        ensure!(peer < self.keys.len(), "unknown peer");
        Ok(Zeroizing::new(hash(
            b"private-channel-key",
            &[&self.keys[peer], &self.aad(sender, recipient)],
        )))
    }
    pub fn seal(&self, recipient: usize, packet: &Packet) -> Result<Sealed> {
        let key = self.key(recipient, self.id, recipient)?;
        let raw = Zeroizing::new(bincode::serialize(packet)?);
        ensure!(
            raw.len() <= MAX_FRAME_BYTES - 256,
            "private packet exceeds transport frame limit"
        );
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("randomness: {e}"))?;
        let ciphertext = Aes256Gcm::new_from_slice(&*key)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &raw,
                    aad: &self.aad(self.id, recipient),
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        Ok(Sealed { nonce, ciphertext })
    }
    pub fn open(&self, sender: usize, packet: &Sealed) -> Result<Packet> {
        ensure!(
            packet.ciphertext.len() <= MAX_FRAME_BYTES - 240,
            "oversized encrypted payload"
        );
        let key = self.key(sender, sender, self.id)?;
        let raw = Zeroizing::new(
            Aes256Gcm::new_from_slice(&*key)
                .unwrap()
                .decrypt(
                    Nonce::from_slice(&packet.nonce),
                    Payload {
                        msg: &packet.ciphertext,
                        aad: &self.aad(sender, self.id),
                    },
                )
                .map_err(|_| anyhow::anyhow!("invalid private packet"))?,
        );
        Ok(bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(MAX_FRAME_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize(&raw)?)
    }
}
pub struct PrivateEndpoint {
    pub endpoint: Endpoint<Sealed>,
    pub cipher: Cipher,
}
impl PrivateEndpoint {
    pub fn bind(node: &Node, component: &str) -> Result<Self> {
        Ok(Self {
            cipher: Cipher::new(node, component)?,
            endpoint: Endpoint::bind(node, component)?,
        })
    }
    pub fn send(&self, recipient: usize, packet: &Packet) -> Result<()> {
        self.endpoint.send(SendAction {
            recipient,
            message: self.cipher.seal(recipient, packet)?,
        })
    }
    pub async fn recv(&mut self) -> Option<(usize, Packet)> {
        while let Some((sender, sealed)) = self.endpoint.recv.recv().await {
            if let Ok(packet) = self.cipher.open(sender, &sealed) {
                return Some((sender, packet));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn node(id: usize) -> Node {
        let mut n = Node::new();
        n.num_nodes = 4;
        n.id = id;
        n.session_id = [1; 32];
        n.weight_threshold = Some(sdc_types::Weight::from(1));
        for p in 0..4 {
            n.net_map.insert(p, format!("127.0.0.1:{}", 30000 + p));
            n.sk_map.insert(
                p,
                hash(b"test/key", &[&[id.min(p) as u8, id.max(p) as u8]]).to_vec(),
            );
        }
        n
    }
    #[test]
    fn encrypted_packets_bind_sender_recipient_component_session_and_integrity() {
        let a = Cipher::new(&node(0), "private").unwrap();
        let b = Cipher::new(&node(1), "private").unwrap();
        let packet = Packet {
            epoch: 3,
            dealer: 0,
            kind: 0,
            payload: vec![77; 104],
        };
        let sealed = a.seal(1, &packet).unwrap();
        assert!(!sealed.ciphertext.windows(32).any(|s| s == [77; 32]));
        assert_eq!(b.open(0, &sealed).unwrap().payload, packet.payload);
        assert!(b.open(2, &sealed).is_err());
        assert!(
            Cipher::new(&node(2), "private")
                .unwrap()
                .open(0, &sealed)
                .is_err()
        );
        assert!(
            Cipher::new(&node(1), "recovery")
                .unwrap()
                .open(0, &sealed)
                .is_err()
        );
        let mut changed = node(1);
        changed.session_id = [2; 32];
        assert!(
            Cipher::new(&changed, "private")
                .unwrap()
                .open(0, &sealed)
                .is_err()
        );
        let mut tampered = sealed;
        tampered.ciphertext[0] ^= 1;
        assert!(b.open(0, &tampered).is_err());
        assert!(a.seal(8, &packet).is_err());
    }
}
