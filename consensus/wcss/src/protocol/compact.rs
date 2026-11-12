//! Ordinary circuit CSS: authenticated inputs, gate ciphertexts, and a transcript tag.
//! Omits all per-wire digests. Full AX regeneration, rather than local fault evidence,
//! authenticates the resulting opening. The circuit and gate evaluator are shared.
use super::{Backend, Setup, sharing};
use crypto::Block;
use types::{Error, Result};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    inner: sharing::Public,
}
impl Public {
    pub fn encoded_len(setup: &Setup) -> usize {
        96 + 32 * (setup.circuit.policy().n() + setup.correction_blocks())
    }
    pub fn byte_len(&self) -> usize {
        self.inner.byte_len()
    }
    pub fn valid_shape(&self, setup: &Setup) -> bool {
        sharing::valid_shape(setup, &self.inner, false)
    }
    pub fn encoded_parts(&self) -> impl Iterator<Item = &[u8]> {
        self.inner.encoded_parts(&self.inner.tag)
    }
    pub fn encode(&self) -> Vec<u8> {
        self.inner.encode()
    }
    pub fn decode(setup: &Setup, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::encoded_len(setup) {
            return Err(Error::Encoding);
        }
        let mut chunks = bytes.as_chunks::<32>().0.iter();
        let mut take = || *chunks.next().expect("fixed layout validated");
        Ok(Self {
            inner: sharing::Public {
                true_token: take(),
                inputs: (0..setup.circuit.policy().n()).map(|_| take()).collect(),
                wires: vec![],
                gates: (0..if setup.backend() == Backend::Independent {
                    setup.circuit.gates().len()
                } else {
                    0
                })
                    .map(|_| [take(), take()])
                    .collect(),
                corrections: (0..if setup.backend() == Backend::GeneratedAnd0Or1 {
                    setup.correction_blocks()
                } else {
                    0
                })
                    .map(|_| take())
                    .collect(),
                encrypted_key: take(),
                tag: take(),
            },
        })
    }
}
pub fn share(
    setup: &Setup,
    context: &Block,
    key: &Block,
    seed: &Block,
) -> (Public, Zeroizing<Vec<Block>>) {
    let (inner, shares) = sharing::share_with_wires(setup, context, key, seed, false);
    (Public { inner }, shares)
}
pub fn share_public(setup: &Setup, context: &Block, key: &Block, seed: &Block) -> Public {
    Public {
        inner: sharing::share_internal(setup, context, key, seed, false, false).0,
    }
}

pub fn verify_input(
    setup: &Setup,
    context: &Block,
    public: &Public,
    party: usize,
    token: &Block,
) -> bool {
    sharing::verify_input_with_wires(setup, context, &public.inner, party, token, false)
}
pub fn reconstruct(
    setup: &Setup,
    context: &Block,
    public: &Public,
    shares: &[(usize, Block)],
) -> Result<Block> {
    sharing::reconstruct_with_wires(setup, context, &public.inner, shares, false)
}

/// Canonical compact CSS fields borrowed from a complete replicated record.
#[derive(Clone, Copy, Debug)]
pub struct PublicView<'a> {
    bytes: &'a [u8],
    n: usize,
    gates: usize,
    setup_id: Block,
}
impl<'a> PublicView<'a> {
    pub fn decode(setup: &Setup, bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != Public::encoded_len(setup) {
            return Err(Error::Encoding);
        }
        Ok(Self {
            bytes,
            n: setup.circuit().policy().n(),
            gates: setup.circuit().gates().len(),
            setup_id: setup.id(),
        })
    }
    fn block(&self, offset: usize) -> Block {
        self.bytes[offset..offset + 32]
            .try_into()
            .expect("validated compact layout")
    }
    pub fn verify_input(&self, context: &Block, party: usize, token: &Block) -> bool {
        party < self.n
            && crypto::equal(
                &crypto::input_commitment(context, party, token),
                &self.block(32 + 32 * party),
            )
    }
    /// Returns only the authenticated, deduplicated inputs, for AX regeneration checks.
    pub fn reconstruct(
        &self,
        setup: &Setup,
        context: &Block,
        shares: impl IntoIterator<Item = (usize, Block)>,
    ) -> Result<sharing::RecoveredKey> {
        sharing::reconstruct_fields(setup, context, self, shares, false)
    }
}
impl sharing::RecoveryFields for PublicView<'_> {
    fn valid_shape(&self, setup: &Setup, with_wires: bool) -> bool {
        !with_wires
            && self.setup_id == setup.id()
            && self.n == setup.circuit().policy().n()
            && self.gates == setup.circuit().gates().len()
            && self.bytes.len() == Public::encoded_len(setup)
    }
    fn true_token(&self) -> Block {
        self.block(0)
    }
    fn input(&self, party: usize) -> Block {
        self.block(32 + 32 * party)
    }
    fn wire(&self, _: usize) -> Block {
        unreachable!("compact CSS has no wire digests")
    }
    fn correction(&self, index: usize) -> Block {
        self.block(32 + 32 * self.n + 32 * index)
    }
    fn encrypted_key(&self) -> Block {
        self.block(self.bytes.len() - 64)
    }
    fn tag(&self) -> Block {
        self.block(self.bytes.len() - 32)
    }
    fn transcript_tag(&self, context: &Block, root: &Block) -> Block {
        crypto::hash_with_tail(
            b"transcript",
            &[context, root],
            self.bytes.len(),
            [&self.bytes[..self.bytes.len() - 32], &[0; 32]],
        )
    }
}
