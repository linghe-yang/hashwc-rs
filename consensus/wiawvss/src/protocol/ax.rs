use crypto::{Block, equal, hash, random, xor};
use types::{Error, Instance, Result};
use wcss::Setup;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAGIC: &[u8; 8] = b"HWAX0001";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub instance: Instance,
    pub associated_data: Vec<u8>,
    pub id: Block,
}
impl Context {
    pub fn new(setup: &Setup, instance: Instance, associated_data: Vec<u8>) -> Result<Self> {
        if instance.dealer >= setup.circuit().policy().n() {
            return Err(Error::Parameters("dealer out of range"));
        }
        if associated_data.len() > 65536 {
            return Err(Error::ResourceLimit("associated data"));
        }
        let id = hash(
            b"context",
            &[&setup.id(), &instance.encode(), &associated_data],
        );
        Ok(Self {
            instance,
            associated_data,
            id,
        })
    }
    pub fn id(&self) -> Block {
        self.id
    }
    pub fn instance(&self) -> &Instance {
        &self.instance
    }
    pub fn associated_data(&self) -> &[u8] {
        &self.associated_data
    }
    pub fn validate(&self, setup: &Setup) -> Result<()> {
        if self.instance.dealer >= setup.circuit().policy().n()
            || self.associated_data.len() > 65536
            || hash(
                b"context",
                &[&setup.id(), &self.instance.encode(), &self.associated_data],
            ) != self.id
        {
            return Err(Error::Parameters("context/setup mismatch"));
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrivateShare {
    pub setup_id: Block,
    pub context_id: Block,
    pub party: usize,
    pub token: Block,
}
impl std::fmt::Debug for PrivateShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateShare")
            .field("party", &self.party)
            .finish_non_exhaustive()
    }
}
impl PrivateShare {
    pub const ENCODED_LEN: usize = 104;
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(Vec::with_capacity(Self::ENCODED_LEN));
        b.extend_from_slice(&self.setup_id);
        b.extend_from_slice(&self.context_id);
        b.extend_from_slice(&(self.party as u64).to_le_bytes());
        b.extend_from_slice(&self.token);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != Self::ENCODED_LEN {
            return Err(Error::Encoding);
        }
        Ok(Self {
            setup_id: b[..32].try_into().unwrap(),
            context_id: b[32..64].try_into().unwrap(),
            party: usize::try_from(u64::from_le_bytes(b[64..72].try_into().unwrap()))
                .map_err(|_| Error::Encoding)?,
            token: b[72..].try_into().unwrap(),
        })
    }
}
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct Opening {
    pub message: Block,
    pub randomness: Block,
}
impl std::fmt::Debug for Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Opening([REDACTED])")
    }
}
#[derive(Debug)]
pub struct Recovery {
    pub opening: Opening,
    pub shares: Vec<PrivateShare>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub setup_id: Block,
    pub context_id: Block,
    pub base: wcss::Public,
    pub ciphertext: Block,
    pub randomness_ciphertext: Block,
    pub commitment: [u8; 64],
}
impl Public {
    pub fn encoded_len(setup: &Setup) -> usize {
        200 + wcss::Public::encoded_len(setup)
    }
    pub fn byte_len(&self) -> usize {
        200 + self.base.byte_len()
    }
    pub fn encoded_parts(&self) -> impl Iterator<Item = &[u8]> {
        [
            MAGIC.as_slice(),
            self.setup_id.as_slice(),
            self.context_id.as_slice(),
        ]
        .into_iter()
        .chain(self.base.encoded_parts(&self.base.tag))
        .chain([
            self.ciphertext.as_slice(),
            self.randomness_ciphertext.as_slice(),
            self.commitment.as_slice(),
        ])
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.byte_len());
        for part in self.encoded_parts() {
            b.extend_from_slice(part);
        }
        b
    }
    /// Compare canonical bytes without allocating another bulk buffer.
    pub fn matches_encoded(&self, bytes: &[u8]) -> bool {
        if bytes.len() != self.byte_len() {
            return false;
        }
        let mut offset = 0;
        self.encoded_parts().fold(true, |same, part| {
            let end = offset + part.len();
            let matched = equal(part, &bytes[offset..end]);
            offset = end;
            same & matched
        })
    }
    pub fn same_encoding(&self, other: &Self) -> bool {
        if self.base.inputs.len() != other.base.inputs.len()
            || self.base.wires.len() != other.base.wires.len()
            || self.base.gates.len() != other.base.gates.len()
        {
            return false;
        }
        self.encoded_parts()
            .zip(other.encoded_parts())
            .fold(true, |same, (a, b)| same & equal(a, b))
    }
    pub fn decode(setup: &Setup, context: &Context, b: &[u8]) -> Result<Self> {
        if b.len() != Self::encoded_len(setup)
            || &b[..8] != MAGIC
            || b[8..40] != setup.id()
            || b[40..72] != context.id
        {
            return Err(Error::Encoding);
        }
        context.validate(setup)?;
        let end = 72 + wcss::Public::encoded_len(setup);
        Ok(Self {
            setup_id: setup.id(),
            context_id: context.id,
            base: wcss::Public::decode(setup, &b[72..end])?,
            ciphertext: b[end..end + 32].try_into().unwrap(),
            randomness_ciphertext: b[end + 32..end + 64].try_into().unwrap(),
            commitment: b[end + 64..].try_into().unwrap(),
        })
    }
    pub fn digest(&self) -> Block {
        crypto::hash_with_tail(b"public", &[], self.byte_len(), self.encoded_parts())
    }
    fn validate(&self, setup: &Setup, context: &Context) -> Result<()> {
        context.validate(setup)?;
        if self.setup_id != setup.id()
            || self.context_id != context.id
            || !self.base.valid_shape(setup)
        {
            return Err(Error::InvalidCommitment);
        }
        Ok(())
    }
}
/// Messages use canonical big-endian p25519 encodings. The shared AX key uses all 256 bits.
pub fn canonical_message(m: &Block) -> bool {
    let mut modulus = [255u8; 32];
    modulus[0] = 127;
    modulus[31] = 237;
    m < &modulus
}
fn derive(context: &Context, opening: &Opening) -> ([u8; 64], Zeroizing<Block>, Zeroizing<Block>) {
    let mut material = Zeroizing::new([0; 128]);
    crypto::expand_into(
        b"AX/derive",
        &[&context.id, &opening.message, &opening.randomness],
        &mut *material,
    );
    (
        material[..64].try_into().unwrap(),
        Zeroizing::new(material[64..96].try_into().unwrap()),
        Zeroizing::new(material[96..].try_into().unwrap()),
    )
}
fn mask(key: &Block, label: &[u8]) -> Block {
    hash(b"AX/mask", &[key, label])
}
/// Explicit randomness supports reproducible research and full share regeneration.
/// Production callers should use share(), which samples fresh OS randomness.
pub fn generate(
    setup: &Setup,
    context: &Context,
    opening: &Opening,
) -> Result<(Public, Vec<PrivateShare>)> {
    context.validate(setup)?;
    if !canonical_message(&opening.message) {
        return Err(Error::Parameters("noncanonical p25519 message"));
    }
    let (commitment, key, seed) = derive(context, opening);
    let (base, tokens) = wcss::share(setup, &context.id, &key, &seed);
    let shares = tokens
        .iter()
        .enumerate()
        .map(|(party, &token)| PrivateShare {
            setup_id: setup.id(),
            context_id: context.id,
            party,
            token,
        })
        .collect();
    Ok((
        Public {
            setup_id: setup.id(),
            context_id: context.id,
            base,
            ciphertext: xor(&opening.message, &mask(&key, b"msg")),
            randomness_ciphertext: xor(&opening.randomness, &mask(&key, b"rnd")),
            commitment,
        },
        shares,
    ))
}
pub fn share(
    setup: &Setup,
    context: &Context,
    message: Block,
) -> Result<(Public, Vec<PrivateShare>)> {
    generate(
        setup,
        context,
        &Opening {
            message,
            randomness: random().map_err(|_| Error::Randomness)?,
        },
    )
}
pub fn verify_share(
    setup: &Setup,
    context: &Context,
    public: &Public,
    share: &PrivateShare,
) -> bool {
    public.validate(setup, context).is_ok()
        && share.setup_id == setup.id()
        && share.context_id == context.id
        && wcss::verify_input(setup, &context.id, &public.base, share.party, &share.token)
}
/// Public success verification compares EVERY committed field, including absent inputs.
pub fn verify_opening(
    setup: &Setup,
    context: &Context,
    public: &Public,
    opening: &Opening,
) -> bool {
    if public.validate(setup, context).is_err() {
        return false;
    }
    generate(setup, context, opening).is_ok_and(|(expected, _)| expected.same_encoding(public))
}
pub fn reconstruct(
    setup: &Setup,
    context: &Context,
    public: &Public,
    shares: &[PrivateShare],
) -> Result<Recovery> {
    public.validate(setup, context)?;
    let accepted = Zeroizing::new(
        shares
            .iter()
            .filter(|s| verify_share(setup, context, public, s))
            .map(|s| (s.party, s.token))
            .collect::<Vec<_>>(),
    );
    let key = Zeroizing::new(wcss::reconstruct(
        setup,
        &context.id,
        &public.base,
        &accepted,
    )?);
    let opening = Opening {
        message: xor(&public.ciphertext, &mask(&key, b"msg")),
        randomness: xor(&public.randomness_ciphertext, &mask(&key, b"rnd")),
    };
    let (j, expected_key, _) = derive(context, &opening);
    if !equal(&j, &public.commitment)
        || !equal(&*key, &*expected_key)
        || !canonical_message(&opening.message)
    {
        return Err(Error::InvalidCommitment);
    }
    let (expected, all_shares) = generate(setup, context, &opening)?;
    if !equal(&expected.encode(), &public.encode()) {
        return Err(Error::InvalidCommitment);
    }
    for &(party, token) in accepted.iter() {
        if !equal(&token, &all_shares[party].token) {
            return Err(Error::InvalidCommitment);
        }
    }
    Ok(Recovery {
        opening,
        shares: all_shares,
    })
}
