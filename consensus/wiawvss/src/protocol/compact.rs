//! CSS+AX with full-record replication and local recovery, without PVR wire digests.
//! Canonical regeneration checks every field, including branches not used to recover.
use super::ax::{self, Context, Opening, PrivateShare, Recovery};
use crypto::{Block, equal, xor};
use types::{Error, Result};
use wcss::Setup;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"HWAC0001";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub setup_id: Block,
    pub context_id: Block,
    pub base: wcss::compact::Public,
    pub ciphertext: Block,
    pub randomness_ciphertext: Block,
    pub commitment: [u8; 64],
}
impl Public {
    pub fn encoded_len(setup: &Setup) -> usize {
        200 + wcss::compact::Public::encoded_len(setup)
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
        .chain(self.base.encoded_parts())
        .chain([
            self.ciphertext.as_slice(),
            self.randomness_ciphertext.as_slice(),
            self.commitment.as_slice(),
        ])
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.byte_len());
        for part in self.encoded_parts() {
            bytes.extend_from_slice(part);
        }
        bytes
    }
    pub fn same_encoding(&self, other: &Self) -> bool {
        self.byte_len() == other.byte_len()
            && self
                .encoded_parts()
                .zip(other.encoded_parts())
                .fold(true, |same, (a, b)| same & equal(a, b))
    }
    /// Compare every field without materializing another serialized bulk.
    pub fn matches_encoded(&self, bytes: &[u8]) -> bool {
        if bytes.len() != self.byte_len() {
            return false;
        }
        let mut offset = 0;
        self.encoded_parts().fold(true, |same, part| {
            let end = offset + part.len();
            let matches = equal(part, &bytes[offset..end]);
            offset = end;
            same & matches
        })
    }
    pub fn decode(setup: &Setup, context: &Context, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::encoded_len(setup)
            || &bytes[..8] != MAGIC
            || bytes[8..40] != setup.id()
            || bytes[40..72] != context.id
        {
            return Err(Error::Encoding);
        }
        context.validate(setup)?;
        let end = 72 + wcss::compact::Public::encoded_len(setup);
        Ok(Self {
            setup_id: setup.id(),
            context_id: context.id,
            base: wcss::compact::Public::decode(setup, &bytes[72..end])?,
            ciphertext: bytes[end..end + 32].try_into().unwrap(),
            randomness_ciphertext: bytes[end + 32..end + 64].try_into().unwrap(),
            commitment: bytes[end + 64..].try_into().unwrap(),
        })
    }
    pub fn validate(&self, setup: &Setup, context: &Context) -> Result<()> {
        context.validate(setup)?;
        if self.setup_id != setup.id()
            || self.context_id != context.id
            || !self.base.valid_shape(setup)
        {
            return Err(Error::InvalidCommitment);
        }
        Ok(())
    }
    pub fn digest(&self) -> Block {
        crypto::hash_with_tail(
            b"compact-public",
            &[],
            self.byte_len(),
            self.encoded_parts(),
        )
    }
}
pub fn generate(
    setup: &Setup,
    context: &Context,
    opening: &Opening,
) -> Result<(Public, Vec<PrivateShare>)> {
    generate_inner(setup, context, opening, true)
}
/// Complete AX regeneration for verification, omitting unused private outputs.
pub fn generate_public(setup: &Setup, context: &Context, opening: &Opening) -> Result<Public> {
    generate_inner(setup, context, opening, false).map(|(public, _)| public)
}
fn generate_inner(
    setup: &Setup,
    context: &Context,
    opening: &Opening,
    with_shares: bool,
) -> Result<(Public, Vec<PrivateShare>)> {
    let _profile = sdc_util::profile::span("ax.generate.compact");
    context.validate(setup)?;
    if !ax::canonical_message(&opening.message) {
        return Err(Error::Parameters("noncanonical p25519 message"));
    }
    let (commitment, key, seed) = ax::derive(context, opening);
    let (base, tokens) = if with_shares {
        wcss::compact::share(setup, &context.id, &key, &seed)
    } else {
        (
            wcss::compact::share_public(setup, &context.id, &key, &seed),
            Zeroizing::new(Vec::new()),
        )
    };
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
            ciphertext: xor(&opening.message, &ax::mask(&key, b"msg")),
            randomness_ciphertext: xor(&opening.randomness, &ax::mask(&key, b"rnd")),
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
            randomness: crypto::random().map_err(|_| Error::Randomness)?,
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
        && wcss::compact::verify_input(setup, &context.id, &public.base, share.party, &share.token)
}
pub fn verify_opening(
    setup: &Setup,
    context: &Context,
    public: &Public,
    opening: &Opening,
) -> bool {
    public.validate(setup, context).is_ok()
        && generate_public(setup, context, opening)
            .is_ok_and(|expected| expected.same_encoding(public))
}
/// Insufficient authenticated weight is pending; a failed full AX check is rejection.
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
    let key = Zeroizing::new(wcss::compact::reconstruct(
        setup,
        &context.id,
        &public.base,
        &accepted,
    )?);
    let opening = Opening {
        message: xor(&public.ciphertext, &ax::mask(&key, b"msg")),
        randomness: xor(&public.randomness_ciphertext, &ax::mask(&key, b"rnd")),
    };
    let (j, expected_key, _) = ax::derive(context, &opening);
    if !equal(&j, &public.commitment)
        || !equal(&*key, &*expected_key)
        || !ax::canonical_message(&opening.message)
    {
        return Err(Error::InvalidCommitment);
    }
    let (expected, all_shares) = generate(setup, context, &opening)?;
    if !expected.same_encoding(public)
        || accepted
            .iter()
            .any(|(i, token)| !equal(token, &all_shares[*i].token))
    {
        return Err(Error::InvalidCommitment);
    }
    Ok(Recovery {
        opening,
        shares: all_shares,
    })
}

/// Complete compact AX record borrowed from RBC delivery. Decoding checks the
/// context and layout once; field access never copies the bulk into gate vectors.
#[derive(Clone, Copy, Debug)]
pub struct PublicView<'a> {
    bytes: &'a [u8],
    base: wcss::compact::PublicView<'a>,
    end: usize,
    setup_id: Block,
    context_id: Block,
}
impl<'a> PublicView<'a> {
    pub fn decode(setup: &Setup, context: &Context, bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() != Public::encoded_len(setup)
            || &bytes[..8] != MAGIC
            || bytes[8..40] != setup.id()
            || bytes[40..72] != context.id
        {
            return Err(Error::Encoding);
        }
        context.validate(setup)?;
        let end = 72 + wcss::compact::Public::encoded_len(setup);
        Ok(Self {
            bytes,
            base: wcss::compact::PublicView::decode(setup, &bytes[72..end])?,
            end,
            setup_id: setup.id(),
            context_id: context.id,
        })
    }
    pub fn digest(&self) -> Block {
        crypto::hash(b"compact-public", &[self.bytes])
    }
    pub fn verify_share(&self, share: &PrivateShare) -> bool {
        share.setup_id == self.setup_id
            && share.context_id == self.context_id
            && self
                .base
                .verify_input(&self.context_id, share.party, &share.token)
    }
    pub fn reconstruct<'s>(
        &self,
        setup: &Setup,
        context: &Context,
        shares: impl IntoIterator<Item = &'s PrivateShare>,
    ) -> Result<Recovery> {
        let _profile = sdc_util::profile::span("css.recover.compact");
        context.validate(setup)?;
        if setup.id() != self.setup_id || context.id != self.context_id {
            return Err(Error::InvalidCommitment);
        }
        // Identity is checked here; CSS authenticates and deduplicates tokens
        // once and returns exactly the accepted set for the final AX comparison.
        let recovered = self.base.reconstruct(
            setup,
            &context.id,
            shares
                .into_iter()
                .filter(|s| s.setup_id == self.setup_id && s.context_id == self.context_id)
                .map(|s| (s.party, s.token)),
        )?;
        let block = |offset| {
            self.bytes[offset..offset + 32]
                .try_into()
                .expect("validated AX layout")
        };
        let opening = Opening {
            message: xor(&block(self.end), &ax::mask(&recovered.key, b"msg")),
            randomness: xor(&block(self.end + 32), &ax::mask(&recovered.key, b"rnd")),
        };
        let (commitment, expected_key, _) = ax::derive(context, &opening);
        if !equal(&commitment, &self.bytes[self.end + 64..])
            || !equal(&*recovered.key, &*expected_key)
            || !ax::canonical_message(&opening.message)
        {
            return Err(Error::InvalidCommitment);
        }
        let (expected, all_shares) = generate(setup, context, &opening)?;
        if !expected.matches_encoded(self.bytes)
            || recovered
                .inputs
                .iter()
                .any(|(i, t)| !equal(t, &all_shares[*i].token))
        {
            return Err(Error::InvalidCommitment);
        }
        Ok(Recovery {
            opening,
            shares: all_shares,
        })
    }
}
