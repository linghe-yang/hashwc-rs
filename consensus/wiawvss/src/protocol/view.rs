//! Borrowed canonical public fields. No wire/gate vectors or bulk copies.
use super::{
    certified::Layout,
    terminal::{self, SemanticFields},
};
use crate::{Context, Opening, Public, ax};
use crypto::Block;
use types::{Error, Result};
use wcss::Setup;

#[derive(Clone, Debug)]
pub struct PublicView<'a> {
    pub bytes: &'a [u8],
    pub layout: Layout,
}
impl<'a> PublicView<'a> {
    pub fn decode(setup: &Setup, context: &Context, bytes: &'a [u8]) -> Result<Self> {
        let view = Self {
            bytes,
            layout: Layout::new(setup),
        };
        view.validate(setup, context)?;
        Ok(view)
    }
    pub fn field<const N: usize>(&self, offset: usize) -> [u8; N] {
        self.bytes[offset..offset + N]
            .try_into()
            .expect("validated public layout")
    }
}
impl SemanticFields for PublicView<'_> {
    fn true_token(&self) -> Block {
        self.field(72)
    }
    fn input(&self, party: usize) -> Block {
        self.field(self.layout.input(party))
    }
    fn wire(&self, wire: usize) -> Block {
        self.field(self.layout.wire(wire))
    }
    fn gate(&self, gate: usize, branch: usize) -> Block {
        self.field(self.layout.gate(gate, branch))
    }
}
/// A complete public transcript, as owned fields or a borrowed canonical view.
pub trait RecoveryPublic: SemanticFields {
    fn validate(&self, setup: &Setup, context: &Context) -> Result<()>;
    fn candidate(&self, context: &Context, output: usize, token: &Block) -> Opening;
    fn matches_public(&self, expected: &Public) -> bool;
    fn verify_opening(&self, setup: &Setup, context: &Context, opening: &Opening) -> bool {
        self.validate(setup, context).is_ok()
            && ax::generate(setup, context, opening).is_ok_and(|(p, _)| self.matches_public(&p))
    }
}
impl RecoveryPublic for Public {
    fn validate(&self, setup: &Setup, context: &Context) -> Result<()> {
        self.validate(setup, context)
    }
    fn candidate(&self, context: &Context, output: usize, token: &Block) -> Opening {
        terminal::candidate(context, self, output, token)
    }
    fn matches_public(&self, expected: &Public) -> bool {
        expected.same_encoding(self)
    }
}
impl RecoveryPublic for PublicView<'_> {
    fn validate(&self, setup: &Setup, context: &Context) -> Result<()> {
        context.validate(setup)?;
        let expected = Layout::new(setup);
        if self.bytes.len() != expected.bytes
            || self.layout.n != expected.n
            || self.layout.nodes != expected.nodes
            || self.layout.gates != expected.gates
            || self.layout.bytes != expected.bytes
            || self.bytes[..72] != Layout::prefix(setup, context)
        {
            return Err(Error::Encoding);
        }
        Ok(())
    }
    fn candidate(&self, context: &Context, output: usize, token: &Block) -> Opening {
        terminal::candidate_fields(
            context,
            output,
            token,
            &self.field(self.layout.key()),
            &self.field(self.layout.cipher()),
            &self.field(self.layout.cipher() + 32),
        )
    }
    fn matches_public(&self, expected: &Public) -> bool {
        expected.matches_encoded(self.bytes)
    }
}
