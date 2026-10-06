//! Per-dealer recovery cache, bound to an immutable, authenticated WAVID file.
use crate::{
    Context, PrivateShare, PublicView,
    certified::{self, Certificate, Header},
    terminal::{self, SemanticFields, Terminal},
};
use anyhow::{Result, ensure};
use crypto::{Block, equal, input_commitment, wire_commitment};
use num_bigint::BigUint;
use wavid::{Codec, ValidatedFile};
use wcss::Setup;

pub struct IncrementalRecovery {
    pub file: ValidatedFile,
    pub setup_id: Block,
    pub context_id: Block,
    pub root: Block,
    pub checked: Vec<Option<Block>>,
    pub accepted: Vec<Option<PrivateShare>>,
    pub weight: BigUint,
    pub terminal: Option<Terminal>,
    pub bits: Option<usize>,
    /// Number of distinct tokens whose commitments were checked (diagnostics).
    pub token_checks: usize,
}
impl IncrementalRecovery {
    pub fn new(setup: &Setup, context: &Context, file: ValidatedFile) -> Result<Self> {
        let p = PublicView::decode(setup, context, &file)?;
        let terminal = if !equal(
            &wire_commitment(&context.id(), 1, &p.true_token()),
            &p.wire(1),
        ) {
            Some(Terminal::TrueFault)
        } else {
            None
        };
        let n = setup.circuit().policy().n();
        Ok(Self {
            root: file.root(),
            file,
            setup_id: setup.id(),
            context_id: context.id(),
            checked: vec![None; n],
            accepted: vec![None; n],
            weight: 0u8.into(),
            terminal,
            bits: None,
            token_checks: 0,
        })
    }
    pub fn recover<'a>(
        &mut self,
        setup: &Setup,
        context: &Context,
        codec: &Codec,
        header: &Header,
        shares: impl IntoIterator<Item = &'a PrivateShare>,
        bits: usize,
    ) -> Result<Option<Certificate>> {
        ensure!(
            bits <= 256 && self.bits.is_none_or(|b| b == bits),
            "recovery precision changed"
        );
        ensure!(
            self.setup_id == setup.id()
                && self.context_id == context.id()
                && self.root == self.file.root()
                && certified::file_binding(setup, context, codec, header, &self.file),
            "incremental recovery source binding"
        );
        self.bits = Some(bits);
        let p = PublicView::decode(setup, context, &self.file)?;
        let policy = setup.circuit().policy();
        if self.terminal.is_none() {
            for s in shares {
                if s.party >= policy.n()
                    || s.setup_id != self.setup_id
                    || s.context_id != self.context_id
                {
                    continue;
                }
                // Valid inputs never count twice. Cache a rejected token as well.
                if self.accepted[s.party].is_some() || self.checked[s.party] == Some(s.token) {
                    continue;
                }
                self.checked[s.party] = Some(s.token);
                self.token_checks += 1;
                if !equal(
                    &input_commitment(&context.id(), s.party, &s.token),
                    &p.input(s.party),
                ) {
                    continue;
                }
                if !equal(
                    &wire_commitment(&context.id(), s.party + 2, &s.token),
                    &p.wire(s.party + 2),
                ) {
                    self.terminal = Some(Terminal::InputFault {
                        party: s.party,
                        token: s.token,
                    });
                    break;
                }
                self.accepted[s.party] = Some(s.clone());
                self.weight += &policy.weights()[s.party];
            }
            if self.terminal.is_none() && self.weight >= *policy.threshold() {
                self.terminal = Some(terminal::evaluate(
                    setup,
                    context,
                    &p,
                    self.accepted.iter().flatten(),
                    bits,
                )?);
            }
        }
        self.terminal
            .as_ref()
            .map(|t| certified::certify(setup, codec, header, &self.file, t.clone()))
            .transpose()
    }
}

impl Drop for IncrementalRecovery {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.checked);
    }
}
