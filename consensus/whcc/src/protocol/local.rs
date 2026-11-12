//! Provenance for dealer self-reuse: no constructor from a supplied Public/file.
use crate::Parameters;
use anyhow::Result;
use wcss::Setup;
use wiawvss::{
    Context, Opening, PrivateShare, ax,
    certified::{self, Certificate, Evidence, Header},
};

pub(super) struct LocalMaterial {
    header: Header,
    file: wavid::ValidatedFile,
    opening: Opening,
}
impl LocalMaterial {
    /// Generate honest AX and its canonical dispersal together. Raw test/fault
    /// material and network material cannot obtain this provenance.
    pub(super) fn generate(
        setup: &Setup,
        context: &Context,
        codec: &wavid::Codec,
        params: &Parameters,
    ) -> Result<(Self, wavid::Dispersal, Vec<PrivateShare>)> {
        let opening = Opening {
            message: params.sample_message()?,
            randomness: crypto::random().map_err(|e| anyhow::anyhow!("randomness: {e}"))?,
        };
        let (public, shares) = ax::generate(setup, context, &opening)?;
        let prepared =
            codec.prepare_dispersal(public.encode(), &certified::receipt_blocks(setup, codec))?;
        let file = prepared.file().clone();
        let header = Header::new(setup, context, file.root());
        Ok((
            Self {
                header,
                file,
                opening,
            },
            prepared,
            shares,
        ))
    }
    pub(super) fn file(&self) -> &wavid::ValidatedFile {
        &self.file
    }
    /// Caller must additionally enforce own dealer ID, K_d, Complete and Freeze.
    pub(super) fn certificate(
        &self,
        setup: &Setup,
        context: &Context,
        codec: &wavid::Codec,
        header: &Header,
    ) -> Option<Certificate> {
        (header.id() == self.header.id()
            && certified::file_binding(setup, context, codec, header, &self.file))
        .then(|| Certificate {
            header_id: header.id(),
            evidence: Evidence::Success(self.opening.clone()),
        })
    }
}
