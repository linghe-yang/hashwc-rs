use crate::{
    compact::{CompactMsg, MAX_PARTIES},
    ProtMsg,
};
use anyhow::Result;
use config::Node;
use types::SendAction;
use util::weighted::Endpoint;

pub(crate) enum Transport {
    Legacy(Endpoint<ProtMsg>),
    Compact(Endpoint<CompactMsg>),
}
impl Transport {
    pub fn bind(config: &Node, compact: bool) -> Result<Self> {
        if compact {
            anyhow::ensure!(
                config.num_nodes <= MAX_PARTIES,
                "compact BinAA requires at most 91 parties"
            );
            Ok(Self::Compact(Endpoint::bind_with_wire_domain(
                config,
                "wbinaa",
                "wbinaa/compact91/v1",
            )?))
        } else {
            Ok(Self::Legacy(Endpoint::bind(config, "wbinaa")?))
        }
    }
    pub async fn recv(&mut self) -> Option<(usize, ProtMsg)> {
        match self {
            Self::Legacy(e) => e.recv.recv().await,
            Self::Compact(e) => e.recv.recv().await.map(|(sender, msg)| (sender, msg.0)),
        }
    }
    pub fn send_batch(&self, actions: Vec<SendAction<ProtMsg>>) -> Result<()> {
        match self {
            Self::Legacy(e) => e.sender().send_batch(actions),
            Self::Compact(e) => e.sender().send_batch_single_pass(
                actions
                    .into_iter()
                    .map(|a| SendAction {
                        recipient: a.recipient,
                        message: CompactMsg(a.message),
                    })
                    .collect(),
            ),
        }
    }
}
