//! Reuse the external node format verbatim. Coin options are a separate protocol parameter file.
use anyhow::{Result, ensure};
pub use sdc_config::Node;
use std::{collections::BTreeSet, net::SocketAddr};
pub const SERVICE_COUNT: usize = 7;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Service {
    Rbc = 0,
    Ra = 1,
    Gather = 2,
    BinAa = 3,
    Private = 4,
    Recovery = 5,
    Avid = 6,
}
impl Service {
    pub const ALL: [Self; 7] = [
        Self::Rbc,
        Self::Ra,
        Self::Gather,
        Self::BinAa,
        Self::Private,
        Self::Recovery,
        Self::Avid,
    ];
}
#[derive(Clone, Debug)]
pub struct Ports {
    pub stride: u16,
}
impl Ports {
    pub fn new(node: &Node, stride: Option<u16>) -> Result<Self> {
        node.validate_weighted()?;
        let stride = stride.unwrap_or(u16::try_from(node.num_nodes)?);
        ensure!(stride > 0, "port stride must be positive");
        let plan = Self { stride };
        let mut seen = BTreeSet::new();
        for service in Service::ALL {
            let config = plan.node(node, service)?;
            for id in 0..node.num_nodes {
                let addr: SocketAddr = config.net_map[&id].parse()?;
                ensure!(
                    addr.is_ipv4() && !addr.ip().is_unspecified() && addr.port() != 0,
                    "net_map requires explicit IPv4 peer endpoints with nonzero ports"
                );
                // The upstream listener binds 0.0.0.0; loopback aliases share a host.
                let ip = if addr.ip().is_loopback() {
                    "127.0.0.1".parse().unwrap()
                } else {
                    addr.ip()
                };
                ensure!(
                    seen.insert((ip, addr.port())),
                    "duplicate protocol endpoint {addr}: choose a larger port stride"
                );
            }
        }
        Ok(plan)
    }
    pub fn stride(&self) -> u16 {
        self.stride
    }
    pub fn node(&self, node: &Node, service: Service) -> Result<Node> {
        let offset = self
            .stride
            .checked_mul(service as u16)
            .ok_or_else(|| anyhow::anyhow!("protocol port offset overflow"))?;
        Ok(node.with_protocol_port_offset(offset)?)
    }
}
pub fn load(path: impl AsRef<std::path::Path>) -> Result<Node> {
    let node: Node = serde_json::from_slice(&std::fs::read(path)?)?;
    node.validate_weighted()?;
    Ok(node)
}
pub fn policy(node: &Node) -> Result<types::Policy> {
    let membership = node.weighted_membership()?;
    Ok(types::Policy::from_strings(
        &membership
            .weights
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        &membership.threshold.to_string(),
    )?)
}
