use serde::{Deserialize, Serialize};
use types::Policy;
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Wiawvss,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub protocol: Protocol,
    pub weights: Vec<String>,
    pub threshold: String,
    #[serde(default)]
    pub dealer: usize,
}
impl Config {
    pub fn policy(&self) -> anyhow::Result<Policy> {
        let p = Policy::from_strings(&self.weights, &self.threshold)?;
        p.validate_async()?;
        anyhow::ensure!(self.dealer < p.n(), "dealer out of range");
        Ok(p)
    }
    pub fn load(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        config.policy()?;
        Ok(config)
    }
}
