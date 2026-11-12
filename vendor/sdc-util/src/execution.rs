//! Local execution settings, identical for all sizes, weights and protocols.
//! These never enter the protocol's cryptographic parameters or decision rules.
use anyhow::{ensure, Result};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Settings {
    pub actor_inbox: usize,
    pub compute_jobs: usize,
    pub transport_receive_capacity: usize,
    pub transport_stall_ms: u64,
}
impl Settings {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }
    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        fn value(
            get: &impl Fn(&str) -> Option<String>,
            name: &str,
            default: usize,
            max: usize,
        ) -> Result<usize> {
            let n = get(name)
                .map(|v| v.parse::<usize>())
                .transpose()?
                .unwrap_or(default);
            ensure!(n > 0 && n <= max, "{} must be between 1 and {}", name, max);
            Ok(n)
        }
        Ok(Self {
            actor_inbox: value(&get, "HASHWC_ACTOR_INBOX", 4096, 65536)?,
            compute_jobs: value(&get, "HASHWC_COMPUTE_JOBS", 2, 64)?,
            transport_receive_capacity: value(&get, "HASHWC_RECEIVE_CAPACITY", 1024, 65536)?,
            transport_stall_ms: value(&get, "HASHWC_TRANSPORT_STALL_MS", 5000, 3600000)? as u64,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validated_local_settings_do_not_depend_on_party_count_or_weights() {
        let default = Settings::from_lookup(|_| None).unwrap();
        assert_eq!(default.transport_stall_ms, 5000);
        assert_eq!(default.actor_inbox, 4096);
        let tuned =
            Settings::from_lookup(|k| (k == "HASHWC_TRANSPORT_STALL_MS").then(|| "30000".into()))
                .unwrap();
        assert_eq!(tuned.transport_stall_ms, 30000);
        for invalid in ["0", "-1", "abc", "65537"] {
            assert!(
                Settings::from_lookup(|k| (k == "HASHWC_ACTOR_INBOX").then(|| invalid.into()))
                    .is_err()
            );
        }
    }
}
