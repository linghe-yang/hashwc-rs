//! Read-only application-service observations for all-honest single-coin runs.
//! This is not a distributed termination detector or a protocol decision.
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct ServiceProgress {
    pub schema_version: u32,
    pub output_observed: bool,
    pub all_honest_services_complete: bool,
    pub pending: BTreeMap<&'static str, usize>,
}
impl ServiceProgress {
    pub fn new(output: bool, pending: BTreeMap<&'static str, usize>) -> Self {
        let complete = output && pending.values().all(|&n| n == 0);
        Self {
            schema_version: 1,
            output_observed: output,
            all_honest_services_complete: complete,
            pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_or_quiet_transport_does_not_clear_application_work() {
        assert!(!ServiceProgress::new(false, BTreeMap::new()).all_honest_services_complete);
        let pending = [("late_receipt", 1)].iter().copied().collect();
        assert!(!ServiceProgress::new(true, pending).all_honest_services_complete);
        assert!(
            ServiceProgress::new(true, [("late_receipt", 0)].iter().copied().collect())
                .all_honest_services_complete
        );
    }
}


/// Optional, process-local counters for single-coin experiments.
pub mod bulk_audit {
    use std::collections::BTreeMap;
    use std::sync::{LazyLock, Mutex, OnceLock};
    type Rows = BTreeMap<(usize, &'static str), u64>;
    static COUNTERS: LazyLock<Mutex<Rows>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));
    pub fn enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| std::env::var("COIN_BULK_AUDIT").as_deref() == Ok("1"))
    }
    pub fn add(dealer: usize, field: &'static str, value: usize) {
        if enabled() {
            *COUNTERS.lock().unwrap().entry((dealer, field)).or_default() += value as u64;
        }
    }
    pub fn snapshot() -> Vec<(usize, &'static str, u64)> {
        COUNTERS.lock().unwrap().iter().map(|(&(d,k), &v)| (d,k,v)).collect()
    }
}
