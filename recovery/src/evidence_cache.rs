//! Bounded memoization of rejected certificates, after per-sender authorization.
use crypto::Block;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct RejectedEvidence {
    // Whether the rejected bytes decoded successfully (for existing audit events).
    entries: BTreeMap<Block, bool>,
}
impl RejectedEvidence {
    /// `scope` must bind all verification parameters (normally the immutable
    /// sharing header ID). Successful results are deliberately never cached.
    pub fn check<T>(
        &mut self,
        scope: Block,
        raw: &[u8],
        limit: usize,
        verify: impl FnOnce() -> (bool, Option<T>),
    ) -> (bool, Option<T>) {
        let key = crypto::hash(b"recovery/rejected-evidence/v1", &[&scope, raw]);
        if let Some(&decoded) = self.entries.get(&key) {
            return (decoded, None);
        }
        let result = verify();
        if result.1.is_none() && self.entries.len() < limit {
            self.entries.insert(key, result.0);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn repeated_rejections_are_cached_but_scopes_successes_and_limits_remain_distinct() {
        let calls = Cell::new(0);
        let reject = || {
            calls.set(calls.get() + 1);
            (true, None::<()>)
        };
        let mut cache = RejectedEvidence::default();
        assert_eq!(cache.check([1; 32], b"proof", 2, reject), (true, None));
        assert_eq!(cache.check([1; 32], b"proof", 2, reject), (true, None));
        assert_eq!(calls.get(), 1);
        cache.check([2; 32], b"proof", 2, reject);
        assert_eq!(calls.get(), 2);
        for _ in 0..2 {
            cache.check([3; 32], b"uncached", 2, reject);
        }
        assert_eq!(calls.get(), 4);
        assert_eq!(cache.entries.len(), 2);
        for _ in 0..2 {
            assert_eq!(
                cache.check([1; 32], b"valid", 2, || {
                    calls.set(calls.get() + 1);
                    (true, Some(7))
                }),
                (true, Some(7))
            );
        }
        assert_eq!(calls.get(), 6);
        let mut malformed = RejectedEvidence::default();
        assert_eq!(
            malformed.check([1; 32], b"malformed", 1, || (false, None::<()>)),
            (false, None)
        );
        assert_eq!(
            malformed.check([1; 32], b"malformed", 1, || panic!("cached")),
            (false, None::<()>)
        );
    }
}
