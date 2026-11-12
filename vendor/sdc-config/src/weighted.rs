use crate::{Node, ParseError};
use crypto::hash::{do_hash, Hash};
use types::{Weight, WeightedMembership};
impl Node {
    pub fn participant_weights(&self) -> Vec<Weight> {
        if self.weights.is_empty() {
            vec![Weight::from(1); self.num_nodes]
        } else {
            self.weights.clone()
        }
    }
    pub fn validate_weights(&self) -> Result<(), ParseError> {
        let weights = self.participant_weights();
        if self.num_nodes == 0
            || weights.len() != self.num_nodes
            || weights.iter().any(|w| w.0 == 0u8.into())
        {
            return Err(ParseError::Weighted(
                "provide one strictly positive integer weight per physical participant".into(),
            ));
        }
        Ok(())
    }
    /// All legacy public protocol entry points call this before binding sockets.
    pub fn validate_unweighted(&self) -> Result<(), ParseError> {
        self.validate_weights()?;
        if self.participant_weights().iter().any(|w| w.0 != 1u8.into()) {
            return Err(ParseError::Weighted(
                "legacy protocol requires every participant weight to be exactly 1".into(),
            ));
        }
        Ok(())
    }
    pub fn weighted_membership(&self) -> Result<WeightedMembership, ParseError> {
        self.validate_weights()?;
        let threshold = self.weight_threshold.clone().ok_or_else(|| {
            ParseError::Weighted(
                "weighted protocol requires weight_threshold (exclusive bound T)".into(),
            )
        })?;
        WeightedMembership::new(self.participant_weights(), threshold).map_err(ParseError::Weighted)
    }
    pub fn validate_weighted(&self) -> Result<(), ParseError> {
        self.weighted_membership()?;
        if self.num_nodes > 4096 || self.id >= self.num_nodes || self.session_id == [0; 32] {
            return Err(ParseError::Weighted(
                "at most 4096 participants, valid local ID and nonzero shared session_id required"
                    .into(),
            ));
        }
        for id in 0..self.num_nodes {
            if !self.net_map.contains_key(&id)
                || self
                    .sk_map
                    .get(&id)
                    .map_or(true, |k| k.len() != crypto::SECRET_KEY_SIZE)
            {
                return Err(ParseError::Weighted(
                    "missing participant endpoint or pairwise MAC key".into(),
                ));
            }
            self.net_map[&id]
                .parse::<std::net::SocketAddr>()
                .map_err(|_| ParseError::Weighted("invalid participant endpoint".into()))?;
        }
        Ok(())
    }
    /// Allocate a separate physical port range when composing protocol services.
    /// Membership, keys, session identity, and the optional synchronizer endpoint stay unchanged.
    pub fn with_protocol_port_offset(&self, offset: u16) -> Result<Self, ParseError> {
        let mut config = self.clone();
        for id in 0..self.num_nodes {
            let address = self
                .net_map
                .get(&id)
                .ok_or_else(|| ParseError::Weighted("missing participant endpoint".into()))?;
            let mut address: std::net::SocketAddr = address
                .parse()
                .map_err(|_| ParseError::Weighted("invalid participant endpoint".into()))?;
            let port = address.port().checked_add(offset).ok_or_else(|| {
                ParseError::Weighted("protocol port offset overflows 65535".into())
            })?;
            address.set_port(port);
            config.net_map.insert(id, address.to_string());
        }
        Ok(config)
    }
    pub fn weighted_public_id(&self, component: &str) -> Hash {
        // Identity order is canonical. Private keys and the extra synchronizer entry are excluded.

        do_hash(
            &bincode::serialize(&(
                "weighted-protocols/v1",
                component,
                self.session_id,
                self.participant_weights(),
                &self.weight_threshold,
            ))
            .expect("public config serialization"),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_weights_are_exactly_one() {
        let mut n = Node::new();
        n.num_nodes = 4;
        assert!(n.validate_unweighted().is_ok());
        n.weights = vec![Weight::from(3); 4];
        assert!(n.validate_unweighted().is_err());
        n.weight_threshold = Some(Weight::from(4));
        assert!(n.weighted_membership().is_ok());
        n.weights = vec![Weight::from(1); 4];
        assert!(n.weighted_membership().is_err());
    }
}
