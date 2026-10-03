use anyhow::{Result, ensure};
use commoncoin::Coin;
use num_bigint::BigUint;
use std::collections::{BTreeMap, BTreeSet};

/// Benchmark control state only. Thresholds always count distinct identities by weight.
pub struct State {
    pub output_bits: u32,
    pub weights: Vec<BigUint>,
    pub total: BigUint,
    pub threshold: BigUint,
    pub prepared: BTreeSet<usize>,
    pub prepared_weight: BigUint,
    pub finishes: BTreeMap<usize, Coin>,
    pub finish_weights: BTreeMap<Coin, BigUint>,
    pub started: bool,
    pub result: Option<Coin>,
}
impl State {
    pub fn new(weights: Vec<BigUint>, threshold: BigUint, output_bits: u32) -> Result<Self> {
        ensure!((1..=256).contains(&output_bits), "invalid output_bits");
        let total: BigUint = weights.iter().sum();
        ensure!(
            !weights.is_empty() && weights.iter().all(|w| *w > BigUint::ZERO),
            "positive weights required"
        );
        ensure!(
            threshold > BigUint::ZERO && &threshold * 3u8 <= total,
            "require 0 < T <= W/3"
        );
        Ok(Self {
            output_bits,
            weights,
            total,
            threshold,
            prepared: BTreeSet::new(),
            prepared_weight: BigUint::ZERO,
            finishes: BTreeMap::new(),
            finish_weights: BTreeMap::new(),
            started: false,
            result: None,
        })
    }
    pub fn prepare(&mut self, party: usize) -> Result<bool> {
        ensure!(party < self.weights.len(), "unknown party");
        if self.result.is_some() || !self.prepared.insert(party) {
            return Ok(false);
        }
        self.prepared_weight += &self.weights[party];
        if !self.started && self.prepared_weight > &self.total - &self.threshold {
            self.started = true;
            return Ok(true);
        }
        Ok(false)
    }
    pub fn finish(&mut self, party: usize, coin: Coin) -> Result<bool> {
        coin.validate()?;
        ensure!(
            party < self.weights.len() && coin.bits == self.output_bits,
            "invalid FINISH width/party"
        );
        ensure!(
            self.started && self.prepared.contains(&party),
            "FINISH before preparation/start"
        );
        if self.result.is_some() || self.finishes.contains_key(&party) {
            return Ok(false);
        }
        self.finishes.insert(party, coin);
        let weight = self.finish_weights.entry(coin).or_default();
        *weight += &self.weights[party];
        if *weight > self.threshold {
            self.result = Some(coin);
            return Ok(true);
        }
        Ok(false)
    }
}
