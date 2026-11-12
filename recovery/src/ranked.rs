//! Canonical colex ranking of a public-quota subset, padded to fixed 64 B blocks.
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use num_traits::{One, Zero};

pub const BLOCK_BYTES: usize = 64;
pub type Block = [[u8; 32]; 2];

pub fn binomial(n: usize, k: usize) -> BigUint {
    if k > n {
        return BigUint::zero();
    }
    let k = k.min(n - k);
    let mut value = BigUint::one();
    for j in 1..=k {
        value = value * (n - k + j) / j;
    }
    value
}

#[derive(Clone, Debug)]
pub struct Codec {
    n: usize,
    d: usize,
    possibilities: BigUint,
    rank_bytes: usize,
}
impl Codec {
    pub fn new(n: usize, d: usize) -> Result<Self> {
        ensure!((1..=4096).contains(&n) && d <= n, "ranked-list dimensions");
        let possibilities = binomial(n, d);
        let rank_bytes = (&possibilities - BigUint::one()).bits().div_ceil(8) as usize;
        Ok(Self {
            n,
            d,
            possibilities,
            rank_bytes,
        })
    }
    pub fn rank_bytes(&self) -> usize {
        self.rank_bytes
    }
    pub fn blocks(&self) -> usize {
        (32 + self.rank_bytes).div_ceil(BLOCK_BYTES)
    }
    pub fn encoded_len(&self) -> usize {
        self.blocks() * BLOCK_BYTES
    }
    pub fn encode(&self, context: [u8; 32], list: &[usize]) -> Result<Vec<u8>> {
        ensure!(
            list.len() == self.d
                && list.iter().all(|&x| x < self.n)
                && list.windows(2).all(|p| p[0] < p[1]),
            "noncanonical ranked list"
        );
        let rank: BigUint = list
            .iter()
            .enumerate()
            .map(|(j, &x)| binomial(x, j + 1))
            .sum();
        ensure!(rank < self.possibilities, "rank out of range");
        let mut out = vec![0; self.encoded_len()];
        out[..32].copy_from_slice(&context);
        if self.rank_bytes != 0 {
            let raw = rank.to_bytes_le();
            out[32..32 + raw.len()].copy_from_slice(&raw);
        }
        Ok(out)
    }
    pub fn decode(&self, context: [u8; 32], bytes: &[u8]) -> Result<Vec<usize>> {
        ensure!(bytes.len() == self.encoded_len(), "ranked-list length");
        ensure!(
            bytes[..32] == context && bytes[32 + self.rank_bytes..].iter().all(|&b| b == 0),
            "ranked-list context/padding"
        );
        let mut rank = BigUint::from_bytes_le(&bytes[32..32 + self.rank_bytes]);
        ensure!(rank < self.possibilities, "rank out of range");
        let mut out = vec![0; self.d];
        let mut upper = self.n - 1;
        for j in (1..=self.d).rev() {
            let (mut lo, mut hi) = (j - 1, upper);
            while lo < hi {
                let mid = lo + (hi - lo).div_ceil(2);
                if binomial(mid, j) <= rank {
                    lo = mid;
                } else {
                    hi = mid - 1;
                }
            }
            out[j - 1] = lo;
            rank -= binomial(lo, j);
            upper = lo.saturating_sub(1);
        }
        ensure!(rank.is_zero(), "noncanonical rank");
        Ok(out)
    }
}

pub fn split(bytes: &[u8]) -> Result<Vec<Block>> {
    ensure!(
        !bytes.is_empty() && bytes.len() % BLOCK_BYTES == 0,
        "list chunk length"
    );
    Ok(bytes
        .chunks_exact(BLOCK_BYTES)
        .map(|b| [b[..32].try_into().unwrap(), b[32..].try_into().unwrap()])
        .collect())
}
pub fn join(blocks: impl IntoIterator<Item = Block>) -> Vec<u8> {
    blocks
        .into_iter()
        .flat_map(|b| b.into_iter().flatten())
        .collect()
}
