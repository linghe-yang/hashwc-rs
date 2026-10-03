//! Independent local recovery sampling. Only RBC-delivered declarations authorize work.
use anyhow::{Result, ensure};
use num_bigint::{BigInt, BigUint};
use num_rational::BigRational;
use num_traits::{One, ToPrimitive, Zero};
use types::Policy;

#[derive(Clone, Debug)]
pub struct Parameters {
    pub a: usize,
    pub quotas: Vec<usize>,
    pub statistical_bits: u32,
}
// ln(x) = 2 sum z^(2j+1)/(2j+1), with an explicit positive tail bound.
fn log_ratio_upper(n: usize, d: usize) -> BigRational {
    let z = BigRational::new(BigInt::from(n - d), BigInt::from(n + d));
    let z2 = &z * &z;
    let mut power = z;
    let mut sum = BigRational::zero();
    for j in 0..64 {
        sum += &power / BigInt::from(2 * j + 1);
        power *= &z2;
    }
    (sum + power / ((BigRational::one() - z2) * BigInt::from(129))) * BigInt::from(2)
}
impl Parameters {
    pub fn new(policy: &Policy, bits: u32) -> Result<Self> {
        ensure!(
            (1..=256).contains(&bits),
            "coverage bits must be in 1..=256"
        );
        let n = policy.n();
        ensure!(n <= 4096, "sampling party limit");
        let q = n.ilog2();
        let p = 1usize << q;
        let ln2 = log_ratio_upper(2, 1);
        let x = (ln2 * BigInt::from(bits + q) + log_ratio_upper(n, p))
            * BigRational::new(3.into(), 2.into());
        let a = ((x.numer() + x.denom() - BigInt::one()) / x.denom())
            .to_usize()
            .expect("bounded logarithmic budget");
        let total = policy.total();
        let mut quotas = policy
            .weights()
            .iter()
            .map(|w| {
                ((BigUint::from(a * n) * w + total - BigUint::one()) / total)
                    .min(BigUint::from(n))
                    .to_usize()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        if policy.weights().iter().all(|w| w == &policy.weights()[0]) {
            let t = ((policy.threshold() - BigUint::one()) / &policy.weights()[0])
                .to_usize()
                .unwrap();
            let honest = n - t;
            let rhs = BigUint::from(n).pow(honest as u32);
            let d = (1..=n)
                .find(|&d| {
                    ((BigUint::from(n) * BigUint::from(n - d).pow(honest as u32)) << bits as usize)
                        <= rhs
                })
                .unwrap();
            quotas.fill(d);
        }
        Ok(Self {
            a,
            quotas,
            statistical_bits: bits,
        })
    }
    pub fn edge_bound(&self) -> usize {
        self.quotas.iter().sum()
    }
    pub fn sample(&self, party: usize) -> Result<Vec<usize>> {
        self.sample_with(party, |bytes| {
            getrandom::fill(bytes).map_err(|e| anyhow::anyhow!("randomness: {e}"))
        })
    }
    /// Injectable entropy for tests; production uses the OS CSPRNG above.
    pub fn sample_with(
        &self,
        party: usize,
        mut fill: impl FnMut(&mut [u8]) -> Result<()>,
    ) -> Result<Vec<usize>> {
        ensure!(party < self.quotas.len(), "unknown sampler");
        let n = self.quotas.len();
        let d = self.quotas[party];
        ensure!(d <= n, "invalid sampling quota");
        let mut universe: Vec<_> = (0..n).collect();
        for i in 0..d {
            let bound = (n - i) as u64;
            let rejection = bound.wrapping_neg() % bound;
            let value = loop {
                let mut b = [0; 8];
                fill(&mut b)?;
                let v = u64::from_le_bytes(b);
                if v >= rejection {
                    break v % bound;
                }
            };
            universe.swap(i, i + value as usize);
        }
        universe.truncate(d);
        universe.sort_unstable();
        Ok(universe)
    }
    pub fn encoded_len(&self, party: usize) -> usize {
        32 + 4 * self.quotas[party]
    }
    pub fn encode(&self, context: [u8; 32], party: usize, list: &[usize]) -> Result<Vec<u8>> {
        ensure!(
            party < self.quotas.len() && list.len() == self.quotas[party],
            "wrong declaration quota"
        );
        ensure!(
            list.iter().all(|&x| x < self.quotas.len()) && list.windows(2).all(|p| p[0] < p[1]),
            "noncanonical assignment"
        );
        let mut out = context.to_vec();
        for &d in list {
            out.extend_from_slice(&(d as u32).to_le_bytes());
        }
        Ok(out)
    }
}
#[derive(Debug)]
pub struct Assignments {
    pub parameters: Parameters,
    pub context: [u8; 32],
    pub lists: Vec<Option<Vec<usize>>>,
}
impl Assignments {
    pub fn new(parameters: Parameters, context: [u8; 32]) -> Self {
        Self {
            lists: vec![None; parameters.quotas.len()],
            parameters,
            context,
        }
    }
    /// Caller must supply an authenticated RBC delivery. Invalid delivered lists are final too.
    pub fn deliver(&mut self, party: usize, bytes: &[u8]) -> bool {
        if party >= self.lists.len() || self.lists[party].is_some() {
            return false;
        }
        self.lists[party] = Some(vec![]);
        if bytes.len() != self.parameters.encoded_len(party) || bytes[..32] != self.context {
            return false;
        }
        let list: Vec<_> = bytes[32..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|b| u32::from_le_bytes(*b) as usize)
            .collect();
        if self.parameters.encode(self.context, party, &list).is_err() {
            return false;
        }
        self.lists[party] = Some(list);
        true
    }
    pub fn authorized(&self, party: usize, dealer: usize) -> bool {
        self.lists
            .get(party)
            .and_then(Option::as_ref)
            .is_some_and(|l| l.binary_search(&dealer).is_ok())
    }
    pub fn delivered(&self, party: usize) -> bool {
        self.lists.get(party).is_some_and(Option::is_some)
    }
}
