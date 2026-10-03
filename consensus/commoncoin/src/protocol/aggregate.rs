//! Exact dyadic aggregation: floor((ceil(sum alpha_d v_d) mod 2Delta) / Delta).
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use sdc_types::Dyadic;
pub fn aggregate(
    coefficients: &[Dyadic],
    values: &[Option<BigUint>],
    rounding_bits: u32,
) -> Result<Option<u8>> {
    ensure!(
        !coefficients.is_empty() && coefficients.len() == values.len(),
        "vector dimensions"
    );
    ensure!((1..=252).contains(&rounding_bits), "rounding bits");
    let exponent = coefficients.iter().map(|a| a.exponent).max().unwrap();
    ensure!(
        exponent <= wbinaa::protocol::MAX_ROUNDS,
        "dyadic exponent limit"
    );
    let range = BigUint::one() << (rounding_bits + 2) as usize;
    let mut sum = BigUint::zero();
    for (a, value) in coefficients.iter().zip(values) {
        let numerator = BigUint::from_bytes_be(&a.numerator.0.to_bytes_be());
        ensure!(
            numerator <= (BigUint::one() << a.exponent as usize),
            "coefficient outside [0,1]"
        );
        if numerator.is_zero() {
            continue;
        }
        let Some(value) = value else { return Ok(None) };
        ensure!(value < &range, "contribution outside coin range");
        sum += (numerator * value) << ((exponent - a.exponent) as usize);
    }
    let denominator = BigUint::one() << exponent as usize;
    let residue = ((sum + &denominator - BigUint::one()) / denominator) % range;
    Ok(Some(
        (residue >> ((rounding_bits + 1) as usize)).to_u8().unwrap(),
    ))
}
