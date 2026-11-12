//! Exact dyadic aggregation: floor((ceil(sum alpha_d v_d) mod (2^lambda * Delta)) / Delta).
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sdc_types::Dyadic;
use types::Coin;
pub fn aggregate(
    coefficients: &[Dyadic],
    values: &[Option<BigUint>],
    rounding_bits: u32,
    output_bits: u32,
) -> Result<Option<Coin>> {
    aggregate_borrowed(
        coefficients,
        values.iter().map(Option::as_ref),
        rounding_bits,
        output_bits,
    )
}
/// Borrow dealer values in the event loop instead of cloning all large integers.
pub fn aggregate_borrowed<'a>(
    coefficients: &[Dyadic],
    values: impl ExactSizeIterator<Item = Option<&'a BigUint>>,
    rounding_bits: u32,
    output_bits: u32,
) -> Result<Option<Coin>> {
    ensure!(
        !coefficients.is_empty() && coefficients.len() == values.len(),
        "vector dimensions"
    );
    crate::Parameters::validate_widths(rounding_bits, output_bits)?;
    let exponent = coefficients.iter().map(|a| a.exponent).max().unwrap();
    ensure!(
        exponent <= wbinaa::protocol::MAX_ROUNDS,
        "dyadic exponent limit"
    );
    let range = BigUint::one() << (rounding_bits + output_bits + 1) as usize;
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
    let word = (residue >> ((rounding_bits + 1) as usize)).to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - word.len()..].copy_from_slice(&word);
    Ok(Some(Coin::from_be_bytes(output_bits, bytes)?))
}
