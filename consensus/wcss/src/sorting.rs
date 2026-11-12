//! The shared Batcher odd-even comparator schedule.
//! Missing positions are +infinity padding; callers implement a min/max comparator.
use types::{Error, Result};

pub fn odd_even_sort(
    wires: &mut [usize],
    mut comparator: impl FnMut(usize, usize) -> Result<(usize, usize)>,
) -> Result<()> {
    fn sort(
        wires: &mut [usize],
        start: usize,
        size: usize,
        comparator: &mut impl FnMut(usize, usize) -> Result<(usize, usize)>,
    ) -> Result<()> {
        if size > 1 {
            sort(wires, start, size / 2, comparator)?;
            sort(wires, start + size / 2, size / 2, comparator)?;
            merge(wires, start, size, 1, comparator)?;
        }
        Ok(())
    }
    if wires.len() > 1 {
        let width = wires
            .len()
            .checked_next_power_of_two()
            .ok_or(Error::ResourceLimit("sort width"))?;
        sort(wires, 0, width, &mut comparator)?;
    }
    Ok(())
}

fn merge(
    wires: &mut [usize],
    start: usize,
    size: usize,
    stride: usize,
    comparator: &mut impl FnMut(usize, usize) -> Result<(usize, usize)>,
) -> Result<()> {
    let double = 2 * stride;
    if double < size {
        merge(wires, start, size, double, comparator)?;
        merge(wires, start + stride, size, double, comparator)?;
        for i in (start + stride..start + size - stride).step_by(double) {
            if i + stride < wires.len() {
                (wires[i], wires[i + stride]) = comparator(wires[i], wires[i + stride])?;
            }
        }
    } else if start + stride < wires.len() {
        (wires[start], wires[start + stride]) = comparator(wires[start], wires[start + stride])?;
    }
    Ok(())
}

/// Merge two ascending lists. The maximum wire must represent the largest value
/// (true for Boolean circuits). Padding is removed from the high end.
pub fn odd_even_merge(
    left: &[usize],
    right: &[usize],
    maximum: usize,
    mut comparator: impl FnMut(usize, usize) -> Result<(usize, usize)>,
) -> Result<Vec<usize>> {
    if left.is_empty() {
        return Ok(right.to_vec());
    }
    if right.is_empty() {
        return Ok(left.to_vec());
    }
    let width = left
        .len()
        .max(right.len())
        .checked_next_power_of_two()
        .ok_or(Error::ResourceLimit("merge width"))?;
    let size = width
        .checked_mul(2)
        .ok_or(Error::ResourceLimit("merge width"))?;
    let mut refs = Vec::with_capacity(size);
    refs.extend_from_slice(left);
    refs.resize(width, maximum);
    refs.extend_from_slice(right);
    refs.resize(size, maximum);
    merge(&mut refs, 0, size, 1, &mut comparator)?;
    refs.truncate(left.len() + right.len());
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merge_handles_unequal_lengths_and_boolean_padding() {
        for a in 0..=17 {
            for b in 0..=17 {
                for ones_a in 0..=a {
                    for ones_b in 0..=b {
                        let left: Vec<_> = (0..a).map(|i| usize::from(i >= a - ones_a)).collect();
                        let right: Vec<_> = (0..b).map(|i| usize::from(i >= b - ones_b)).collect();
                        let out = odd_even_merge(&left, &right, 1, |x, y| Ok((x.min(y), x.max(y))))
                            .unwrap();
                        let expected: Vec<_> = (0..a + b)
                            .map(|i| usize::from(i >= a + b - ones_a - ones_b))
                            .collect();
                        assert_eq!(out, expected);
                    }
                }
            }
        }
    }
}
