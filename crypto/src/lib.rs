//! Domain-separated, length-prefixed SHAKE256 and 256-bit hash commitments.
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use subtle::ConstantTimeEq;
pub type Block = [u8; 32];

pub fn expand(domain: &[u8], parts: &[&[u8]], len: usize) -> Vec<u8> {
    let mut output = vec![0; len];
    expand_into(domain, parts, &mut output);
    output
}
/// Identical framing to expand(), with caller-owned output storage.
pub fn expand_into(domain: &[u8], parts: &[&[u8]], output: &mut [u8]) {
    let mut h = prefix(domain, output.len(), parts.len());
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.finalize_xof().read(output);
}
fn prefix(domain: &[u8], len: usize, parts: usize) -> Shake256 {
    let mut h = Shake256::default();
    h.update(b"hashwc/v1\0");
    h.update(&(domain.len() as u64).to_le_bytes());
    h.update(domain);
    h.update(&(len as u64).to_le_bytes());
    h.update(&(parts as u64).to_le_bytes());
    h
}
pub fn hash(domain: &[u8], parts: &[&[u8]]) -> Block {
    let mut output = [0; 32];
    expand_into(domain, parts, &mut output);
    output
}
/// Hash a final, length-prefixed part without materializing its concatenation.
pub fn hash_with_tail<'a>(
    domain: &[u8],
    parts: &[&[u8]],
    tail_len: usize,
    tail: impl IntoIterator<Item = &'a [u8]>,
) -> Block {
    let mut h = prefix(domain, 32, parts.len() + 1);
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    h.update(&(tail_len as u64).to_le_bytes());
    let mut seen = 0;
    for chunk in tail {
        h.update(chunk);
        seen += chunk.len();
    }
    assert_eq!(seen, tail_len, "canonical hash part length");
    let mut output = [0; 32];
    h.finalize_xof().read(&mut output);
    output
}
pub fn equal(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}
pub fn xor(a: &Block, b: &Block) -> Block {
    std::array::from_fn(|i| a[i] ^ b[i])
}
pub fn random() -> Result<Block, getrandom::Error> {
    let mut b = [0; 32];
    getrandom::fill(&mut b)?;
    Ok(b)
}

pub fn input_commitment(context: &Block, party: usize, token: &Block) -> Block {
    hash(b"input", &[context, &(party as u64).to_le_bytes(), token])
}
pub fn wire_commitment(context: &Block, wire: usize, token: &Block) -> Block {
    hash(b"wire", &[context, &(wire as u64).to_le_bytes(), token])
}
pub fn edge_pad(
    context: &Block,
    wire: usize,
    branch: usize,
    source: usize,
    token: &Block,
) -> Block {
    hash(
        b"pad",
        &[
            context,
            &(wire as u64).to_le_bytes(),
            &(branch as u64).to_le_bytes(),
            &(source as u64).to_le_bytes(),
            token,
        ],
    )
}
