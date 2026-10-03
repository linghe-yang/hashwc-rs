use hashwc_crypto::*;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn python_hashlib_known_answers() {
    // Independently generated with Python hashlib.shake_256 and struct.pack('<Q', ...).
    assert_eq!(
        hex(&input_commitment(&[1; 32], 2, &[3; 32])),
        "09d3a311955044052bd7e9f6f333b8dbdbf9e589260d90ec0abe1bc86af0ebcf"
    );
    assert_eq!(
        hex(&expand(b"AX/derive", &[&[1; 32], &[2; 32], &[3; 32]], 128)),
        "584cc3e12974b6c5d600fd798da986fc9a94a7e2a2eac28b85fdfe19d267ba9407da554b2a1025176c2e9011335491d94ba353b1fa7f9b97b1a11d1cbb23b33b8a6e59cd26145d64b142620421e171e5a74d5757d8ea46bd221b5902bc8ae92db4f859a1a8af71ea80d381883eaedd5243f704d5cc5310134cd666e3ecfea1a6"
    );
}
#[test]
fn domains_indices_lengths_and_tuple_boundaries_are_distinct() {
    let context = [1; 32];
    let token = [2; 32];
    let input = input_commitment(&context, 0, &token);
    assert_ne!(input, wire_commitment(&context, 0, &token));
    assert_ne!(input, input_commitment(&context, 1, &token));
    assert_ne!(input, input_commitment(&[3; 32], 0, &token));
    assert_ne!(
        wire_commitment(&context, 0, &token),
        edge_pad(&context, 0, 0, 0, &token)
    );
    assert_ne!(hash(b"test", &[b"ab", b"c"]), hash(b"test", &[b"a", b"bc"]));
    assert_ne!(
        expand(b"test", &[b"a"], 32),
        expand(b"test", &[b"a"], 64)[..32]
    );
}
