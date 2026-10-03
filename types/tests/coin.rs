use num_bigint::BigUint;
use types::{Coin, coin::U256};
#[test]
fn canonical_encoding_bit_extraction_and_json_preserve_high_bits() {
    let word = Coin::from_hex(128, "0xabcdef0123456789fedcba9876543211").unwrap();
    assert_eq!(word.to_hex(), "0xabcdef0123456789fedcba9876543211");
    assert_eq!(word.bit(0).unwrap(), 1);
    assert_eq!(word.truncate(8).unwrap().to_hex(), "0x11");
    assert_eq!(Coin::from_be_bytes(128, word.to_be_bytes()).unwrap(), word);
    assert_eq!(
        serde_json::from_str::<Coin>(&serde_json::to_string(&word).unwrap()).unwrap(),
        word
    );
    for text in ["0x20", "0x1F", "0x1", "1f", "0x001f"] {
        assert!(Coin::from_hex(5, text).is_err());
    }
    assert_eq!(Coin::from_hex(5, "0x1f").unwrap().value.bits(), 5);
    assert!(word.bit(128).is_err());
    assert!(word.truncate(129).is_err());
    assert!(Coin::new(0, U256::ZERO).is_err());
    assert!(Coin::new(257, U256::ZERO).is_err());
    assert!(serde_json::from_str::<Coin>(r#"{"bits":1,"hex":"0x2"}"#).is_err());
    assert!(
        serde_json::to_string(&Coin {
            bits: 1,
            value: U256::MAX
        })
        .is_err()
    );
}
#[test]
fn fixed_width_arithmetic_matches_arbitrary_precision_including_overflow() {
    for bits in [1, 5, 64, 128, 189, 252, 256] {
        let modulus = BigUint::from(1u8) << bits as usize;
        let a = &modulus - BigUint::from(1u8);
        let b = &modulus / BigUint::from(2u8);
        let coin = |n: &BigUint| {
            let src = n.to_bytes_be();
            let mut bytes = [0; 32];
            bytes[32 - src.len()..].copy_from_slice(&src);
            Coin::from_be_bytes(bits, bytes).unwrap()
        };
        let (x, y) = (coin(&a), coin(&b));
        assert_eq!(x.add_mod(&y).unwrap(), coin(&((&a + &b) % &modulus)));
        assert_eq!(
            y.sub_mod(&x).unwrap(),
            coin(&((&b + &modulus - &a) % &modulus))
        );
        assert_eq!(x.mul_mod(&y).unwrap(), coin(&((&a * &b) % &modulus)));
    }
    assert!(
        Coin::from_hex(1, "0x1")
            .unwrap()
            .add_mod(&Coin::from_hex(2, "0x1").unwrap())
            .is_err()
    );
}
