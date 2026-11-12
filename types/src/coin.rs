//! Fixed-width public random words. Arithmetic is in Z/(2^bits), not a prime field.
use crate::{Error, Result};
pub use crypto_bigint::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Coin {
    pub bits: u32,
    pub value: U256,
}
impl Coin {
    pub fn new(bits: u32, value: U256) -> Result<Self> {
        let coin = Self { bits, value };
        coin.validate()?;
        Ok(coin)
    }
    pub fn validate(&self) -> Result<()> {
        if !(1..=256).contains(&self.bits) || self.value.bits() > self.bits {
            return Err(Error::Parameters("coin must fit its declared bit width"));
        }
        Ok(())
    }
    pub fn from_be_bytes(bits: u32, bytes: [u8; 32]) -> Result<Self> {
        Self::new(bits, U256::from_be_slice(&bytes))
    }
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.value
            .to_be_bytes()
            .as_ref()
            .try_into()
            .expect("U256 width")
    }
    /// Bit zero is the least significant bit. Any fixed bit yields a binary coin.
    pub fn bit(&self, index: u32) -> Result<u8> {
        self.validate()?;
        if index >= self.bits {
            return Err(Error::Parameters("coin bit index"));
        }
        Ok(u8::from(self.value.bit_vartime(index)))
    }
    pub fn truncate(&self, bits: u32) -> Result<Self> {
        self.validate()?;
        if bits == 0 || bits > self.bits {
            return Err(Error::Parameters("coin truncation width"));
        }
        Self::new(bits, self.value & U256::MAX.unbounded_shr(256 - bits))
    }
    fn same_width(&self, other: &Self) -> Result<()> {
        self.validate()?;
        other.validate()?;
        if self.bits != other.bits {
            return Err(Error::Parameters("coin width mismatch"));
        }
        Ok(())
    }
    pub fn add_mod(&self, other: &Self) -> Result<Self> {
        self.same_width(other)?;
        Self::new(256, self.value.wrapping_add(&other.value))?.truncate(self.bits)
    }
    pub fn sub_mod(&self, other: &Self) -> Result<Self> {
        self.same_width(other)?;
        Self::new(256, self.value.wrapping_sub(&other.value))?.truncate(self.bits)
    }
    pub fn mul_mod(&self, other: &Self) -> Result<Self> {
        self.same_width(other)?;
        Self::new(256, self.value.wrapping_mul(&other.value))?.truncate(self.bits)
    }
    pub fn to_hex(&self) -> String {
        let full = format!("{:064x}", self.value);
        let digits = self.bits.clamp(1, 256).div_ceil(4) as usize;
        format!("0x{}", &full[64 - digits..])
    }
    pub fn from_hex(bits: u32, hex: &str) -> Result<Self> {
        if !(1..=256).contains(&bits)
            || hex.len() != 2 + bits.div_ceil(4) as usize
            || !hex.starts_with("0x")
        {
            return Err(Error::Encoding);
        }
        let mut bytes = [0u8; 32];
        let digits = hex.as_bytes().get(2..).ok_or(Error::Encoding)?;
        for (i, &digit) in digits.iter().rev().enumerate() {
            let value = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                _ => return Err(Error::Encoding),
            };
            bytes[31 - i / 2] |= value << (4 * (i % 2));
        }
        Self::from_be_bytes(bits, bytes)
    }
}
impl std::fmt::Display for Coin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Encoding {
    pub bits: u32,
    pub hex: String,
}
impl Serialize for Coin {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        Encoding {
            bits: self.bits,
            hex: self.to_hex(),
        }
        .serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Coin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let encoded = Encoding::deserialize(deserializer)?;
        Self::from_hex(encoded.bits, &encoded.hex).map_err(serde::de::Error::custom)
    }
}
