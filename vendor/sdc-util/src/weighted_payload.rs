//! Serialize once into a bounded temporary buffer; publish only on complete success.
use bincode::Options;
use serde::Serialize;
use std::io::{self, Write};

struct Bounded {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            self.exceeded = true;
            return Err(io::Error::other("weighted payload exceeds limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn encode<T: Serialize>(message: &T, limit: usize) -> bincode::Result<Vec<u8>> {
    let mut buffer = Bounded {
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    // Bincode's with_limit serializer first traverses T to compute its size.
    // Here the writer enforces the identical byte bound during the single pass.
    let result = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize_into(&mut buffer, message);
    // Even a custom serializer that ignores a Write error cannot publish a prefix.
    if buffer.exceeded {
        return Err(Box::new(bincode::ErrorKind::SizeLimit));
    }
    result?;
    Ok(buffer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{ser::SerializeTuple, Serializer};
    use std::cell::Cell;

    fn previous<T: Serialize>(message: &T, limit: usize) -> bincode::Result<Vec<u8>> {
        let mut out = vec![];
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(limit as u64)
            .serialize_into(&mut out, message)?;
        Ok(out)
    }
    #[test]
    fn exact_bytes_and_limit_decisions_match_the_previous_serializer() {
        for n in [0, 1, 31, 32, 255, 256, 1024, 32768] {
            let value = (
                Some(17u64),
                (0..n)
                    .map(|i| (i as u32, (i % 255) as u8))
                    .collect::<Vec<_>>(),
                "weighted payload".to_string(),
                vec![42u8; n],
            );
            let raw = previous(&value, 1024 * 1024).unwrap();
            for limit in [0, 1, 7, 8, 31, 32, raw.len() - 1, raw.len(), raw.len() + 1] {
                match (previous(&value, limit), encode(&value, limit)) {
                    (Ok(old), Ok(new)) => assert_eq!(old, new),
                    (Err(old), Err(new)) => {
                        assert!(matches!(*old, bincode::ErrorKind::SizeLimit));
                        assert!(matches!(*new, bincode::ErrorKind::SizeLimit));
                    }
                    _ => panic!("different size-limit decision"),
                }
            }
        }
    }
    struct Counted<'a>(&'a Cell<usize>);
    impl Serialize for Counted<'_> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            self.0.set(self.0.get() + 1);
            (17u64, vec![1u8; 100]).serialize(s)
        }
    }
    #[test]
    fn one_traversal_instead_of_size_preflight_and_write() {
        let calls = Cell::new(0);
        let old = previous(&Counted(&calls), 1024).unwrap();
        assert_eq!(calls.get(), 2);
        calls.set(0);
        let new = encode(&Counted(&calls), 1024).unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(old, new);
    }
    struct IgnoresWriteFailure;
    impl Serialize for IgnoresWriteFailure {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut tuple = s.serialize_tuple(10)?;
            for _ in 0..10 {
                let _ = tuple.serialize_element(&1u8);
            }
            tuple.end()
        }
    }
    #[test]
    fn bounded_writer_retains_failure_and_never_extends_past_limit() {
        let mut b = Bounded {
            bytes: vec![],
            limit: 4,
            exceeded: false,
        };
        b.write_all(&[1; 4]).unwrap();
        assert!(b.write_all(&[2; 1]).is_err());
        assert_eq!(b.bytes, vec![1; 4]);
        assert!(b.exceeded);
        assert!(matches!(
            *encode(&IgnoresWriteFailure, 4).unwrap_err(),
            bincode::ErrorKind::SizeLimit
        ));
    }
}
