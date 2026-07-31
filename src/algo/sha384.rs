use crate::algo::{
    Algo, HashingResult, ValidationError, ValidationResult,
    sha2::{HashSize, Sha2, Sha2Params},
};

/// The SHA-384 (Secure Hash Algorithms) hashing algorithm implementation.
#[derive(Default)]
pub struct Sha384 {}

impl Algo for Sha384 {
    /// Hashes the input buffer and returns the digest as a lowercase hex string.
    ///
    /// ```
    /// use rash::algo::{Algo, sha384::Sha384};
    ///
    /// let sha384 = Sha384::new();
    /// assert_eq!(
    ///     sha384.hash(Box::new(&b"abc"[..])).unwrap(),
    ///     "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    /// );
    /// assert_eq!(
    ///     sha384.hash(Box::new(&b""[..])).unwrap(),
    ///     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    /// );
    /// ```
    fn hash(&self, reader: Box<dyn std::io::prelude::BufRead>) -> HashingResult {
        // These are the words that will compose the final hash digest.
        let hash_words: [u64; 8] = [
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ];

        Sha2::hash::<u64>(
            reader,
            Sha2Params::for_sha384_512(hash_words, HashSize::Sha384),
        )
    }

    /// Validate a hash.
    ///
    /// ### Examples
    ///
    /// ```
    /// use rash::algo::{Algo, sha384::Sha384, ValidationError};
    ///
    /// let sha384 = Sha384::new();
    /// assert_eq!(
    ///     sha384.validate("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
    ///     Ok(())
    /// );
    /// assert_eq!(sha384.validate("abc123"), Err(ValidationError("Invalid length.".to_string())));
    /// ```
    fn validate(&self, hash: &str) -> ValidationResult {
        if hash.len() != 96 {
            Err(ValidationError("Invalid length.".to_string()))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 / NIST test vectors.
    #[test]
    fn hashes_test_vectors() {
        let sha384 = Sha384::new();

        [
            (
                "",
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            ),
            (
                "a",
                "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
            ),
            (
                "abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                "message digest",
                "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
            ),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026",
            ),
        ]
        .iter()
        .for_each(|&(input, expected)| {
            assert_eq!(
                sha384.hash(Box::new(input.as_bytes())),
                Ok(expected.to_string())
            );
        });
    }

    // Exercises the padding boundary (message length % 128 == 112).
    #[test]
    fn handles_112_byte_input() {
        let sha384 = Sha384::new();
        let input = vec![0u8; 112];
        assert_eq!(
            sha384.hash(Box::new(std::io::Cursor::new(input))),
            Ok("3e0cbf3aee0e3aa70415beae1bd12dd7db821efa446440f12132edffce76f635e53526a111491e75ee8e27b9700eec20".to_string())
        );
    }

    #[test]
    fn validates_an_invalid_hash() {
        let sha384 = Sha384::new();
        let result = sha384.validate("invalid_hash");
        assert_eq!(result, Err(ValidationError("Invalid length.".to_string())));
    }

    #[test]
    fn validates_a_valid_hash() {
        let sha384 = Sha384::new();
        let result = sha384.validate("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        assert_eq!(result, Ok(()));
    }
}
