use crate::algo::{
    Algo, HashingResult, ValidationError, ValidationResult,
    sha2::{HashSize, Sha2, Sha2Params},
};

/// The SHA-256 (Secure Hash Algorithms) hashing algorithm implementation.
#[derive(Default)]
pub struct Sha256 {}

impl Algo for Sha256 {
    /// Hashes the input buffer and returns the digest as a lowercase hex string.
    ///
    /// ```
    /// use rash::algo::{Algo, sha256::Sha256};
    ///
    /// let sha256 = Sha256::new();
    /// assert_eq!(
    ///     sha256.hash(Box::new(&b"abc"[..])).unwrap(),
    ///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    /// );
    /// assert_eq!(
    ///     sha256.hash(Box::new(&b""[..])).unwrap(),
    ///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    /// );
    /// ```
    fn hash(&self, reader: Box<dyn std::io::prelude::BufRead>) -> HashingResult {
        // These are the words that will compose the final hash digest.
        let hash_words: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        Sha2::hash::<u32>(
            reader,
            Sha2Params::for_sha224_256(hash_words, HashSize::Sha256_512),
        )
    }

    /// Validate a hash.
    ///
    /// ### Examples
    ///
    /// ```
    /// use rash::algo::{Algo, sha256::Sha256, ValidationError};
    ///
    /// let sha256 = Sha256::new();
    /// assert_eq!(
    ///     sha256.validate("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ///     Ok(())
    /// );
    /// assert_eq!(sha256.validate("abc123"), Err(ValidationError("Invalid length.".to_string())));
    /// ```
    fn validate(&self, hash: &str) -> ValidationResult {
        if hash.len() != 64 {
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
        let sha256 = Sha256::new();

        [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "a",
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "message digest",
                "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
            ),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
            ),
        ]
        .iter()
        .for_each(|&(input, expected)| {
            assert_eq!(
                sha256.hash(Box::new(input.as_bytes())),
                Ok(expected.to_string())
            );
        });
    }

    // Exercises the padding boundary (message length % 64 == 56).
    #[test]
    fn handles_56_byte_input() {
        let sha256 = Sha256::new();
        let input = vec![0u8; 56];
        assert_eq!(
            sha256.hash(Box::new(std::io::Cursor::new(input))),
            Ok("d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb".to_string())
        );
    }

    #[test]
    fn validates_an_invalid_hash() {
        let sha256 = Sha256::new();
        let result = sha256.validate("invalid_hash");
        assert_eq!(result, Err(ValidationError("Invalid length.".to_string())));
    }

    #[test]
    fn validates_a_valid_hash() {
        let sha256 = Sha256::new();
        let result =
            sha256.validate("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(result, Ok(()));
    }
}
