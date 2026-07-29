use crate::algo::{
    Algo, HashingResult, ValidationError, ValidationResult,
    sha2::{Sha2, Variant},
};

/// The SHA-224 (Secure Hash Algorithms) hashing algorithm implementation.
#[derive(Default)]
pub struct Sha224 {}

impl Algo for Sha224 {
    /// Hashes the input buffer and returns the digest as a lowercase hex string.
    ///
    /// ```
    /// use rash::algo::{Algo, sha224::Sha224};
    ///
    /// let sha224 = Sha224::new();
    /// assert_eq!(
    ///     sha224.hash(Box::new(&b"abc"[..])).unwrap(),
    ///     "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
    /// );
    /// assert_eq!(
    ///     sha224.hash(Box::new(&b""[..])).unwrap(),
    ///     "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    /// );
    /// ```
    fn hash(&self, reader: Box<dyn std::io::prelude::BufRead>) -> HashingResult {
        // These are the words that will compose the final hash digest.
        let hash_words: [u32; 8] = [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
            0xbefa4fa4,
        ];

        return Sha2::hash(hash_words, reader, Variant::Sha224);
    }

    /// Validate a hash.
    ///
    /// ### Examples
    ///
    /// ```
    /// use rash::algo::{Algo, sha224::Sha224, ValidationError};
    ///
    /// let sha224 = Sha224::new();
    /// assert_eq!(
    ///     sha224.validate("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
    ///     Ok(())
    /// );
    /// assert_eq!(sha224.validate("abc123"), Err(ValidationError("Invalid length.".to_string())));
    /// ```
    fn validate(&self, hash: &str) -> ValidationResult {
        if hash.len() != 56 {
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
        let sha224 = Sha224::new();

        [
            (
                "",
                "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
            ),
            (
                "a",
                "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
            ),
            (
                "abc",
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            ),
            (
                "message digest",
                "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
            ),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e",
            ),
        ]
        .iter()
        .for_each(|&(input, expected)| {
            assert_eq!(
                sha224.hash(Box::new(input.as_bytes())),
                Ok(expected.to_string())
            );
        });
    }

    // Exercises the padding boundary (message length % 64 == 56).
    #[test]
    fn handles_56_byte_input() {
        let sha224 = Sha224::new();
        let input = vec![0u8; 56];
        assert_eq!(
            sha224.hash(Box::new(std::io::Cursor::new(input))),
            Ok("5c3e25b69d0ea26f260cfae87e23759e1eca9d1ecc9fbf3c62266804".to_string())
        );
    }

    #[test]
    fn validates_an_invalid_hash() {
        let sha224 = Sha224::new();
        let result = sha224.validate("invalid_hash");
        assert_eq!(result, Err(ValidationError("Invalid length.".to_string())));
    }

    #[test]
    fn validates_a_valid_hash() {
        let sha224 = Sha224::new();
        let result =
            sha224.validate("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
        assert_eq!(result, Ok(()));
    }
}
