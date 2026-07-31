use crate::algo::{
    Algo, HashingResult, ValidationError, ValidationResult,
    sha2::{HashSize, Sha2, Sha2Params},
};

/// The SHA-512 (Secure Hash Algorithms) hashing algorithm implementation.
#[derive(Default)]
pub struct Sha512 {}

impl Algo for Sha512 {
    /// Hashes the input buffer and returns the digest as a lowercase hex string.
    ///
    /// ```
    /// use rash::algo::{Algo, sha512::Sha512};
    ///
    /// let sha512 = Sha512::new();
    /// assert_eq!(
    ///     sha512.hash(Box::new(&b"abc"[..])).unwrap(),
    ///     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    /// );
    /// assert_eq!(
    ///     sha512.hash(Box::new(&b""[..])).unwrap(),
    ///     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    /// );
    /// ```
    fn hash(&self, reader: Box<dyn std::io::prelude::BufRead>) -> HashingResult {
        // These are the words that will compose the final hash digest.
        let hash_words: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];

        Sha2::hash::<u64>(
            reader,
            Sha2Params::for_sha384_512(hash_words, HashSize::Sha256_512),
        )
    }

    /// Validate a hash.
    ///
    /// ### Examples
    ///
    /// ```
    /// use rash::algo::{Algo, sha512::Sha512, ValidationError};
    ///
    /// let sha512 = Sha512::new();
    /// assert_eq!(
    ///     sha512.validate("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
    ///     Ok(())
    /// );
    /// assert_eq!(sha512.validate("abc123"), Err(ValidationError("Invalid length.".to_string())));
    /// ```
    fn validate(&self, hash: &str) -> ValidationResult {
        if hash.len() != 128 {
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
        let sha512 = Sha512::new();

        [
            (
                "",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
            (
                "a",
                "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
            ),
            (
                "abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                "message digest",
                "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
            ),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
            ),
        ]
        .iter()
        .for_each(|&(input, expected)| {
            assert_eq!(
                sha512.hash(Box::new(input.as_bytes())),
                Ok(expected.to_string())
            );
        });
    }

    // Exercises the padding boundary (message length % 128 == 112).
    #[test]
    fn handles_112_byte_input() {
        let sha512 = Sha512::new();
        let input = vec![0u8; 112];
        assert_eq!(
            sha512.hash(Box::new(std::io::Cursor::new(input))),
            Ok("2be2e788c8a8adeaa9c89a7f78904cacea6e39297d75e0573a73c756234534d6627ab4156b48a6657b29ab8beb73334040ad39ead81446bb09c70704ec707952".to_string())
        );
    }

    #[test]
    fn validates_an_invalid_hash() {
        let sha512 = Sha512::new();
        let result = sha512.validate("invalid_hash");
        assert_eq!(result, Err(ValidationError("Invalid length.".to_string())));
    }

    #[test]
    fn validates_a_valid_hash() {
        let sha512 = Sha512::new();
        let result = sha512.validate("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        assert_eq!(result, Ok(()));
    }
}
