use crate::{
    algo::{Algo, HashingError, HashingResult, ValidationError, ValidationResult},
    utils::read_in_chunks_padded::{Endianess, Options, read_in_chunks_padded},
};

// The SHA-256 (Secure Hash Algorithms) hashing algorithm implementation.
#[derive(Default)]
pub struct Sha256 {}

impl Algo for Sha256 {
    /// Hashes the input buffer and returns the digest as a lowercase hex string.
    fn hash(&self, mut reader: Box<dyn std::io::prelude::BufRead>) -> HashingResult {
        // The 6 logical functions used by the SHA-256 algorithm.
        let ch = |x: u32, y: u32, z: u32| (x & y) ^ ((!x) & z);
        let maj = |x: u32, y: u32, z: u32| (x & y) ^ (x & z) ^ (y & z);
        let bsig0 = |x: u32| x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22);
        let bsig1 = |x: u32| x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25);
        let ssig0 = |x: u32| x.rotate_right(7) ^ x.rotate_right(18) ^ x >> 3;
        let ssig1 = |x: u32| x.rotate_right(17) ^ x.rotate_right(19) ^ x >> 10;

        // These are the first 32-bits of the fractional part of the cube root of the first 64 prime
        // numbers.
        let constants: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        // These are the words that will compose the final hash digest.
        let mut hash_words: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let mut chunk_index = 0;
        let mut process_chunk = |chunk: &[u8]| {
            // Prepare the message schedule.
            let mut message_schedule = [0u32; 64];

            for index in 0..16 {
                message_schedule[index] =
                    u32::from_be_bytes(chunk[index * 4..index * 4 + 4].try_into().unwrap());
            }

            for index in 16..64 {
                message_schedule[index] = ssig1(message_schedule[index - 2])
                    .wrapping_add(message_schedule[index - 7])
                    .wrapping_add(ssig0(message_schedule[index - 15]))
                    .wrapping_add(message_schedule[index - 16]);
            }

            // Initialize the working variables.
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash_words;

            // Prepare the main hash computation.
            for index in 0..64 {
                let temporary1 = h
                    .wrapping_add(bsig1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(constants[index])
                    .wrapping_add(message_schedule[index]);
                let temporary2 = bsig0(a).wrapping_add(maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temporary1);
                d = c;
                c = b;
                b = a;
                a = temporary1.wrapping_add(temporary2);
            }

            // Compute the intermediate hash value.
            hash_words[0] = a.wrapping_add(hash_words[0]);
            hash_words[1] = b.wrapping_add(hash_words[1]);
            hash_words[2] = c.wrapping_add(hash_words[2]);
            hash_words[3] = d.wrapping_add(hash_words[3]);
            hash_words[4] = e.wrapping_add(hash_words[4]);
            hash_words[5] = f.wrapping_add(hash_words[5]);
            hash_words[6] = g.wrapping_add(hash_words[6]);
            hash_words[7] = h.wrapping_add(hash_words[7]);

            chunk_index += 1;
        };

        // Process 512-bits (64 bytes) blocks.
        let mut buffer = [0; 64];

        read_in_chunks_padded(
            &mut buffer,
            &mut reader,
            |chunk| process_chunk(chunk),
            Options {
                endianess: Endianess::Big,
            },
        )
        .map_err(HashingError)?;

        Ok(hash_words.map(|word| format!("{:08x}", word)).join(""))
    }

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
