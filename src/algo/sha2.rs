use crate::{
    algo::{HashingError, HashingResult},
    utils::read_in_chunks_padded::{Endianess, Options, read_in_chunks_padded},
};

pub enum Variant {
    Sha224,
    Sha256,
}

/// The SHA-2 (Secure Hash Algorithms) hashing implementations.
pub struct Sha2 {}

impl Sha2 {
    /// Hashes the input buffer and returns the digest as a lowercase hex string.
    ///
    /// ```
    /// use rash::algo::sha2::{Sha2, Variant};
    ///
    /// let hash_words: [u32; 8] = [
    ///     0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    ///     0x5be0cd19,
    /// ];
    /// assert_eq!(
    ///     Sha2::hash(hash_words, Box::new(&b"abc"[..]), Variant::Sha256).unwrap(),
    ///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    /// );
    /// ```
    pub fn hash(
        mut hash_words: [u32; 8],
        mut reader: Box<dyn std::io::prelude::BufRead>,
        variant: Variant,
    ) -> HashingResult {
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

        let take = match variant {
            Variant::Sha224 => 7,
            Variant::Sha256 => 8,
        };

        Ok(hash_words
            .iter()
            .take(take)
            .map(|word| format!("{:08x}", word))
            .collect::<Vec<String>>()
            .join(""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    const SHA224_IV: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];

    #[test]
    fn sha256_variant_returns_a_64_char_digest() {
        let digest = Sha2::hash(SHA256_IV, Box::new(&b"abc"[..]), Variant::Sha256).unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha224_variant_returns_a_56_char_digest() {
        let digest = Sha2::hash(SHA224_IV, Box::new(&b"abc"[..]), Variant::Sha224).unwrap();
        assert_eq!(digest.len(), 56);
        assert_eq!(
            digest,
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
    }

    // Exercises the padding boundary (message length % 64 == 56) directly against Sha2::hash.
    #[test]
    fn handles_56_byte_input() {
        let input = vec![0u8; 56];
        let digest = Sha2::hash(SHA256_IV, Box::new(std::io::Cursor::new(input)), Variant::Sha256)
            .unwrap();
        assert_eq!(
            digest,
            "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb"
        );
    }
}
