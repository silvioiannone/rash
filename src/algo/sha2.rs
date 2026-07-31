use std::io::BufRead;

use crate::{
    algo::{HashingError, HashingResult},
    utils::read_in_chunks_padded::{Endianess, Options, read_in_chunks_padded},
};

const MAX_ROUNDS: usize = 80;
const MAX_BLOCK_BYTES: usize = 128;

#[derive(Clone, Copy)]
pub enum CompressionRounds {
    Sha224_256 = 64,
    Sha384_512 = 80,
}

pub enum HashSize {
    Sha224 = 7,
    Sha384 = 6,
    Sha256_512 = 8,
}

/// This struct holds only the differences between all the SHA2 algorithms (SHA-248, SHA-256,
/// SHA-384, and SHA-512).
///
/// Each of SHA2 algorithms has to provide each argurment.
pub struct Sha2Params<W: 'static> {
    // The words used to initialize the final digest.
    pub hash_words: [W; 8],

    // The size of the final hash.
    pub hash_size: HashSize,

    /// Number of compression rounds (e.g. 64 for SHA-224/256, 80 for SHA-384/512).
    pub rounds: CompressionRounds,

    /// Round constants (K), one per round.
    pub constants: &'static [W],

    /// Modular addition for the word type W.
    pub wrapping_add: fn(W, W) -> W,

    /// Parses a word from big-endian bytes.
    pub from_be_bytes: fn(&[u8]) -> W,

    /// Big sigma 0: the message schedule/compression function Σ0.
    pub bsig0: fn(W) -> W,

    /// Big sigma 1: the message schedule/compression function Σ1.
    pub bsig1: fn(W) -> W,

    /// Small sigma 0: the message schedule function σ0.
    pub ssig0: fn(W) -> W,

    /// Small sigma 1: the message schedule function σ1.
    pub ssig1: fn(W) -> W,
}

impl Sha2Params<u32> {
    /// The constant values used when calculating SHA-224 and SHA-256 hashes.
    ///
    /// These are the first 32-bits of the fractional part of the cube root of the first 64 prime
    /// numbers.
    const CONSTANTS: [u32; 64] = [
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

    /// Create the SHA2 params for a SHA-224 or SHA-256 implementation.
    pub fn for_sha224_256(hash_words: [u32; 8], hash_size: HashSize) -> Self {
        Sha2Params {
            hash_words,
            hash_size,
            rounds: CompressionRounds::Sha224_256,
            constants: &Self::CONSTANTS,
            wrapping_add: u32::wrapping_add,
            from_be_bytes: |bytes| u32::from_be_bytes(bytes.try_into().unwrap()),
            bsig0: |x| x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22),
            bsig1: |x| x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25),
            ssig0: |x| x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3),
            ssig1: |x| x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10),
        }
    }
}

impl Sha2Params<u64> {
    /// The constant values used when calculating SHA-384 and SHA-512 hashes.
    ///
    /// These are the first 64-bits of the fractional part of the cube root of the first 80 prime
    /// numbers.
    const CONSTANTS: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    /// Create the SHA2 params for a SHA-384 or SHA-512 implementation.
    pub fn for_sha384_512(hash_words: [u64; 8], hash_size: HashSize) -> Self {
        Sha2Params {
            hash_words,
            hash_size,
            rounds: CompressionRounds::Sha384_512,
            constants: &Self::CONSTANTS,
            wrapping_add: u64::wrapping_add,
            from_be_bytes: |bytes| u64::from_be_bytes(bytes.try_into().unwrap()),
            bsig0: |x| x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39),
            bsig1: |x| x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41),
            ssig0: |x| x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7),
            ssig1: |x| x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6),
        }
    }
}

/// The SHA-2 (Secure Hash Algorithms) hashing implementations.
pub struct Sha2 {}

impl Sha2 {
    /// Hashes the input buffer and returns the digest as a lowercase hex string.
    ///
    /// ```
    /// use rash::algo::sha2::{Sha2, Sha2Params, HashSize};
    ///
    /// let hash_words: [u32; 8] = [
    ///     0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    ///     0x5be0cd19,
    /// ];
    ///
    /// let result = Sha2::hash(
    ///     Box::new(&b"abc"[..]),
    ///     Sha2Params::for_sha224_256(hash_words, HashSize::Sha224),
    /// );
    ///
    /// assert_eq!(
    ///     result.unwrap(),
    ///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
    /// );
    /// ```
    pub fn hash<W>(mut reader: Box<dyn BufRead>, params: Sha2Params<W>) -> HashingResult
    where
        W: Copy
            + Default
            + std::fmt::LowerHex
            + std::ops::BitAnd<Output = W>
            + std::ops::BitXor<Output = W>
            + std::ops::Not<Output = W>,
    {
        let word_bytes: usize = std::mem::size_of::<W>();
        let block_bytes: usize = word_bytes * 16;
        let add = params.wrapping_add;
        let mut hash_words = params.hash_words;

        // These, together with the 4 functions (`bsig0`, `bsig1`, `ssig0`, and `ssig1``) defined in
        // `u32` and `u64` implementations of `Word` are the 6 logical functions used by the SHA-2
        // algorithms.
        let ch = |x: W, y: W, z: W| (x & y) ^ (!x & z);
        let maj = |x: W, y: W, z: W| (x & y) ^ (x & z) ^ (y & z);

        let mut process_chunk = |chunk: &[u8]| {
            // Prepare the message schedule.
            let mut message_schedule = [W::default(); MAX_ROUNDS];

            for index in 0..16 {
                message_schedule[index] = (params.from_be_bytes)(
                    &chunk[index * word_bytes..index * word_bytes + word_bytes],
                );
            }

            for index in 16..params.rounds as usize {
                message_schedule[index] = add(
                    add(
                        add(
                            (params.ssig1)(message_schedule[index - 2]),
                            message_schedule[index - 7],
                        ),
                        (params.ssig0)(message_schedule[index - 15]),
                    ),
                    message_schedule[index - 16],
                );
            }

            // Initialize the working variables.
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash_words;

            // Prepare the main hash computation.
            for (index, current_message_schedule) in message_schedule
                .iter()
                .enumerate()
                .take(params.rounds as usize)
            {
                let temporary1 = add(
                    add(
                        add(add(h, (params.bsig1)(e)), ch(e, f, g)),
                        params.constants[index],
                    ),
                    *current_message_schedule,
                );
                let temporary2 = add((params.bsig0)(a), maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = add(d, temporary1);
                d = c;
                c = b;
                b = a;
                a = add(temporary1, temporary2);
            }

            // Compute the intermediate hash value.
            hash_words[0] = add(a, hash_words[0]);
            hash_words[1] = add(b, hash_words[1]);
            hash_words[2] = add(c, hash_words[2]);
            hash_words[3] = add(d, hash_words[3]);
            hash_words[4] = add(e, hash_words[4]);
            hash_words[5] = add(f, hash_words[5]);
            hash_words[6] = add(g, hash_words[6]);
            hash_words[7] = add(h, hash_words[7]);
        };

        let mut buffer = [0u8; MAX_BLOCK_BYTES];
        read_in_chunks_padded(
            &mut buffer[..block_bytes],
            &mut reader,
            |chunk| process_chunk(chunk),
            Options {
                endianess: Endianess::Big,
                length_bytes: word_bytes * 2,
            },
        )
        .map_err(HashingError)?;

        Ok(hash_words
            .iter()
            .take(params.hash_size as usize)
            .map(|word| format!("{:0width$x}", word, width = word_bytes * 2))
            .collect::<Vec<String>>()
            .join(""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-4 / NIST test vectors, exercising the u64 (SHA-384/512) params constructor.
    #[test]
    fn hashes_sha384_and_sha512_test_vectors() {
        let sha384_words: [u64; 8] = [
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ];
        let sha512_words: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];

        assert_eq!(
            Sha2::hash::<u64>(
                Box::new(&b"abc"[..]),
                Sha2Params::for_sha384_512(sha384_words, HashSize::Sha384),
            ),
            Ok(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
                    .to_string()
            )
        );

        assert_eq!(
            Sha2::hash::<u64>(
                Box::new(&b"abc"[..]),
                Sha2Params::for_sha384_512(sha512_words, HashSize::Sha256_512),
            ),
            Ok(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                    .to_string()
            )
        );
    }
}
