use std::{array, io::BufRead};

use crate::{
    algo::{Algo, HashingError, HashingResult, ValidationError, ValidationResult},
    utils::read_in_chunks_padded::{Endianess, Options, read_in_chunks_padded},
};

/// The MD5 message-digest algorithm is a widely used hash function producing a 128-bit hash value.
#[derive(Default)]
pub struct Md5 {}

impl Algo for Md5 {
    /// Hashes the input buffer and returns the digest as a lowercase hex string.
    ///
    /// ```
    /// use rash::algo::{Algo, md5::Md5};
    ///
    /// let md5 = Md5::new();
    /// assert_eq!(md5.hash(Box::new(&b"abc"[..])).unwrap(), "900150983cd24fb0d6963f7d28e17f72");
    /// assert_eq!(md5.hash(Box::new(&b""[..])).unwrap(), "d41d8cd98f00b204e9800998ecf8427e");
    /// ```
    fn hash(&self, mut reader: Box<dyn BufRead>) -> HashingResult {
        // A four-word buffer (A,B,C,D) is used to compute the message digest. Here each of A, B, C,
        // D is a 32-bit register. These will be used to output the final digest.
        let mut a: u32 = 0x67452301;
        let mut b: u32 = 0xefcdab89;
        let mut c: u32 = 0x98badcfe;
        let mut d: u32 = 0x10325476;

        // These are the 4 auxiliary functions that are used in each round to calculate the value
        // for the 4 buffers.
        let f = |x: u32, y: u32, z: u32| (x & y) | ((!x) & z);
        let g = |x: u32, y: u32, z: u32| (z & x) | ((!z) & y);
        let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
        let i = |x: u32, y: u32, z: u32| y ^ (x | (!z));

        // This step also requires a 64-elements table computed using the sine function. In this
        // case the constants are pre-computed for performance.
        let constants = [
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
            0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
            0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
            0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
            0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
            0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
            0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
            0xeb86d391,
        ];

        // Alternatively, the values can also be calculated on the fly using the following
        // algorithm:
        // let constants: Vec<u32> = (0..64)
        //     .map(|i| {
        //         let mut i = (i + 1) as f64;
        //         i = i.sin().abs() * 2_f64.powi(32);
        //         i = i.floor();
        //         return i as u32;
        //     })
        //     .collect();

        // Each round performs some operations, and each operation performs some bit shifting. This
        // table matches each round with the related amount of bits to be shifted.
        let shifts_table = [
            // Round 1 shifts amounts.
            [7, 12, 17, 22],
            // Round 2 shifts amounts.
            [5, 9, 14, 20],
            // Round 3 shifts amounts.
            [4, 11, 16, 23],
            // Round 4 shifts amounts.
            [6, 10, 15, 21],
        ];

        // Define the function that processes each message in 16-word (64 byte) chunks.
        let mut process_chunk = |chunk: &[u8]| {
            // MD5 words are 32-bit little-endian, 4 bytes each.
            let words: [u32; 16] = array::from_fn(|index| {
                let index_start = index * 4;
                u32::from_le_bytes(chunk[index_start..index_start + 4].try_into().unwrap())
            });

            // Initialize hash values for this chunk using the message digest buffers.
            let mut aa = a;
            let mut bb = b;
            let mut cc = c;
            let mut dd = d;

            // Main loop: 4 rounds of 16 operations each, using the `f`/`g`/`h`/`i` auxiliary
            // functions.
            for index in 0..64 {
                // `k` selects which of the 16 message words feeds this step; each round uses its
                // own permutation of word indices, per the RFC.
                let (round, k, shift) = match index {
                    // Round 1 (F): words in order, 0..16.
                    0..16 => (f(bb, cc, dd), index, shifts_table[0][index % 4]),
                    // Round 2 (G): word index (5i + 1) mod 16.
                    16..32 => (
                        g(bb, cc, dd),
                        (5 * index + 1) % 16,
                        shifts_table[1][index % 4],
                    ),
                    // Round 3 (H): word index (3i + 5) mod 16.
                    32..48 => (
                        h(bb, cc, dd),
                        (3 * index + 5) % 16,
                        shifts_table[2][index % 4],
                    ),
                    // Round 4 (I): word index (7i) mod 16.
                    48..64 => (i(bb, cc, dd), (7 * index) % 16, shifts_table[3][index % 4]),
                    _ => unreachable!(),
                };

                // Combine the round function's output with the current state, the round constant,
                // and the selected message word.
                let temp = round
                    .wrapping_add(aa)
                    .wrapping_add(constants[index])
                    .wrapping_add(words[k]);

                // Rotate the state registers (A,B,C,D) for the next step, folding in `temp`.
                aa = dd;
                dd = cc;
                cc = bb;
                bb = bb.wrapping_add(temp.rotate_left(shift))
            }

            a = a.wrapping_add(aa);
            b = b.wrapping_add(bb);
            c = c.wrapping_add(cc);
            d = d.wrapping_add(dd);
        };

        // Process every full 64-byte block straight out of the reader.
        let mut buffer = [0u8; 64];

        read_in_chunks_padded(
            &mut buffer,
            &mut reader,
            |chunk| process_chunk(chunk),
            Options {
                endianess: Endianess::Little,
            },
        )
        .map_err(HashingError)?;

        // Step 5: Output.
        //
        // Return the resulting 128-bit long message digest. We begin with the low-order byte of A,
        // and end with the high-order byte of D.
        Ok(format!(
            "{:08x}{:08x}{:08x}{:08x}",
            a.swap_bytes(),
            b.swap_bytes(),
            c.swap_bytes(),
            d.swap_bytes()
        ))
    }

    /// Validate a hash.
    ///
    /// ### Examples
    ///
    /// ```
    /// use rash::algo::{Algo, md5::Md5, ValidationError};
    ///
    /// let md5 = Md5::new();
    /// assert_eq!(md5.validate("900150983cd24fb0d6963f7d28e17f72"), Ok(()));
    /// assert_eq!(md5.validate("abc123"), Err(ValidationError("Invalid hash length.".to_string())));
    /// ```
    fn validate(&self, hash: &str) -> ValidationResult {
        if hash.len() == 32 {
            Ok(())
        } else {
            Err(ValidationError("Invalid hash length.".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1321 test vectors.
    #[test]
    fn hashes_rfc1321_vectors() {
        let md5 = Md5::new();

        [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ]
        .iter()
        .for_each(|&(input, expected)| {
            assert_eq!(
                md5.hash(Box::new(input.as_bytes())),
                Ok(expected.to_string())
            );
        });
    }

    // Exercises the padding boundary (message length % 64 == 56).
    #[test]
    fn handles_56_byte_input() {
        let md5 = Md5::new();
        let input = vec![0u8; 56];
        assert_eq!(
            md5.hash(Box::new(std::io::Cursor::new(input))),
            Ok("e3c4dd21a9171fd39d208efa09bf7883".to_string())
        );
    }

    #[test]
    fn validates_an_invalid_hash() {
        let md5 = Md5::new();
        let result = md5.validate("invalid_hash");
        assert_eq!(
            result,
            Err(ValidationError("Invalid hash length.".to_string()))
        );
    }

    #[test]
    fn validates_a_valid_hash() {
        let md5 = Md5::new();
        let result = md5.validate("d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(result, Ok(()));
    }
}
