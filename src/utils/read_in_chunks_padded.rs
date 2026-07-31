use std::io::BufRead;

use crate::utils::read_in_chunks::read_in_chunks;

pub enum Endianess {
    Little,
    Big,
}

pub struct Options {
    /// Specify the endianess to use when appending the message's size at the end.
    pub endianess: Endianess,

    /// Number of bytes reserved at the end of the padded chunk(s) for the message's bit length.
    pub length_bytes: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            endianess: Endianess::Big,
            length_bytes: 8,
        }
    }
}

/// Reads `reader` in `buffer`-sized chunks, invoking `callback` for each full chunk read, then
/// pads the left-over tail and feeds the resulting chunk(s) to `callback` as well.
///
/// ### Returns
/// Returns `Ok(())` once every whole and padded chunk has been passed to `callback`, or an error
/// if the underlying read failed.
///
/// ### Example
/// ```
/// use rash::utils::read_in_chunks_padded::{read_in_chunks_padded, Options};
/// use std::io::{BufRead, Cursor};
///
/// let mut buffer = [0u8; 64];
/// let mut reader: Box<dyn BufRead> = Box::new(Cursor::new(b"abc".to_vec()));
/// let mut chunks: Vec<Vec<u8>> = Vec::new();
///
/// read_in_chunks_padded(
///     &mut buffer,
///     &mut reader,
///     |chunk| chunks.push(chunk.to_vec()),
///     Options::default(),
/// )
/// .unwrap();
///
/// assert_eq!(chunks.len(), 1);
/// assert_eq!(&chunks[0][..3], b"abc");
/// assert_eq!(chunks[0][3], 0x80);
/// assert_eq!(&chunks[0][56..], &24u64.to_be_bytes());
/// ```
pub fn read_in_chunks_padded<C: FnMut(&[u8])>(
    buffer: &mut [u8],
    reader: &mut Box<dyn BufRead>,
    mut callback: C,
    options: Options,
) -> Result<(), String> {
    let chunk_size = buffer.len();

    let Ok((bytes_read, left_over)) = read_in_chunks(buffer, reader, |buffer| {
        callback(buffer);
    }) else {
        return Err("Unable to read input.".to_string());
    };

    // At this point we have completely read all the buffer's whole-chunks. What is left is a
    // partially filled chunk and the padding.

    let mut tail = left_over.to_vec();

    // The padding starts with a 1, but since we cannot append just a single bit we append a
    // whole byte (0x80) instead.
    tail.push(0b1000_0000);

    // Then, keep adding 0s until the tail length is a multiple of the chunk size, minus
    // `length_bytes` bytes, which will contain the message length in bits.
    while tail.len() % chunk_size != chunk_size - options.length_bytes {
        tail.push(0x00);
    }

    let bit_length = bytes_read.wrapping_mul(8);
    let bit_length = match options.endianess {
        Endianess::Big => bit_length.to_be_bytes(),
        Endianess::Little => bit_length.to_le_bytes(),
    };

    // The length field may be wider than the native word size (e.g. SHA-384/512 use a 128-bit
    // length), so pad it with leading/trailing zeros on the side away from the significant bytes.
    let mut length_field = vec![0u8; options.length_bytes];
    match options.endianess {
        Endianess::Big => {
            let start = options.length_bytes - bit_length.len();
            length_field[start..].copy_from_slice(&bit_length);
        }
        Endianess::Little => {
            length_field[..bit_length.len()].copy_from_slice(&bit_length);
        }
    }

    tail.extend(length_field);

    for chunk in tail.chunks_exact(chunk_size) {
        callback(chunk);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn run(input: &[u8], options: Options) -> Vec<Vec<u8>> {
        let mut buffer = [0u8; 64];
        let mut reader: Box<dyn BufRead> = Box::new(Cursor::new(input.to_vec()));
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        read_in_chunks_padded(
            &mut buffer,
            &mut reader,
            |chunk| chunks.push(chunk.to_vec()),
            options,
        )
        .unwrap();
        chunks
    }

    // Regression test: the padding boundary must be driven by the chunk size (64), not by how
    // many bytes were read. Using the latter previously underflowed and panicked on inputs
    // shorter than 8 bytes, and mis-padded longer non-boundary inputs.
    #[test]
    fn pads_to_a_multiple_of_the_chunk_size_for_any_input_length() {
        for len in [0, 3, 55, 56, 63, 64, 100] {
            let total_out: usize = run(&vec![0u8; len], Options::default())
                .iter()
                .map(Vec::len)
                .sum();
            assert_eq!(total_out % 64, 0, "failed for input length {len}");
            assert!(total_out > 0, "failed for input length {len}");
        }
    }

    #[test]
    fn pads_empty_input_into_a_single_chunk() {
        let chunks = run(b"", Options::default());

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0][0], 0x80);
        assert!(chunks[0][1..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn pads_short_input_in_place_within_a_single_chunk() {
        let chunks = run(b"abc", Options::default());

        assert_eq!(chunks.len(), 1);
        assert_eq!(&chunks[0][..3], b"abc");
        assert_eq!(chunks[0][3], 0x80);
        assert!(chunks[0][4..56].iter().all(|&byte| byte == 0));
        assert_eq!(&chunks[0][56..], &24u64.to_be_bytes());
    }

    // Exercises the padding boundary (message length % 64 == 56): the `1` bit and length no
    // longer fit in the same chunk as the data, so padding spills into a second, otherwise-empty
    // chunk. Mirrors the `handles_56_byte_input` tests in `md5.rs` and `sha256.rs`.
    #[test]
    fn spills_into_a_second_chunk_at_the_56_byte_boundary() {
        let chunks = run(&[0u8; 56], Options::default());

        assert_eq!(chunks.len(), 2);
        assert!(chunks[0][..56].iter().all(|&byte| byte == 0));
        assert_eq!(chunks[0][56], 0x80);
        assert!(chunks[0][57..].iter().all(|&byte| byte == 0));
        assert!(chunks[1][..56].iter().all(|&byte| byte == 0));
        assert_eq!(&chunks[1][56..], &(56u64 * 8).to_be_bytes());
    }

    // Regression test: with a 128-byte chunk and a 16-byte length field (SHA-384/512), the `1`
    // bit no longer fits alongside the data once the message reaches 112 bytes, so padding must
    // spill into a second chunk instead of fitting the (8-byte-only) length in the first one.
    #[test]
    fn spills_into_a_second_chunk_at_the_112_byte_boundary_with_a_16_byte_length_field() {
        let mut buffer = [0u8; 128];
        let mut reader: Box<dyn BufRead> = Box::new(Cursor::new(vec![0u8; 112]));
        let mut chunks: Vec<Vec<u8>> = Vec::new();

        read_in_chunks_padded(
            &mut buffer,
            &mut reader,
            |chunk| chunks.push(chunk.to_vec()),
            Options {
                length_bytes: 16,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(chunks.len(), 2);
        assert!(chunks[0][..112].iter().all(|&byte| byte == 0));
        assert_eq!(chunks[0][112], 0x80);
        assert!(chunks[0][113..].iter().all(|&byte| byte == 0));
        assert!(chunks[1][..112].iter().all(|&byte| byte == 0));
        assert_eq!(&chunks[1][112..120], &[0u8; 8]);
        assert_eq!(&chunks[1][120..], &(112u64 * 8).to_be_bytes());
    }

    // A whole-chunk input is passed straight to `callback` by the inner reader with no leftover
    // bytes, so padding still needs to append one more, otherwise-empty, chunk.
    #[test]
    fn appends_a_dedicated_chunk_when_input_is_an_exact_multiple_of_the_chunk_size() {
        let input = [0xffu8; 64];
        let chunks = run(&input, Options::default());

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], input);
        assert_eq!(chunks[1][0], 0x80);
        assert!(chunks[1][1..56].iter().all(|&byte| byte == 0));
        assert_eq!(&chunks[1][56..], &(64u64 * 8).to_be_bytes());
    }

    #[test]
    fn encodes_the_bit_length_using_the_requested_endianess() {
        let big = run(
            b"abc",
            Options {
                endianess: Endianess::Big,
                ..Default::default()
            },
        );
        let little = run(
            b"abc",
            Options {
                endianess: Endianess::Little,
                ..Default::default()
            },
        );

        assert_eq!(&big[0][56..], &24u64.to_be_bytes());
        assert_eq!(&little[0][56..], &24u64.to_le_bytes());
        assert_ne!(big[0], little[0]);
    }
}
