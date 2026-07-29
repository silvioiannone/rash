use std::io::BufRead;

/// Keep reading from a `BufRead` until `buffer` is filled. Once it is filled, call `callback`.
///
/// ### Returns
/// Returns a result containing the a tuple with the amount of bytes read and the left-over buffer
/// slice, or an error if something went wrong while reading the buffer.
///
/// ### Example
/// ```
/// use rash::utils::keep_reading_into_buffer::keep_reading_into_buffer;
/// use std::io::{BufRead, Cursor};
///
/// let mut buffer = [0u8; 4];
/// let mut reader: Box<dyn BufRead> = Box::new(Cursor::new(b"abcdefg".to_vec()));
/// let mut chunks: Vec<Vec<u8>> = Vec::new();
///
/// let (total, left_over) = keep_reading_into_buffer(&mut buffer, &mut reader, |chunk| {
///     chunks.push(chunk.to_vec())
/// })
/// .unwrap();
///
/// assert_eq!(total, 7);
/// assert_eq!(left_over, b"efg");
/// assert_eq!(chunks, vec![b"abcd".to_vec()]);
/// ```
pub fn keep_reading_into_buffer<'b, C: FnMut(&[u8])>(
    buffer: &'b mut [u8],
    reader: &'b mut Box<dyn BufRead>,
    mut callback: C,
) -> Result<(usize, &'b [u8]), String> {
    let mut filled = 0;
    let mut total_bytes = 0;

    loop {
        let read_bytes = reader
            .read(&mut buffer[filled..])
            .expect("Failed to read input.");

        if read_bytes == 0 {
            return Ok((total_bytes, &buffer[..filled]));
        }

        filled += read_bytes;
        total_bytes += read_bytes;

        if filled == buffer.len() {
            callback(buffer);
            filled = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    fn reader_for(data: &[u8]) -> Box<dyn BufRead> {
        Box::new(Cursor::new(data.to_vec()))
    }

    // A reader that only ever returns 1 byte per `read` call, regardless of the requested
    // buffer size, to exercise readers that do short reads (pipes, sockets, ...).
    struct OneByteAtATime {
        data: Vec<u8>,
        pos: usize,
    }

    impl io::Read for OneByteAtATime {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    impl io::BufRead for OneByteAtATime {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Ok(&self.data[self.pos..])
        }

        fn consume(&mut self, amt: usize) {
            self.pos += amt;
        }
    }

    #[test]
    fn returns_empty_leftover_for_empty_input() {
        let mut buffer = [0u8; 4];
        let mut reader = reader_for(b"");
        let mut calls = 0;

        let (total, left_over) =
            keep_reading_into_buffer(&mut buffer, &mut reader, |_| calls += 1).unwrap();

        assert_eq!(total, 0);
        assert_eq!(left_over, &[] as &[u8]);
        assert_eq!(calls, 0);
    }

    #[test]
    fn returns_input_as_leftover_when_smaller_than_buffer() {
        let mut buffer = [0u8; 8];
        let mut reader = reader_for(b"abc");
        let mut calls = 0;

        let (total, left_over) =
            keep_reading_into_buffer(&mut buffer, &mut reader, |_| calls += 1).unwrap();

        assert_eq!(total, 3);
        assert_eq!(left_over, b"abc");
        assert_eq!(calls, 0);
    }

    #[test]
    fn invokes_callback_once_per_full_buffer_with_no_leftover() {
        let mut buffer = [0u8; 4];
        let mut reader = reader_for(b"abcdefgh");
        let mut chunks: Vec<Vec<u8>> = Vec::new();

        let (total, left_over) = keep_reading_into_buffer(&mut buffer, &mut reader, |chunk| {
            chunks.push(chunk.to_vec())
        })
        .unwrap();

        assert_eq!(total, 8);
        assert_eq!(left_over, &[] as &[u8]);
        assert_eq!(chunks, vec![b"abcd".to_vec(), b"efgh".to_vec()]);
    }

    #[test]
    fn carries_leftover_bytes_across_full_chunks() {
        let mut buffer = [0u8; 4];
        let mut reader = reader_for(b"abcdefg");
        let mut chunks: Vec<Vec<u8>> = Vec::new();

        let (total, left_over) = keep_reading_into_buffer(&mut buffer, &mut reader, |chunk| {
            chunks.push(chunk.to_vec())
        })
        .unwrap();

        assert_eq!(total, 7);
        assert_eq!(left_over, b"efg");
        assert_eq!(chunks, vec![b"abcd".to_vec()]);
    }

    #[test]
    fn assembles_chunks_correctly_across_short_reads() {
        let mut buffer = [0u8; 4];
        let mut reader: Box<dyn BufRead> = Box::new(OneByteAtATime {
            data: b"abcdefgh".to_vec(),
            pos: 0,
        });
        let mut chunks: Vec<Vec<u8>> = Vec::new();

        let (total, left_over) = keep_reading_into_buffer(&mut buffer, &mut reader, |chunk| {
            chunks.push(chunk.to_vec())
        })
        .unwrap();

        assert_eq!(total, 8);
        assert_eq!(left_over, &[] as &[u8]);
        assert_eq!(chunks, vec![b"abcd".to_vec(), b"efgh".to_vec()]);
    }
}
