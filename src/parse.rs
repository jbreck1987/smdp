use crate::format::{MIN_PKT_SIZE, SmdpPacket};
use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use std::{
    io::{ErrorKind, Read, Write},
    time::{Duration, Instant},
};

const STX: u8 = 0x02;
const EDX: u8 = 0x1D;

/// Required methods for a Framer. Primarily used for testing.
trait Framer {
    /// Push bytes into Framer buffer for framing. Syncon is request/response, so
    /// there should only ever be one response frame per request.
    fn push_bytes(&mut self, data: &[u8]) -> Result<Bytes>;
}

/// Feedback to Reader on the state of the
/// Framer. Will not return partial packets since they are
/// to be ignored in the protocol.
enum FramerStatus {
    FrameTooSmall,
    MaxSizeOverflow,
    InvalidFormat,
}
/// Handles the framing logic for the SMDP protocol. The framer validates
/// the structure of a stream of bytes and extracts a candidate packet, it does no parsing
/// of fields (E.g. will not verify checksum).
struct SmdpFramer {
    // Buffer that holds incoming bytes from the reader.
    buf: BytesMut,
}
impl SmdpFramer {
    fn new(max_size: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(max_size),
        }
    }
}
impl Framer for SmdpFramer {
    fn push_bytes(&mut self, data: &[u8]) -> Result<Bytes> {
        if data.len() == 0 {
            return Err(anyhow!("No bytes read"));
        }
        // Look for STX:
        // If at least one found, find pos of STX with the highest idx.
        // If none found, return InvalidFormat.
        let stx_pos = data
            .iter()
            .rposition(|b| *b == STX)
            .ok_or(anyhow!("Invalid format, STX not found"))?;

        // Look for EDX starting from idx after the stx position:
        // If at least one found, find pos of EDX with the lowest idx. Append data from [STX, EDX].
        // If this would cause an overflow, return MaxSizeOverflow. If none found, return InvalidFormat.
        let edx_pos = data[stx_pos + 1..]
            .iter()
            .position(|b| *b == EDX)
            .ok_or(anyhow!("Invalid format, EDX not found"))?
            + (stx_pos + 1);

        if data[stx_pos..=edx_pos].len() <= self.buf.capacity() {
            self.buf.extend_from_slice(&data[stx_pos..=edx_pos]);
        } else {
            return Err(anyhow!(
                "Frame too large, recvd {} bytes, max bytes allowed {}",
                &data[stx_pos..=edx_pos].len(),
                self.buf.capacity()
            ));
        }

        // Check for min length. If too small, clear buffer and return FrameTooSmall. Otherwise
        // return valid frame.
        if self.buf.len() < MIN_PKT_SIZE {
            let buf_len = self.buf.len();
            self.buf.clear();
            return Err(anyhow!(
                "Frame too small, recvd {} bytes, min allowed {}",
                buf_len,
                MIN_PKT_SIZE
            ));
        } else {
            eprintln!("buf_len: {}", self.buf.len());
            Ok(self.buf.split().freeze())
        }
    }
}

/// Manages reading/writing bytes to/from IO and delegate reads to protocol framer.
/// Only uses the basic Read/Write API, customization is up to the caller.
struct SmdpIoHandler<T: Read + Write, F: Framer> {
    io_handle: T,
    framer: F,
    // Timeout for one read operation in milliseconds.
    read_timeout: Duration,
    // Read buffer
    read_buf: Vec<u8>,
    // Chunk buffer
    chunk: Vec<u8>,
}
impl<T, F> SmdpIoHandler<T, F>
where
    T: Read + Write,
    F: Framer,
{
    fn new(
        io_handle: T,
        framer: F,
        read_timeout: usize,
        read_chunk_size: usize,
        max_frame_size: usize,
    ) -> Self {
        todo!()
    }
    // Attempts to read and frame bytes after a request for one
    // candidate SMDP packet.
    fn poll_once(&mut self) -> Result<Bytes> {
        self.read_buf.clear();
        let timer = Instant::now();
        let mut total_bytes_read = 0usize;

        // Canonical chunked read loop
        loop {
            match self.io_handle.read(&mut self.chunk) {
                // EOF reached
                Ok(0) => break,
                Ok(n_read) => {
                    if let Some(buf_slice) = self
                        .read_buf
                        .get_mut(total_bytes_read..total_bytes_read + n_read)
                    {
                        buf_slice.copy_from_slice(&self.chunk[..n_read]);
                        total_bytes_read += n_read;
                    } else {
                        self.chunk.clear();
                        return Err(anyhow!("Max frame size reached."));
                    }
                }
                // Chunk read blocked, continue to next chunk read
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    self.chunk.clear();
                    return Err(anyhow!(e));
                }
            }
            // Check timer
            if timer.elapsed() >= self.read_timeout {
                break;
            }
        }
        // Attempt to frame read bytes
        self.framer.push_bytes(&self.read_buf)
    }
}

/// Packages all the individual components to go from the wire to serialized SmdpPacket.
pub struct SmpdProtocol<T: Read + Write> {
    reader: SmdpIoHandler<T, SmdpFramer>,
}
impl<T> SmpdProtocol<T>
where
    T: Read + Write,
{
    fn new(
        io_handle: T,
        read_timeout: usize,
        num_retries: usize,
        read_chunk_size: usize,
        max_frame_size: usize,
    ) -> Self {
        todo!()
    }
    /// Attempts to read one SMDP packet from the wire after a request.
    pub fn poll_once(&mut self) -> Result<SmdpPacket> {
        todo!()
    }
    fn parse_frame(&mut self, frame: Bytes) -> Result<SmdpPacket> {
        // Verify Address is in-range
        // Verify fields of CMD_RSP byte are valid
        // Unescape Data field
        // Verify checksum
        // Deserialize into packet struct
        todo!()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    const STX: u8 = 0x02;
    const EDX: u8 = 0x1D;
    // Used for testing the Framer functionality
    fn make_framer() -> SmdpFramer {
        SmdpFramer::new(1024)
    }
    // Used for testing the IoHandler functionality in generality.
    // Can simulate any network condition via passed in closure/function.
    struct MockReader<F: Fn(&mut [u8]) -> std::io::Result<usize>> {
        f: F,
    }
    impl<F> Read for MockReader<F>
    where
        F: Fn(&mut [u8]) -> std::io::Result<usize>,
    {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            (self.f)(buf)
        }
    }

    #[test]
    fn test_one_stx_one_edx() {
        let mut framer = make_framer();
        let data = vec![STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX];
        let frame = framer.push_bytes(&data).unwrap();
        assert_eq!(
            frame,
            Bytes::from(vec![STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX])
        );
    }

    #[test]
    fn test_multiple_stx_one_edx() {
        let mut framer = make_framer();
        let data = vec![EDX, EDX, 0x09, STX, STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX];
        let frame = framer.push_bytes(&data).unwrap();
        // Should start from the last STX
        assert_eq!(
            frame,
            Bytes::from(vec![STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX])
        );
    }

    #[test]
    fn test_multiple_stx_multiple_edx() {
        let mut framer = make_framer();
        let data = vec![STX, STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX, 0x60, EDX];
        let frame = framer.push_bytes(&data).unwrap();
        // Should start from the last STX and end at the first EDX after it
        assert_eq!(
            frame,
            Bytes::from(vec![STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX])
        );
    }

    #[test]
    fn test_multiple_stx_separated_one_edx() {
        let mut framer = make_framer();
        let data = vec![STX, 0x01, 0x02, STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX];
        let frame = framer.push_bytes(&data).unwrap();
        // Should start from the last STX
        assert_eq!(
            frame,
            Bytes::from(vec![STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX])
        );
    }

    #[test]
    fn test_multiple_stx_separated_multiple_edx() {
        let mut framer = make_framer();
        let data = vec![
            EDX, STX, 0x01, 0x02, STX, 0x10, 0x19, 0x45, 0x20, 0x30, 0x40, 0x50, EDX, 0x60, EDX,
        ];
        let frame = framer.push_bytes(&data).unwrap();
        // Should start from the last STX and end at the first EDX after it
        assert_eq!(
            frame,
            Bytes::from(vec![STX, 0x10, 0x19, 0x45, 0x20, 0x30, 0x40, 0x50, EDX])
        );
    }
}
