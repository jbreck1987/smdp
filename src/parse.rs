use crate::format::{
    ESCAPE_CHAR, HEX_0D_ESC, HEX_02_ESC, HEX_07_ESC, MIN_PKT_SIZE, SmdpPacket, mod256_checksum,
};
use anyhow::{Context, Result, anyhow};
use bitfield::{Bit, BitRange};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    io::{ErrorKind, Read, Write},
    time::{Duration, Instant},
};

const STX: u8 = 0x02;
const EDX: u8 = 0x1D;
const READ_CHUNK_SIZE: usize = 512;

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
    read_timeout_ms: Duration,
    // Read buffer
    read_buf: Vec<u8>,
    // Chunk buffer
    chunk: [u8; READ_CHUNK_SIZE],
}
impl<T, F> SmdpIoHandler<T, F>
where
    T: Read + Write,
    F: Framer,
{
    fn new(io_handle: T, framer: F, read_timeout_ms: usize, max_frame_size: usize) -> Self {
        Self {
            io_handle,
            framer,
            read_timeout_ms: Duration::from_millis(read_timeout_ms as u64),
            read_buf: Vec::with_capacity(max_frame_size),
            chunk: [0; READ_CHUNK_SIZE],
        }
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
                        self.chunk.fill(0);
                        return Err(anyhow!("Max frame size reached."));
                    }
                }
                // Chunk read blocked, continue to next chunk read
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => {
                    self.chunk.fill(0);
                    return Err(anyhow!(e));
                }
            }
            // Check timer
            if timer.elapsed() >= self.read_timeout_ms {
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
    fn new(io_handle: T, read_timeout_ms: usize, max_frame_size: usize) -> Self {
        let framer = SmdpFramer::new(max_frame_size);
        let reader = SmdpIoHandler::new(io_handle, framer, read_timeout_ms, max_frame_size);
        Self { reader }
    }
    /// Attempts to read one SMDP packet from the wire after a request.
    pub fn poll_once(&mut self) -> Result<SmdpPacket> {
        let mut frame = self.reader.poll_once()?;
        Self::parse_frame(&mut frame)
    }
    /// Parses a candidate frame (minus) into a well-formed SMDP packet if valid. Currently supports
    /// only V2 and below.
    fn parse_frame(frame: &mut Bytes) -> Result<SmdpPacket> {
        // Discard STX
        _ = frame.try_get_u8().map_err(|_| anyhow!("Frame is empty"));

        // Verify Address is in-range
        let addr = frame.try_get_u8().map_err(|_| anyhow!("Frame too small"))?;
        if addr < 0x10 || addr > 0xFE {
            return Err(anyhow!(
                "{} is an invalid address. Valid addresses are 16 - 254",
                addr
            ));
        }
        // Verify fields of CMD_RSP byte are valid
        let cmd_rsp = frame.try_get_u8().map_err(|_| anyhow!("Frame too small"))?;
        let cmd: u8 = cmd_rsp.bit_range(7, 4);
        if cmd < 0x01 || cmd > 0xFE {
            return Err(anyhow!("CMD field invalid"));
        }
        // No need to check RSPF bit, either 0 or 1 is valid.
        let rsp: u8 = cmd_rsp.bit_range(2, 0);
        if rsp < 0x01 || rsp > 0x07 {
            return Err(anyhow!("RSP field invalid"));
        }
        // Unescape Data field
        let mut data: Vec<u8> = Vec::with_capacity(frame.remaining() - 2);
        let mut escaped = false;
        while frame.remaining() > 3 {
            // 3 => two checksum bytes + EDX
            let mut curr_byte = frame.get_u8();
            if escaped {
                curr_byte = match curr_byte {
                    HEX_02_ESC => 0x02,
                    HEX_07_ESC => 0x07,
                    HEX_0D_ESC => 0x0D,
                    other => return Err(anyhow!("Invalid escaped value: {other}")),
                };
                escaped = false;
            }
            if !escaped && curr_byte == ESCAPE_CHAR {
                escaped = true;
                continue;
            }
            data.push(curr_byte);
        }
        // Verify checksum. Should be exactly 3 bytes remaining.
        let calculated_chk = mod256_checksum(&data, addr, cmd_rsp);
        let framed_chk = (frame.get_u8() << 4) | (frame.get_u8() & 0b00001111);
        if calculated_chk != framed_chk {
            return Err(anyhow!("Checksum mismatch."));
        }

        // Deserialize into packet struct
        Ok(SmdpPacket::new(addr, cmd_rsp, data))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // Used for testing the Framer functionality
    fn make_framer() -> SmdpFramer {
        SmdpFramer::new(1024)
    }
    struct MockFramer<F: Fn(&[u8]) -> Result<Bytes>> {
        f: F,
    }
    impl<F> Framer for MockFramer<F>
    where
        F: Fn(&[u8]) -> Result<Bytes>,
    {
        fn push_bytes(&mut self, data: &[u8]) -> Result<Bytes> {
            (self.f)(data)
        }
    }
    // Used for testing the IoHandler functionality in generality.
    // Can simulate any network condition via passed in closures/functions.
    struct MockIo<R, W>
    where
        R: Fn(&mut [u8]) -> std::io::Result<usize>,
        W: Fn(&[u8]) -> std::io::Result<usize>,
    {
        r: R,
        w: W,
    }
    impl<R, W> Read for MockIo<R, W>
    where
        R: Fn(&mut [u8]) -> std::io::Result<usize>,
        W: Fn(&[u8]) -> std::io::Result<usize>,
    {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            (self.r)(buf)
        }
    }
    impl<R, W> Write for MockIo<R, W>
    where
        R: Fn(&mut [u8]) -> std::io::Result<usize>,
        W: Fn(&[u8]) -> std::io::Result<usize>,
    {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            (self.w)(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
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
