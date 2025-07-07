use crate::format::{
    DeserializePacket, EDX, ESCAPE_CHAR, HEX_0D_ESC, HEX_02_ESC, HEX_07_ESC, MIN_PKT_SIZE,
    PacketFormat, STX, SmdpPacketV2, mod256_checksum,
};
use anyhow::{Context, Error, Result, anyhow};
use bitfield::{Bit, BitRange};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    io::{ErrorKind, Read, Write},
    time::{Duration, Instant},
};

const READ_CHUNK_SIZE: usize = 512;

/// Required methods for a Framer. Primarily used for testing.
pub trait Framer {
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
pub(crate) struct SmdpFramer {
    // Buffer that holds incoming bytes from the reader.
    buf: BytesMut,
}
impl SmdpFramer {
    pub(crate) fn new(max_size: usize) -> Self {
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
            read_buf: vec![0; max_frame_size],
            chunk: [0; READ_CHUNK_SIZE],
        }
    }
    // Attempts to read and frame bytes after a request for one
    // candidate SMDP packet.
    fn poll_once(&mut self) -> Result<Bytes> {
        self.read_buf.fill(0);
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
                        return Err(anyhow!("Max frame size reached."));
                    }
                }
                // Chunk read blocked, continue to next chunk read
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => {
                    return Err(anyhow!(e));
                }
            }
            // Check timer
            if timer.elapsed() >= self.read_timeout_ms {
                break;
            }
        }
        // Attempt to frame bytes that were read
        self.framer.push_bytes(&self.read_buf[..total_bytes_read])
    }
    /// Delegates `write_all` functionality to inner IO handle
    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.io_handle.write_all(bytes).map_err(anyhow::Error::from)
    }
}

/// Packages all the individual components to go from the wire to serialized SmdpPacket.
pub struct SmpdProtocol<T: Read + Write, P: PacketFormat + Clone> {
    io_handler: SmdpIoHandler<T, SmdpFramer>,
    /// Copy of the most recently serialized frame for comparison
    /// to return value.
    sent: Option<P>,
}
impl<T, P> SmpdProtocol<T, P>
where
    T: Read + Write,
    P: PacketFormat + Clone,
{
    pub fn new(io_handle: T, read_timeout_ms: usize, max_frame_size: usize) -> Self {
        let framer = SmdpFramer::new(max_frame_size);
        let handler = SmdpIoHandler::new(io_handle, framer, read_timeout_ms, max_frame_size);
        Self {
            io_handler: handler,
            sent: None,
        }
    }
}
impl<T, P> SmpdProtocol<T, P>
where
    T: Read + Write,
    P: PacketFormat + Clone,
    // This bound necessary while using Anyhow (required by Into<anyhow::Error>)
    P::DeserializerError: std::error::Error + Send + Sync + 'static,
{
    /// Attempts to read one SMDP packet from the IO handle after a request.
    pub fn poll_once(&mut self) -> Result<P> {
        let frame = self.io_handler.poll_once()?;
        P::from_bytes(frame.as_ref()).map_err(Error::from)
    }
}
impl<T, P> SmpdProtocol<T, P>
where
    T: Read + Write,
    P: PacketFormat + Clone,
    // This bound necessary while using Anyhow (required by Into<anyhow::Error>)
    P::SerializerError: std::error::Error + Send + Sync + 'static,
{
    /// Attempts to write one SMDP packet to the underlying IO handle.
    pub fn write_once(&mut self, packet: &P) -> Result<()> {
        let bytes = packet.to_bytes_vec()?;
        self.io_handler.write_all(bytes.as_ref())?;

        // If successful write, set sent as serialized packet.
        self.sent = Some(packet.clone());
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{format::mod256_checksum_split, test_utils::*};
    use rand::{Rng, thread_rng};
    use std::io::Cursor;

    /* FRAMER TESTING */
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
    /* IOHANDLER TESTING */
    #[test]
    fn test_io_read_bytes_no_chunk_delay_long_stream() {
        // Create random data
        let mut rng = thread_rng();
        let mut data: [u8; 1024] = [0; 1024];
        rng.fill(&mut data);
        let mut data_reader = Cursor::new(data.clone());

        // Build MockIO
        let writer = |_: &[u8]| return Ok(0usize);
        let reader = |buf: &mut [u8]| data_reader.read(buf);
        let mock_io = MockIo::new(reader, writer);

        // Build MockFramer
        let mock_framer = MockFramer::new(|buf| Ok(Bytes::copy_from_slice(buf)));

        // Build IoHandler and verify read is correct
        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 200, 1024);
        let resp = handler.poll_once();
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap(), Bytes::copy_from_slice(&data));
    }
    #[test]
    fn test_io_read_bytes_no_chunk_delay_short_stream() {
        // Create random data
        let mut rng = thread_rng();
        let mut data: [u8; 20] = [0; 20];
        rng.fill(&mut data);
        let mut data_reader = Cursor::new(data.clone());

        // Build MockIO
        let writer = |_: &[u8]| return Ok(0usize);
        let reader = |buf: &mut [u8]| data_reader.read(buf);
        let mock_io = MockIo::new(reader, writer);

        // Build MockFramer
        let mock_framer = MockFramer::new(|buf| Ok(Bytes::copy_from_slice(buf)));

        // Build IoHandler and verify read is correct
        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 200, 1024);
        let resp = handler.poll_once();
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap(), Bytes::copy_from_slice(&data));
    }
    #[test]
    fn test_io_read_bytes_no_50ms_chunk_delay() {
        // Create random data
        let mut rng = thread_rng();
        let mut data: [u8; 1024] = [0; 1024];
        rng.fill(&mut data);
        let mut data_reader = Cursor::new(data.clone());

        // Build MockIO with a delayed sender
        let writer = |_: &[u8]| return Ok(0usize);
        let reader = |buf: &mut [u8]| {
            std::thread::sleep(Duration::from_millis(50));
            data_reader.read(buf)
        };
        let mock_io = MockIo::new(reader, writer);

        // Build MockFramer
        let mock_framer = MockFramer::new(|buf| Ok(Bytes::copy_from_slice(buf)));

        // Build IoHandler and verify read is correct
        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 200, 1024);
        let resp = handler.poll_once();
        assert!(resp.is_ok());
        assert_eq!(resp.unwrap(), Bytes::copy_from_slice(&data));
    }
    #[test]
    fn test_io_read_too_many_bytes() {
        // Create random data
        let mut rng = thread_rng();
        let mut data: [u8; 2048] = [0; 2048];
        rng.fill(&mut data);
        let mut data_reader = Cursor::new(data.clone());

        // Build MockIO with a delayed sender
        let writer = |_: &[u8]| return Ok(0usize);
        let reader = |buf: &mut [u8]| {
            std::thread::sleep(Duration::from_millis(50));
            data_reader.read(buf)
        };
        let mock_io = MockIo::new(reader, writer);

        // Build MockFramer
        let mock_framer = MockFramer::new(|buf| Ok(Bytes::copy_from_slice(buf)));

        // Build IoHandler and verify read is correct
        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 200, 1024);
        let resp = handler.poll_once();
        assert!(resp.is_err());
    }
    #[test]
    fn test_io_lower_read_error() {
        // Create random data
        let mut rng = thread_rng();
        let mut data: [u8; 2048] = [0; 2048];
        rng.fill(&mut data);
        let mut data_reader = Cursor::new(data.clone());

        // Build MockIO with a delayed sender
        let writer = |_: &[u8]| return Ok(0usize);
        let reader = |_: &mut [u8]| Err(std::io::Error::new(ErrorKind::TimedOut, "Timed out"));
        let mock_io = MockIo::new(reader, writer);

        // Build MockFramer
        let mock_framer = MockFramer::new(|buf| Ok(Bytes::copy_from_slice(buf)));

        // Build IoHandler and verify read is correct
        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 200, 1024);
        let resp = handler.poll_once();
        assert!(resp.is_err());
    }
    #[test]
    fn test_io_read_timeout() {
        // Create random data
        let mut rng = thread_rng();
        let mut data: [u8; 1024] = [0; 1024];
        rng.fill(&mut data);
        let mut data_reader = Cursor::new(data.clone());

        // Build MockIO with a delayed sender
        let writer = |_: &[u8]| return Ok(0usize);
        let reader = |buf: &mut [u8]| {
            std::thread::sleep(Duration::from_millis(200));
            data_reader.read(buf)
        };
        let mock_io = MockIo::new(reader, writer);

        // Build MockFramer
        let mock_framer = MockFramer::new(|buf| Ok(Bytes::copy_from_slice(buf)));

        // Build IoHandler and verify read is correct
        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 200, 1024);
        let resp = handler.poll_once();
        assert!(resp.is_ok());
        assert_ne!(resp.unwrap(), Bytes::copy_from_slice(&data));
    }

    /* SMDP PROTOCOL TESTING */
    #[test]
    fn test_smdp_protocol_valid_frame_read() {
        // Build valid frame to read and mock IO handler
        let addr = 0x10u8;
        let cmd_rsp = 0x81u8;
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let (chk1, chk2) = mod256_checksum_split(&data, addr, cmd_rsp);

        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(data.as_ref());
        frame.extend_from_slice(&[chk1, chk2]);
        frame.push(EDX);

        // Wrap vec to give it Read
        let mut data_reader = Cursor::new(frame.clone());

        // Given a buffer, the reader will push the bytes from the frame into it.
        // Writer is trivial as it is not being tested.
        let mock_io = MockIo::new(|buf| data_reader.read(buf), |_| Ok(0usize));

        // Build SmdpProtocl and give it the mock IO
        let mut proto: SmpdProtocol<_, SmdpPacketV2> = SmpdProtocol::new(mock_io, 200, 64);
        let packet = proto.poll_once();

        // Check deserialized packet against frame
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.addr(), addr);
        assert_eq!(packet.cmd_rsp(), cmd_rsp);
        assert_eq!(packet.data(), data);
        assert_eq!(packet.checksum_split(), (chk1, chk2));
    }

    #[test]
    fn test_smdp_protocol_valid_frame_write() {
        // Build valid frame to compare against serialized packet.
        let addr = 0x10u8;
        let cmd_rsp = 0x81u8;
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let (chk1, chk2) = mod256_checksum_split(&data, addr, cmd_rsp);

        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(data.as_ref());
        frame.extend_from_slice(&[chk1, chk2]);
        frame.push(EDX);

        // Build a packet
        let packet = SmdpPacketV2::new(addr, cmd_rsp, data.clone());

        // All value checking should be done in the writer, thats where the serialized bytes will
        // end up. Reader is trivial, it's not being tested.
        let mock_io = MockIo::new(
            |_| Ok(0usize),
            |buf| {
                assert_eq!(buf, frame);
                Ok(buf.len())
            },
        );

        // Build SmdpProtocl and give it the mock IO
        let mut proto: SmpdProtocol<_, SmdpPacketV2> = SmpdProtocol::new(mock_io, 200, 64);
        let _ = proto.write_once(&packet);
    }
}
