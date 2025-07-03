use crate::format::{MIN_PKT_SIZE, SmdpPacket};
use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use std::{
    io::{Read, Write},
    time::Duration,
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
    Complete,
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
        // Look for STX:
        // If at least one found, set head of buf to idx
        // of STX with the highest idx. If none found, return InvalidFormat.
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
            .ok_or(anyhow!("Invalid format, EDX not found"))?;

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
            Ok(self.buf.split_to(edx_pos + 1).freeze())
        }
    }
}
/// Manages reading from bytes from IO and delegates protocol framing.
struct SmdpReader<T: Read + Write, F: Framer> {
    io_handle: T,
    framer: F,
    // Number of read retries if framer signals an intermediate state.
    retries: usize,
    // Timeout for one read operation
    read_timeout: Duration,
    // Size of read chunk when iterating over input buffer.
    read_chunk_size: usize,
    // Read buffer
    read_buf: Vec<u8>,
}
impl<T, F> SmdpReader<T, F>
where
    T: Read + Write,
    F: Framer,
{
    fn new(
        io_handle: T,
        framer: F,
        read_timeout: usize,
        num_retries: usize,
        read_chunk_size: usize,
        max_frame_size: usize,
    ) -> Self {
        todo!()
    }
    // Attempts to read and frame bytes after a request for one
    // candidate SMDP packet.
    fn poll_once(&mut self) -> Result<Bytes> {
        todo!()
    }
}

/// Packages all the individual components to go from the wire to serialized SmdpPacket.
pub struct SmpdProtocol<T: Read + Write> {
    reader: SmdpReader<T, SmdpFramer>,
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
