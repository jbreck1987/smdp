use crate::format::SmdpPacket;
use anyhow::{Context, Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    io::{Read, Write},
    time::Duration,
};

/// Required methods for a Framer. Primarily used for testing.
trait Framer {
    /// Push bytes into Framer buffer.
    fn push_bytes(&mut self, data: &[u8]) -> FramerStatus;
    /// Called by Reader to signal finished status.
    fn finalize(&mut self) -> FramerStatus;
    /// Yields next valid frame if found.
    fn next_packet(&mut self) -> Result<Bytes>;
}

/// Feedback to Reader on the state of the
/// Framer. Will not return partial packets since they are
/// to be ignored in the protocol.
enum FramerStatus {
    PacketTooLarge,
    PacketTooSmall,
    InvalidFormat,
    Incomplete,
}
/// Handles the framing logic for the SMDP protocol. The framer only validates
/// the structure of a stream of bytes and extracts candidate packets, it does no parsing
/// of fields (E.g. will not verify checksum).
struct SmdpFramer {
    // Buffer that holds incoming bytes from the reader.
    buf: BytesMut,
    // Max size of the buffer/packet (including STX/ETX)
    max_size: usize,
}
impl Framer for SmdpFramer {
    fn push_bytes(&mut self, data: &[u8]) -> FramerStatus {
        todo!()
    }

    fn finalize(&mut self) -> FramerStatus {
        todo!()
    }

    fn next_packet(&mut self) -> Result<Bytes> {
        todo!()
    }
}
/// Manages reading from a buffer, retries, timeouts, etc.
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
    fn parse_frame(&mut self, frame: Bytes) -> Result<SmdpPacket> {
        // Verify Address is in-range
        // Verify fields of CMD_RSP byte are valid
        // Unescape Data field
        // Verify checksum
        // Deserialize into packet struct
        todo!()
    }
    /// Tries to read one SMDP packet from the wire after a request.
    pub fn poll_once(&mut self) -> Result<SmdpPacket> {
        todo!()
    }
}
