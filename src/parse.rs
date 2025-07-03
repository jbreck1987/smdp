use crate::format::SmdpPacket;
use anyhow::{Context, Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    io::{Read, Write},
    time::Duration,
};

/// Required methods for a Framer
trait Framer {
    /// Push bytes into Framer buffer.
    fn push_bytes(&mut self, data: &[u8]) -> FramerStatus;
    /// Called by Reader to signal finished status.
    fn finalize(&mut self) -> FramerStatus;
    /// Yields next valid frame if found.
    fn next_packet(&mut self) -> Option<Bytes>;
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
}
// Handles packet validation after receiving a candidate packet from the framer.
// Returns valid, deserialized SmdpPacket.
struct SmdpParser {
    framed_bytes: Bytes,
}

/// Packages all the individual components to go from the wire to serialized SmdpPacket.
struct SmpdProtocol {}

/// Function that parses a frame
fn parse_frame(frame: Bytes) -> Option<SmdpPacket> {
    todo!()
}
