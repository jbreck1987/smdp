use std::time::Duration;

use crate::format::SmdpPacket;
use anyhow::{Context, Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};

/// Required methods for a Framer
// Bundling these into a trait for decoupling and easier testing.
trait Framer {}

/// Feedback to Reader on the state of the
/// Framer. Will not return partial packets since they are
/// to be ignored in the protocol.
enum FramerStatus {
    PacketTooLarge,
    PacketTooSmall,
    PacketComplete(Bytes),
    InvalidFormat,
}
/// Handles the framing logic for the SMDP protocol. The framer only validates
/// the structure of a stream of bytes and extracts candidate packets, it does no parsing
/// of fields (E.g. will not verify checksum).
struct SmdpFramer {}
/// Manages reading from a buffer, retries, timeouts, etc. This type does NOT
/// manage the actual handle to underlying I/O.
struct SmdpReader {
    framer: SmdpFramer,
    // Number of read retries if framer signals an intermediate state.
    retries: usize,
    // Timeout for one read operation
    read_timeout: Duration,
}
// Handles packet validation after receiving a candidate packet from the framer.
// Returns valid, deserialized SmdpPacket.
struct SmdpParser {}

/// Packages all the individual components to go from the wire to serialized SmdpPacket.
struct SmpdProtocol {}
