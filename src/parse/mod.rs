mod parse_sync;
pub use parse_sync::SmdpPacketHandler;

use crate::format::{EDX, MIN_PKT_SIZE, STX};
use bytes::Bytes;
use thiserror;

const READ_CHUNK_SIZE: usize = 512;

/// Required methods for a Framer. Primarily used for testing.
pub trait Framer {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Push bytes into Framer buffer for framing. Syncon is request/response, so
    /// there should only ever be one response frame per request.
    fn push_bytes(&mut self, data: &[u8]) -> Result<Bytes, Self::Error>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ParseError {
    #[error("Frame too small, got {size} bytes. Min: {}", MIN_PKT_SIZE)]
    FrameTooSmall { size: u8 },
    #[error("Max frame size overflow, got {recvd}. Max: {max}")]
    MaxSizeOverflow { max: usize, recvd: usize },
    #[error("{0}")]
    Framer(String),
    #[error("{0}")]
    InvalidFormat(String),
    #[error("{0}")]
    Other(String),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}
type ParseResult<T> = Result<T, ParseError>;

/// Handles the framing logic for the SMDP protocol. The framer validates
/// the structure of a stream of bytes and extracts a candidate packet, it does no parsing
/// of fields (E.g. will not verify checksum).
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct SmdpFramer {
    // Buffer that holds incoming bytes from the reader.
    buf: Vec<u8>,
}
impl SmdpFramer {
    pub(crate) fn new(max_size: usize) -> Self {
        Self {
            buf: Vec::with_capacity(max_size),
        }
    }
}
impl Framer for SmdpFramer {
    type Error = ParseError;

    fn push_bytes(&mut self, data: &[u8]) -> ParseResult<Bytes> {
        self.buf.clear();
        if data.len() == 0 {
            return Err(ParseError::FrameTooSmall { size: 0 });
        }
        // Look for STX:
        // If at least one found, find pos of STX with the highest idx.
        // If none found, return InvalidFormat.
        let stx_pos = data
            .iter()
            .rposition(|b| *b == STX)
            .ok_or(ParseError::InvalidFormat("STX not found".to_owned()))?;

        // Look for EDX starting from idx after the stx position:
        // If at least one found, find pos of EDX with the lowest idx. Append data from [STX, EDX].
        // If this would cause an overflow, return MaxSizeOverflow. If none found, return InvalidFormat.
        let edx_pos = data[stx_pos + 1..]
            .iter()
            .position(|b| *b == EDX)
            .ok_or(ParseError::InvalidFormat("EDX not found".to_owned()))?
            + (stx_pos + 1);

        if data[stx_pos..=edx_pos].len() <= self.buf.capacity() {
            self.buf.extend_from_slice(&data[stx_pos..=edx_pos]);
        } else {
            return Err(ParseError::MaxSizeOverflow {
                max: self.buf.capacity(),
                recvd: data[stx_pos..=edx_pos].len(),
            });
        }

        // Check for min length. If too small, clear buffer and return FrameTooSmall. Otherwise
        // return valid frame.
        if self.buf.len() < MIN_PKT_SIZE {
            let buf_len = self.buf.len();
            self.buf.clear();
            return Err(ParseError::FrameTooSmall {
                size: buf_len as u8,
            });
        } else {
            Ok(Bytes::copy_from_slice(&self.buf))
        }
    }
}
