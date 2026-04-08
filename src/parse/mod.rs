mod parse_sync;
pub use parse_sync::SmdpPacketHandler;

use crate::format::{EDX, MIN_PKT_SIZE, STX};
use bytes::{Bytes, BytesMut};
use thiserror;

const READ_CHUNK_SIZE: usize = 512;

/// Required methods for a Framer. Primarily used for testing.
///
/// Framers accumulate bytes across calls and return `Ok(Some(frame))` once a
/// complete frame is detected, or `Ok(None)` when more data is needed.
/// This follows the same pattern as `tokio_util::codec::Decoder::decode`.
pub trait Framer {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Push bytes into the framer's internal buffer. Returns `Ok(Some(frame))`
    /// when a complete frame is found, `Ok(None)` when more data is needed.
    fn push_bytes(&mut self, data: &[u8]) -> Result<Option<Bytes>, Self::Error>;
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

/// Handles the framing logic for the SMDP protocol. The framer accumulates
/// bytes across calls via an internal `BytesMut` buffer and extracts a candidate
/// packet once both STX and EDX delimiters are present. It does no parsing
/// of fields (e.g. will not verify checksum).
#[derive(Debug, Clone)]
pub(crate) struct SmdpFramer {
    buf: BytesMut,
    max_size: usize,
}
impl SmdpFramer {
    pub(crate) fn new(max_size: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(max_size),
            max_size,
        }
    }
}
impl Framer for SmdpFramer {
    type Error = ParseError;

    fn push_bytes(&mut self, data: &[u8]) -> ParseResult<Option<Bytes>> {
        self.buf.extend_from_slice(data);

        if self.buf.len() > self.max_size {
            let recvd = self.buf.len();
            self.buf.clear();
            return Err(ParseError::MaxSizeOverflow {
                max: self.max_size,
                recvd,
            });
        }

        // Find latest STX (handles garbage/retransmits before the real frame)
        let Some(stx_pos) = self.buf.iter().rposition(|b| *b == STX) else {
            // No STX yet — discard everything
            self.buf.clear();
            return Ok(None);
        };

        // Find first EDX after that STX
        let Some(edx_offset) = self.buf[stx_pos + 1..].iter().position(|b| *b == EDX) else {
            // Have STX but no EDX yet — discard pre-STX garbage, wait for more
            if stx_pos > 0 {
                let _ = self.buf.split_to(stx_pos);
            }
            return Ok(None);
        };
        let edx_pos = stx_pos + 1 + edx_offset;
        let frame_len = edx_pos - stx_pos + 1;

        if frame_len < MIN_PKT_SIZE {
            // Discard the malformed frame
            let _ = self.buf.split_to(edx_pos + 1);
            return Err(ParseError::FrameTooSmall {
                size: frame_len as u8,
            });
        }

        // Discard pre-frame garbage, extract the frame
        let _ = self.buf.split_to(stx_pos);
        let frame = self.buf.split_to(frame_len).freeze();
        Ok(Some(frame))
    }
}
