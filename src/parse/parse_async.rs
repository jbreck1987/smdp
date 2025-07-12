use super::*;
use crate::SmdpPacketV2;
use crate::error::{Error, SmdpResult};
use crate::format::{CommandCode, PacketFormat};
use bytes::{Buf, BufMut, Bytes};
use std::time::{Duration, Instant};
use tokio::{
    self,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ErrorKind},
};

/// Manages reading/writing bytes to/from IO and delegate reads to protocol framer.
/// Only uses the basic Read/Write API, customization is up to the caller.
#[derive(Debug)]
struct IoHandlerAsync<T: AsyncRead + AsyncWrite, F: Framer> {
    io_handle: T,
    framer: F,
    // Timeout for one read operation in milliseconds.
    read_timeout_ms: Duration,
    // Read buffer
    read_buf: Vec<u8>,
    // Chunk buffer
    chunk: [u8; READ_CHUNK_SIZE],
}
impl<T, F> IoHandlerAsync<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin,
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
    async fn poll_once(&mut self) -> SmdpResult<Bytes> {
        let bytes_read = self.read_frame().await.map_err(Error::into_parse)?;
        // Attempt to frame bytes that were read
        self.framer
            .push_bytes(&self.read_buf[..bytes_read])
            .map_err(Error::into_parse)
    }
    async fn poll_once_with_framer<F2: Framer>(&mut self, framer: &mut F2) -> SmdpResult<Bytes> {
        let bytes_read = self.read_frame().await.map_err(Error::into_parse)?;
        // Attempt to frame bytes that were read
        framer
            .push_bytes(&self.read_buf[..bytes_read])
            .map_err(Error::into_parse)
    }
    // Reads bytes from the low-level I/O handle
    async fn read_frame(&mut self) -> ParseResult<usize> {
        self.read_buf.fill(0);
        let timer = Instant::now();
        let mut total_bytes_read = 0usize;

        // Canonical chunked read loop
        while timer.elapsed() < self.read_timeout_ms {
            match self.io_handle.read(&mut self.chunk).await {
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
                        return Err(ParseError::MaxSizeOverflow {
                            max: self.read_buf.capacity(),
                            recvd: total_bytes_read + n_read,
                        });
                    }
                }
                // Chunk read blocked, continue to next chunk read
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                // In case the handler does not send EOF appropriately
                Err(ref e) if e.kind() == ErrorKind::TimedOut => continue,
                Err(e) => {
                    return Err(ParseError::IOError(e));
                }
            }
        }
        Ok(total_bytes_read)
    }
    /// Delegates `write_all` functionality to inner IO handle
    async fn write_all(&mut self, bytes: &[u8]) -> SmdpResult<()> {
        self.io_handle
            .write_all(bytes)
            .await
            .map_err(Error::into_parse)
    }
}

/// Packages all the individual components to go to/from the IO from/to serialized SmdpPacket.
#[derive(Debug)]
pub struct SmdpPacketHandlerAsync<T: AsyncRead + AsyncWrite + Unpin> {
    io_handler: IoHandlerAsync<T, SmdpFramer>,
}
impl<T> SmdpPacketHandlerAsync<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io_handle: T, read_timeout_ms: usize, max_frame_size: usize) -> Self {
        let framer = SmdpFramer::new(max_frame_size);
        let handler = IoHandlerAsync::new(io_handle, framer, read_timeout_ms, max_frame_size);
        Self {
            io_handler: handler,
        }
    }
    /// Attempts to read one SMDP packet from the IO handle after a request using the
    /// default Framer.
    pub async fn poll_once<P: PacketFormat>(&mut self) -> SmdpResult<P> {
        let frame = self.io_handler.poll_once().await?;
        P::from_bytes(frame.as_ref()).map_err(Error::into_parse)
    }
    /// Attempts to read one SMDP packet from the IO handle after a request using
    /// Framer passed by caller.
    pub async fn poll_once_with_framer<P: PacketFormat, F: Framer>(
        &mut self,
        framer: &mut F,
    ) -> SmdpResult<P> {
        let frame = self.io_handler.poll_once_with_framer(framer).await?;
        P::from_bytes(frame.as_ref()).map_err(Error::into_parse)
    }
    /// Attempts to write one SMDP packet to the underlying IO handle.
    pub async fn write_once<P: PacketFormat>(&mut self, packet: &P) -> SmdpResult<()> {
        let bytes = packet.to_bytes_vec().map_err(Error::into_parse)?;
        self.io_handler.write_all(&bytes).await?;
        Ok(())
    }
    /// Attempts to poll the slave to return the Sycon product ID, returned as decimal string,
    /// using the well-known opcode 0x30. Uses V2 format.
    pub async fn product_id(&mut self, addr: u8) -> SmdpResult<String> {
        let cmd_code: u8 = CommandCode::ProdId.try_into()?;
        let resp = self.well_known_opcode_helper(addr, cmd_code).await?;
        Ok(String::from_utf8(resp).map_err(Error::into_parse)?)
    }
    /// Attempts to poll the slave to return its software version, returned as decimal string,
    /// using the well-known opcode 0x40. Uses V2 format.
    pub async fn sw_ver(&mut self, addr: u8) -> SmdpResult<String> {
        let cmd_code: u8 = CommandCode::SwVersion.try_into()?;
        let resp = self.well_known_opcode_helper(addr, cmd_code).await?;
        Ok(String::from_utf8(resp).map_err(Error::into_parse)?)
    }
    /// Attempts to instruct slave to reset using the well-known opcode 0x50. Uses V2 format.
    pub async fn reset(&mut self, addr: u8) -> SmdpResult<()> {
        let cmd_code: u8 = CommandCode::Reset.try_into()?;
        let _ = self.well_known_opcode_helper(addr, cmd_code).await?;
        Ok(())
    }
    /// Acknowledges the receipt of an RSPF bit set from a slave using the well-known opcode 0x60.
    /// Uses V2 format.
    pub async fn clear_rspf(&mut self, addr: u8) -> SmdpResult<()> {
        let cmd_code: u8 = CommandCode::AckPf.try_into()?;
        let _ = self.well_known_opcode_helper(addr, cmd_code).await?;
        Ok(())
    }
    /// Attempts to poll the slave to return its protocl stack version, returned as decimal string,
    /// using the well-known opcode 0x70. Uses V2 format.
    pub async fn proto_ver(&mut self, addr: u8) -> SmdpResult<String> {
        let cmd_code: u8 = CommandCode::ProcotolVer.try_into()?;
        let resp = self.well_known_opcode_helper(addr, cmd_code).await?;
        Ok(String::from_utf8(resp).map_err(Error::into_parse)?)
    }
    /// Private helper for the well-known opcode requests
    async fn well_known_opcode_helper(&mut self, addr: u8, code: u8) -> SmdpResult<Vec<u8>> {
        let v2_pkt = SmdpPacketV2::new(addr, code << 4, vec![]);
        self.write_once(&v2_pkt).await?;
        let resp: SmdpPacketV2 = self.poll_once().await?;

        // Make sure there are errors in the RSP field
        let resp_result = match resp.rsp()? {
            crate::format::ResponseCode::Ok => Ok(()),
            crate::format::ResponseCode::ErrInvalidCmd => Err("Invalid command"),
            crate::format::ResponseCode::ErrSyntax => Err("Syntax error"),
            crate::format::ResponseCode::ErrRange => Err("Range error"),
            crate::format::ResponseCode::ErrInhibited => Err("Inhibited"),
            crate::format::ResponseCode::ErrObsolete => Err("Obsolete comand"),
            crate::format::ResponseCode::Reserved => Err("Rsp value 0x00 is reserved"),
        };
        match resp_result {
            Ok(_) => Ok(resp.data().to_vec()),
            Err(e) => {
                return Err(Error::into_parse(ParseError::Other(format!(
                    "Received non-OK RSP value in response: {}",
                    e
                ))));
            }
        }
    }
}
