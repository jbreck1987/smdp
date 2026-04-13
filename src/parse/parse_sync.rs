use super::*;
use crate::SmdpPacketV2;
use crate::error::{Error, SmdpResult};
use crate::format::{CommandCode, PacketFormat, ResponseCode};
use bytes::Bytes;
use std::{
    io::{ErrorKind, Read, Write},
    time::{Duration, Instant},
};

/// Manages reading/writing bytes to/from IO and delegates reads to protocol framer.
/// Only uses the basic Read/Write API, customization is up to the caller.
///
/// The framer accumulates bytes across chunk reads and signals completion as soon
/// as a full frame is detected, so the read timeout is a ceiling for error cases
/// rather than the expected read duration.
#[derive(Debug)]
struct SmdpIoHandler<T: Read + Write, F: Framer> {
    io_handle: T,
    framer: F,
    /// Maximum time to wait for a complete frame. Successful reads return as
    /// soon as the framer detects a complete STX...EDX frame.
    read_timeout_ms: Duration,
    // Chunk buffer for individual reads
    chunk: [u8; READ_CHUNK_SIZE],
}
impl<T, F> SmdpIoHandler<T, F>
where
    T: Read + Write,
    F: Framer,
{
    fn new(io_handle: T, framer: F, read_timeout_ms: usize) -> Self {
        Self {
            io_handle,
            framer,
            read_timeout_ms: Duration::from_millis(read_timeout_ms as u64),
            chunk: [0; READ_CHUNK_SIZE],
        }
    }
    /// Read bytes and push them to the framer until a complete frame is found
    /// or the timeout expires.
    fn poll_once(&mut self) -> ParseResult<Bytes> {
        self.poll_loop(&mut None::<&mut F>)
    }
    /// Read bytes and push them to a caller-supplied framer until a complete frame
    /// is found or the timeout expires.
    fn poll_once_with_framer<F2: Framer>(&mut self, framer: &mut F2) -> ParseResult<Bytes> {
        self.poll_loop(&mut Some(framer))
    }
    /// Shared read loop. Pushes each chunk to either the caller-supplied framer
    /// or the internal one, returning as soon as a complete frame is detected.
    fn poll_loop<F2: Framer>(&mut self, ext_framer: &mut Option<&mut F2>) -> ParseResult<Bytes> {
        let timer = Instant::now();

        while timer.elapsed() < self.read_timeout_ms {
            match self.io_handle.read(&mut self.chunk) {
                Ok(0) => break,
                Ok(n_read) => {
                    let result = if let Some(f) = ext_framer {
                        f.push_bytes(&self.chunk[..n_read])
                            .map_err(|e| ParseError::Framer(e.to_string()))
                    } else {
                        self.framer
                            .push_bytes(&self.chunk[..n_read])
                            .map_err(|e| ParseError::Framer(e.to_string()))
                    };
                    match result? {
                        Some(frame) => return Ok(frame),
                        None => continue,
                    }
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(ref e) if e.kind() == ErrorKind::TimedOut => continue,
                Err(e) => return Err(ParseError::IOError(e)),
            }
        }
        Err(ParseError::Framer("Read timed out waiting for complete frame".to_owned()))
    }
    /// Delegates `write_all` functionality to inner IO handle
    fn write_all(&mut self, bytes: &[u8]) -> ParseResult<()> {
        self.io_handle.write_all(bytes).map_err(ParseError::IOError)
    }
}

/// Packages all the individual components to go to/from the IO from/to serialized SmdpPacket
/// using the default framer.
#[derive(Debug)]
pub struct SmdpPacketHandler<T: Read + Write> {
    io_handler: SmdpIoHandler<T, SmdpFramer>,
}
impl<T> SmdpPacketHandler<T>
where
    T: Read + Write,
{
    pub fn new(io_handle: T, read_timeout_ms: usize, max_frame_size: usize) -> Self {
        let framer = SmdpFramer::new(max_frame_size);
        let handler = SmdpIoHandler::new(io_handle, framer, read_timeout_ms);
        Self {
            io_handler: handler,
        }
    }
    /// Attempts to read one SMDP packet from the IO handle after a request using the
    /// default Framer.
    pub fn poll_once<P: PacketFormat>(&mut self) -> SmdpResult<P> {
        let frame = self.io_handler.poll_once().map_err(|e| match e {
            ParseError::IOError(e) => Error::into_io(e),
            err => Error::into_parse(err),
        })?;
        P::from_bytes(frame.as_ref()).map_err(Error::into_parse)
    }
    /// Attempts to read one SMDP packet from the IO handle after a request using
    /// Framer passed by caller.
    pub fn poll_once_with_framer<P: PacketFormat, F: Framer>(
        &mut self,
        framer: &mut F,
    ) -> SmdpResult<P> {
        let frame = self
            .io_handler
            .poll_once_with_framer(framer)
            .map_err(|e| match e {
                ParseError::IOError(e) => Error::into_io(e),
                err => Error::into_parse(err),
            })?;
        P::from_bytes(frame.as_ref()).map_err(Error::into_parse)
    }
    /// Attempts to write one SMDP packet to the underlying IO handle.
    pub fn write_once<P: PacketFormat>(&mut self, packet: &P) -> SmdpResult<()> {
        let bytes = packet.to_bytes_vec().map_err(Error::into_parse)?;
        self.io_handler.write_all(&bytes).map_err(Error::into_io)?;
        Ok(())
    }
    /// Attempts to poll the slave to return the Sycon product ID, returned as decimal string,
    /// using the well-known opcode 0x30. Uses V2 format.
    pub fn product_id(&mut self, addr: u8) -> SmdpResult<String> {
        let cmd_code: u8 = CommandCode::ProdId.try_into()?;
        let resp = self.well_known_opcode_helper(addr, cmd_code)?;
        Ok(String::from_utf8(resp).map_err(Error::into_parse)?)
    }
    /// Attempts to poll the slave to return its software version, returned as decimal string,
    /// using the well-known opcode 0x40. Uses V2 format.
    pub fn sw_ver(&mut self, addr: u8) -> SmdpResult<String> {
        let cmd_code: u8 = CommandCode::SwVersion.try_into()?;
        let resp = self.well_known_opcode_helper(addr, cmd_code)?;
        Ok(String::from_utf8(resp).map_err(Error::into_parse)?)
    }
    /// Attempts to instruct slave to reset using the well-known opcode 0x50. Uses V2 format.
    pub fn reset(&mut self, addr: u8) -> SmdpResult<()> {
        let cmd_code: u8 = CommandCode::Reset.try_into()?;
        let _ = self.well_known_opcode_helper(addr, cmd_code)?;
        Ok(())
    }
    /// Acknowledges the receipt of an RSPF bit set from a slave using the well-known opcode 0x60.
    /// Uses V2 format.
    pub fn clear_rspf(&mut self, addr: u8) -> SmdpResult<()> {
        let cmd_code: u8 = CommandCode::AckPf.try_into()?;
        let _ = self.well_known_opcode_helper(addr, cmd_code)?;
        Ok(())
    }
    /// Attempts to poll the slave to return its protocl stack version, returned as decimal string,
    /// using the well-known opcode 0x70. Uses V2 format.
    pub fn proto_ver(&mut self, addr: u8) -> SmdpResult<String> {
        let cmd_code: u8 = CommandCode::ProcotolVer.try_into()?;
        let resp = self.well_known_opcode_helper(addr, cmd_code)?;
        Ok(String::from_utf8(resp).map_err(Error::into_parse)?)
    }
    /// Private helper for the well-known opcode requests
    fn well_known_opcode_helper(&mut self, addr: u8, code: u8) -> SmdpResult<Vec<u8>> {
        let v2_pkt = SmdpPacketV2::new(addr, code << 4, vec![]);
        self.write_once(&v2_pkt)?;
        let resp: SmdpPacketV2 = self.poll_once()?;
        match resp.rsp()? {
            ResponseCode::Ok => Ok(resp.data().to_vec()),
            other => {
                return Err(Error::into_parse(ParseError::InvalidFormat(format!(
                    "Received non-OK RSP value in response: {}",
                    other
                ))));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        format::{SmdpPacketV2, mod256_checksum_split_v2},
        test_utils::*,
    };
    use rand::{Rng, thread_rng};
    use std::io::Cursor;

    /* FRAMER TESTING */
    #[test]
    fn test_one_stx_one_edx() {
        let mut framer = make_framer();
        let data = vec![STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX];
        let frame = framer.push_bytes(&data).unwrap().unwrap();
        assert_eq!(
            frame,
            Bytes::from(vec![STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX])
        );
    }

    #[test]
    fn test_multiple_stx_one_edx() {
        let mut framer = make_framer();
        let data = vec![EDX, EDX, 0x09, STX, STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX];
        let frame = framer.push_bytes(&data).unwrap().unwrap();
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
        let frame = framer.push_bytes(&data).unwrap().unwrap();
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
        let frame = framer.push_bytes(&data).unwrap().unwrap();
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
        let frame = framer.push_bytes(&data).unwrap().unwrap();
        // Should start from the last STX and end at the first EDX after it
        assert_eq!(
            frame,
            Bytes::from(vec![STX, 0x10, 0x19, 0x45, 0x20, 0x30, 0x40, 0x50, EDX])
        );
    }

    #[test]
    fn test_framer_accumulates_across_pushes() {
        let mut framer = make_framer();
        // Push STX + partial payload — no EDX yet
        assert!(framer.push_bytes(&[STX, 0x10, 0x20]).unwrap().is_none());
        // Push rest of payload + EDX — frame should complete
        let frame = framer.push_bytes(&[0x30, 0x40, 0x50, EDX]).unwrap().unwrap();
        assert_eq!(
            frame,
            Bytes::from(vec![STX, 0x10, 0x20, 0x30, 0x40, 0x50, EDX])
        );
    }

    #[test]
    fn test_framer_returns_none_without_stx() {
        let mut framer = make_framer();
        assert!(framer.push_bytes(&[0x10, 0x20, 0x30]).unwrap().is_none());
    }

    #[test]
    fn test_framer_returns_none_with_stx_but_no_edx() {
        let mut framer = make_framer();
        assert!(framer.push_bytes(&[STX, 0x10, 0x20]).unwrap().is_none());
    }
    /* IOHANDLER TESTING */
    #[test]
    fn test_io_early_return_on_frame() {
        // MockFramer returns Some on every push, so poll_once should return
        // immediately after the first chunk rather than waiting for the timeout.
        let mut rng = thread_rng();
        let mut data: [u8; 20] = [0; 20];
        rng.fill(&mut data);
        let mut data_reader = Cursor::new(data.clone());

        let mock_io = MockIo::new(
            |buf| data_reader.read(buf),
            |_| Ok(0usize),
        );
        let mock_framer = MockFramer::new(|buf| Ok(Some(Bytes::copy_from_slice(buf))));

        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 200);
        let start = Instant::now();
        let resp = handler.poll_once();
        let elapsed = start.elapsed();

        assert!(resp.is_ok());
        assert_eq!(resp.unwrap(), Bytes::copy_from_slice(&data));
        // Should return well before the 200ms timeout
        assert!(elapsed < Duration::from_millis(50));
    }

    #[test]
    fn test_io_early_return_with_chunk_delay() {
        // Even with a 50ms delay per IO read, poll_once should return after
        // the first successful chunk rather than collecting until timeout.
        let mut rng = thread_rng();
        let mut data: [u8; 20] = [0; 20];
        rng.fill(&mut data);
        let mut data_reader = Cursor::new(data.clone());

        let mock_io = MockIo::new(
            |buf| {
                std::thread::sleep(Duration::from_millis(50));
                data_reader.read(buf)
            },
            |_| Ok(0usize),
        );
        let mock_framer = MockFramer::new(|buf| Ok(Some(Bytes::copy_from_slice(buf))));

        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 500);
        let start = Instant::now();
        let resp = handler.poll_once();
        let elapsed = start.elapsed();

        assert!(resp.is_ok());
        assert_eq!(resp.unwrap(), Bytes::copy_from_slice(&data));
        // Should return after ~50ms (one read), not the full 500ms timeout
        assert!(elapsed < Duration::from_millis(200));
    }

    #[test]
    fn test_io_timeout_when_framer_never_completes() {
        // Framer always returns None — poll_once should time out.
        let mock_io = MockIo::new(
            |_| Err(std::io::Error::new(ErrorKind::WouldBlock, "Would block")),
            |_| Ok(0usize),
        );
        let mock_framer = MockFramer::new(|_| Ok(None));

        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 20);
        let resp = handler.poll_once();
        assert!(resp.is_err());
    }

    #[test]
    fn test_io_lower_read_error() {
        let mock_io = MockIo::new(
            |_| Err(std::io::Error::new(ErrorKind::Interrupted, "Interrupted")),
            |_| Ok(0usize),
        );
        let mock_framer = MockFramer::new(|buf| Ok(Some(Bytes::copy_from_slice(buf))));

        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 200);
        let resp = handler.poll_once();
        assert!(resp.is_err());
    }

    #[test]
    fn test_io_eof_before_frame_is_error() {
        // IO returns EOF immediately (empty cursor) — no frame possible.
        let mut data_reader = Cursor::new(Vec::<u8>::new());
        let mock_io = MockIo::new(
            |buf| data_reader.read(buf),
            |_| Ok(0usize),
        );
        let mock_framer = MockFramer::new(|buf| Ok(Some(Bytes::copy_from_slice(buf))));

        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 200);
        let resp = handler.poll_once();
        assert!(resp.is_err());
    }

    /* SMDP PROTOCOL TESTING */
    #[test]
    fn test_smdp_protocol_valid_frame_read() {
        // Build valid frame to read and mock IO handler
        let addr = 0x10u8;
        let cmd_rsp = 0x81u8;
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let (chk1, chk2) = mod256_checksum_split_v2(&data, addr, cmd_rsp);

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
        let mut proto = SmdpPacketHandler::new(mock_io, 200, 64);
        let packet = proto.poll_once();

        // Check deserialized packet against frame
        assert!(packet.is_ok());
        let packet: SmdpPacketV2 = packet.unwrap();
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
        let (chk1, chk2) = mod256_checksum_split_v2(&data, addr, cmd_rsp);

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
        let mut proto = SmdpPacketHandler::new(mock_io, 200, 64);
        let _ = proto.write_once(&packet);
    }
}
