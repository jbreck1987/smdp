use super::*;
use crate::SmdpPacketV2;
use crate::error::{Error, SmdpResult};
use crate::format::{CommandCode, PacketFormat, ResponseCode};
use bytes::Bytes;
use std::{
    io::{ErrorKind, Read, Write},
    time::{Duration, Instant},
};

/// Manages reading/writing bytes to/from IO and delegate reads to protocol framer.
/// Only uses the basic Read/Write API, customization is up to the caller.
#[derive(Debug)]
struct SmdpIoHandler<T: Read + Write, F: Framer> {
    io_handle: T,
    framer: F,
    /// Timeout for one read operation in milliseconds. This is the primary value that affects the responsiveness
    /// of the handler.
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
    /// Read bytes into buffer until timeout.
    fn poll_once(&mut self) -> ParseResult<Bytes> {
        let bytes_read = self.read_frame()?;
        // Attempt to frame bytes that were read
        self.framer
            .push_bytes(&self.read_buf[..bytes_read])
            .map_err(|e| ParseError::Framer(e.to_string()))
    }
    /// Read bytes into buffer until timeout with custom framer.
    fn poll_once_with_framer<F2: Framer>(&mut self, framer: &mut F2) -> ParseResult<Bytes> {
        let bytes_read = self.read_frame()?;
        // Attempt to frame bytes that were read
        framer
            .push_bytes(&self.read_buf[..bytes_read])
            .map_err(|e| ParseError::Framer(e.to_string()))
    }
    // Reads bytes from the low-level I/O handle
    fn read_frame(&mut self) -> ParseResult<usize> {
        self.read_buf.fill(0);
        let timer = Instant::now();
        let mut total_bytes_read = 0usize;

        // Canonical chunked read loop
        while timer.elapsed() < self.read_timeout_ms {
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
                        return Err(ParseError::MaxSizeOverflow {
                            max: self.read_buf.capacity(),
                            recvd: total_bytes_read + n_read,
                        });
                    }
                }
                // Chunk read blocked, continue to next chunk read
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                // In case the low-level handler does not send EOF appropriately
                Err(ref e) if e.kind() == ErrorKind::TimedOut => continue,
                Err(e) => {
                    return Err(ParseError::IOError(e));
                }
            }
        }
        Ok(total_bytes_read)
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
        let handler = SmdpIoHandler::new(io_handle, framer, read_timeout_ms, max_frame_size);
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
    use std::{
        io::Cursor,
        sync::mpsc::{Sender, TryRecvError},
        thread::JoinHandle,
    };

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

        // Build MockIO with a delayed sender
        let writer = |_: &[u8]| return Ok(0usize);
        let reader = |_: &mut [u8]| Err(std::io::Error::new(ErrorKind::Interrupted, "Interrupted"));
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

        // Create a thread that simulates a delayed sender (200ms between sends)
        let (tx1, rx1) = std::sync::mpsc::channel();
        let (tx2, rx2) = std::sync::mpsc::channel();
        enum Signal {
            End,
        }

        let jh: JoinHandle<()> = std::thread::spawn(move || {
            loop {
                _ = tx2.send(());
                std::thread::sleep(Duration::from_millis(200));
                match rx1.try_recv() {
                    Ok(Signal::End) => break,
                    Err(ref e) if *e == TryRecvError::Empty => continue,
                    _ => break,
                }
            }
        });

        // Build MockIO with a delayed sender
        let writer = |_: &[u8]| return Ok(0usize);
        let main_tx1 = Sender::clone(&tx1);
        let reader = |buf: &mut [u8]| {
            if let Ok(_) = rx2.try_recv() {
                let n_read = data_reader.read(buf).unwrap();
                Ok(n_read)
            } else {
                return Err(std::io::Error::new(ErrorKind::WouldBlock, "Would block"));
            }
        };
        let mock_io = MockIo::new(reader, writer);

        // Build MockFramer
        let mock_framer = MockFramer::new(|buf| Ok(Bytes::copy_from_slice(buf)));

        // Build IoHandler with short read timeout and verify recvd bytes are incomplete.
        let mut handler = SmdpIoHandler::new(mock_io, mock_framer, 20, 1024);
        let resp = handler.poll_once();
        assert_ne!(resp.unwrap().as_ref(), data);
        _ = main_tx1.send(Signal::End);
        _ = jh.join();
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
