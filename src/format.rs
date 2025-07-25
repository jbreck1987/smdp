/* Handles both versions of the SMDP frame formatting */

use crate::error::{Error, SmdpResult};
use bitfield::{Bit, BitRange};
use bytes::{Buf, BytesMut};
use std::{fmt::Display, io::Write};
use thiserror;

// Since the protocol is binary transparent, STX and carriage
// return characters are not allowed in the data field. Need escape character plus
// a way to signal '\r' and 0x02.
pub(crate) const ESCAPE_CHAR: u8 = 0x07;
pub(crate) const HEX_02_ESC: u8 = 0x30; // ASCII '0'
pub(crate) const HEX_0D_ESC: u8 = 0x31; // ASCII '1'
pub(crate) const HEX_07_ESC: u8 = 0x32; // ASCII '2'

pub(crate) const MIN_PKT_SIZE: usize = 6;
pub(crate) const STX: u8 = 0x02;
pub(crate) const EDX: u8 = 0x0D;

#[derive(thiserror::Error, Debug)]
pub enum FormatError {
    #[error("Buffer too small for serialization.")]
    BufTooSmall,
    #[error("{recvd} is an invalid address. Valid addresses are 16 - 254")]
    InvalidAddress { recvd: u8 },
    #[error("CMD field invalid.")]
    InvalidCmd,
    #[error("RSP field invalid.")]
    InvalidRsp,
    #[error("Invalid escaped value: {recvd}")]
    InvalidEscapedVal { recvd: u8 },
    #[error("Invalid SRLNO {recvd}: Valid addresses are 17 - 255")]
    InvalidSrlNo { recvd: u8 },
    #[error("Checksum Mismatch")]
    ChecksumMismatch,
}

// Traits used to handle packet format versioning
pub trait SerizalizePacket {
    type SerializerError: std::error::Error + Send + Sync + 'static;

    fn to_bytes_into(&self, buf: &mut impl Write) -> Result<(), Self::SerializerError>;

    /// Optional, default convenience method returning owned buffer
    fn to_bytes_vec(&self) -> Result<Vec<u8>, Self::SerializerError> {
        let mut ret: Vec<u8> = Vec::with_capacity(64);
        self.to_bytes_into(&mut ret)?;
        Ok(ret)
    }
}
pub trait DeserializePacket: Sized {
    type DeserializerError: std::error::Error + Send + Sync + 'static;

    fn from_bytes(buf: &[u8]) -> Result<Self, Self::DeserializerError>;
}
/// Convenience marker trait with blanket implementation
/// coupling SerizalizePacket and DeserializePacket
pub trait PacketFormat: DeserializePacket + SerizalizePacket {}
impl<T: SerizalizePacket + DeserializePacket> PacketFormat for T {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ResponseCode {
    /// Command understood and executed. 0x01
    Ok,
    /// Illegal command (CMD code not valid). 0x02
    ErrInvalidCmd,
    /// Syntax error. (too many bytes in data field, not enough bytes, etc). 0x03
    ErrSyntax,
    /// Data range error. 0x04
    ErrRange,
    /// Inhibited. 0x05
    ErrInhibited,
    /// Obsolete command. No action taken, but not really an error. 0x07
    ErrObsolete,
    /// Reserved for future protocol stack use. 0x07
    Reserved,
}
impl TryFrom<u8> for ResponseCode {
    type Error = Error;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        let res = match code {
            0x01 => ResponseCode::Ok,
            0x02 => ResponseCode::ErrInvalidCmd,
            0x03 => ResponseCode::ErrSyntax,
            0x04 => ResponseCode::ErrRange,
            0x05 => ResponseCode::ErrInhibited,
            0x06 => ResponseCode::ErrObsolete,
            0x07 => ResponseCode::Reserved,
            _ => return Err(Error::into_format(FormatError::InvalidRsp)),
        };
        Ok(res)
    }
}
impl Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ResponseCode::Ok => "Ok",
            ResponseCode::ErrInvalidCmd => "Invalid Command",
            ResponseCode::ErrSyntax => "Invalid syntax",
            ResponseCode::ErrRange => "Data range error",
            ResponseCode::ErrInhibited => "Inhibited",
            ResponseCode::ErrObsolete => "Obsolete Command",
            ResponseCode::Reserved => "Reserved response code value",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CommandCode {
    /// Reserved for future protocol stack use. 0x01
    ReservedOne,
    /// Reserved for future protocol stack use. 0x02
    ReservedTwo,
    /// Product ID, returned as decimal string. 0x03
    ProdId,
    /// Request slave to return software version string. 0x04
    SwVersion,
    /// Request slave to reset. 0x05
    Reset,
    /// Request slave to clear RSPF bit/flag. 0x06
    AckPf,
    /// Request slave to return protocol stack version as decimal string. 0x07
    ProcotolVer,
    /// Available for application use.
    App(u8),
}
impl TryFrom<u8> for CommandCode {
    type Error = Error;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        let res = match code {
            0x01 => CommandCode::ReservedOne,
            0x02 => CommandCode::ReservedTwo,
            0x03 => CommandCode::ProdId,
            0x04 => CommandCode::SwVersion,
            0x05 => CommandCode::Reset,
            0x06 => CommandCode::AckPf,
            0x07 => CommandCode::ProcotolVer,
            c @ 0x08..=0x0F => CommandCode::App(c),
            _ => return Err(Error::into_format(FormatError::InvalidCmd)),
        };
        Ok(res)
    }
}
impl TryFrom<CommandCode> for u8 {
    type Error = Error;
    fn try_from(code: CommandCode) -> Result<Self, Self::Error> {
        match code {
            CommandCode::ReservedOne => Ok(0x01),
            CommandCode::ReservedTwo => Ok(0x02),
            CommandCode::ProdId => Ok(0x03),
            CommandCode::SwVersion => Ok(0x04),
            CommandCode::Reset => Ok(0x05),
            CommandCode::AckPf => Ok(0x06),
            CommandCode::ProcotolVer => Ok(0x07),
            CommandCode::App(c) => {
                if (0x08u8..=0x0F).contains(&c) {
                    Ok(c)
                } else {
                    Err(Error::into_format(FormatError::InvalidCmd))
                }
            }
        }
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
struct CommandResponse(u8);
impl CommandResponse {
    /// CMD = Command. These are the commands the master can issue to the slave. All
    /// Sycon products must respond to commands in the range of 1-7. CMDS 1-7 are
    /// handled in the protocol, at the protocol layer. Applications are not to use
    /// commands 1-7 except to implement the protocol specification. CMD codes 8-15
    /// are set aside for product application specific use.
    pub(crate) fn cmd(&self) -> SmdpResult<CommandCode> {
        let code: u8 = self.0.bit_range(7, 4);
        code.try_into()
    }
    /// Response Flag? Going from master to slave, RSPF
    /// bit is zero. From slave to master if this bit is 1, then the slave
    /// has been reset since the last ack power fail flag was received.
    pub(crate) fn rspf(&self) -> bool {
        self.0.bit(3)
    }
    /// Once the packet is sent to the slave, the slave receives and acknowledges the
    /// packet, and sends it’s response. In the CMD_RSP byte, the CMD bits are
    /// unchanged from the master, but the RSP bits are filled in according to the status
    /// of the slave (from table)
    pub(crate) fn rsp(&self) -> SmdpResult<ResponseCode> {
        let code: u8 = self.0.bit_range(2, 0);
        code.try_into()
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SmdpPacketV2 {
    /// Start of text character (hex 02). Multiple STX characters in a row are allowed.
    /// Similarly, any data between STX characters is ignored. A single STX character
    /// syncs the receiver up to receive a new message, purging any data collected since
    /// the last STX char or carriage return received.
    stx: u8,
    /// Address field. This is a one byte field. Valid ranges of a valid address are 10 hex
    /// to FE hex (16 to 254 decimal). Addresses less than 10 hex are not allowed as they
    /// may be mistaken for framing characters. An address of FF hex is reserved as it is
    /// used as an extention, to indicate another byte of address information follows, for
    /// products that have an address range higher than an address of FE hex.
    addr: u8,
    /// Command/Response field. When packet is going from master to slave, RSPF
    /// bit is zero, and the RSP field (3 bits) is zero. When packet is going from slave to
    /// master, CMD bits are the same as in the message that was sent, but the RSP field
    /// will be non-zero (indicating actual unit response status). This allows the direction
    /// to be positively indicated, as well as the command preserved on the return reply.
    cmd_rsp: CommandResponse,
    data: Vec<u8>,
    checksum_1: u8,
    checksum_2: u8,
}
impl SmdpPacketV2 {
    pub fn new(addr: u8, cmd_rsp: u8, data: Vec<u8>) -> Self {
        let (checksum_1, checksum_2) = mod256_checksum_split_v2(&data, addr, cmd_rsp);
        Self {
            stx: 0x02,
            addr,
            cmd_rsp: CommandResponse(cmd_rsp),
            data,
            checksum_1,
            checksum_2,
        }
    }
    /// Getter for the Address field
    pub fn addr(&self) -> u8 {
        self.addr
    }
    /// Getter for the CMD_RSP field
    pub fn cmd_rsp(&self) -> u8 {
        self.cmd_rsp.0
    }
    /// Getter for the CMD value
    pub fn cmd(&self) -> SmdpResult<CommandCode> {
        self.cmd_rsp.cmd()
    }
    /// Getter for the RSP value
    pub fn rsp(&self) -> SmdpResult<ResponseCode> {
        self.cmd_rsp.rsp()
    }
    /// Getter for the RSPF value
    pub fn rspf(&self) -> bool {
        self.cmd_rsp.rspf()
    }
    /// Getter for the data bytes
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
    /// Getter for the split checksum
    pub fn checksum_split(&self) -> (u8, u8) {
        (self.checksum_1, self.checksum_2)
    }
}
impl SerizalizePacket for SmdpPacketV2 {
    type SerializerError = Error;
    /// Serializes the packet into bytes after escaping characters in the payload.
    fn to_bytes_into(&self, buf: &mut impl std::io::Write) -> Result<(), Self::SerializerError> {
        // Write STX and "header" fields
        buf.write_all(&[self.stx, self.addr, self.cmd_rsp.0])
            .map_err(Error::into_io)?;

        // Walk data and escape characters as necessary before writing.
        for b in self.data.iter() {
            match b {
                0x02 => {
                    buf.write_all(&[ESCAPE_CHAR, HEX_02_ESC])
                        .map_err(Error::into_io)?;
                }
                0x0D => {
                    buf.write_all(&[ESCAPE_CHAR, HEX_0D_ESC])
                        .map_err(Error::into_io)?;
                }
                0x07 => {
                    buf.write_all(&[ESCAPE_CHAR, HEX_07_ESC])
                        .map_err(Error::into_io)?;
                }
                _ => {
                    buf.write_all(&[*b]).map_err(Error::into_io)?;
                }
            }
        }
        // Write "Footer" fields and EDX
        buf.write_all(&[self.checksum_1, self.checksum_2, EDX])
            .map_err(Error::into_io)?;
        Ok(())
    }
}
impl DeserializePacket for SmdpPacketV2 {
    type DeserializerError = Error;

    fn from_bytes(buf: &[u8]) -> Result<Self, Self::DeserializerError> {
        let mut buf = BytesMut::from(buf);
        // Discard STX
        _ = buf
            .try_get_u8()
            .map_err(|_| Error::into_format(FormatError::BufTooSmall))?;

        // Verify Address is in-range
        let addr = buf
            .try_get_u8()
            .map_err(|_| Error::into_format(FormatError::BufTooSmall))?;
        if addr < 0x10 || addr > 0xFE {
            return Err(Error::into_format(FormatError::InvalidAddress {
                recvd: addr,
            }));
        }
        // Verify fields of CMD_RSP byte are valid
        let cmd_rsp = buf
            .try_get_u8()
            .map_err(|_| Error::into_format(FormatError::BufTooSmall))?;
        let cmd: u8 = cmd_rsp.bit_range(7, 4);
        if cmd < 0x01 || cmd > 0x0F {
            return Err(Error::into_format(FormatError::InvalidCmd));
        }
        // No need to check RSPF bit, either 0 or 1 is valid.
        let rsp: u8 = cmd_rsp.bit_range(2, 0);
        if rsp < 0x01 {
            return Err(Error::into_format(FormatError::InvalidRsp));
        }
        // Unescape Data field
        let mut data: Vec<u8> = Vec::with_capacity(buf.remaining() - 2);
        let mut escaped = false;
        while buf.remaining() > 3 {
            // 3 => two checksum bytes + EDX
            let mut curr_byte = buf.get_u8();
            if escaped {
                curr_byte = match curr_byte {
                    HEX_02_ESC => 0x02,
                    HEX_07_ESC => 0x07,
                    HEX_0D_ESC => 0x0D,
                    other => {
                        return Err(Error::into_format(FormatError::InvalidEscapedVal {
                            recvd: other,
                        }));
                    }
                };
                escaped = false;
            }
            if !escaped && curr_byte == ESCAPE_CHAR {
                escaped = true;
                continue;
            }
            data.push(curr_byte);
        }
        // Verify checksum. Should be exactly 3 bytes remaining.
        if (buf.get_u8(), buf.get_u8()) != mod256_checksum_split_v2(&data, addr, cmd_rsp) {
            return Err(Error::into_format(FormatError::ChecksumMismatch));
        }

        // Deserialize into packet struct
        Ok(SmdpPacketV2::new(addr, cmd_rsp, data))
    }
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SmdpPacketV3 {
    /// Address field. This is a one byte field. Valid ranges of a valid address are 10 hex
    /// to FE hex (16 to 254 decimal). Addresses less than 10 hex are not allowed as they
    /// may be mistaken for framing characters. An address of FF hex is reserved as it is
    /// used as an extention, to indicate another byte of address information follows, for
    /// products that have an address range higher than an address of FE hex.
    addr: u8,
    /// Command/Response field. When packet is going from master to slave, RSPF
    /// bit is zero, and the RSP field (3 bits) is zero. When packet is going from slave to
    /// master, CMD bits are the same as in the message that was sent, but the RSP field
    /// will be non-zero (indicating actual unit response status). This allows the direction
    /// to be positively indicated, as well as the command preserved on the return reply.
    cmd_rsp: CommandResponse,
    data: Vec<u8>,
    // Serial number for matching response to a request (like sequence number in TCP).
    // Value is incremented for each request (by caller) modulo 256
    srlno: u8,
    checksum_1: u8,
    checksum_2: u8,
}
impl SmdpPacketV3 {
    pub fn new(addr: u8, cmd_rsp: u8, srlno: u8, data: Vec<u8>) -> Self {
        let (checksum_1, checksum_2) = mod256_checksum_split_v3(&data, addr, cmd_rsp, srlno);
        Self {
            addr,
            cmd_rsp: CommandResponse(cmd_rsp),
            data,
            srlno,
            checksum_1,
            checksum_2,
        }
    }
    /// Getter for the Address field
    pub fn addr(&self) -> u8 {
        self.addr
    }
    /// Getter for the CMD_RSP field
    pub fn cmd_rsp(&self) -> u8 {
        self.cmd_rsp.0
    }
    /// Getter for the CMD value
    pub fn cmd(&self) -> SmdpResult<CommandCode> {
        self.cmd_rsp.cmd()
    }
    /// Getter for the RSP value
    pub fn rsp(&self) -> SmdpResult<ResponseCode> {
        self.cmd_rsp.rsp()
    }
    /// Getter for the RSPF value
    pub fn rspf(&self) -> bool {
        self.cmd_rsp.rspf()
    }
    /// Getter for the data bytes
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
    /// Getter for the data bytes
    pub fn srlno(&self) -> u8 {
        self.srlno
    }
    /// Getter for the split checksum
    pub fn checksum_split(&self) -> (u8, u8) {
        (self.checksum_1, self.checksum_2)
    }
}
impl SerizalizePacket for SmdpPacketV3 {
    type SerializerError = Error;
    /// Serializes the packet into bytes after escaping characters in the payload.
    fn to_bytes_into(&self, buf: &mut impl std::io::Write) -> Result<(), Self::SerializerError> {
        // Write "header" field
        buf.write_all(&[STX, self.addr, self.cmd_rsp.0])
            .map_err(Error::into_io)?;

        // Walk data and escape characters as necessary before writing.
        for b in self.data.iter() {
            match b {
                0x02 => {
                    buf.write_all(&[ESCAPE_CHAR, HEX_02_ESC])
                        .map_err(Error::into_io)?;
                }
                0x0D => {
                    buf.write_all(&[ESCAPE_CHAR, HEX_0D_ESC])
                        .map_err(Error::into_io)?;
                }
                0x07 => {
                    buf.write_all(&[ESCAPE_CHAR, HEX_07_ESC])
                        .map_err(Error::into_io)?;
                }
                _ => {
                    buf.write_all(&[*b]).map_err(Error::into_io)?;
                }
            }
        }
        // Write "Footer" fields and EDX
        buf.write_all(&[self.srlno, self.checksum_1, self.checksum_2, EDX])
            .map_err(Error::into_io)?;
        Ok(())
    }
}
impl DeserializePacket for SmdpPacketV3 {
    type DeserializerError = Error;

    fn from_bytes(buf: &[u8]) -> Result<Self, Self::DeserializerError> {
        let mut buf = BytesMut::from(buf);
        // Discard STX
        _ = buf
            .try_get_u8()
            .map_err(|_| Error::into_format(FormatError::BufTooSmall))?;

        // Verify Address is in-range
        let addr = buf
            .try_get_u8()
            .map_err(|_| Error::into_format(FormatError::BufTooSmall))?;
        if addr < 0x10 || addr > 0xFE {
            return Err(Error::into_format(FormatError::InvalidAddress {
                recvd: addr,
            }));
        }
        // Verify fields of CMD_RSP byte are valid
        let cmd_rsp = buf
            .try_get_u8()
            .map_err(|_| Error::into_format(FormatError::BufTooSmall))?;
        let cmd: u8 = cmd_rsp.bit_range(7, 4);
        if cmd < 0x01 || cmd > 0x0F {
            return Err(Error::into_format(FormatError::InvalidCmd));
        }
        // No need to check RSPF bit, either 0 or 1 is valid.
        let rsp: u8 = cmd_rsp.bit_range(2, 0);
        if rsp < 0x01 {
            return Err(Error::into_format(FormatError::InvalidRsp));
        }
        // Unescape Data field. Reserving the maximum capacity (I.E. every byte is escaped)
        let mut unesc_data: Vec<u8> = Vec::with_capacity(buf.remaining() - 3);
        let mut escaped = false;
        while buf.remaining() > 4 {
            // 4 => srlno + two checksum bytes + EDX
            let mut curr_byte = buf.get_u8();
            if escaped {
                curr_byte = match curr_byte {
                    HEX_02_ESC => 0x02,
                    HEX_07_ESC => 0x07,
                    HEX_0D_ESC => 0x0D,
                    other => {
                        return Err(Error::into_format(FormatError::InvalidEscapedVal {
                            recvd: other,
                        }));
                    }
                };
                escaped = false;
            }
            if !escaped && curr_byte == ESCAPE_CHAR {
                escaped = true;
                continue;
            }
            unesc_data.push(curr_byte);
        }
        // Should be exactly 4 bytes remaining, get serial number and verify
        // value
        let srlno = buf.get_u8();
        if srlno <= 0x10 {
            return Err(Error::into_format(FormatError::InvalidSrlNo {
                recvd: srlno,
            }));
        }
        // Verify checksum. Should be exactly 3 bytes remaining.
        if (buf.get_u8(), buf.get_u8())
            != mod256_checksum_split_v3(&unesc_data, addr, cmd_rsp, srlno)
        {
            return Err(Error::into_format(FormatError::ChecksumMismatch));
        }

        // Deserialize into packet struct
        Ok(SmdpPacketV3::new(addr, cmd_rsp, srlno, unesc_data))
    }
}

/// Computes the Modulo 256 checksum of the Address, Command Response, and Data fields
/// of the packet. Note that this should be performed BEFORE escaping!
pub(crate) fn mod256_checksum_v2(data: &[u8], addr: u8, cmd_rsp: u8) -> u8 {
    // `wrapping_add()` gives mod 256 behavior for u8 sums
    let acc = addr.wrapping_add(cmd_rsp);
    data.iter().fold(acc, |acc, el| acc.wrapping_add(*el))
}
/// Computes the Modulo 256 checksum of the Address, Command Response, Data, and SRLNO fields
/// of the V3 packet. Note that this should be performed BEFORE escaping!
pub(crate) fn mod256_checksum_v3(data: &[u8], addr: u8, cmd_rsp: u8, srlno: u8) -> u8 {
    // `wrapping_add()` gives mod 256 behavior for u8 sums
    let acc = addr.wrapping_add(cmd_rsp).wrapping_add(srlno);
    data.iter().fold(acc, |acc, el| acc.wrapping_add(*el))
}
/// Convenience function to return the split mod256 checksum (MS nibble, LS nibble) plus
/// offset required by the packet format. V2 only due to seed.
pub(crate) fn mod256_checksum_split_v2(data: &[u8], addr: u8, cmd_rsp: u8) -> (u8, u8) {
    let chk = mod256_checksum_v2(data, addr, cmd_rsp);
    (((chk & 0b11110000) >> 4) + 0x30, (chk & 0b1111) + 0x30)
}
/// Convenience function to return the split mod256 checksum (MS nibble, LS nibble) plus
/// offset required by the packet format. V3 only due to seed.
pub(crate) fn mod256_checksum_split_v3(data: &[u8], addr: u8, cmd_rsp: u8, srlno: u8) -> (u8, u8) {
    let chk = mod256_checksum_v3(data, addr, cmd_rsp, srlno);
    (((chk & 0b11110000) >> 4) + 0x40, (chk & 0b1111) + 0x40)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_mod256_checksum_no_wrap() {
        let addr = 0x01u8;
        let cmd_rsp = 0x02u8;
        let data_sum: u8 = (0x03u8..=0x06).sum();
        let sum = addr + cmd_rsp + data_sum;
        assert_eq!(
            sum,
            mod256_checksum_v2(&vec![0x03u8, 0x04, 0x05, 0x06], addr, cmd_rsp)
        );
    }
    #[test]
    fn test_mod256_checksum_with_wrap() {
        let addr = 100u8;
        let cmd_rsp = 155u8;
        let wrapped_sum = 9; // 0 indexing
        assert_eq!(
            wrapped_sum,
            mod256_checksum_v2(&vec![1u8; 10], addr, cmd_rsp)
        );
    }
    #[test]
    fn test_mod256_checksum_split_v1() {
        let addr = 100u8;
        let cmd_rsp = 165u8;
        let empty = vec![];
        let (cksum1, cksum2) = mod256_checksum_split_v2(&empty, addr, cmd_rsp);
        assert_eq!(cksum1, 0x30);
        assert_eq!(cksum2, 0x39);
    }
    #[test]
    fn test_mod256_checksum_split_v2() {
        let addr = 100u8;
        let cmd_rsp = 165u8;
        let empty = vec![];
        let (cksum1, cksum2) = mod256_checksum_split_v3(&empty, addr, cmd_rsp, 0);
        assert_eq!(cksum1, 0x40);
        assert_eq!(cksum2, 0x49);
    }

    #[test]
    fn test_command_code_from_u8_reserved() {
        let code = 1u8;
        let res: SmdpResult<CommandCode> = code.try_into();
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), CommandCode::ReservedOne);

        let code = 2u8;
        let res: SmdpResult<CommandCode> = code.try_into();
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), CommandCode::ReservedTwo);
    }
    #[test]
    fn test_command_response_ok() {
        let cmd_rsp = CommandResponse(0b11010101u8);
        assert_eq!(cmd_rsp.cmd().unwrap(), CommandCode::App(13));
        assert_eq!(cmd_rsp.rspf(), false);
        assert_eq!(cmd_rsp.rsp().unwrap(), ResponseCode::ErrInhibited);
    }

    #[test]
    fn extract_cmd_rsp_vals_from_packet_ok() {
        let packet = SmdpPacketV2::new(16, 0x80, vec![10, 20]);
        let cmd_rsp = packet.cmd_rsp;
        assert_eq!(cmd_rsp.cmd().unwrap(), CommandCode::App(8));
        assert_eq!(cmd_rsp.rspf(), false);
        assert!(cmd_rsp.rsp().is_err());
    }
    #[test]
    fn serialize_packet_into_no_checksum_wrap_no_escape() {
        let packet = SmdpPacketV2::new(16, 0x80, vec![10, 20]);
        let mut bytes: Vec<u8> = Vec::new();
        packet.to_bytes_into(&mut bytes).unwrap();
        let checksum = 16u8 + 128 + 30;
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![0x02u8, 0x10, 0x80, 0x0A, 0x14, chk1, chk2, b'\r'],
            bytes
        );
    }
    #[test]
    fn serialize_packet_into_with_checksum_wrap_no_escape() {
        let packet = SmdpPacketV2::new(150, 0x80, vec![10, 20]);
        let mut bytes: Vec<u8> = Vec::with_capacity(64);
        packet.to_bytes_into(&mut bytes).unwrap();
        let checksum = 150u8.wrapping_add(128).wrapping_add(30);
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![0x02u8, 0x96, 0x80, 0x0A, 0x14, chk1, chk2, b'\r'],
            bytes
        );
    }
    #[test]
    fn serialize_packet_into_no_checksum_wrap_with_escape() {
        let packet = SmdpPacketV2::new(16, 0x80, vec![5, 2, 7, 13]);
        let mut bytes: Vec<u8> = Vec::with_capacity(64);
        packet.to_bytes_into(&mut bytes).unwrap();
        // Checksum calculated on non-escaped data!
        let checksum = 16u8 + 128 + 27;
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![
                0x02u8,
                0x10,
                0x80,
                0x05,
                ESCAPE_CHAR,
                HEX_02_ESC,
                ESCAPE_CHAR,
                HEX_07_ESC,
                ESCAPE_CHAR,
                HEX_0D_ESC,
                chk1,
                chk2,
                b'\r'
            ],
            bytes
        );
    }
    #[test]
    fn serialize_packet_into_with_checksum_wrap_with_escape() {
        let packet = SmdpPacketV2::new(150, 0x80, vec![5, 2, 7, 13]);
        let mut bytes: Vec<u8> = Vec::new();
        packet.to_bytes_into(&mut bytes).unwrap();
        // Checksum calculated on non-escaped data!
        let checksum = 150u8.wrapping_add(128).wrapping_add(27);
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![
                0x02u8,
                0x96,
                0x80,
                0x05,
                ESCAPE_CHAR,
                HEX_02_ESC,
                ESCAPE_CHAR,
                HEX_07_ESC,
                ESCAPE_CHAR,
                HEX_0D_ESC,
                chk1,
                chk2,
                b'\r'
            ],
            bytes
        );
    }
    #[test]
    fn serialize_packet_vec_no_checksum_wrap_no_escape() {
        let packet = SmdpPacketV2::new(16, 0x80, vec![10, 20]);
        let bytes = packet.to_bytes_vec().unwrap();
        let checksum = 16u8 + 128 + 30;
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![0x02u8, 0x10, 0x80, 0x0A, 0x14, chk1, chk2, b'\r'],
            bytes
        );
    }
    #[test]
    fn serialize_packet_vec_with_checksum_wrap_no_escape() {
        let packet = SmdpPacketV2::new(150, 0x80, vec![10, 20]);
        let bytes = packet.to_bytes_vec().unwrap();
        let checksum = 150u8.wrapping_add(128).wrapping_add(30);
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![0x02u8, 0x96, 0x80, 0x0A, 0x14, chk1, chk2, b'\r'],
            bytes
        );
    }
    #[test]
    fn serialize_packet_vec_no_checksum_wrap_with_escape() {
        let packet = SmdpPacketV2::new(16, 0x80, vec![5, 2, 7, 13]);
        let bytes = packet.to_bytes_vec().unwrap();
        // Checksum calculated on non-escaped data!
        let checksum = 16u8 + 128 + 27;
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![
                0x02u8,
                0x10,
                0x80,
                0x05,
                ESCAPE_CHAR,
                HEX_02_ESC,
                ESCAPE_CHAR,
                HEX_07_ESC,
                ESCAPE_CHAR,
                HEX_0D_ESC,
                chk1,
                chk2,
                b'\r'
            ],
            bytes
        );
    }
    #[test]
    fn serialize_packet_vec_with_checksum_wrap_with_escape() {
        let packet = SmdpPacketV2::new(150, 0x80, vec![5, 2, 7, 13]);
        let bytes = packet.to_bytes_vec().unwrap();
        // Checksum calculated on non-escaped data!
        let checksum = 150u8.wrapping_add(128).wrapping_add(27);
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![
                0x02u8,
                0x96,
                0x80,
                0x05,
                ESCAPE_CHAR,
                HEX_02_ESC,
                ESCAPE_CHAR,
                HEX_07_ESC,
                ESCAPE_CHAR,
                HEX_0D_ESC,
                chk1,
                chk2,
                b'\r'
            ],
            bytes
        );
    }

    /* DESERIALIZATION */
    #[test]
    fn test_deser_valid_frame_v1() {
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let addr = 0x10u8;
        let cmd_rsp = 0x81u8;
        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(&data);
        let (ck1, ck2) = mod256_checksum_split_v2(&data, addr, cmd_rsp);
        frame.extend_from_slice(&[ck1, ck2, EDX]);
        let de = SmdpPacketV2::from_bytes(&frame);
        assert_eq!(de.unwrap(), SmdpPacketV2::new(addr, cmd_rsp, data));
    }
    #[test]
    fn test_deser_valid_frame_v2() {
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let addr = 0x10u8;
        let cmd_rsp = 0x81u8;
        let srlno = 0x18u8;
        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(&data);
        let (ck1, ck2) = mod256_checksum_split_v3(&data, addr, cmd_rsp, srlno);
        frame.extend_from_slice(&[srlno, ck1, ck2, EDX]);
        let de = SmdpPacketV3::from_bytes(&frame);
        assert_eq!(de.unwrap(), SmdpPacketV3::new(addr, cmd_rsp, srlno, data));
    }
    #[test]
    fn test_deser_invalid_frame_rsp_0_v2() {
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let addr = 0x10u8;
        let cmd_rsp = 0x80u8;
        let srlno = 0x18u8;
        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(&data);
        let (ck1, ck2) = mod256_checksum_split_v3(&data, addr, cmd_rsp, srlno);
        frame.extend_from_slice(&[srlno, ck1, ck2, EDX]);
        let de = SmdpPacketV3::from_bytes(&frame);
        assert!(de.is_err());
    }
    #[test]
    fn test_deser_invalid_frame_rsp_0_v1() {
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let addr = 0x10u8;
        let cmd_rsp = 0x80u8;
        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(&data);
        let (ck1, ck2) = mod256_checksum_split_v2(&data, addr, cmd_rsp);
        frame.extend_from_slice(&[ck1, ck2, EDX]);
        let de = SmdpPacketV2::from_bytes(&frame);
        assert!(de.is_err());
    }
    #[test]
    fn test_deser_invalid_frame_addr_hi_v2() {
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let addr = 0xFFu8;
        let cmd_rsp = 0x81u8;
        let srlno = 0x18u8;
        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(&data);
        let (ck1, ck2) = mod256_checksum_split_v3(&data, addr, cmd_rsp, srlno);
        frame.extend_from_slice(&[srlno, ck1, ck2, EDX]);
        let de = SmdpPacketV3::from_bytes(&frame);
        assert!(de.is_err());
    }
    #[test]
    fn test_deser_invalid_frame_addr_hi_v1() {
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let addr = 0xFFu8;
        let cmd_rsp = 0x81u8;
        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(&data);
        let (ck1, ck2) = mod256_checksum_split_v2(&data, addr, cmd_rsp);
        frame.extend_from_slice(&[ck1, ck2, EDX]);
        let de = SmdpPacketV2::from_bytes(&frame);
        assert!(de.is_err());
    }
    #[test]
    fn test_deser_invalid_frame_addr_lo_v2() {
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let addr = 0x0Fu8;
        let cmd_rsp = 0x81u8;
        let srlno = 0x18u8;
        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(&data);
        let (ck1, ck2) = mod256_checksum_split_v3(&data, addr, cmd_rsp, srlno);
        frame.extend_from_slice(&[srlno, ck1, ck2, EDX]);
        let de = SmdpPacketV3::from_bytes(&frame);
        assert!(de.is_err());
    }
    #[test]
    fn test_deser_invalid_frame_addr_lo_v1() {
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let addr = 0x0Fu8;
        let cmd_rsp = 0x81u8;
        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(&data);
        let (ck1, ck2) = mod256_checksum_split_v2(&data, addr, cmd_rsp);
        frame.extend_from_slice(&[ck1, ck2, EDX]);
        let de = SmdpPacketV2::from_bytes(&frame);
        assert!(de.is_err());
    }
    #[test]
    fn test_deser_invalid_frame_srlno_lo_v2() {
        let data = vec![0x63u8, 0x45, 0x4C, 0x00];
        let addr = 0x10u8;
        let cmd_rsp = 0x81u8;
        let srlno = 0x10u8;
        let mut frame = vec![STX, addr, cmd_rsp];
        frame.extend_from_slice(&data);
        let (ck1, ck2) = mod256_checksum_split_v3(&data, addr, cmd_rsp, srlno);
        frame.extend_from_slice(&[srlno, ck1, ck2, EDX]);
        let de = SmdpPacketV3::from_bytes(&frame);
        assert!(de.is_err());
    }
}
