use anyhow::{Error, Result, anyhow};
use bitfield::{Bit, BitRange};
use bytes::Bytes;

// Since the protocol is binary transparent, STX and carriage
// return characters are not allowed in the data field. Need escape character plus
// a way to signal '\r' and 0x02.
const ESCAPE_CHAR: u8 = 0x07;
const HEX_02_ESC: u8 = 0x30; // ASCII '0'
const HEX_0D_ESC: u8 = 0x31; // ASCII '1'
const HEX_07_ESC: u8 = 0x32; // ASCII '2'
const MIN_PKT_SIZE: usize = 6;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResponseCode {
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
            other => return Err(anyhow!("{} is not a valid response code.", other)),
        };
        Ok(res)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CommandCode {
    /// Reserved for future protocol stack use. 0x01, 0x02
    Reserved,
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
            0x01 | 0x02 => CommandCode::Reserved,
            0x03 => CommandCode::ProdId,
            0x04 => CommandCode::SwVersion,
            0x05 => CommandCode::Reset,
            0x06 => CommandCode::AckPf,
            0x07 => CommandCode::ProcotolVer,
            c @ 0x08..=0x0F => CommandCode::App(c),
            other => return Err(anyhow!("{} is not a valid command code.", other)),
        };
        Ok(res)
    }
}
pub(crate) struct CommandResponse(u8);
impl CommandResponse {
    /// CMD = Command. These are the commands the master can issue to the slave. All
    /// Sycon products must respond to commands in the range of 1-7. CMDS 1-7 are
    /// handled in the protocol, at the protocol layer. Applications are not to use
    /// commands 1-7 except to implement the protocol specification. CMD codes 8-15
    /// are set aside for product application specific use.
    pub(crate) fn cmd(&self) -> Result<CommandCode> {
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
    pub(crate) fn rsp(&self) -> Result<ResponseCode> {
        let code: u8 = self.0.bit_range(2, 0);
        code.try_into()
    }
}
pub struct SmdpPacket {
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
impl SmdpPacket {
    pub fn new(addr: u8, cmd_code: u8, data: Vec<u8>) -> Result<Self> {
        // Input validation. Using in case slaves do not handle
        // error handling appropriately.
        if addr < 0x10 || addr > 0xFE {
            return Err(anyhow!(
                "{} is an invalid address. Valid addresses are 16 - 254",
                addr
            ));
        }
        if cmd_code < 0x01 || cmd_code > 0x0F {
            return Err(anyhow!(
                "{} is an invalid command code. Valid codes are 1 - 15",
                cmd_code
            ));
        }

        let cmd_rsp = CommandResponse(cmd_code << 4);
        let (checksum_1, checksum_2) = Self::mod256_checksum_split(&data, addr, cmd_rsp.0);
        Ok(Self {
            stx: 0x02,
            addr,
            cmd_rsp,
            data,
            checksum_1,
            checksum_2,
        })
    }
    /// Serializes the packet into bytes after escaping characters in the payload.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MIN_PKT_SIZE + self.data.len());
        bytes.push(self.stx);
        bytes.push(self.addr);
        bytes.push(self.cmd_rsp.0);

        // Walk data and escape characters as necessary.
        let mut data = Vec::with_capacity(self.data.len() + 10);
        self.data.iter().for_each(|b| match b {
            0x02 => {
                data.push(ESCAPE_CHAR);
                data.push(HEX_02_ESC);
            }
            0x0D => {
                data.push(ESCAPE_CHAR);
                data.push(HEX_0D_ESC);
            }
            0x07 => {
                data.push(ESCAPE_CHAR);
                data.push(HEX_07_ESC);
            }
            _ => data.push(*b),
        });
        bytes.extend(data.into_iter());
        bytes.push(self.checksum_1);
        bytes.push(self.checksum_2);
        bytes.push(b'\r');
        bytes
    }
    /// Computes the Modulo 256 checksum of the Address, Command Response, and Data fields
    /// of the packet. Note that this should be performed BEFORE escaping!
    fn mod256_checksum(data: &[u8], addr: u8, cmd_rsp: u8) -> u8 {
        // `wrapping_add()` gives mod 256 behavior for u8 sums
        let acc = addr.wrapping_add(cmd_rsp);
        data.iter().fold(acc, |acc, el| acc.wrapping_add(*el))
    }
    /// Convenience function to return the split mod256 checksum (MS nibble, LS nibble) plus
    /// offset required by the packet format.
    fn mod256_checksum_split(data: &[u8], addr: u8, cmd_rsp: u8) -> (u8, u8) {
        let acc = Self::mod256_checksum(data, addr, cmd_rsp);
        (((acc & 0b11110000) >> 4) + 0x30, (acc & 0b1111) + 0x30)
    }
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_command_code_from_u8_reserved() {
        let code = 1u8;
        let res: Result<CommandCode> = code.try_into();
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), CommandCode::Reserved);

        let code = 2u8;
        let res: Result<CommandCode> = code.try_into();
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), CommandCode::Reserved);
    }
    #[test]
    fn test_command_response_ok() {
        let cmd_rsp = CommandResponse(0b11010101u8);
        assert_eq!(cmd_rsp.cmd().unwrap(), CommandCode::App(13));
        assert_eq!(cmd_rsp.rspf(), false);
        assert_eq!(cmd_rsp.rsp().unwrap(), ResponseCode::ErrInhibited);
    }
    #[test]
    fn build_new_packet_ok() {
        let packet = SmdpPacket::new(16, 8, vec![10, 20]);
        assert!(packet.is_ok());
    }

    #[test]
    fn extract_cmd_rsp_vals_from_packet_ok() {
        let packet = SmdpPacket::new(16, 8, vec![10, 20]);
        assert!(packet.is_ok());
        let cmd_rsp = packet.unwrap().cmd_rsp;
        assert_eq!(cmd_rsp.cmd().unwrap(), CommandCode::App(8));
        assert_eq!(cmd_rsp.rspf(), false);
        assert!(cmd_rsp.rsp().is_err());
    }
    #[test]
    fn serialize_packet_no_checksum_wrap_no_escape() {
        let packet = SmdpPacket::new(16, 8, vec![10, 20]);
        assert!(packet.is_ok());
        let bytes = packet.unwrap().to_bytes();
        let checksum = 16u8 + 128 + 30;
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![0x02u8, 0x10, 0x80, 0x0A, 0x14, chk1, chk2, b'\r'],
            bytes
        );
    }
    #[test]
    fn serialize_packet_with_checksum_wrap_no_escape() {
        let packet = SmdpPacket::new(150, 8, vec![10, 20]);
        assert!(packet.is_ok());
        let bytes = packet.unwrap().to_bytes();
        let checksum = 150u8.wrapping_add(128).wrapping_add(30);
        let chk1 = ((checksum & 0b11110000) >> 4) + 0x30;
        let chk2 = (checksum & 0b1111) + 0x30;
        assert_eq!(
            vec![0x02u8, 0x96, 0x80, 0x0A, 0x14, chk1, chk2, b'\r'],
            bytes
        );
    }
    #[test]
    fn serialize_packet_no_checksum_wrap_with_escape() {
        let packet = SmdpPacket::new(16, 8, vec![5, 2, 7, 13]);
        assert!(packet.is_ok());
        let bytes = packet.unwrap().to_bytes();
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
    fn serialize_packet_with_checksum_wrap_with_escape() {
        let packet = SmdpPacket::new(150, 8, vec![5, 2, 7, 13]);
        assert!(packet.is_ok());
        let bytes = packet.unwrap().to_bytes();
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
}
