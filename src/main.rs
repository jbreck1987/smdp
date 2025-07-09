use std::{
    io::{Read, Write},
    time::Duration,
};

use bytes::BufMut;
use serialport;
use smdp::{
    GenSmdpStack, SerizalizePacket, SmdpPacketV1, SmdpPacketV2,
    format::{CommandCode, ResponseCode},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let com = "/dev/tty.usbserial-FT0AVM2G";
    let io_handle = serialport::new(com, 115200)
        .data_bits(serialport::DataBits::Eight)
        .stop_bits(serialport::StopBits::One)
        .parity(serialport::Parity::None)
        .open_native()?;
    let mut proto: GenSmdpStack<_, SmdpPacketV1> = GenSmdpStack::new(io_handle, 20, 32);

    // Format data to read compressor active minutes
    let mut comp_mins_data = vec![];
    comp_mins_data.put_u32(0x63454C00);

    // Make packet
    let comp_mins_pkt = SmdpPacketV1::new(16, 0x80, comp_mins_data);

    // Send packet/parse reply
    proto.write_once(&comp_mins_pkt)?;
    let comp_mins_reply = proto.poll_once()?;

    // Get last 4 bytes and convert to u32;
    let comp_mins = comp_mins_reply
        .data()
        .get(comp_mins_reply.data().len().saturating_sub(4)..)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or("Not enough data bytes to make u32")?;
    println!("Compressor on minutes: {}", comp_mins);
    Ok(())
}
