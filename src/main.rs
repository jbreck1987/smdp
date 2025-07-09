use std::time::Duration;

use bytes::BufMut;
use serialport;
use smdp::{
    GenSmdpStack, SerizalizePacket, SmdpPacketV1,
    format::{CommandCode, ResponseCode},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let com = "/dev/tty.usbserial-130";
    let io_handle = serialport::new(com, 115200)
        .data_bits(serialport::DataBits::Eight)
        .stop_bits(serialport::StopBits::One)
        .parity(serialport::Parity::None)
        .timeout(Duration::from_millis(2000))
        .open_native()?;
    let mut proto: GenSmdpStack<_, SmdpPacketV1> = GenSmdpStack::new(io_handle, 2500, 64);

    // Format data to read compressor active minutes
    let mut comp_mins_data = vec![];
    comp_mins_data.put_u32(0x63454C00);
    let empty: Vec<u8> = vec![];

    // Make packet
    let comp_mins_pkt = SmdpPacketV1::new(16, 0x80, comp_mins_data);
    println!("{:?}", comp_mins_pkt.to_bytes_vec()?);

    // Send packet/parse reply
    proto.write_once(&comp_mins_pkt)?;
    std::thread::sleep(Duration::from_millis(200));
    let comp_mins_reply = proto.poll_once()?;
    println!("{:?}", comp_mins_reply.data());

    Ok(())
}
