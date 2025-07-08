use std::time::Duration;

use bytes::BufMut;
use serialport;
use smdp::{
    GenSmdpStack, SmdpPacketV2,
    format::{CommandCode, ResponseCode},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let com = "/dev/tty.usbserial-140";
    let io_handle = serialport::new(com, 115200)
        .timeout(Duration::from_millis(20))
        .open_native()?;
    let mut proto: GenSmdpStack<_, SmdpPacketV2> = GenSmdpStack::new(io_handle, 2000, 64);

    // Format data to read compressor active minutes
    let mut comp_mins_data = vec![];
    comp_mins_data.put_u32(0x63454C00);

    // Make packet
    let comp_mins_pkt = SmdpPacketV2::new(0x10, 0x80, comp_mins_data.clone());

    // Send packet/parse reply
    proto.write_once(&comp_mins_pkt)?;
    let comp_mins_reply = proto.poll_once()?;
    println!("{:?}", comp_mins_reply.data());

    Ok(())
}
