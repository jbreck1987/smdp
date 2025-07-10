use std::{
    io::{Read, Write},
    time::Duration,
};

use bytes::BufMut;
use serialport;
use smdp::{PacketFormat, SmdpPacketHandler, SmdpPacketV1, SmdpPacketV2};

fn extract_data(data: &[u8]) -> Result<u32, &'static str> {
    data.get(data.len().saturating_sub(4)..)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or("Not enough data bytes to make u32")
}
fn send_get_cmd<T: Read + Write, P: PacketFormat + Clone>(
    packet: P,
    stack: &mut SmdpPacketHandler<T>,
) -> Result<P, Box<dyn std::error::Error>> {
    // Send packet/parse reply
    stack.write_once(&packet)?;
    Ok(stack.poll_once()?)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let com = "/dev/tty.usbserial-FT0AVM2G";
    let io_handle = serialport::new(com, 115200)
        .data_bits(serialport::DataBits::Eight)
        .stop_bits(serialport::StopBits::One)
        .parity(serialport::Parity::None)
        .open_native()?;
    let mut proto = SmdpPacketHandler::new(io_handle, 50, 32);
    let mut ctr = 0usize;

    while ctr < 20 {
        // Format data to read compressor active minutes and build packet.
        // Finally, extract data portion of reply and format as u32.
        let mut comp_mins_data = vec![];
        comp_mins_data.put_u32(0x63454C00);
        let comp_mins_pkt = SmdpPacketV2::new(16, 0x80, 18, comp_mins_data);
        let comp_mins = extract_data(send_get_cmd(comp_mins_pkt, &mut proto)?.data())?;
        println!("Compressor on minutes: {}", comp_mins);

        let mut cpu_temp_data = vec![];
        cpu_temp_data.put_u32(0x63357400);
        let cpu_temp_pkt = SmdpPacketV2::new(16, 0x80, 19, cpu_temp_data);
        // Temp in units of 0.1C
        let cpu_temp = extract_data(send_get_cmd(cpu_temp_pkt, &mut proto)?.data())?;
        println!("CPU Temp: {}", cpu_temp as f32 * 0.1);

        let mut batt_low_data = vec![];
        batt_low_data.put_u32(0x63357400);
        let batt_low_pkt = SmdpPacketV2::new(16, 0x80, 20, batt_low_data);
        let batt_low = extract_data(send_get_cmd(batt_low_pkt, &mut proto)?.data())?;
        println!("Battery Low: {}", batt_low != 0);
        ctr += 1;
        std::thread::sleep(Duration::from_secs(1));
    }

    Ok(())
}
