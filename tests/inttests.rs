/* Testing SmdpProtocol and other higher level types */

#[cfg(test)]
mod tests {
    const EDX: u8 = 0x0D;
    const STX: u8 = 0x02;
    use smdp::test_utils::*;

    #[test]
    fn test_smdp_protocol_read_valid_frame() {
        // Create a valid frame
        let frame = vec![STX, 0x63u8, 0x45, 0x4C, 0x00, EDX];
    }
}
