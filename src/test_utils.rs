/* Common functionality used across unit and integration tests */

use crate::error::{Error, SmdpResult};
use crate::parse::{Framer, SmdpFramer};
use bytes::Bytes;
use std::io::{Read, Write};

// Used for testing the Framer functionality
pub(crate) fn make_framer() -> SmdpFramer {
    SmdpFramer::new(1024)
}
#[derive(Debug)]
pub(crate) struct MockFramer<F: Fn(&[u8]) -> SmdpResult<Bytes>> {
    f: F,
}
impl<F> MockFramer<F>
where
    F: Fn(&[u8]) -> SmdpResult<Bytes>,
{
    pub(crate) fn new(f: F) -> Self {
        Self { f }
    }
}
impl<F> Framer for MockFramer<F>
where
    F: Fn(&[u8]) -> SmdpResult<Bytes>,
{
    type Error = Error;
    fn push_bytes(&mut self, data: &[u8]) -> SmdpResult<Bytes> {
        (self.f)(data)
    }
}
// Used for testing the IoHandler functionality in generality.
// Can simulate any network condition via passed in closures/functions.
#[derive(Debug, Clone)]
pub struct MockIo<R, W>
where
    R: FnMut(&mut [u8]) -> std::io::Result<usize>,
    W: Fn(&[u8]) -> std::io::Result<usize>,
{
    r: R,
    w: W,
}
impl<R, W> MockIo<R, W>
where
    R: FnMut(&mut [u8]) -> std::io::Result<usize>,
    W: Fn(&[u8]) -> std::io::Result<usize>,
{
    pub fn new(r: R, w: W) -> Self {
        Self { r, w }
    }
}
impl<R, W> Read for MockIo<R, W>
where
    R: FnMut(&mut [u8]) -> std::io::Result<usize>,
    W: Fn(&[u8]) -> std::io::Result<usize>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (self.r)(buf)
    }
}
impl<R, W> Write for MockIo<R, W>
where
    R: FnMut(&mut [u8]) -> std::io::Result<usize>,
    W: Fn(&[u8]) -> std::io::Result<usize>,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (self.w)(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
