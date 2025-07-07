/* Common functionality used across unit and integration tests */

#[cfg(test)]
use crate::parse::{Framer, SmdpFramer};
#[cfg(test)]
use anyhow::Result;
#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use std::io::{Read, Write};

// Used for testing the Framer functionality
#[cfg(test)]
pub(crate) fn make_framer() -> SmdpFramer {
    SmdpFramer::new(1024)
}
#[cfg(test)]
pub(crate) struct MockFramer<F: Fn(&[u8]) -> Result<Bytes>> {
    f: F,
}
#[cfg(test)]
impl<F> MockFramer<F>
where
    F: Fn(&[u8]) -> Result<Bytes>,
{
    pub(crate) fn new(f: F) -> Self {
        Self { f }
    }
}
#[cfg(test)]
impl<F> Framer for MockFramer<F>
where
    F: Fn(&[u8]) -> Result<Bytes>,
{
    fn push_bytes(&mut self, data: &[u8]) -> Result<Bytes> {
        (self.f)(data)
    }
}
// Used for testing the IoHandler functionality in generality.
// Can simulate any network condition via passed in closures/functions.
#[cfg(test)]
pub(crate) struct MockIo<R, W>
where
    R: FnMut(&mut [u8]) -> std::io::Result<usize>,
    W: Fn(&[u8]) -> std::io::Result<usize>,
{
    r: R,
    w: W,
}
#[cfg(test)]
impl<R, W> MockIo<R, W>
where
    R: FnMut(&mut [u8]) -> std::io::Result<usize>,
    W: Fn(&[u8]) -> std::io::Result<usize>,
{
    pub(crate) fn new(r: R, w: W) -> Self {
        Self { r, w }
    }
}
#[cfg(test)]
impl<R, W> Read for MockIo<R, W>
where
    R: FnMut(&mut [u8]) -> std::io::Result<usize>,
    W: Fn(&[u8]) -> std::io::Result<usize>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        (self.r)(buf)
    }
}
#[cfg(test)]
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
