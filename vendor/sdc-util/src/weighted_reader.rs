//! Bound receive read-ahead and reuse frame storage; never wait to fill a batch.
use super::MAX_FRAME_BYTES;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

pub(super) const READ_AHEAD_BYTES: usize = 8 * 1024;
pub(super) const RETAIN_FRAME_BYTES: usize = 64 * 1024;
pub(super) struct FrameReader<S> {
    stream: BufReader<S>,
    frame: Vec<u8>,
}
impl<S: AsyncRead + Unpin> FrameReader<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream: BufReader::with_capacity(READ_AHEAD_BYTES, stream),
            frame: Vec::new(),
        }
    }
    #[cfg(test)]
    pub fn stream_mut(&mut self) -> &mut S {
        // ACKs bypass buffering and are written immediately as before.
        self.stream.get_mut()
    }
    pub async fn next(&mut self) -> io::Result<&[u8]> {
        // Release an exceptional large allocation before awaiting another prefix.
        if self.frame.capacity() > RETAIN_FRAME_BYTES {
            self.frame = Vec::new();
        }
        let size = self.stream.read_u32_le().await? as usize;
        if size == 0 || size > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid frame size",
            ));
        }
        // Retain initialized bytes when the size repeats; read_exact overwrites all
        // of them before a view can escape. EOF/partial bodies are never delivered.
        self.frame.resize(size, 0);
        self.stream.read_exact(&mut self.frame).await?;
        Ok(&self.frame)
    }
}

#[cfg(test)]
#[path = "weighted_reader_tests.rs"]
mod tests;
