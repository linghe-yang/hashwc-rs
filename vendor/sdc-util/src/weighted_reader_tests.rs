use super::super::metrics::{Counted, Counters};
use super::*;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncWriteExt, ReadBuf};

struct Fragmented<'a> {
    bytes: &'a [u8],
    chunk: usize,
    pending: bool,
}
impl AsyncRead for Fragmented<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pending {
            self.pending = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.pending = true;
        let n = self.bytes.len().min(self.chunk).min(out.remaining());
        out.put_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Poll::Ready(Ok(()))
    }
}
fn wire(sizes: &[usize]) -> Vec<u8> {
    let mut bytes = vec![];
    for (i, size) in sizes.iter().enumerate() {
        bytes.extend_from_slice(&(*size as u32).to_le_bytes());
        bytes.extend(std::iter::repeat_n((i % 251) as u8, *size));
    }
    bytes
}
#[tokio::test]
async fn all_fragment_sizes_preserve_boundaries_and_pending_progress() {
    let sizes = [103, 128, 10000, 96, 300];
    let bytes = wire(&sizes);
    for chunk in [1, 2, 3, 7, 64, 8192, bytes.len()] {
        let counts = Arc::new(Counters::default());
        let source = Fragmented {
            bytes: &bytes,
            chunk,
            pending: true,
        };
        let mut input = FrameReader::new(Counted::with_observations(source, counts.clone(), true));
        for (i, size) in sizes.iter().enumerate() {
            assert_eq!(input.next().await.unwrap(), vec![(i % 251) as u8; *size]);
        }
        assert_eq!(
            input.next().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let c = counts.current();
        assert_eq!(c.received_bytes as usize, bytes.len());
        assert!(c.io_observed);
        assert!(c.io_read_pending > 0);
        assert!(c.io_read_polls >= c.io_read_successes + c.io_read_pending);
    }
}
#[tokio::test]
async fn truncation_and_oversized_prefix_do_not_deliver_or_allocate_a_body() {
    let bytes = wire(&[103]);
    for end in 0..bytes.len() {
        let mut input = FrameReader::new(&bytes[..end]);
        assert_eq!(
            input.next().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    for size in [0, MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
        let raw = size.to_le_bytes();
        let mut input = FrameReader::new(raw.as_slice());
        assert_eq!(
            input.next().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(input.frame.capacity(), 0);
    }
}
#[tokio::test]
async fn repeated_frames_reuse_storage_and_large_frames_are_released_before_idle() {
    let bytes = wire(&[103, 103, MAX_FRAME_BYTES]);
    let mut input = FrameReader::new(bytes.as_slice());
    let first = input.next().await.unwrap().as_ptr();
    assert_eq!(input.next().await.unwrap().as_ptr(), first);
    assert_eq!(input.next().await.unwrap().len(), MAX_FRAME_BYTES);
    assert!(input.frame.capacity() > RETAIN_FRAME_BYTES);
    assert!(input.next().await.is_err());
    assert_eq!(input.frame.capacity(), 0);
}
#[tokio::test]
async fn one_frame_returns_while_peer_waits_for_its_ack() {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let (mut peer, stream) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            peer.write_all(&wire(&[103])).await.unwrap();
            let mut ack = [0; 32];
            peer.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack, [9; 32]);
            // Peer sent nothing beyond the first frame before receiving its ACK.
        });
        let mut input = FrameReader::new(stream);
        assert_eq!(input.next().await.unwrap(), &[0; 103]);
        input.stream_mut().write_all(&[9; 32]).await.unwrap();
        task.await.unwrap();
    })
    .await
    .expect("reader waited for another frame");
}
#[tokio::test]
async fn burst_read_counts_are_reduced_without_changing_bytes() {
    println!("READER_COUNTS,frame_bytes,frames,old_reads,new_reads,wire_bytes");
    for size in [103, 128, 4096, 32768] {
        let sizes = vec![size; 128];
        let bytes = wire(&sizes);
        let old = Arc::new(Counters::default());
        let new = Arc::new(Counters::default());
        let mut source = Counted::with_observations(bytes.as_slice(), old.clone(), true);
        for (i, size) in sizes.iter().enumerate() {
            assert_eq!(source.read_u32_le().await.unwrap() as usize, *size);
            let mut body = vec![0; *size];
            source.read_exact(&mut body).await.unwrap();
            assert_eq!(body, vec![(i % 251) as u8; *size]);
        }
        let mut source = FrameReader::new(Counted::with_observations(
            bytes.as_slice(),
            new.clone(),
            true,
        ));
        for (i, size) in sizes.iter().enumerate() {
            assert_eq!(source.next().await.unwrap(), vec![(i % 251) as u8; *size]);
        }
        let (a, b) = (old.current(), new.current());
        assert_eq!(a.received_bytes, b.received_bytes);
        assert_eq!(a.io_read_successes, 256);
        assert!(b.io_read_successes <= a.io_read_successes);
        if size == 103 {
            assert_eq!(
                b.io_read_successes,
                (bytes.len() as u64).div_ceil(READ_AHEAD_BYTES as u64)
            );
        }
        println!(
            "READER_COUNTS,{size},128,{},{},{}",
            a.io_read_successes, b.io_read_successes, a.received_bytes
        );
    }
}
