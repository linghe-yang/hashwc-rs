use super::*;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::ReadBuf;

struct Fragments<'a> {
    bytes: &'a [u8],
    chunk: usize,
    pending: bool,
}
impl AsyncRead for Fragments<'_> {
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
        let n = self.chunk.min(self.bytes.len()).min(out.remaining());
        out.put_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Poll::Ready(Ok(()))
    }
}
fn bytes() -> Vec<u8> {
    (0..128).flat_map(|i| [i as u8; 32]).collect()
}
#[tokio::test]
async fn ack_fragments_and_coalescing_preserve_every_boundary() {
    let bytes = bytes();
    for chunk in [1, 7, 13, 31, 32, 33, 1024, bytes.len()] {
        let mut source = ack_reader(Fragments {
            bytes: &bytes,
            chunk,
            pending: true,
        });
        for i in 0..128 {
            let mut ack = [0; 32];
            // Match the sender's incremental, cancellation-safe reads.
            let mut offset = 0;
            while offset < ack.len() {
                let n = source.read(&mut ack[offset..]).await.unwrap();
                assert_ne!(n, 0);
                offset += n;
            }
            assert_eq!(ack, [i as u8; 32]);
        }
        assert_eq!(source.read(&mut [0; 32]).await.unwrap(), 0);
    }
}
#[tokio::test]
async fn ack_burst_reads_fall_without_changing_bytes_or_single_ack_progress() {
    let bytes = bytes();
    let old = Arc::new(metrics::Counters::default());
    let new = Arc::new(metrics::Counters::default());
    let mut plain = metrics::Counted::with_observations(bytes.as_slice(), old.clone(), true);
    let mut buffered = ack_reader(metrics::Counted::with_observations(
        bytes.as_slice(),
        new.clone(),
        true,
    ));
    for i in 0..128 {
        let mut a = [0; 32];
        let mut b = [0; 32];
        plain.read_exact(&mut a).await.unwrap();
        buffered.read_exact(&mut b).await.unwrap();
        assert_eq!(a, b);
        assert_eq!(a, [i as u8; 32]);
    }
    assert_eq!(old.current().received_bytes, new.current().received_bytes);
    assert_eq!(old.current().io_read_successes, 128);
    assert_eq!(new.current().io_read_successes, 4);
    println!(
        "ACK_COUNTS,128,{},{},{}",
        old.current().io_read_successes,
        new.current().io_read_successes,
        new.current().received_bytes
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        let (mut peer, stream) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            peer.write_all(&[9; 32]).await.unwrap();
            assert_eq!(peer.read_u8().await.unwrap(), 42);
        });
        let mut input = ack_reader(stream);
        let mut ack = [0; 32];
        input.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, [9; 32]);
        input.get_mut().write_u8(42).await.unwrap();
        task.await.unwrap();
    })
    .await
    .expect("one ACK waited for read-ahead capacity");
}
#[tokio::test]
async fn eof_in_a_partial_ack_never_completes_it() {
    for end in 0..32 {
        let bytes = [7; 32];
        let mut source = ack_reader(&bytes[..end]);
        let mut ack = [0; 32];
        assert_eq!(
            source.read_exact(&mut ack).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
