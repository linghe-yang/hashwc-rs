//! Per-peer bounded RAM queue with FIFO disk overflow. Silent peers cannot block healthy peers.
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tokio::sync::Notify;
const MEMORY_BYTES: usize = 2 * 1024 * 1024;
const MEMORY_MESSAGES: usize = 1024;
struct Spill {
    file: File,
    path: Option<PathBuf>,
    read: u64,
    write: u64,
}
impl Spill {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "weighted-send-{}-{}.tmp",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    // On Unix an anonymous open file is reclaimed even after a process crash.
                    #[cfg(unix)]
                    let path = {
                        std::fs::remove_file(&path)?;
                        None
                    };
                    #[cfg(not(unix))]
                    let path = Some(path);
                    return Ok(Self {
                        file,
                        path,
                        read: 0,
                        write: 0,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot create weighted spill file",
        ))
    }
}
impl Drop for Spill {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}
#[derive(Default)]
struct Inner {
    memory: VecDeque<Arc<Vec<u8>>>,
    bytes: usize,
    spill: Option<Spill>,
    closed: bool,
}
#[derive(Default)]
pub(super) struct Queue {
    inner: Mutex<Inner>,
    ready: Notify,
}
impl Queue {
    pub fn push(&self, bytes: Arc<Vec<u8>>) -> io::Result<()> {
        let mut q = self.inner.lock().unwrap();
        if q.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "weighted sender stopped",
            ));
        }
        let spilling = q.spill.as_ref().is_some_and(|s| s.read < s.write);
        if !spilling && q.bytes + bytes.len() <= MEMORY_BYTES && q.memory.len() < MEMORY_MESSAGES {
            q.bytes += bytes.len();
            q.memory.push_back(bytes);
        } else {
            if q.spill.is_none() {
                q.spill = Some(Spill::new()?);
            }
            let s = q.spill.as_mut().unwrap();
            let offset = s.write;
            s.file.seek(SeekFrom::Start(offset))?;
            s.file.write_all(&(bytes.len() as u32).to_le_bytes())?;
            s.file.write_all(&bytes)?;
            s.write += 4 + bytes.len() as u64;
        }
        drop(q);
        self.ready.notify_one();
        Ok(())
    }
    pub fn try_pop(&self) -> io::Result<Option<Arc<Vec<u8>>>> {
        let mut q = self.inner.lock().unwrap();
        if q.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "weighted sender stopped",
            ));
        }
        if let Some(b) = q.memory.pop_front() {
            q.bytes -= b.len();
            return Ok(Some(b));
        }
        if let Some(s) = q.spill.as_mut() {
            if s.read < s.write {
                s.file.seek(SeekFrom::Start(s.read))?;
                let mut len = [0; 4];
                s.file.read_exact(&mut len)?;
                let mut b = vec![0; u32::from_le_bytes(len) as usize];
                s.file.read_exact(&mut b)?;
                s.read += 4 + b.len() as u64;
                if s.read == s.write {
                    s.file.set_len(0)?;
                    s.read = 0;
                    s.write = 0;
                }
                return Ok(Some(Arc::new(b)));
            }
        }
        Ok(None)
    }
    pub fn close(&self) {
        let mut q = self.inner.lock().unwrap();
        q.closed = true;
        q.memory.clear();
        q.bytes = 0;
        q.spill = None;
        drop(q);
        self.ready.notify_one();
    }
    pub async fn pop(&self) -> io::Result<Arc<Vec<u8>>> {
        loop {
            let ready = self.ready.notified();
            if let Some(b) = self.try_pop()? {
                return Ok(b);
            }
            ready.await;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn spill_preserves_fifo_and_caps_memory() {
        let q = Queue::default();
        for i in 0u32..200 {
            let mut b = vec![0; 32768];
            b[..4].copy_from_slice(&i.to_le_bytes());
            q.push(Arc::new(b)).unwrap();
        }
        {
            let inner = q.inner.lock().unwrap();
            assert!(inner.bytes <= MEMORY_BYTES);
            assert!(inner.spill.as_ref().unwrap().write > 0);
        }
        for i in 0u32..200 {
            assert_eq!(&q.pop().await.unwrap()[..4], &i.to_le_bytes());
        }
        assert!(q.try_pop().unwrap().is_none());
        let inner = q.inner.lock().unwrap();
        assert_eq!(
            inner.spill.as_ref().unwrap().file.metadata().unwrap().len(),
            0
        );
    }
}
