//! Serial CPU state machine with an independently drained, bounded input queue.
//! No protocol decision, authentication check or release gate moves to the relay.
use crate::observation::ServiceProgress;
use anyhow::{anyhow, Result};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use tokio::{
    sync::{mpsc, Notify},
    task::JoinHandle,
};

#[derive(Clone, Default)]
pub struct Meter(Arc<AtomicUsize>);
impl Meter {
    pub fn pending(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
    pub fn annotate(&self, mut progress: ServiceProgress) -> ServiceProgress {
        progress
            .pending
            .insert("execution_pipeline", self.pending());
        progress.all_honest_services_complete =
            progress.output_observed && progress.pending.values().all(|&n| n == 0);
        progress
    }
    fn ticket(&self) -> Ticket {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ticket(self.clone())
    }
}
struct Ticket(Meter);
impl Drop for Ticket {
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Input<I> {
    value: I,
    ticket: Ticket,
}
pub struct Inbox<I> {
    tx: mpsc::Sender<Input<I>>,
    meter: Meter,
}
impl<I> Clone for Inbox<I> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            meter: self.meter.clone(),
        }
    }
}
impl<I> Inbox<I> {
    pub async fn send(&self, value: I) -> Result<()> {
        // The ticket also covers a relay waiting for input capacity. Cancelling
        // the send drops its payload and ticket; successful sends preserve FIFO.
        let input = Input {
            value,
            ticket: self.meter.ticket(),
        };
        self.tx
            .send(input)
            .await
            .map_err(|_| anyhow!("CPU state worker stopped"))
    }
}
pub struct Dispatch<O> {
    pub value: O,
    // Retained through action dispatch, not merely through CPU completion.
    _ticket: Ticket,
}
pub struct Worker {
    cancelled: Arc<AtomicBool>,
    wake: Arc<Notify>,
    task: Option<JoinHandle<()>>,
    pub meter: Meter,
}
impl Worker {
    pub async fn shutdown(&mut self) -> Result<()> {
        self.cancelled.store(true, Ordering::SeqCst);
        self.wake.notify_one();
        if let Some(task) = self.task.take() {
            task.await?;
        }
        Ok(())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.wake.notify_one();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
pub fn spawn<S, I, O, F>(
    state: S,
    capacity: usize,
    apply: F,
) -> (
    Inbox<I>,
    mpsc::UnboundedReceiver<Result<Dispatch<O>>>,
    Worker,
)
where
    S: Send + 'static,
    I: Send + 'static,
    O: Send + 'static,
    F: FnMut(&mut S, I) -> Result<Option<O>> + Send + 'static,
{
    spawn_resumable(state, capacity, apply, |_| false, |_| Ok(None))
}

/// Interleave one bounded local continuation with at most one queued input.
/// No continuation waits for a new network event or an inbox slot. Each step
/// publishes effects independently, and keeps a progress ticket while pending.
pub fn spawn_resumable<S, I, O, F, P, C>(
    mut state: S,
    capacity: usize,
    mut apply: F,
    pending: P,
    mut resume: C,
) -> (
    Inbox<I>,
    mpsc::UnboundedReceiver<Result<Dispatch<O>>>,
    Worker,
)
where
    S: Send + 'static,
    I: Send + 'static,
    O: Send + 'static,
    F: FnMut(&mut S, I) -> Result<Option<O>> + Send + 'static,
    P: Fn(&S) -> bool + Send + 'static,
    C: FnMut(&mut S) -> Result<Option<O>> + Send + 'static,
{
    assert!(capacity > 0);
    let (tx, mut rx) = mpsc::channel::<Input<I>>(capacity);
    // Effects replace the state's existing action/event vectors. Empty and
    // rejected inputs produce no batch. This queue must not block the CPU actor:
    // blocking it behind a primitive whose output fills the input queue would
    // introduce a bounded-channel cycle. Protocol manifests bound valid effects.
    let (out, output) = mpsc::unbounded_channel();
    let meter = Meter::default();
    let cancelled = Arc::new(AtomicBool::new(false));
    let wake = Arc::new(Notify::new());
    let stop = cancelled.clone();
    let signal = wake.clone();
    let runtime = tokio::runtime::Handle::current();
    let continuation_meter = meter.clone();
    let task = tokio::task::spawn_blocking(move || {
        let mut local_ticket = pending(&state).then(|| continuation_meter.ticket());
        let mut prefer_local = false;
        loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            // A perpetually busy ingress cannot starve local work; conversely,
            // continuing local work cannot prevent consuming a queued input.
            let next = if local_ticket.is_some() {
                if prefer_local {
                    None
                } else {
                    rx.try_recv().ok()
                }
            } else {
                runtime.block_on(async {
                    tokio::select! {
                        biased;
                        _ = signal.notified() => None,
                        value = rx.recv() => value,
                    }
                })
            };
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let (result, ticket) = if let Some(Input { value, ticket }) = next {
                prefer_local = true;
                (apply(&mut state, value), ticket)
            } else if let Some(ticket) = local_ticket.take() {
                prefer_local = false;
                (resume(&mut state), ticket)
            } else {
                break;
            };
            if pending(&state) {
                if local_ticket.is_none() {
                    local_ticket = Some(continuation_meter.ticket());
                }
            } else {
                local_ticket = None;
            }
            // Shutdown can wait for the current finite calculation but must
            // never publish its effects after cancellation.
            if stop.load(Ordering::SeqCst) {
                break;
            }
            match result {
                Ok(Some(value)) => {
                    if out
                        .send(Ok(Dispatch {
                            value,
                            _ticket: ticket,
                        }))
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = out.send(Err(error));
                    break;
                }
            }
        }
    });
    (
        Inbox {
            tx,
            meter: meter.clone(),
        },
        output,
        Worker {
            cancelled,
            wake,
            task: Some(task),
            meter,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, time::Duration};
    #[tokio::test(flavor = "current_thread")]
    async fn blocked_cpu_keeps_receiver_live_and_effects_counted() {
        let (entered, mut entered_rx) = mpsc::unbounded_channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let (input, mut output, mut worker) = spawn(Vec::new(), 2, move |state, value| {
            if value == 0 {
                entered.send(()).unwrap();
                blocked.recv().unwrap();
            }
            state.push(value);
            Ok(Some(state.clone()))
        });
        input.send(0).await.unwrap();
        entered_rx.recv().await.unwrap();
        // A single Tokio thread can continue receiving while CPU work is blocked.
        tokio::time::timeout(Duration::from_secs(2), async {
            input.send(1).await.unwrap();
            input.send(2).await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(worker.meter.pending(), 3);
        let progress = ServiceProgress::new(true, BTreeMap::new());
        assert!(
            !worker
                .meter
                .annotate(progress.clone())
                .all_honest_services_complete
        );
        release.send(()).unwrap();
        for expected in [vec![0], vec![0, 1], vec![0, 1, 2]] {
            let effect = output.recv().await.unwrap().unwrap();
            assert_eq!(effect.value, expected);
            assert!(worker.meter.pending() > 0);
            drop(effect);
        }
        assert_eq!(worker.meter.pending(), 0);
        assert!(worker.meter.annotate(progress).all_honest_services_complete);
        worker.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn worker_error_is_delivered_and_idle_shutdown_does_not_need_input() {
        let (input, mut output, mut worker) = spawn((), 1, |_, _: ()| -> Result<Option<()>> {
            Err(anyhow!("invalid calculation"))
        });
        input.send(()).await.unwrap();
        assert!(output.recv().await.unwrap().is_err());
        worker.shutdown().await.unwrap();
        let (_input, _output, mut worker) = spawn((), 1, |_, _: ()| Ok(None::<()>));
        tokio::time::timeout(Duration::from_secs(2), worker.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
}

#[cfg(test)]
mod resumable_tests {
    use super::*;
    use std::{collections::VecDeque, time::Duration};

    #[tokio::test(flavor = "current_thread")]
    async fn resumes_without_network_input_and_accounts_pending_effects() {
        let (input, mut output, mut worker) = spawn_resumable(
            VecDeque::new(),
            1,
            |state: &mut VecDeque<usize>, count| {
                state.extend(0..count);
                Ok(Some(99))
            },
            |state| !state.is_empty(),
            |state| Ok(state.pop_front()),
        );
        input.send(3).await.unwrap();
        for expected in [99, 0, 1, 2] {
            let effect = tokio::time::timeout(Duration::from_secs(2), output.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(effect.value, expected);
            assert!(worker.meter.pending() > 0);
            drop(effect);
        }
        worker.shutdown().await.unwrap();
        assert_eq!(worker.meter.pending(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_ingress_and_local_work_both_make_progress() {
        let (entered, signal) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let mut entered = Some(entered);
        let (input, mut output, mut worker) = spawn_resumable(
            VecDeque::new(),
            8,
            move |state: &mut VecDeque<usize>, value| {
                if value == 0 {
                    state.extend(0..3);
                    entered.take().unwrap().send(()).unwrap();
                    blocked.recv().unwrap();
                }
                Ok(Some(("input", value)))
            },
            |state| !state.is_empty(),
            |state| Ok(state.pop_front().map(|v| ("local", v))),
        );
        input.send(0).await.unwrap();
        signal.await.unwrap();
        for value in 1..4 {
            input.send(value).await.unwrap();
        }
        release.send(()).unwrap();
        for expected in [
            ("input", 0),
            ("local", 0),
            ("input", 1),
            ("local", 1),
            ("input", 2),
            ("local", 2),
            ("input", 3),
        ] {
            let effect = tokio::time::timeout(Duration::from_secs(2), output.recv())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(effect.value, expected);
        }
        worker.shutdown().await.unwrap();
        assert_eq!(worker.meter.pending(), 0);
    }
}
