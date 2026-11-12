use super::*;
use std::{
    future::{ready, Future},
    pin::pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Wake, Waker},
};
#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
#[test]
fn frame_and_byte_limits_yield_only_after_work_and_self_wake() {
    for (frames, bytes) in [(2, 0), (0, 250)] {
        let counts = metrics::Counters::default();
        let mut work = ReceiveBudget::with_limits(&counts, true, frames, bytes);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(!work.yields_after(150));
        {
            let mut first = pin!(work.complete(150));
            assert!(first.as_mut().poll(&mut cx).is_ready());
        }
        assert!(work.yields_after(150));
        let mut second = pin!(work.complete(150));
        assert!(second.as_mut().poll(&mut cx).is_pending());
        assert!(wakes.0.load(Ordering::Relaxed) > 0);
        assert_eq!(counts.current().receive_frames, 2);
        assert_eq!(counts.current().receive_max_bytes_per_turn, 300);
        assert_eq!(counts.current().receive_budget_yields, 1);
        assert!(second.as_mut().poll(&mut cx).is_ready());
    }
}
#[test]
fn natural_pending_resets_budget_without_losing_partial_work() {
    let counts = metrics::Counters::default();
    let mut work = ReceiveBudget::with_limits(&counts, true, 2, 0);
    let waker = Waker::from(Arc::new(Wakes::default()));
    let mut cx = Context::from_waker(&waker);
    assert!(pin!(work.complete(100)).as_mut().poll(&mut cx).is_ready());
    let mut polls = 0;
    {
        let f = poll_fn(|cx| {
            polls += 1;
            if polls == 1 {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(17)
            }
        });
        let mut tracked = pin!(work.track(f));
        assert!(tracked.as_mut().poll(&mut cx).is_pending());
        assert_eq!(tracked.as_mut().poll(&mut cx), Poll::Ready(17));
    }
    assert_eq!(polls, 2);
    assert!(!work.yields_after(100));
    assert!(pin!(work.complete(100)).as_mut().poll(&mut cx).is_ready());
    assert_eq!(counts.current().receive_turns, 2);
    assert_eq!(counts.current().receive_max_frames_per_turn, 1);
    assert_eq!(counts.current().receive_budget_yields, 0);
    assert_eq!(
        pin!(work.track(ready(42))).as_mut().poll(&mut cx),
        Poll::Ready(42)
    );
}
#[test]
fn disabled_policy_and_observations_do_not_add_yields_or_counters() {
    let counts = metrics::Counters::default();
    let mut work = ReceiveBudget::with_limits(&counts, false, 0, 0);
    let waker = Waker::from(Arc::new(Wakes::default()));
    let mut cx = Context::from_waker(&waker);
    for _ in 0..1000 {
        assert_eq!(
            pin!(work.track(ready(42))).as_mut().poll(&mut cx),
            Poll::Ready(42)
        );
        assert!(pin!(work.complete(1024 * 1024))
            .as_mut()
            .poll(&mut cx)
            .is_ready());
    }
    assert_eq!(counts.current().receive_frames, 0);
    assert_eq!(counts.current().receive_budget_yields, 0);
}
