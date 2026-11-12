//! Opt-in synchronous CPU profiling. Never hold a span across `.await`.
//! Labels describe public operations only; no protocol data is retained.
use serde::Serialize;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    marker::PhantomData,
    rc::Rc,
    sync::{Mutex, OnceLock},
    time::Instant,
};

#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub calls: u64,
    pub inclusive_wall_ns: u64,
    pub exclusive_wall_ns: u64,
    pub inclusive_cpu_ns: u64,
    pub exclusive_cpu_ns: u64,
    /// CPU totals are usable only when this equals `calls`.
    pub cpu_measured_calls: u64,
}
static ENABLED: OnceLock<bool> = OnceLock::new();
static TOTALS: OnceLock<Mutex<BTreeMap<&'static str, Snapshot>>> = OnceLock::new();
thread_local! {
    static STACK: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
}

pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var("COIN_PROFILE").is_ok_and(|v| v == "1"))
}

fn cpu_ns() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut t = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime initializes the valid timespec on success.
        if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, t.as_mut_ptr()) } != 0 {
            return None;
        }
        let t = unsafe { t.assume_init() };
        Some((t.tv_sec as u64).saturating_mul(1_000_000_000) + t.tv_nsec as u64)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// `!Send` and `!Sync`: thread CPU and the nesting stack must stay on one thread.
pub struct Span {
    active: Option<Active>,
    _thread_bound: PhantomData<Rc<()>>,
}
struct Active {
    label: &'static str,
    wall: Instant,
    cpu: Option<u64>,
}
#[inline]
pub fn span(label: &'static str) -> Span {
    if enabled() {
        Span::start(label)
    } else {
        Span {
            active: None,
            _thread_bound: PhantomData,
        }
    }
}
impl Span {
    fn start(label: &'static str) -> Self {
        STACK.with(|s| s.borrow_mut().push((0, 0)));
        Self {
            active: Some(Active {
                label,
                wall: Instant::now(),
                cpu: cpu_ns(),
            }),
            _thread_bound: PhantomData,
        }
    }
}
fn accumulate(total: &mut Snapshot, wall: u64, cpu: Option<u64>, children: (u64, u64)) {
    total.calls += 1;
    total.inclusive_wall_ns += wall;
    total.exclusive_wall_ns += wall.saturating_sub(children.0);
    if let Some(cpu) = cpu {
        total.cpu_measured_calls += 1;
        total.inclusive_cpu_ns += cpu;
        total.exclusive_cpu_ns += cpu.saturating_sub(children.1);
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let Some(a) = self.active.take() else {
            return;
        };
        let cpu = a
            .cpu
            .zip(cpu_ns())
            .map(|(start, end)| end.saturating_sub(start));
        let wall = a.wall.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        let children = STACK.with(|s| {
            let mut s = s.borrow_mut();
            let children = s.pop().expect("profile span nesting");
            if let Some(parent) = s.last_mut() {
                parent.0 += wall;
                parent.1 += cpu.unwrap_or(0);
            }
            children
        });
        let mut totals = TOTALS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        accumulate(totals.entry(a.label).or_default(), wall, cpu, children);
    }
}
pub fn snapshot() -> BTreeMap<&'static str, Snapshot> {
    TOTALS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_totals_do_not_double_count_child_time() {
        let mut total = Snapshot::default();
        accumulate(&mut total, 100, Some(80), (40, 30));
        accumulate(&mut total, 200, Some(90), (50, 20));
        assert_eq!((total.calls, total.cpu_measured_calls), (2, 2));
        assert_eq!(
            (total.inclusive_wall_ns, total.exclusive_wall_ns),
            (300, 210)
        );
        assert_eq!((total.inclusive_cpu_ns, total.exclusive_cpu_ns), (170, 120));
        accumulate(&mut total, 10, None, (0, 0));
        assert_eq!((total.calls, total.cpu_measured_calls), (3, 2));
    }
    #[test]
    fn spans_unwind_and_thread_totals_merge() {
        let _ = std::panic::catch_unwind(|| {
            let _outer = Span::start("test.unwind.outer");
            let _inner = Span::start("test.unwind.inner");
            panic!("test early exit");
        });
        assert!(STACK.with(|s| s.borrow().is_empty()));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..10 {
                        let _s = Span::start("test.parallel");
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let totals = snapshot();
        assert_eq!(totals["test.parallel"].calls, 40);
        assert_eq!(totals["test.unwind.inner"].calls, 1);
        assert!(
            totals["test.unwind.outer"].inclusive_wall_ns
                >= totals["test.unwind.inner"].inclusive_wall_ns
        );
        #[cfg(target_os = "linux")]
        assert_eq!(totals["test.parallel"].cpu_measured_calls, 40);
    }
}
