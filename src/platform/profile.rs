//! Opt-in sampled stage timing. No root profiler attachment is required: the
//! daemon measures its own thread CPU clock. Not compiled into normal builds.
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub enum Stage {
    UtunRead,
    UdpRead,
    UtunWrite,
    UdpWrite,
    Encrypt,
    ReceiveSetup,
    SendSetup,
}
const STAGES: [&str; 7] = [
    "utun-read",
    "udp-read",
    "utun-write",
    "udp-write",
    "encrypt-batch",
    "receive-setup",
    "send-setup",
];
const EVERY: u64 = 64;
#[derive(Clone, Copy, Default)]
struct Counts {
    calls: u64,
    samples: u64,
    cpu_ns: u64,
    wall_ns: u64,
}
struct Profile {
    counts: [Counts; 7],
    next: Instant,
}
thread_local! {
    static PROFILE: RefCell<Profile> = RefCell::new(Profile {
        counts: [Counts::default(); 7], next: Instant::now() + Duration::from_secs(5),
    });
}
fn cpu_ns() -> Option<u64> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: t is initialized storage for a timespec. This clock measures
    // CPU consumed by the calling thread, excluding time blocked/descheduled.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) };
    (rc == 0).then(|| t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64)
}
/// A sampled timing span. Scope it around one non-overlapping stage; clocks
/// themselves have a cost, so use these estimates for attribution, not ceilings.
pub struct Span {
    stage: Stage,
    start: Option<(Instant, u64)>,
}
impl Span {
    pub fn new(stage: Stage) -> Self {
        let sample = PROFILE.with_borrow_mut(|p| {
            let c = &mut p.counts[stage as usize];
            c.calls += 1;
            c.calls % EVERY == 1
        });
        Self {
            stage,
            start: if sample {
                cpu_ns().map(|cpu| (Instant::now(), cpu))
            } else {
                None
            },
        }
    }
    pub fn syscall(tun: bool, send: bool) -> Self {
        Self::new(match (tun, send) {
            (true, false) => Stage::UtunRead,
            (false, false) => Stage::UdpRead,
            (true, true) => Stage::UtunWrite,
            (false, true) => Stage::UdpWrite,
        })
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let Some((start, cpu)) = self.start else {
            return;
        };
        let wall = start.elapsed().as_nanos() as u64;
        let Some(end_cpu) = cpu_ns() else {
            return;
        };
        PROFILE.with_borrow_mut(|p| {
            let c = &mut p.counts[self.stage as usize];
            c.samples += 1;
            c.wall_ns += wall;
            c.cpu_ns += end_cpu.saturating_sub(cpu);
        });
    }
}
pub fn report(peer: usize, now: Instant) {
    PROFILE.with_borrow_mut(|p| {
        if now < p.next { return; }
        for (stage,c) in STAGES.into_iter().zip(p.counts) {
            if c.samples == 0 { continue; }
            eprintln!("peer={peer} worker={} profile={stage} calls={} samples={} sampled_cpu_ns={} sampled_wall_ns={}",
                std::thread::current().name().unwrap_or("unnamed"), c.calls,c.samples,c.cpu_ns,c.wall_ns);
        }
        p.counts = [Counts::default(); 7];
        p.next = now + Duration::from_secs(5);
    });
}
