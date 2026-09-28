//! Diagnostic counters for the bridge and its worker's readiness loop.
use std::{
    cell::RefCell,
    io,
    time::{Duration, Instant},
};
#[derive(Default, Clone, Copy)]
struct Counts {
    calls: u64,
    packets: u64,
    notifications: u64,
    blocked: u64,
    errors: u64,
}
#[derive(Default)]
struct Polls {
    calls: u64,
    blocking: u64,
    udp_events: u64,
    timeouts: u64,
}
struct Metrics {
    counts: [Counts; 2],
    polls: Polls,
    next: Instant,
}
thread_local! {
    static METRICS: RefCell<Metrics> = RefCell::new(Metrics {
        counts: [Counts::default(); 2], polls: Polls::default(), next: Instant::now() + Duration::from_secs(5),
    });
}
pub fn record(send: bool, notifications: usize, result: &io::Result<usize>) {
    METRICS.with_borrow_mut(|m| {
        let c = &mut m.counts[usize::from(send)];
        c.calls += 1;
        c.notifications += notifications as u64;
        match result {
            Ok(n) => c.packets += *n as u64,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => c.blocked += 1,
            Err(_) => c.errors += 1,
        }
    });
}
pub fn poll(blocking: bool, events: &mio::Events, udp: mio::Token) {
    METRICS.with_borrow_mut(|m| {
        m.polls.calls += 1;
        m.polls.blocking += u64::from(blocking);
        m.polls.udp_events += events.iter().filter(|e| e.token() == udp).count() as u64;
        m.polls.timeouts += u64::from(blocking && events.is_empty());
    });
}
pub fn report(peer: usize, now: Instant) {
    METRICS.with_borrow_mut(|m| {
        if now < m.next { return; }
        let current = std::thread::current();
        let worker = current.name().unwrap_or("unnamed");
        if m.counts.iter().any(|c| c.calls != 0) {
            for (name, c) in ["rx", "tx"].into_iter().zip(m.counts) {
                if c.calls == 0 { continue; }
                eprintln!("peer={peer} worker={worker} network={name} calls={} packets={} notifications={} would_block={} errors={}",
                    c.calls,c.packets,c.notifications,c.blocked,c.errors);
            }
            let p = &m.polls;
            eprintln!("peer={peer} worker={worker} network=poll calls={} blocking={} udp_events={} timeouts={}",
                p.calls,p.blocking,p.udp_events,p.timeouts);
        }
        m.counts = [Counts::default(); 2];
        m.polls = Polls::default();
        m.next = now + Duration::from_secs(5);
    });
}
