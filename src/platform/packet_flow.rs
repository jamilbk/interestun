//! Callback adapter for public NEPacketTunnelFlow. No utun fd or Skywalk SPI.
//! Input is copied once into the encryption pool. Output batches lease packet
//! storage until Foundation releases its last reference, including after stop.
use super::{
    batch::Received,
    readiness::{Poll, Token, Waker},
};
use crate::packet::{self, BATCH, HEADROOM, Packet, Pool};
use crossbeam_queue::ArrayQueue;
use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

pub const PENDING: usize = 1024;

pub struct OutputBatch {
    pub packets: Vec<Packet>,
}

/// Implementations may retain a batch beyond the call. Packet bytes are immutable.
pub trait WriteBatch: Send + Sync {
    fn write(&self, batch: &Arc<OutputBatch>) -> bool;
}

#[derive(Default, Debug)]
pub struct Metrics {
    pub input_batches: u64,
    pub input_packets: u64,
    pub input_drops: u64,
    pub output_batches: u64,
    pub output_packets: u64,
    pub output_failures: u64,
}

pub struct Adapter {
    incoming: ArrayQueue<Packet>,
    pool: Pool,
    reader: Mutex<Option<Waker>>,
    writer: Box<dyn WriteBatch>,
    mtu: usize,
    failed: AtomicBool,
    counters: [AtomicU64; 6],
}

impl Adapter {
    pub fn new(mtu: usize, writer: Box<dyn WriteBatch>) -> io::Result<Self> {
        if !(1280..=2000).contains(&mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet flow MTU must be 1280..=2000",
            ));
        }
        Ok(Self {
            incoming: ArrayQueue::new(PENDING),
            pool: packet::pool(PENDING + BATCH),
            reader: Mutex::new(None),
            writer,
            mtu,
            failed: AtomicBool::new(false),
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }

    pub fn register(&self, poll: &Poll, token: Token) -> io::Result<()> {
        let mut reader = self
            .reader
            .lock()
            .map_err(|_| io::Error::other("packet flow waker poisoned"))?;
        let waker = Waker::new(poll, token)?;
        // Registering races with input publication; both sides use this lock.
        if !self.incoming.is_empty() || self.failed.load(Ordering::Acquire) {
            waker.wake()?;
        }
        *reader = Some(waker);
        Ok(())
    }

    pub fn feed<'a>(&self, packets: impl IntoIterator<Item = (&'a [u8], u32)>) -> usize {
        self.counters[0].fetch_add(1, Ordering::Relaxed);
        let mut accepted = 0;
        for (bytes, family) in packets {
            let valid_family = matches!((bytes.first().map(|v| v >> 4), family),
                (Some(4), x) if x == libc::AF_INET as u32)
                || matches!((bytes.first().map(|v| v >> 4), family),
                    (Some(6), x) if x == libc::AF_INET6 as u32);
            if self.failed.load(Ordering::Acquire)
                || !valid_family
                || bytes.len() > self.mtu
                || packet::addresses(bytes).is_none()
            {
                self.counters[2].fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let Some(mut packet) = Packet::new(&self.pool) else {
                self.counters[2].fetch_add(1, Ordering::Relaxed);
                continue;
            };
            packet.start = HEADROOM;
            packet.len = bytes.len();
            packet.data_mut().copy_from_slice(bytes);
            if self.incoming.push(packet).is_err() {
                self.counters[2].fetch_add(1, Ordering::Relaxed);
            } else {
                accepted += 1;
            }
        }
        self.counters[1].fetch_add(accepted as u64, Ordering::Relaxed);
        if accepted != 0 {
            match self.reader.lock() {
                Ok(reader) => {
                    if let Some(waker) = &*reader
                        && waker.wake().is_err()
                    {
                        self.failed.store(true, Ordering::Release);
                    }
                }
                Err(_) => self.failed.store(true, Ordering::Release),
            }
        }
        accepted
    }

    pub fn receive(&self, mut consume: impl FnMut(Received)) -> io::Result<usize> {
        if self.failed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet flow failed",
            ));
        }
        let mut count = 0;
        for _ in 0..BATCH {
            let Some(packet) = self.incoming.pop() else {
                break;
            };
            consume(Received {
                packet,
                source: None,
            });
            count += 1;
        }
        if count == 0 {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            Ok(count)
        }
    }

    pub fn flush(&self, queue: &mut VecDeque<Packet>) -> io::Result<usize> {
        if self.failed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "packet flow failed",
            ));
        }
        let count = queue.len().min(BATCH);
        if count == 0 {
            return Ok(0);
        }
        if queue
            .iter()
            .take(count)
            .any(|p| p.len > self.mtu || packet::addresses(p.data()).is_none())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid packet flow output",
            ));
        }
        // One ownership allocation per batch; the payload stays in its existing
        // pool buffer. Swift retains this lease for each Foundation packet data.
        let batch = Arc::new(OutputBatch {
            packets: queue.drain(..count).collect(),
        });
        self.counters[3].fetch_add(1, Ordering::Relaxed);
        if !self.writer.write(&batch) {
            self.counters[5].fetch_add(1, Ordering::Relaxed);
            self.failed.store(true, Ordering::Release);
            // Public API has no consumed-prefix result. Never retry ambiguous writes.
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "NEPacketTunnelFlow rejected a batch; stopped without retry",
            ));
        }
        self.counters[4].fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }

    pub fn metrics(&self) -> Metrics {
        let v = self.counters.each_ref().map(|c| c.load(Ordering::Relaxed));
        Metrics {
            input_batches: v[0],
            input_packets: v[1],
            input_drops: v[2],
            output_batches: v[3],
            output_packets: v[4],
            output_failures: v[5],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::readiness::Events;
    use std::time::Duration;

    #[derive(Default)]
    struct Sink(Mutex<Vec<Arc<OutputBatch>>>);
    impl WriteBatch for Arc<Sink> {
        fn write(&self, batch: &Arc<OutputBatch>) -> bool {
            self.0.lock().unwrap().push(batch.clone());
            true
        }
    }
    fn ip() -> [u8; 20] {
        let mut ip = [0; 20];
        ip[0] = 0x45;
        ip[3] = 20;
        ip[12] = 10;
        ip[16] = 11;
        ip
    }
    #[test]
    fn callback_wakes_reader_and_preserves_headroom_and_bounded_batches() {
        let adapter = Adapter::new(1420, Box::new(Arc::new(Sink::default()))).unwrap();
        let mut poll = Poll::new().unwrap();
        let bytes = ip();
        // Publish before registration too, so startup cannot lose the first callback.
        assert_eq!(
            adapter.feed((0..130).map(|_| (bytes.as_slice(), libc::AF_INET as u32))),
            130
        );
        adapter.register(&poll, Token(2)).unwrap();
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.token() == Token(2) && e.is_readable())
        );
        assert_eq!(
            adapter
                .receive(|p| {
                    assert_eq!(p.packet.start, HEADROOM);
                    assert_eq!(p.packet.data(), bytes);
                })
                .unwrap(),
            BATCH
        );
        assert_eq!(adapter.receive(|_| {}).unwrap(), 2);
        assert_eq!(
            adapter.receive(|_| {}).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(adapter.feed([(bytes.as_slice(), libc::AF_INET as u32)]), 1);
        poll.poll(&mut events, Some(Duration::from_millis(100)))
            .unwrap();
        assert!(events.iter().any(|e| e.token() == Token(2)));
    }
    #[test]
    fn leased_output_survives_adapter_stop_without_recycling_payload() {
        let sink = Arc::new(Sink::default());
        let adapter = Adapter::new(1420, Box::new(sink.clone())).unwrap();
        let pool = packet::pool(140);
        let mut queue = VecDeque::new();
        for _ in 0..140 {
            let mut p = Packet::new(&pool).unwrap();
            p.len = 20;
            p.data_mut().copy_from_slice(&ip());
            queue.push_back(p);
        }
        let original = queue[0].data().as_ptr();
        assert_eq!(adapter.flush(&mut queue).unwrap(), 128);
        assert_eq!(adapter.flush(&mut queue).unwrap(), 12);
        drop(adapter);
        assert_eq!(pool.len(), 0);
        let mut batches = sink.0.lock().unwrap();
        assert_eq!(batches[0].packets[0].data().as_ptr(), original);
        assert_eq!(batches[0].packets[0].data(), ip());
        batches.clear();
        assert_eq!(pool.len(), 140);
    }
    #[test]
    fn input_bounds_and_family_validation_drop_without_unbounded_allocation() {
        let adapter = Adapter::new(1420, Box::new(Arc::new(Sink::default()))).unwrap();
        let bytes = ip();
        assert_eq!(adapter.feed([(bytes.as_slice(), libc::AF_INET6 as u32)]), 0);
        assert_eq!(
            adapter.feed((0..PENDING + 10).map(|_| (bytes.as_slice(), libc::AF_INET as u32))),
            PENDING
        );
        assert_eq!(adapter.metrics().input_drops, 11);
    }
    #[test]
    fn rejected_write_is_terminal_and_cannot_duplicate_a_partial_batch() {
        struct Reject;
        impl WriteBatch for Reject {
            fn write(&self, _: &Arc<OutputBatch>) -> bool {
                false
            }
        }
        let adapter = Adapter::new(1420, Box::new(Reject)).unwrap();
        let pool = packet::pool(1);
        let mut p = Packet::new(&pool).unwrap();
        p.len = 20;
        p.data_mut().copy_from_slice(&ip());
        let mut queue = VecDeque::from([p]);
        assert_eq!(
            adapter.flush(&mut queue).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(queue.is_empty());
        assert_eq!(
            adapter.flush(&mut queue).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(adapter.metrics().output_batches, 1);
    }
}
