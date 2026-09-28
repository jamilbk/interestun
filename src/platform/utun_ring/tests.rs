//! Exercises the production batch engine with ordinary owned memory. These
//! tests do not load Skywalk symbols, create utuns, map channels, or need root.
use super::engine::{Direction, Engine, Slots};
use crate::packet::{self, BATCH, Packet, Pool};
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
};

struct MemoryRing {
    data: Vec<Vec<u8>>,
    lengths: Vec<usize>,
    head: usize,
    used: usize,
}
impl MemoryRing {
    fn new(slots: usize) -> Self {
        Self {
            data: vec![vec![0; 2048]; slots],
            lengths: vec![0; slots],
            head: 0,
            used: 0,
        }
    }
    fn capacity(&self) -> usize {
        self.data.len() - 1
    }
    fn push_rx(&mut self, frame: &[u8]) {
        assert!(self.used < self.capacity());
        let index = (self.head + self.used) % self.data.len();
        self.data[index][..frame.len()].copy_from_slice(frame);
        self.lengths[index] = frame.len();
        self.used += 1;
    }
    fn next(&self, previous: Option<usize>, available: usize) -> Option<usize> {
        let slots = self.data.len();
        let index = previous.map_or(self.head, |i| (i + 1) % slots);
        (((index + slots - self.head) % slots) < available).then_some(index)
    }
    fn count(&self, last: usize) -> usize {
        (last + self.data.len() - self.head) % self.data.len() + 1
    }
}

struct MemoryChannel {
    rx: MemoryRing,
    tx: MemoryRing,
    output: Vec<Vec<u8>>,
    advances: Vec<(Direction, usize)>,
    syncs: [usize; 2],
    drain_tx: bool,
    defunct: bool,
    sync_error: Option<Direction>,
    advance_error: Option<Direction>,
    arrival_on_sync: Option<Vec<u8>>,
    tx_short_after: Option<usize>,
}
impl MemoryChannel {
    fn new(slots: usize) -> Self {
        Self {
            rx: MemoryRing::new(slots),
            tx: MemoryRing::new(slots),
            output: vec![],
            advances: vec![],
            syncs: [0; 2],
            drain_tx: true,
            defunct: false,
            sync_error: None,
            advance_error: None,
            arrival_on_sync: None,
            tx_short_after: None,
        }
    }
}
impl Slots for MemoryChannel {
    type Cursor = usize;
    fn check(&self) -> io::Result<()> {
        if self.defunct {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(())
        }
    }
    fn available(&self, direction: Direction) -> usize {
        match direction {
            Direction::Rx => self.rx.used,
            Direction::Tx => self.tx.capacity() - self.tx.used,
        }
    }
    fn rx_next(&mut self, previous: Option<usize>) -> io::Result<Option<(usize, &[u8])>> {
        Ok(self
            .rx
            .next(previous, self.rx.used)
            .map(|i| (i, &self.rx.data[i][..self.rx.lengths[i]])))
    }
    fn tx_next(&mut self, previous: Option<usize>) -> io::Result<Option<(usize, &mut [u8])>> {
        let available = self
            .available(Direction::Tx)
            .min(self.tx_short_after.unwrap_or(usize::MAX));
        Ok(self
            .tx
            .next(previous, available)
            .map(|i| (i, self.tx.data[i].as_mut_slice())))
    }
    fn tx_len(&mut self, slot: usize, len: usize) -> io::Result<()> {
        assert!(len <= self.tx.data[slot].len());
        self.tx.lengths[slot] = len;
        Ok(())
    }
    fn advance(&mut self, direction: Direction, last: usize) -> io::Result<()> {
        if self.advance_error == Some(direction) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let ring = match direction {
            Direction::Rx => &mut self.rx,
            Direction::Tx => &mut self.tx,
        };
        let count = ring.count(last);
        match direction {
            Direction::Rx => {
                assert!(count <= ring.used);
                // Simulate immediate kernel reuse: consumer payloads must survive.
                for n in 0..count {
                    let i = (ring.head + n) % ring.data.len();
                    ring.data[i].fill(0xcc);
                }
                ring.used -= count;
            }
            Direction::Tx => {
                assert!(count <= ring.capacity() - ring.used);
                ring.used += count;
            }
        }
        ring.head = (last + 1) % ring.data.len();
        self.advances.push((direction, count));
        Ok(())
    }
    fn sync(&mut self, direction: Direction) -> io::Result<()> {
        self.syncs[usize::from(direction == Direction::Tx)] += 1;
        if self.sync_error == Some(direction) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if direction == Direction::Rx {
            if let Some(frame) = self.arrival_on_sync.take() {
                self.rx.push_rx(&frame);
            }
        } else if self.drain_tx {
            let slots = self.tx.data.len();
            let first = (self.tx.head + slots - self.tx.used) % slots;
            for n in 0..self.tx.used {
                let i = (first + n) % slots;
                self.output
                    .push(self.tx.data[i][..self.tx.lengths[i]].to_vec());
            }
            self.tx.used = 0;
        }
        Ok(())
    }
}

fn ip(marker: u32, v6: bool) -> Vec<u8> {
    let mut ip = vec![0; if v6 { 48 } else { 32 }];
    if v6 {
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&8u16.to_be_bytes());
    } else {
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&32u16.to_be_bytes());
    }
    let end = ip.len();
    ip[end - 4..].copy_from_slice(&marker.to_be_bytes());
    ip
}
fn frame(marker: u32, v6: bool) -> Vec<u8> {
    let af = if v6 { libc::AF_INET6 } else { libc::AF_INET } as u32;
    [af.to_be_bytes().as_slice(), ip(marker, v6).as_slice()].concat()
}
fn packet(pool: &Pool, marker: u32) -> Packet {
    let data = ip(marker, marker % 2 == 1);
    let mut packet = Packet::new(pool).unwrap();
    packet.start = packet::HEADROOM;
    packet.len = data.len();
    packet.data_mut().copy_from_slice(&data);
    packet
}
fn buffers(pool: &Pool) -> Vec<Packet> {
    (0..BATCH).filter_map(|_| Packet::new(pool)).collect()
}

#[test]
#[allow(clippy::assertions_on_constants)] // Deliberate interlock: unit tests must never attach.
fn attach_is_rejected_before_loading_apis_or_opening_a_control_socket() {
    assert!(
        !super::LIVE_ATTACH_ENABLED,
        "refusing to exercise open with live attachment enabled"
    );
    let result = crate::platform::utun::Utun::open("utun", 1420);
    let error = result.err().expect("live attachment must remain disabled");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("no interface was opened"));
}

#[test]
fn tx_batches_are_bounded_and_partial_batches_flush_without_waiting() {
    let pool = packet::pool(300);
    let mut queue: VecDeque<_> = (0..300).map(|i| packet(&pool, i)).collect();
    let mut engine = Engine::new(MemoryChannel::new(256), 1420);
    for expected in [128, 128, 44] {
        assert_eq!(engine.flush(&mut queue).unwrap(), expected);
    }
    assert!(queue.is_empty());
    assert_eq!(
        engine.channel.advances,
        [
            (Direction::Tx, 128),
            (Direction::Tx, 128),
            (Direction::Tx, 44)
        ]
    );
    assert_eq!(engine.channel.syncs, [0, 3]);
    for (i, actual) in engine.channel.output.iter().enumerate() {
        assert_eq!(*actual, frame(i as u32, i % 2 == 1));
    }
}

#[test]
fn rx_wraparound_releases_only_copied_slots_and_payload_survives_reuse() {
    let pool = packet::pool(16);
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    for cycle in 0..200 {
        for i in 0..7 {
            engine.channel.rx.push_rx(&frame(cycle * 7 + i, i % 2 == 1));
        }
        let mut scratch = buffers(&pool);
        let mut output = Vec::new();
        assert_eq!(
            engine
                .receive(&mut scratch, |r| output.push(r.packet))
                .unwrap(),
            7
        );
        assert_eq!(engine.channel.rx.used, 0);
        for (i, actual) in output.iter().enumerate() {
            assert_eq!(actual.data(), ip(cycle * 7 + i as u32, i % 2 == 1));
        }
    }
    assert_eq!(engine.channel.syncs, [200, 0]);
    assert_eq!(pool.len(), 16);
}

#[test]
fn full_tx_preserves_tail_and_resumes_after_kernel_reclaim() {
    let pool = packet::pool(20);
    let mut queue: VecDeque<_> = (0..20).map(|i| packet(&pool, i)).collect();
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    engine.channel.drain_tx = false;
    assert_eq!(engine.flush(&mut queue).unwrap(), 7);
    assert_eq!(queue.len(), 13);
    assert_eq!(
        engine.flush(&mut queue).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(queue.front().unwrap().data(), ip(7, true));
    engine.channel.drain_tx = true;
    while !queue.is_empty() {
        engine.flush(&mut queue).unwrap();
    }
    assert_eq!(engine.channel.output.len(), 20);
    for (i, actual) in engine.channel.output.iter().enumerate() {
        assert_eq!(*actual, frame(i as u32, i % 2 == 1));
    }
}

#[test]
fn short_slot_availability_publishes_only_the_completed_prefix() {
    let pool = packet::pool(8);
    let mut queue: VecDeque<_> = (0..8).map(|i| packet(&pool, i)).collect();
    let mut engine = Engine::new(MemoryChannel::new(256), 1420);
    engine.channel.tx_short_after = Some(3);
    assert_eq!(engine.flush(&mut queue).unwrap(), 3);
    assert_eq!(queue.len(), 5);
    assert_eq!(engine.channel.advances, [(Direction::Tx, 3)]);
}

#[test]
fn rx_pool_exhaustion_leaves_the_ring_untouched() {
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    engine.channel.rx.push_rx(&frame(1, false));
    assert_eq!(
        engine
            .receive(&mut vec![], |_| panic!("no packet expected"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(engine.channel.rx.used, 1);
    assert!(engine.channel.advances.is_empty());
    assert_eq!(engine.channel.syncs, [0, 0]);
}

#[test]
fn empty_rx_refreshes_before_would_block_and_detects_arrival() {
    let pool = packet::pool(8);
    let mut scratch = buffers(&pool);
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    assert_eq!(
        engine
            .receive(&mut scratch, |_| panic!("empty"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    engine.channel.arrival_on_sync = Some(frame(12, true));
    let mut seen = 0;
    assert_eq!(
        engine
            .receive(&mut scratch, |r| {
                assert_eq!(r.packet.data(), ip(12, true));
                seen += 1;
            })
            .unwrap(),
        1
    );
    assert_eq!(seen, 1);
}

#[test]
fn malformed_rx_is_consumed_without_delivery_or_losing_valid_neighbors() {
    let pool = packet::pool(16);
    let mut engine = Engine::new(MemoryChannel::new(16), 1420);
    for bytes in [
        vec![],
        vec![0, 0, 0],
        vec![0; 8],
        [&(libc::AF_INET6 as u32).to_be_bytes()[..], &ip(1, false)].concat(),
        vec![0; 2048],
        frame(77, true),
    ] {
        engine.channel.rx.push_rx(&bytes);
    }
    let mut seen = 0;
    assert_eq!(
        engine
            .receive(&mut buffers(&pool), |r| {
                assert_eq!(r.packet.data(), ip(77, true));
                seen += 1;
            })
            .unwrap(),
        6
    );
    assert_eq!(seen, 1);
    assert_eq!(engine.channel.syncs, [1, 0]);
}

#[test]
fn invalid_tx_is_rejected_before_any_publication() {
    let pool = packet::pool(8);
    let mut queue = VecDeque::from([packet(&pool, 0), packet(&pool, 1)]);
    queue[1].len = 1421;
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    assert_eq!(
        engine.flush(&mut queue).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(queue.len(), 2);
    assert!(engine.channel.advances.is_empty());
    assert_eq!(engine.channel.syncs, [0, 0]);
}

#[test]
fn failed_tx_sync_cannot_retry_an_already_published_prefix() {
    let pool = packet::pool(10);
    let mut queue: VecDeque<_> = (0..10).map(|i| packet(&pool, i)).collect();
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    engine.channel.sync_error = Some(Direction::Tx);
    assert_eq!(
        engine.flush(&mut queue).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(queue.len(), 3);
    assert_eq!(queue.front().unwrap().data(), ip(7, true));
    engine.channel.sync_error = None;
    assert_eq!(
        engine.flush(&mut queue).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(engine.channel.advances, [(Direction::Tx, 7)]);
}

#[test]
fn failed_advance_and_defunct_state_are_terminal() {
    let pool = packet::pool(4);
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    engine.channel.advance_error = Some(Direction::Tx);
    let mut queue = VecDeque::from([packet(&pool, 0)]);
    assert_eq!(
        engine.flush(&mut queue).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(queue.len(), 1);
    engine.channel.advance_error = None;
    assert_eq!(
        engine.flush(&mut queue).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    engine.channel.defunct = true;
    assert_eq!(
        engine
            .receive(&mut buffers(&pool), |_| panic!("defunct"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(engine.channel.syncs, [0, 0]);
}

#[test]
fn rx_sync_failure_does_not_deliver_an_ambiguous_batch() {
    let pool = packet::pool(4);
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    engine.channel.rx.push_rx(&frame(1, false));
    engine.channel.sync_error = Some(Direction::Rx);
    assert_eq!(
        engine
            .receive(&mut buffers(&pool), |_| panic!("failed batch"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(engine.channel.rx.used, 0);
}

#[test]
fn concurrent_peer_injection_serializes_batches_and_keeps_each_packet_once() {
    let engine = Arc::new(Mutex::new(Engine::new(MemoryChannel::new(256), 1420)));
    let workers: Vec<_> = (0..4)
        .map(|worker| {
            let engine = engine.clone();
            std::thread::spawn(move || {
                let pool = packet::pool(16);
                for batch in 0..40 {
                    let mut queue = (0..16)
                        .map(|i| packet(&pool, worker * 640 + batch * 16 + i))
                        .collect();
                    assert_eq!(engine.lock().unwrap().flush(&mut queue).unwrap(), 16);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let engine = engine.lock().unwrap();
    let mut markers: Vec<_> = engine
        .channel
        .output
        .iter()
        .map(|f| u32::from_be_bytes(f[f.len() - 4..].try_into().unwrap()))
        .collect();
    markers.sort_unstable();
    assert_eq!(markers, (0..2560).collect::<Vec<_>>());
    assert_eq!(engine.channel.syncs, [0, 160]);
}

#[test]
fn maximum_mtu_v4_and_v6_fit_with_the_family_prefix_and_crypto_headroom() {
    let pool = packet::pool(4);
    let mut engine = Engine::new(MemoryChannel::new(8), 2000);
    for v6 in [false, true] {
        let mut data = ip(0, v6);
        data.resize(2000, 0xab);
        if v6 {
            data[4..6].copy_from_slice(&1960u16.to_be_bytes());
        } else {
            data[2..4].copy_from_slice(&2000u16.to_be_bytes());
        }
        let mut p = Packet::new(&pool).unwrap();
        p.start = packet::HEADROOM;
        p.len = data.len();
        p.data_mut().copy_from_slice(&data);
        assert_eq!(engine.flush(&mut VecDeque::from([p])).unwrap(), 1);
        let frame = engine.channel.output.last().unwrap().clone();
        assert_eq!(frame.len(), 2004);
        engine.channel.rx.push_rx(&frame);
        assert_eq!(
            engine
                .receive(&mut buffers(&pool), |r| {
                    assert_eq!(r.packet.start, packet::HEADROOM);
                    assert_eq!(r.packet.data(), data);
                })
                .unwrap(),
            1
        );
    }
}

#[test]
fn undersized_slot_is_terminal_before_publication() {
    let pool = packet::pool(1);
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    engine.channel.tx.data[0].resize(8, 0);
    let mut queue = VecDeque::from([packet(&pool, 0)]);
    assert_eq!(
        engine.flush(&mut queue).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(queue.len(), 1);
    assert!(engine.channel.advances.is_empty());
    assert!(engine.channel.output.is_empty());
}

#[test]
fn stalled_consumer_keeps_unread_rx_slots_reserved() {
    let pool = packet::pool(3);
    let mut engine = Engine::new(MemoryChannel::new(8), 1420);
    for i in 0..7 {
        engine.channel.rx.push_rx(&frame(i, false));
    }
    let mut held = Vec::new();
    assert_eq!(
        engine
            .receive(&mut buffers(&pool), |r| held.push(r.packet))
            .unwrap(),
        3
    );
    assert_eq!(engine.channel.rx.used, 4);
    assert_eq!(
        engine
            .receive(&mut buffers(&pool), |_| panic!("pool exhausted"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(engine.channel.rx.used, 4);
    for (i, p) in held.iter().enumerate() {
        assert_eq!(p.data(), ip(i as u32, false));
    }
    drop(held);
    let mut next = 3;
    while engine.channel.rx.used != 0 {
        engine
            .receive(&mut buffers(&pool), |r| {
                assert_eq!(r.packet.data(), ip(next, false));
                next += 1;
            })
            .unwrap();
    }
    assert_eq!(next, 7);
    assert_eq!(
        engine.channel.advances,
        [(Direction::Rx, 3), (Direction::Rx, 3), (Direction::Rx, 1)]
    );
}

#[test]
fn rx_budget_caps_each_publication_at_128_packets() {
    let pool = packet::pool(128);
    let mut engine = Engine::new(MemoryChannel::new(512), 1420);
    for i in 0..300 {
        engine.channel.rx.push_rx(&frame(i, false));
    }
    let mut next = 0;
    for expected in [128, 128, 44] {
        assert_eq!(
            engine
                .receive(&mut buffers(&pool), |r| {
                    assert_eq!(r.packet.data(), ip(next, false));
                    next += 1;
                })
                .unwrap(),
            expected
        );
    }
    assert_eq!(next, 300);
    assert_eq!(engine.channel.syncs, [3, 0]);
}
