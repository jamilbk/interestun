//! Receive-side TCP coalescing for raw-IP adapter injection, after authentication
//! and AllowedIPs validation. No wire-format changes and no aggregation delay.
use crate::packet::{BATCH, Packet};
use std::{collections::VecDeque, io};

const MAX_PACKET: usize = 65535;

#[derive(Default, Clone, Copy, Debug)]
pub struct Stats {
    pub writes: u64,
    pub merged: u64,
    pub blocked: u64,
}

pub struct Injector {
    enabled: bool,
    buffer: Vec<u8>,
    // Originals remain queued until a successful write, including on ring-full.
    pending: usize,
    pub stats: Stats,
}
impl Injector {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            buffer: Vec::with_capacity(if enabled { MAX_PACKET } else { 0 }),
            pending: 0,
            stats: Stats::default(),
        }
    }

    pub fn flush(
        &mut self,
        queue: &mut VecDeque<Packet>,
        mut send: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<bool> {
        let mut budget = BATCH * 4;
        while budget > 0 && !queue.is_empty() {
            if self.pending == 0 {
                self.pending = 1;
                if self.enabled && queue.len() > 1 {
                    self.pending = combine(
                        queue.iter().take(budget).map(Packet::data),
                        &mut self.buffer,
                    );
                }
            }
            let data = if self.pending > 1 {
                &self.buffer
            } else {
                queue.front().unwrap().data()
            };
            match send(data) {
                Ok(()) => {
                    self.stats.writes += 1;
                    self.stats.merged += (self.pending - 1) as u64;
                    budget -= self.pending;
                    queue.drain(..self.pending);
                    self.pending = 0;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.stats.blocked += 1;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => break,
                Err(e) => return Err(e),
            }
        }
        // Work left after consuming our budget should run again immediately;
        // blocked writes instead need the runtime's bounded retry delay.
        Ok(budget == 0 && !queue.is_empty())
    }
}

#[derive(Clone, Copy)]
struct Segment<'a> {
    bytes: &'a [u8],
    ip: usize,
    header: usize,
    seq: u32,
}
impl<'a> Segment<'a> {
    fn parse(p: &'a [u8]) -> Option<Self> {
        let ip = match p.first()? >> 4 {
            4 if p.len() >= 40 && p[0] == 0x45 && p[9] == 6 => {
                // Require DF, no reserved/MF bits, no fragments or IP options.
                if p[6..8] != [0x40, 0]
                    || read16(p, 2) as usize != p.len()
                    || checksum(&p[..20]) != 0
                {
                    return None;
                }
                20
            }
            6 if p.len() >= 60 && p[6] == 6 => {
                // No extension headers or jumbograms.
                if read16(p, 4) as usize + 40 != p.len() {
                    return None;
                }
                40
            }
            _ => return None,
        };
        let tcp = &p[ip..];
        let tcp_header = (tcp[12] >> 4) as usize * 4;
        if tcp_header < 20
            || tcp_header >= tcp.len()
            || tcp[12] & 15 != 0
            || !matches!(tcp[13], 0x10 | 0x18)
            || tcp[18..20] != [0, 0]
            || !plain_options(&tcp[20..tcp_header])
            || tcp_checksum(p, ip) != 0
        {
            return None;
        }
        Some(Self {
            bytes: p,
            ip,
            header: ip + tcp_header,
            seq: u32::from_be_bytes(tcp[4..8].try_into().unwrap()),
        })
    }
    fn payload(self) -> &'a [u8] {
        &self.bytes[self.header..]
    }
    fn psh(self) -> bool {
        self.bytes[self.ip + 13] & 8 != 0
    }
    fn compatible(self, next: Self) -> bool {
        if self.ip != next.ip || self.header != next.header {
            return false;
        }
        let (a, b) = (self.bytes, next.bytes);
        let same_ip = if self.ip == 20 {
            // Ignore IPv4 ID only because DF is set on both packets.
            a[..2] == b[..2] && a[6..10] == b[6..10] && a[12..20] == b[12..20]
        } else {
            a[..4] == b[..4] && a[6..40] == b[6..40]
        };
        let (a, b) = (&a[self.ip..], &b[next.ip..]);
        same_ip
            && a[..4] == b[..4]
            && a[8..13] == b[8..13]
            && a[14..16] == b[14..16]
            && a[18..self.header - self.ip] == b[18..next.header - next.ip]
    }
}

// Unknown TCP options may authenticate the original segment (TCP-AO/MD5), or
// carry semantics that cannot survive merging. Only identical timestamps/padding
// are eligible. SYN/SACK negotiation and pure ACKs always pass through unchanged.
fn plain_options(mut options: &[u8]) -> bool {
    let mut timestamp = false;
    while let Some(&kind) = options.first() {
        match kind {
            0 => return options.iter().all(|&byte| byte == 0),
            1 => options = &options[1..],
            8 if !timestamp && options.len() >= 10 && options[1] == 10 => {
                timestamp = true;
                options = &options[10..];
            }
            _ => return false,
        }
    }
    true
}

/// Combine only adjacent, compatible, in-order data already available in a
/// worker's queue. Any other packet is a barrier, preserving all packet ordering.
fn combine<'a>(mut packets: impl Iterator<Item = &'a [u8]>, output: &mut Vec<u8>) -> usize {
    output.clear();
    let Some(first) = packets.next().and_then(Segment::parse) else {
        return 1;
    };
    let mut last = first;
    let mut count = 1;
    for bytes in packets {
        if last.psh() {
            break;
        }
        let Some(next) = Segment::parse(bytes) else {
            break;
        };
        let current_len = if count == 1 {
            first.bytes.len()
        } else {
            output.len()
        };
        if !first.compatible(next)
            || next.seq != last.seq.wrapping_add(last.payload().len() as u32)
            || current_len + next.payload().len() > MAX_PACKET
        {
            break;
        }
        if count == 1 {
            output.extend_from_slice(first.bytes);
        }
        output.extend_from_slice(next.payload());
        count += 1;
        last = next;
    }
    if count > 1 {
        let len = output.len();
        if first.ip == 20 {
            output[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            output[10..12].fill(0);
            let sum = checksum(&output[..20]);
            output[10..12].copy_from_slice(&sum.to_be_bytes());
        } else {
            output[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        }
        output[first.ip + 13] = last.bytes[last.ip + 13];
        output[first.ip + 16..first.ip + 18].fill(0);
        let sum = tcp_checksum(output, first.ip);
        output[first.ip + 16..first.ip + 18].copy_from_slice(&sum.to_be_bytes());
    }
    count
}

fn read16(p: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([p[offset], p[offset + 1]])
}
fn word_sum(bytes: &[u8]) -> u32 {
    // Contiguous 16-bit words let LLVM vectorize the checksum reduction. A
    // per-byte alternating high/low loop prevents that on the Windows target.
    let mut words = bytes.chunks_exact(2);
    let sum: u32 = words
        .by_ref()
        .map(|w| u16::from_be_bytes([w[0], w[1]]) as u32)
        .sum();
    sum + words.remainder().first().map_or(0, |&b| (b as u32) << 8)
}
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn checksum(bytes: &[u8]) -> u16 {
    fold(word_sum(bytes))
}
fn tcp_checksum(p: &[u8], ip: usize) -> u16 {
    let length = (p.len() - ip) as u32;
    let mut pseudo = [0u8; 40];
    let n = if ip == 20 {
        pseudo[..8].copy_from_slice(&p[12..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&(length as u16).to_be_bytes());
        12
    } else {
        pseudo[..32].copy_from_slice(&p[8..40]);
        pseudo[32..36].copy_from_slice(&length.to_be_bytes());
        pseudo[39] = 6;
        40
    };
    fold(word_sum(&pseudo[..n]) + word_sum(&p[ip..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{self, Pool};
    fn tcp(ip: usize, seq: u32, payload: usize, flags: u8) -> Vec<u8> {
        let mut p = vec![0; ip + 20 + payload];
        if ip == 20 {
            p[0] = 0x45;
            p[6] = 0x40;
            p[8] = 64;
            p[9] = 6;
            p[12..20].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        } else {
            p[0] = 0x60;
            p[6] = 6;
            p[7] = 64;
            p[8] = 0xfd;
            p[23] = 1;
            p[24] = 0xfd;
            p[39] = 2;
        }
        p[ip..ip + 4].copy_from_slice(&[0x12, 0x34, 0x14, 0x51]);
        p[ip + 4..ip + 8].copy_from_slice(&seq.to_be_bytes());
        p[ip + 11] = 1;
        p[ip + 12] = 0x50;
        p[ip + 13] = flags;
        p[ip + 14] = 0x80;
        p[ip + 20..].fill(0x61);
        fix(&mut p, ip);
        p
    }
    fn fix(p: &mut [u8], ip: usize) {
        let len = p.len();
        if ip == 20 {
            p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            p[10..12].fill(0);
            let sum = checksum(&p[..20]);
            p[10..12].copy_from_slice(&sum.to_be_bytes());
        } else {
            p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        }
        p[ip + 16..ip + 18].fill(0);
        let sum = tcp_checksum(p, ip);
        p[ip + 16..ip + 18].copy_from_slice(&sum.to_be_bytes());
    }
    fn packet(pool: &Pool, bytes: &[u8]) -> Packet {
        let mut p = Packet::new(pool).unwrap();
        p.buffer()[..bytes.len()].copy_from_slice(bytes);
        p.len = bytes.len();
        p
    }
    #[test]
    fn coalesces_v4_v6_wraparound_odd_lengths_and_psh() {
        // Independently known Internet checksum example, including odd padding.
        assert_eq!(checksum(&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
        assert_eq!(checksum(&[1]), 0xfeff);
        for ip in [20, 40] {
            let a = tcp(ip, u32::MAX - 2, 3, 0x10);
            let b = tcp(ip, 0, 5, 0x18);
            let c = tcp(ip, 5, 2, 0x10);
            let mut out = Vec::new();
            assert_eq!(combine([a.as_slice(), &b, &c].into_iter(), &mut out), 2);
            assert_eq!(out, tcp(ip, u32::MAX - 2, 8, 0x18));
            assert_eq!(tcp_checksum(&out, ip), 0);
        }
    }
    #[test]
    fn incompatible_segments_and_bad_checksums_are_barriers() {
        for ip in [20, 40] {
            let a = tcp(ip, 100, 20, 0x10);
            let b = tcp(ip, 120, 20, 0x10);
            for offset in [
                ip,
                ip + 4,
                ip + 8,
                ip + 14,
                ip + 18,
                if ip == 20 { 8 } else { 7 },
                if ip == 20 { 1 } else { 3 },
            ] {
                let mut bad = b.clone();
                bad[offset] ^= 1;
                fix(&mut bad, ip);
                assert_eq!(
                    combine([a.as_slice(), &bad, &b].into_iter(), &mut Vec::new()),
                    1,
                    "offset {offset}"
                );
            }
            for flags in [0, 1, 2, 4, 0x11, 0x30, 0x50, 0x90] {
                let bad = tcp(ip, 120, 20, flags);
                assert_eq!(
                    combine([a.as_slice(), &bad].into_iter(), &mut Vec::new()),
                    1
                );
            }
            let mut bad = b.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert_eq!(
                combine([a.as_slice(), &bad].into_iter(), &mut Vec::new()),
                1
            );
            let ack = tcp(ip, 120, 0, 0x10);
            assert_eq!(
                combine([a.as_slice(), &ack, &b].into_iter(), &mut Vec::new()),
                1
            );
            for len in 0..b.len() {
                assert!(Segment::parse(&b[..len]).is_none());
            }
        }
    }
    #[test]
    fn rejects_fragments_options_and_oversize_aggregates() {
        let a = tcp(20, 0, 40000, 0x10);
        let b = tcp(20, 40000, 30000, 0x10);
        assert_eq!(combine([a.as_slice(), &b].into_iter(), &mut Vec::new()), 1);
        for flag in [0, 0x20, 0x60, 0x80] {
            let mut p = tcp(20, 0, 10, 0x10);
            p[6] = flag;
            fix(&mut p, 20);
            assert!(Segment::parse(&p).is_none());
        }
        assert!(plain_options(&[1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!plain_options(&[19, 2]));
        assert!(!plain_options(&[29, 2]));
        assert!(!plain_options(&[8, 10, 0]));
        let mut p = tcp(40, 0, 10, 0x10);
        p[6] = 44;
        assert!(Segment::parse(&p).is_none());
    }
    #[test]
    fn timestamps_must_match_and_options_must_be_understood() {
        let options = [1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2];
        let with_options = |seq| {
            let mut p = tcp(20, seq, 10, 0x10);
            p.splice(40..40, options);
            p[32] = 0x80;
            fix(&mut p, 20);
            p
        };
        let a = with_options(0);
        let b = with_options(10);
        assert_eq!(combine([a.as_slice(), &b].into_iter(), &mut Vec::new()), 2);
        for offset in [47, 51] {
            let mut changed = b.clone();
            changed[offset] ^= 1;
            fix(&mut changed, 20);
            assert_eq!(
                combine([a.as_slice(), &changed].into_iter(), &mut Vec::new()),
                1
            );
        }
        let mut auth = b;
        auth[42] = 19;
        fix(&mut auth, 20);
        assert!(Segment::parse(&auth).is_none());
    }
    #[test]
    fn checksum_matches_scalar_reference_on_unaligned_odd_and_large_slices() {
        let bytes: Vec<u8> = (0..65536u32)
            .map(|i| (i.wrapping_mul(197) ^ (i >> 7)) as u8)
            .collect();
        for length in (0..128).chain([511, 1400, 1420, 2048, 65535]) {
            for offset in [0, 1] {
                let p = &bytes[offset..offset + length];
                let mut value = 0u64;
                for (index, byte) in p.iter().enumerate() {
                    value += (*byte as u64) << if index % 2 == 0 { 8 } else { 0 };
                }
                while value > 65535 {
                    value = (value & 65535) + (value >> 16);
                }
                assert_eq!(checksum(p), !(value as u16));
            }
        }
    }
    #[test]
    fn fairness_budget_requests_immediate_progress_but_blocking_does_not() {
        let pool = packet::pool(BATCH * 4 + 1);
        let bytes = tcp(20, 0, 1, 0x18);
        let mut queue = (0..BATCH * 4 + 1).map(|_| packet(&pool, &bytes)).collect();
        let mut injector = Injector::new(true);
        assert!(
            !injector
                .flush(&mut queue, |_| Err(io::ErrorKind::WouldBlock.into()))
                .unwrap()
        );
        assert!(injector.flush(&mut queue, |_| Ok(())).unwrap());
        assert_eq!(queue.len(), 1);
        assert!(!injector.flush(&mut queue, |_| Ok(())).unwrap());
        assert!(queue.is_empty());
    }
    #[test]
    fn ring_full_preserves_prepared_bytes_and_queue_order() {
        let pool = packet::pool(4);
        let a = tcp(20, 0, 11, 0x10);
        let b = tcp(20, 11, 13, 0x18);
        let c = tcp(20, 24, 5, 0x10);
        let mut queue = VecDeque::from([packet(&pool, &a), packet(&pool, &b)]);
        let mut injector = Injector::new(true);
        let mut staged = Vec::new();
        injector
            .flush(&mut queue, |p| {
                staged = p.to_vec();
                Err(io::ErrorKind::WouldBlock.into())
            })
            .unwrap();
        assert_eq!(queue.len(), 2);
        queue.push_back(packet(&pool, &c));
        let mut received = Vec::new();
        injector
            .flush(&mut queue, |p| {
                received.push(p.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(received, [staged, c]);
        assert!(queue.is_empty());
        assert_eq!(pool.len(), 4);
        assert_eq!(injector.stats.writes, 2);
        assert_eq!(injector.stats.merged, 1);
        assert_eq!(injector.stats.blocked, 1);
        let mut injector = Injector::new(false);
        let mut queue = VecDeque::from([packet(&pool, &a), packet(&pool, &b)]);
        let mut received = Vec::new();
        injector
            .flush(&mut queue, |p| {
                received.push(p.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(received, [a, b]);
        assert_eq!(injector.stats.merged, 0);
    }
}
