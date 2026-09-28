//! Merge already-authenticated adjacent TCP segments before batched utun injection.
use super::{batch::Sender, coalesce::combine};
use crate::packet::{BATCH, Packet};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
pub struct Coalescer {
    buffers: Vec<Vec<u8>>,
    counts: [usize; BATCH],
    starts: [usize; BATCH],
    locals: Vec<IpAddr>,
    refresh_at: Instant,
}
impl Default for Coalescer {
    fn default() -> Self {
        Self {
            buffers: (0..BATCH).map(|_| Vec::with_capacity(65535)).collect(),
            counts: [0; BATCH],
            starts: [0; BATCH],
            locals: Vec::new(),
            refresh_at: Instant::now(),
        }
    }
}
impl Coalescer {
    pub fn flush(
        &mut self,
        writer: &mut Sender,
        fd: i32,
        queue: &mut VecDeque<Packet>,
    ) -> io::Result<usize> {
        if Instant::now() >= self.refresh_at {
            self.locals = local_addresses();
            self.refresh_at = Instant::now() + Duration::from_secs(1);
        }
        let limit = queue.len().min(BATCH);
        let (mut consumed, mut batches) = (0, 0);
        while consumed < limit {
            let local = crate::packet::addresses(queue[consumed].data())
                .is_some_and(|(_, dst)| self.locals.contains(&dst));
            let count = if local {
                combine(
                    queue
                        .iter()
                        .skip(consumed)
                        .take(limit - consumed)
                        .map(Packet::data),
                    &mut self.buffers[batches],
                )
            } else {
                1
            };
            self.counts[batches] = count;
            self.starts[batches] = consumed;
            consumed += count;
            batches += 1;
        }
        let data = (0..batches).map(|i| {
            if self.counts[i] == 1 {
                queue[self.starts[i]].data()
            } else {
                self.buffers[i].as_slice()
            }
        });
        let sent = match writer.send_slices(fd, true, data) {
            Ok(sent) => sent,
            Err(error) => {
                // As with ordinary batched injection, non-WouldBlock errors
                // can have ambiguous progress. Never retry that attempted prefix.
                if error.kind() != io::ErrorKind::WouldBlock {
                    queue.drain(..limit);
                }
                return Err(error);
            }
        };
        let originals = self.counts[..sent].iter().sum();
        queue.drain(..originals);
        Ok(originals)
    }
}

// Aggregates are only for local TCP delivery. Forwarded packets must retain
// their original MTU/DF semantics. Refresh because interface addresses can be
// configured after the daemon starts or changed while it is running.
fn local_addresses() -> Vec<IpAddr> {
    let mut head = std::ptr::null_mut();
    let mut addresses = Vec::new();
    // SAFETY: getifaddrs supplies a linked list whose sockaddr family determines
    // its concrete allocation size; freeifaddrs releases the complete list.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return addresses;
        }
        let mut cursor = head;
        while let Some(entry) = cursor.as_ref() {
            if let Some(addr) = entry.ifa_addr.as_ref() {
                match i32::from(addr.sa_family) {
                    libc::AF_INET => {
                        let a = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                        addresses.push(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()).into());
                    }
                    libc::AF_INET6 => {
                        let a = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                        addresses.push(Ipv6Addr::from(a.sin6_addr.s6_addr).into());
                    }
                    _ => {}
                }
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    addresses
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        packet,
        platform::coalesce::tests::{packet as make_packet, tcp},
    };
    use std::{net::UdpSocket, os::fd::AsRawFd};
    #[test]
    fn local_delivery_merges_but_forwarded_packets_keep_their_mtu() {
        let pool = packet::pool(8);
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.connect(rx.local_addr().unwrap()).unwrap();
        let mut writer = Sender::new();
        let mut coalescer = Coalescer {
            locals: vec!["10.0.0.2".parse().unwrap()],
            refresh_at: Instant::now() + Duration::from_secs(60),
            ..Coalescer::default()
        };
        let a = tcp(20, 0, 1000, 0x10);
        let b = tcp(20, 1000, 1000, 0x18);
        let mut queue = VecDeque::from([make_packet(&pool, &a), make_packet(&pool, &b)]);
        assert_eq!(
            coalescer
                .flush(&mut writer, tx.as_raw_fd(), &mut queue)
                .unwrap(),
            2
        );
        assert!(queue.is_empty());
        let mut buffer = [0; 4096];
        let n = rx.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..4], &(libc::AF_INET as u32).to_be_bytes());
        assert_eq!(&buffer[4..n], tcp(20, 0, 2000, 0x18));
        // An ambiguous batch error discards only the attempted originals.
        queue.extend([make_packet(&pool, &a), make_packet(&pool, &b)]);
        assert!(coalescer.flush(&mut writer, -1, &mut queue).is_err());
        assert!(queue.is_empty());
        coalescer.locals.clear();
        queue.extend([make_packet(&pool, &a), make_packet(&pool, &b)]);
        assert_eq!(
            coalescer
                .flush(&mut writer, tx.as_raw_fd(), &mut queue)
                .unwrap(),
            2
        );
        for expected in [&a, &b] {
            let n = rx.recv(&mut buffer).unwrap();
            assert_eq!(&buffer[4..n], expected);
        }
    }
}
