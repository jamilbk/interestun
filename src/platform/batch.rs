//! Darwin batched datagram I/O, with per-message fallback when private symbols are absent.
//! ABI and runtime resolution follow Firezone's Apple TUN implementation.
#[cfg(feature = "io-profile")]
use super::profile::{self, Span, Stage};
use crate::packet::{BATCH, CAPACITY, HEADROOM, Packet, Pool};
use std::{
    collections::VecDeque,
    ffi::c_void,
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::RawFd,
    ptr,
    sync::OnceLock,
};

#[repr(C)]
#[derive(Clone, Copy)]
struct Msg {
    name: *mut c_void,
    namelen: libc::socklen_t,
    iov: *mut libc::iovec,
    iovlen: i32,
    control: *mut c_void,
    controllen: libc::socklen_t,
    flags: i32,
    datalen: usize,
}
const EMPTY: Msg = Msg {
    name: ptr::null_mut(),
    namelen: 0,
    iov: ptr::null_mut(),
    iovlen: 0,
    control: ptr::null_mut(),
    controllen: 0,
    flags: 0,
    datalen: 0,
};
const IOV: libc::iovec = libc::iovec {
    iov_base: ptr::null_mut(),
    iov_len: 0,
};
type Recv = unsafe extern "C" fn(i32, *mut Msg, u32, i32) -> isize;
type Send = unsafe extern "C" fn(i32, *const Msg, u32, i32) -> isize;
fn syscalls() -> Option<(Recv, Send)> {
    static CALLS: OnceLock<Option<(Recv, Send)>> = OnceLock::new();
    *CALLS.get_or_init(|| {
        // SAFETY: Names are nul-terminated; function types match socket_private.h on Darwin LP64.
        unsafe {
            let recv = libc::dlsym(libc::RTLD_DEFAULT, c"recvmsg_x".as_ptr());
            let send = libc::dlsym(libc::RTLD_DEFAULT, c"sendmsg_x".as_ptr());
            if recv.is_null() || send.is_null() {
                None
            } else {
                Some((
                    std::mem::transmute::<*mut c_void, Recv>(recv),
                    std::mem::transmute::<*mut c_void, Send>(send),
                ))
            }
        }
    })
}
pub fn available() -> bool {
    syscalls().is_some()
}
fn result(n: isize) -> io::Result<usize> {
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
fn address(a: &libc::sockaddr_storage) -> Option<SocketAddr> {
    // SAFETY: sockaddr_storage is aligned and large enough for both sockaddr variants.
    unsafe {
        match i32::from(a.ss_family) {
            libc::AF_INET => {
                let a = &*(a as *const _ as *const libc::sockaddr_in);
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes())),
                    u16::from_be(a.sin_port),
                ))
            }
            libc::AF_INET6 => {
                let a = &*(a as *const _ as *const libc::sockaddr_in6);
                Some(
                    std::net::SocketAddrV6::new(
                        Ipv6Addr::from(a.sin6_addr.s6_addr),
                        u16::from_be(a.sin6_port),
                        a.sin6_flowinfo,
                        a.sin6_scope_id,
                    )
                    .into(),
                )
            }
            _ => None,
        }
    }
}

// Diagnostic builds only; production builds have no counter or TLS overhead.
#[cfg(feature = "io-metrics")]
mod metrics {
    use std::{
        cell::RefCell,
        io,
        time::{Duration, Instant},
    };
    #[derive(Clone, Copy, Default)]
    struct Counts {
        calls: u64,
        requested: u64,
        packets: u64,
        blocked: u64,
        errors: u64,
    }
    struct Metrics {
        counts: [Counts; 4],
        next: Instant,
    }
    thread_local! {
        static METRICS: RefCell<Metrics> = RefCell::new(Metrics {
            counts: [Counts::default(); 4], next: Instant::now() + Duration::from_secs(5),
        });
    }
    pub(super) fn record(tun: bool, send: bool, requested: usize, result: &io::Result<usize>) {
        METRICS.with_borrow_mut(|m| {
            let c = &mut m.counts[usize::from(!tun) * 2 + usize::from(send)];
            c.calls += 1;
            c.requested += requested as u64;
            match result {
                Ok(n) => c.packets += *n as u64,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => c.blocked += 1,
                Err(_) => c.errors += 1,
            }
        });
    }
    pub(super) fn report(peer: usize, now: Instant) {
        METRICS.with_borrow_mut(|m| {
            if now < m.next { return; }
            for (name, c) in ["utun-rx", "utun-tx", "udp-rx", "udp-tx"].into_iter().zip(m.counts) {
                eprintln!("peer={peer} worker={} io={name} calls={} requested={} packets={} would_block={} errors={}",
                    std::thread::current().name().unwrap_or("unnamed"), c.calls, c.requested, c.packets, c.blocked, c.errors);
            }
            m.counts = [Counts::default(); 4];
            m.next = now + Duration::from_secs(5);
        });
    }
}
#[cfg(feature = "io-metrics")]
pub fn report_metrics(peer: usize, now: std::time::Instant) {
    metrics::report(peer, now);
    #[cfg(feature = "apple-network")]
    super::network::metrics::report(peer, now);
    #[cfg(feature = "io-profile")]
    profile::report(peer, now);
}

// Allocate once on the I/O thread. Descriptor pointers are refreshed for each
// active slot because pooled payload ownership can change between calls.
struct Descriptors {
    afs: [[u8; 4]; BATCH],
    iovs: [[libc::iovec; 2]; BATCH],
    msgs: [Msg; BATCH],
}
impl Default for Descriptors {
    fn default() -> Self {
        Self {
            afs: [[0; 4]; BATCH],
            iovs: [[IOV; 2]; BATCH],
            msgs: [EMPTY; BATCH],
        }
    }
}
struct ReceiveScratch {
    descriptors: Descriptors,
    addresses: [libc::sockaddr_storage; BATCH],
}
impl Default for ReceiveScratch {
    fn default() -> Self {
        Self {
            descriptors: Descriptors::default(),
            // SAFETY: all-zero sockaddr_storage is valid; recv supplies the
            // complete source address for each successfully received datagram.
            addresses: unsafe { std::mem::zeroed() },
        }
    }
}

pub struct Received {
    pub packet: Packet,
    pub source: Option<SocketAddr>,
}
pub struct Receiver {
    slots: Vec<Packet>,
    pool: Pool,
    scratch: Box<ReceiveScratch>,
}
impl Receiver {
    pub fn new(pool: Pool) -> Self {
        Self {
            slots: Vec::with_capacity(BATCH),
            pool,
            scratch: Box::default(),
        }
    }
    #[cfg(feature = "apple-network")]
    pub(super) fn receive_buffers(&mut self) -> &mut Vec<Packet> {
        while self.slots.len() < BATCH {
            let Some(packet) = Packet::new(&self.pool) else {
                break;
            };
            self.slots.push(packet);
        }
        &mut self.slots
    }
    pub fn receive(
        &mut self,
        fd: RawFd,
        tun: bool,
        mut consume: impl FnMut(Received),
    ) -> io::Result<usize> {
        while self.slots.len() < BATCH {
            let Some(packet) = Packet::new(&self.pool) else {
                break;
            };
            self.slots.push(packet);
        }
        if self.slots.is_empty() {
            // No syscall was made: callers must retain kernel readiness.
            return Err(io::Error::from(io::ErrorKind::OutOfMemory));
        }
        #[cfg(feature = "io-profile")]
        let setup_span = Span::new(Stage::ReceiveSetup);
        let count = self.slots.len();
        let start = if tun { HEADROOM } else { 0 };
        let ReceiveScratch {
            descriptors: Descriptors { afs, iovs, msgs },
            addresses,
        } = &mut *self.scratch;
        for i in 0..count {
            let payload = libc::iovec {
                iov_base: self.slots[i].buffer()[start..].as_mut_ptr().cast(),
                iov_len: CAPACITY - start,
            };
            iovs[i][0] = if tun {
                libc::iovec {
                    iov_base: afs[i].as_mut_ptr().cast(),
                    iov_len: 4,
                }
            } else {
                payload
            };
            iovs[i][1] = payload;
            msgs[i] = Msg {
                iov: iovs[i].as_mut_ptr(),
                iovlen: if tun { 2 } else { 1 },
                name: if tun {
                    ptr::null_mut()
                } else {
                    (&mut addresses[i] as *mut libc::sockaddr_storage).cast()
                },
                namelen: if tun {
                    0
                } else {
                    size_of::<libc::sockaddr_storage>() as _
                },
                ..EMPTY
            };
        }
        #[cfg(feature = "io-profile")]
        drop(setup_span);
        // SAFETY: All message/iovec pointers refer to live, exclusive buffers for this synchronous call.
        let n = unsafe {
            if let Some((recv, _)) = syscalls() {
                #[cfg(feature = "io-profile")]
                let span = Span::syscall(tun, false);
                let result = result(recv(
                    fd,
                    msgs.as_mut_ptr(),
                    count as u32,
                    libc::MSG_DONTWAIT,
                ));
                #[cfg(feature = "io-profile")]
                drop(span);
                #[cfg(feature = "io-metrics")]
                metrics::record(tun, false, count, &result);
                result?
            } else {
                let mut n = 0;
                for msg in &mut msgs[..count] {
                    let mut hdr = libc::msghdr {
                        msg_name: msg.name,
                        msg_namelen: msg.namelen,
                        msg_iov: msg.iov,
                        msg_iovlen: msg.iovlen,
                        msg_control: ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    };
                    #[cfg(feature = "io-profile")]
                    let span = Span::syscall(tun, false);
                    let result = result(libc::recvmsg(fd, &mut hdr, libc::MSG_DONTWAIT));
                    #[cfg(feature = "io-profile")]
                    drop(span);
                    #[cfg(feature = "io-metrics")]
                    metrics::record(
                        tun,
                        false,
                        1,
                        &result
                            .as_ref()
                            .map(|_| 1)
                            .map_err(|e| io::Error::from(e.kind())),
                    );
                    match result {
                        Ok(len) => {
                            msg.datalen = len;
                            msg.flags = hdr.msg_flags;
                            n += 1;
                        }
                        Err(_) if n > 0 => break,
                        Err(e) => return Err(e),
                    }
                }
                n
            }
        };
        // Drain in receive order. The backing allocation remains reusable.
        for (i, mut packet) in self.slots.drain(..n).enumerate() {
            let len = msgs[i].datalen;
            // Darwin's legacy recvmsg_x path can lose MSG_TRUNC during copyout.
            // Valid MTU <= 2000 traffic (plus <= 32 WireGuard bytes) never fills
            // this buffer, so reject a full slot even when flags are missing.
            if msgs[i].flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                || len >= CAPACITY - start + if tun { 4 } else { 0 }
            {
                continue;
            }
            packet.start = start;
            if tun {
                let af = u32::from_be_bytes(afs[i]) as i32;
                if len < 4 || !matches!(af, libc::AF_INET | libc::AF_INET6) {
                    continue;
                }
                packet.len = len - 4;
                let version = packet.data().first().map(|b| b >> 4);
                if version != Some(if af == libc::AF_INET { 4 } else { 6 }) {
                    continue;
                }
            } else {
                packet.len = len;
            }
            consume(Received {
                packet,
                source: if tun { None } else { address(&addresses[i]) },
            });
        }
        Ok(n)
    }
}

/// Reusable send descriptors; create one per direction worker.
#[derive(Default)]
pub struct Sender {
    scratch: Box<Descriptors>,
}
impl Sender {
    pub fn new() -> Self {
        Self::default()
    }
    /// Sends a prefix, preserving the unsent tail on short writes / WouldBlock.
    /// On other batch errors progress is ambiguous, so discard the attempted batch.
    pub fn flush(
        &mut self,
        fd: RawFd,
        tun: bool,
        queue: &mut VecDeque<Packet>,
    ) -> io::Result<usize> {
        let count = queue.len().min(BATCH);
        if count == 0 {
            return Ok(0);
        }
        let result = self.send_slices(fd, tun, queue.iter().take(count).map(Packet::data));
        match result {
            Ok(0) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            Ok(n) => {
                queue.drain(..n);
                Ok(n)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => {
                queue.drain(..count);
                Err(e)
            }
        }
    }
    pub(super) fn send_slices<'a>(
        &mut self,
        fd: RawFd,
        tun: bool,
        data: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> io::Result<usize> {
        let count = data.len().min(BATCH);
        if count == 0 {
            return Ok(0);
        }
        #[cfg(feature = "io-profile")]
        let setup_span = Span::new(Stage::SendSetup);
        let Descriptors { afs, iovs, msgs } = &mut *self.scratch;
        for (i, data) in data.take(count).enumerate() {
            let payload = libc::iovec {
                iov_base: data.as_ptr() as *mut c_void,
                iov_len: data.len(),
            };
            afs[i] = (if data.first().is_some_and(|b| b >> 4 == 6) {
                libc::AF_INET6
            } else {
                libc::AF_INET
            } as u32)
                .to_be_bytes();
            iovs[i][0] = if tun {
                libc::iovec {
                    iov_base: afs[i].as_mut_ptr().cast(),
                    iov_len: 4,
                }
            } else {
                payload
            };
            iovs[i][1] = payload;
            msgs[i] = Msg {
                iov: iovs[i].as_mut_ptr(),
                iovlen: if tun { 2 } else { 1 },
                ..EMPTY
            };
        }
        #[cfg(feature = "io-profile")]
        drop(setup_span);
        #[cfg(feature = "io-profile")]
        let span = Span::syscall(tun, true);
        // SAFETY: send does not mutate payloads; every pointer outlives this synchronous call.
        let result = unsafe {
            if let Some((_, send)) = syscalls() {
                result(send(fd, msgs.as_ptr(), count as u32, libc::MSG_DONTWAIT))
            } else {
                let msg = &msgs[0];
                let hdr = libc::msghdr {
                    msg_name: ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: msg.iov,
                    msg_iovlen: msg.iovlen,
                    msg_control: ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                };
                result(libc::sendmsg(fd, &hdr, libc::MSG_DONTWAIT)).map(|_| 1)
            }
        };
        #[cfg(feature = "io-profile")]
        drop(span);
        #[cfg(feature = "io-metrics")]
        metrics::record(tun, true, if available() { count } else { 1 }, &result);
        result.and_then(|n| {
            if n == 0 {
                Err(io::ErrorKind::WouldBlock.into())
            } else {
                Ok(n)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    fn wait_readable(fd: i32) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a live, initialized single-element poll array.
        assert_eq!(unsafe { libc::poll(&mut pfd, 1, 1000) }, 1);
    }
    #[test]
    fn maximum_utun_packet_roundtrips_with_header_space() {
        use std::os::fd::AsRawFd;
        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        let kernel = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.connect(kernel.local_addr().unwrap()).unwrap();
        kernel.connect(app.local_addr().unwrap()).unwrap();
        app.set_nonblocking(true).unwrap();
        kernel
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut bytes = vec![0; 2004];
        bytes[..4].copy_from_slice(&(libc::AF_INET as u32).to_be_bytes());
        bytes[4] = 0x45;
        bytes[6..8].copy_from_slice(&2000u16.to_be_bytes());
        bytes[2003] = 123;
        kernel.send(&bytes).unwrap();
        wait_readable(app.as_raw_fd());
        let mut receiver = Receiver::new(crate::packet::pool(32));
        let mut pending = VecDeque::new();
        receiver
            .receive(app.as_raw_fd(), true, |r| {
                assert_eq!(r.packet.start, HEADROOM);
                assert_eq!(r.packet.data(), &bytes[4..]);
                pending.push_back(r.packet);
            })
            .unwrap();
        assert_eq!(
            Sender::new()
                .flush(app.as_raw_fd(), true, &mut pending)
                .unwrap(),
            1
        );
        let mut out = [0; 2048];
        let len = kernel.recv(&mut out).unwrap();
        assert_eq!(&out[..len], bytes);
    }
    #[test]
    fn pool_exhaustion_is_not_socket_would_block() {
        use std::os::fd::AsRawFd;
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let pool = crate::packet::pool(1);
        let held = Packet::new(&pool).unwrap();
        let mut rx = Receiver::new(pool);
        assert_eq!(
            rx.receive(socket.as_raw_fd(), false, |_| unreachable!())
                .unwrap_err()
                .kind(),
            io::ErrorKind::OutOfMemory
        );
        drop(held);
        assert_eq!(
            rx.receive(socket.as_raw_fd(), false, |_| unreachable!())
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn layout_and_connected_udp_batch() {
        assert_eq!(size_of::<Msg>(), 56);
        assert_eq!(std::mem::offset_of!(Msg, datalen), 48);
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.connect(b.local_addr().unwrap()).unwrap();
        b.connect(a.local_addr().unwrap()).unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        let pool = crate::packet::pool(BATCH * 2);
        let mut queue = VecDeque::new();
        let mut writer = Sender::new();
        let mut rx = Receiver::new(pool.clone());
        use std::os::fd::AsRawFd;
        // Reuse the same descriptors with both shrinking and growing batches.
        for count in [BATCH, 1, 7] {
            for i in 0..count {
                let mut p = Packet::new(&pool).unwrap();
                p.buffer()[..count].fill(i as u8);
                p.len = count;
                queue.push_back(p);
            }
            while !queue.is_empty() {
                writer.flush(a.as_raw_fd(), false, &mut queue).unwrap();
            }
            let mut seen = Vec::new();
            while seen.len() < count {
                wait_readable(b.as_raw_fd());
                rx.receive(b.as_raw_fd(), false, |r| {
                    assert_eq!(r.source, Some(a.local_addr().unwrap()));
                    assert_eq!(r.packet.len, count);
                    let first = r.packet.data()[0];
                    assert!(r.packet.data().iter().all(|b| *b == first));
                    seen.push(first);
                })
                .unwrap();
            }
            assert_eq!(seen, (0..count as u8).collect::<Vec<_>>());
        }
    }
    #[test]
    fn truncation_and_invalid_utun_family_are_dropped() {
        use std::os::fd::AsRawFd;
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        let pool = crate::packet::pool(128);
        let mut rx = Receiver::new(pool.clone());
        sender.send(&[0u8; CAPACITY + 100]).unwrap();
        let mut delivered = 0;
        wait_readable(receiver.as_raw_fd());
        assert_eq!(
            rx.receive(receiver.as_raw_fd(), false, |_| delivered += 1)
                .unwrap(),
            1
        );
        assert_eq!(delivered, 0);
        sender.send(&[0, 0, 0, 255, 0x45]).unwrap();
        wait_readable(receiver.as_raw_fd());
        assert_eq!(
            rx.receive(receiver.as_raw_fd(), true, |_| delivered += 1)
                .unwrap(),
            1
        );
        assert_eq!(delivered, 0);
        // A valid UDP packet after truncation and a different descriptor mode
        // must not inherit stale flags, lengths, or source-address metadata.
        sender.send(b"valid").unwrap();
        wait_readable(receiver.as_raw_fd());
        rx.receive(receiver.as_raw_fd(), false, |r| {
            assert_eq!(r.packet.data(), b"valid");
            assert_eq!(r.source, Some(sender.local_addr().unwrap()));
            delivered += 1;
        })
        .unwrap();
        assert_eq!(delivered, 1);
        drop(rx);
        assert_eq!(pool.len(), 128);
    }
}
