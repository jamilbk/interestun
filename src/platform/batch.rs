//! Darwin batched datagram I/O, with per-message fallback when private symbols are absent.
//! ABI and runtime resolution follow Firezone's Apple TUN implementation.
use crate::packet::{BATCH, CAPACITY, Packet, Pool};
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

pub struct Received {
    pub packet: Packet,
    pub source: Option<SocketAddr>,
}
pub struct Receiver {
    slots: Vec<Packet>,
    pool: Pool,
}
impl Receiver {
    pub fn new(pool: Pool) -> Self {
        Self {
            slots: Vec::with_capacity(BATCH),
            pool,
        }
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
        let count = self.slots.len();
        let mut afs = [[0u8; 4]; BATCH];
        let mut iovs = [[IOV; 2]; BATCH];
        let mut msgs = [EMPTY; BATCH];
        // SAFETY: zero is a valid representation for sockaddr_storage.
        let mut addresses: [libc::sockaddr_storage; BATCH] = unsafe { std::mem::zeroed() };
        for i in 0..count {
            let payload = libc::iovec {
                iov_base: self.slots[i].buffer().as_mut_ptr().cast(),
                iov_len: CAPACITY,
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
        // SAFETY: All message/iovec pointers refer to live, exclusive buffers for this synchronous call.
        let n = unsafe {
            if let Some((recv, _)) = syscalls() {
                result(recv(
                    fd,
                    msgs.as_mut_ptr(),
                    count as u32,
                    libc::MSG_DONTWAIT,
                ))?
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
                    match result(libc::recvmsg(fd, &mut hdr, libc::MSG_DONTWAIT)) {
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
                || len >= CAPACITY + if tun { 4 } else { 0 }
            {
                continue;
            }
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

/// Sends a prefix, preserving the unsent tail on short writes / WouldBlock.
/// On other batch errors progress is ambiguous, so discard the attempted batch.
pub fn flush(fd: RawFd, tun: bool, queue: &mut VecDeque<Packet>) -> io::Result<usize> {
    let count = queue.len().min(BATCH);
    if count == 0 {
        return Ok(0);
    }
    let mut afs = [[0u8; 4]; BATCH];
    let mut iovs = [[IOV; 2]; BATCH];
    let mut msgs = [EMPTY; BATCH];
    for (i, packet) in queue.iter().take(count).enumerate() {
        let data = packet.data();
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
        let pool = crate::packet::pool(128);
        let mut queue = VecDeque::new();
        for i in 0..BATCH {
            let mut p = Packet::new(&pool).unwrap();
            p.buffer()[0] = i as u8;
            p.len = 1;
            queue.push_back(p);
        }
        use std::os::fd::AsRawFd;
        while !queue.is_empty() {
            flush(a.as_raw_fd(), false, &mut queue).unwrap();
        }
        let mut rx = Receiver::new(pool);
        let mut seen = Vec::new();
        while seen.len() < BATCH {
            wait_readable(b.as_raw_fd());
            rx.receive(b.as_raw_fd(), false, |r| {
                assert_eq!(r.source, Some(a.local_addr().unwrap()));
                seen.push(r.packet.data()[0]);
            })
            .unwrap();
        }
        assert_eq!(seen, (0..BATCH as u8).collect::<Vec<_>>());
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
        drop(rx);
        assert_eq!(pool.len(), 128);
    }
}
