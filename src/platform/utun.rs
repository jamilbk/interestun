use super::batch::{Received, Receiver, Sender};
use crate::packet::Packet;
use std::{
    collections::VecDeque,
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};
#[cfg(not(feature = "apple-utun-ring"))]
use std::{ffi::CStr, mem::size_of};

pub struct Utun {
    device: Device,
    pub name: String,
}
enum Device {
    Bsd(OwnedFd),
    #[cfg(feature = "apple-packet-tunnel")]
    NetworkExtension(OwnedFd),
    #[cfg(feature = "apple-utun-ring")]
    Ring(super::utun_ring::Adapter),
    #[cfg(feature = "apple-packet-tunnel")]
    PacketFlow(std::sync::Arc<super::packet_flow::Adapter>),
}
fn check(n: libc::c_int) -> io::Result<()> {
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
impl Utun {
    pub fn open(name: &str, mtu: u32) -> io::Result<Self> {
        #[cfg(feature = "apple-utun-ring")]
        {
            let (adapter, name) = super::utun_ring::Adapter::open(name, mtu)?;
            Ok(Self {
                device: Device::Ring(adapter),
                name,
            })
        }
        #[cfg(not(feature = "apple-utun-ring"))]
        Self::open_bsd(name, mtu)
    }

    /// Wrap an already-owned datagram descriptor (also used by fake-adapter tests).
    pub fn from_fd(fd: OwnedFd, name: String) -> Self {
        Self {
            device: Device::Bsd(fd),
            name,
        }
    }

    #[cfg(feature = "apple-packet-tunnel")]
    pub fn from_ne_fd(fd: OwnedFd, name: String) -> Self {
        Self {
            device: Device::NetworkExtension(fd),
            name,
        }
    }

    #[cfg(feature = "apple-packet-tunnel")]
    pub fn from_packet_flow(
        adapter: std::sync::Arc<super::packet_flow::Adapter>,
        name: String,
    ) -> Self {
        Self {
            device: Device::PacketFlow(adapter),
            name,
        }
    }

    /// NEPacketTunnelFlow uses callback notifications and has no public descriptor.
    pub fn io_fd(&self) -> Option<RawFd> {
        match &self.device {
            Device::Bsd(fd) => Some(fd.as_raw_fd()),
            #[cfg(feature = "apple-packet-tunnel")]
            Device::NetworkExtension(fd) => Some(fd.as_raw_fd()),
            #[cfg(feature = "apple-utun-ring")]
            Device::Ring(adapter) => Some(adapter.fd()),
            #[cfg(feature = "apple-packet-tunnel")]
            Device::PacketFlow(_) => None,
        }
    }

    pub fn register_readable(
        &self,
        poll: &super::readiness::Poll,
        token: super::readiness::Token,
    ) -> io::Result<()> {
        #[cfg(feature = "apple-packet-tunnel")]
        if let Device::PacketFlow(adapter) = &self.device {
            return adapter.register(poll, token);
        }
        poll.register(
            self.io_fd().expect("descriptor-backed adapter"),
            token,
            super::readiness::Interest::READABLE,
        )
    }

    pub fn supports_socket_coalescing(&self) -> bool {
        // Network Extension's Skywalk netif does not have the ordinary utun
        // oversized-packet injection semantics. Preserve packet boundaries.
        matches!(self.device, Device::Bsd(_))
    }

    pub fn is_ring(&self) -> bool {
        match &self.device {
            Device::Bsd(_) => false,
            #[cfg(feature = "apple-packet-tunnel")]
            Device::NetworkExtension(_) => false,
            #[cfg(feature = "apple-utun-ring")]
            Device::Ring(_) => true,
            #[cfg(feature = "apple-packet-tunnel")]
            Device::PacketFlow(_) => false,
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match &self.device {
            Device::Bsd(_) => "BSD control socket",
            #[cfg(feature = "apple-packet-tunnel")]
            Device::NetworkExtension(_) => "Network Extension utun descriptor",
            #[cfg(feature = "apple-utun-ring")]
            Device::Ring(_) => "Skywalk mapped ring",
            #[cfg(feature = "apple-packet-tunnel")]
            Device::PacketFlow(_) => "NEPacketTunnelFlow (framework-selected path)",
        }
    }

    pub fn receive(
        &self,
        receiver: &mut Receiver,
        consume: impl FnMut(Received),
    ) -> io::Result<usize> {
        match &self.device {
            Device::Bsd(fd) => receiver.receive(fd.as_raw_fd(), true, consume),
            #[cfg(feature = "apple-packet-tunnel")]
            Device::NetworkExtension(fd) => receiver.receive(fd.as_raw_fd(), true, consume),
            #[cfg(feature = "apple-utun-ring")]
            Device::Ring(adapter) => adapter.receive(receiver.receive_buffers(), consume),
            #[cfg(feature = "apple-packet-tunnel")]
            Device::PacketFlow(adapter) => adapter.receive(consume),
        }
    }

    pub fn flush(&self, writer: &mut Sender, queue: &mut VecDeque<Packet>) -> io::Result<usize> {
        match &self.device {
            Device::Bsd(fd) => writer.flush(fd.as_raw_fd(), true, queue),
            #[cfg(feature = "apple-packet-tunnel")]
            Device::NetworkExtension(fd) => writer.flush(fd.as_raw_fd(), true, queue),
            #[cfg(feature = "apple-utun-ring")]
            Device::Ring(adapter) => adapter.flush(queue),
            #[cfg(feature = "apple-packet-tunnel")]
            Device::PacketFlow(adapter) => adapter.flush(queue),
        }
    }

    #[cfg(not(feature = "apple-utun-ring"))]
    fn open_bsd(name: &str, mtu: u32) -> io::Result<Self> {
        let unit = unit(name)?;
        // SAFETY: Each call uses an owned live descriptor and correctly sized Darwin ABI structures.
        unsafe {
            let raw = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL);
            check(raw)?;
            let fd = OwnedFd::from_raw_fd(raw);
            check(libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC))?;
            check(libc::fcntl(raw, libc::F_SETFL, libc::O_NONBLOCK))?;
            let mut info: libc::ctl_info = std::mem::zeroed();
            let control = b"com.apple.net.utun_control";
            for (dst, src) in info.ctl_name.iter_mut().zip(control) {
                *dst = *src as i8;
            }
            check(libc::ioctl(raw, 0xc0644e03, &mut info))?;
            let addr = libc::sockaddr_ctl {
                sc_len: size_of::<libc::sockaddr_ctl>() as u8,
                sc_family: libc::AF_SYSTEM as u8,
                ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                sc_id: info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            };
            check(libc::connect(
                raw,
                (&addr as *const libc::sockaddr_ctl).cast(),
                size_of::<libc::sockaddr_ctl>() as _,
            ))?;
            // The packet limit alone does not enlarge the control socket's
            // byte limit (XNU defaults to 512 KiB). Leave enough byte/mbuf room
            // for 1024 maximum-size packets so packet-count flow control acts
            // before ctl_enqueuembuf starts dropping bursts.
            let receive_bytes: libc::c_int = 4 * 1024 * 1024;
            check(libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&receive_bytes as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as _,
            ))?;
            let mut actual_bytes: libc::c_int = 0;
            let mut byte_len = size_of::<libc::c_int>() as libc::socklen_t;
            check(libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&mut actual_bytes as *mut libc::c_int).cast(),
                &mut byte_len,
            ))?;
            if actual_bytes < receive_bytes {
                return Err(io::Error::other(
                    "utun receive buffer was clamped below 4 MiB",
                ));
            }
            // Darwin defaults to one pending packet, which prevents effective
            // recvmsg_x batches. Allow eight batches of 128 before flow control.
            // UTUN_OPT_MAX_PENDING_PACKETS from bsd/net/if_utun.h.
            const MAX_PENDING_PACKETS: libc::c_int = 16;
            let pending: u32 = 1024;
            check(libc::setsockopt(
                raw,
                libc::SYSPROTO_CONTROL,
                MAX_PENDING_PACKETS,
                (&pending as *const u32).cast(),
                size_of::<u32>() as _,
            ))?;
            let mut actual: u32 = 0;
            let mut actual_len = size_of::<u32>() as libc::socklen_t;
            check(libc::getsockopt(
                raw,
                libc::SYSPROTO_CONTROL,
                MAX_PENDING_PACKETS,
                (&mut actual as *mut u32).cast(),
                &mut actual_len,
            ))?;
            if actual_len as usize != size_of::<u32>() || actual != pending {
                return Err(io::Error::other(
                    "utun pending-packet limit was not applied",
                ));
            }
            eprintln!("utun queue: pending_packets={actual} receive_bytes={actual_bytes}");
            let mut name = [0u8; libc::IFNAMSIZ];
            let mut len = name.len() as libc::socklen_t;
            check(libc::getsockopt(
                raw,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            ))?;
            let name = CStr::from_bytes_until_nul(&name)
                .map_err(|_| io::Error::other("utun name missing NUL"))?
                .to_string_lossy()
                .into_owned();
            let interface = Self::from_fd(fd, name);
            set_mtu(&interface.name, mtu)?;
            Ok(interface)
        }
    }
}

pub(super) fn unit(name: &str) -> io::Result<u32> {
    let suffix = name
        .strip_prefix("utun")
        .ok_or_else(|| io::Error::other("expected utun or utunN"))?;
    if suffix.is_empty() {
        return Ok(0);
    }
    suffix
        .parse::<u32>()
        .ok()
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| io::Error::other("invalid utun index"))
}

pub(super) fn set_mtu(name: &str, mtu: u32) -> io::Result<()> {
    if name.len() >= libc::IFNAMSIZ || !(1280..=2000).contains(&mtu) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid utun name or MTU",
        ));
    }
    // Darwin ifreq is 32 bytes, with a 16-byte name and a 16-byte union.
    #[repr(C)]
    struct IfReq {
        name: [u8; 16],
        mtu: i32,
        padding: [u8; 12],
    }
    let mut req = IfReq {
        name: [0; 16],
        mtu: mtu as i32,
        padding: [0; 12],
    };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: ifreq matches SIOCSIFMTU's Darwin layout; fd is owned until return.
    unsafe {
        let raw = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        check(raw)?;
        let fd = OwnedFd::from_raw_fd(raw);
        check(libc::ioctl(fd.as_raw_fd(), 0x80206934, &req))
    }
}
