use std::{
    ffi::CStr,
    io,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub struct Utun {
    pub fd: OwnedFd,
    pub name: String,
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
        let suffix = name
            .strip_prefix("utun")
            .ok_or_else(|| io::Error::other("expected utun or utunN"))?;
        let unit = if suffix.is_empty() {
            0
        } else {
            suffix
                .parse::<u32>()
                .ok()
                .and_then(|v| v.checked_add(1))
                .ok_or_else(|| io::Error::other("invalid utun index"))?
        };
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
            let interface = Self { fd, name };
            interface.set_mtu(mtu)?;
            Ok(interface)
        }
    }
    fn set_mtu(&self, mtu: u32) -> io::Result<()> {
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
        req.name[..self.name.len()].copy_from_slice(self.name.as_bytes());
        // SAFETY: ifreq matches SIOCSIFMTU's Darwin layout; fd is owned until return.
        unsafe {
            let raw = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            check(raw)?;
            let fd = OwnedFd::from_raw_fd(raw);
            check(libc::ioctl(fd.as_raw_fd(), 0x80206934, &req))
        }
    }
}
