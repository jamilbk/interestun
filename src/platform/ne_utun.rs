//! Inspect the utun already created by Network Extension. Never creates an
//! interface, opens a channel, or changes nexus/attachment options.
use std::{
    ffi::CStr,
    io,
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};

const MAX_PENDING: i32 = 16;

fn check(result: i32) -> io::Result<i32> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn name(fd: RawFd) -> io::Result<String> {
    let mut bytes = [0u8; libc::IFNAMSIZ];
    let mut length = bytes.len() as libc::socklen_t;
    // SAFETY: Output buffer and its initialized length match.
    check(unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            libc::UTUN_OPT_IFNAME,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    })?;
    if length as usize > bytes.len() {
        return Err(io::Error::other("invalid utun name length"));
    }
    CStr::from_bytes_until_nul(&bytes[..length as usize])
        .map_err(|_| io::Error::other("utun name is not terminated"))?
        .to_str()
        .map(str::to_owned)
        .map_err(io::Error::other)
}

/// Duplication preserves Network Extension's ownership of the original fd.
/// The provider must keep its interface alive for this lookup and subsequent I/O.
pub fn find(expected_name: &str) -> io::Result<OwnedFd> {
    if !expected_name.starts_with("utun") || expected_name.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an existing utun name",
        ));
    }
    // SAFETY: All-zero ctl_info is valid; control name is NUL-terminated.
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (dst, byte) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
        *dst = *byte as i8;
    }
    // Firezone/WireGuard technique: inspect this process's descriptor table.
    // Match both control ID and exact interface name, not merely the first utun.
    let limit = unsafe { libc::getdtablesize() };
    for fd in 0..limit.max(0) {
        let mut address: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
        let mut length = size_of::<libc::sockaddr_ctl>() as libc::socklen_t;
        if unsafe {
            libc::getpeername(
                fd,
                (&mut address as *mut libc::sockaddr_ctl).cast(),
                &mut length,
            )
        } != 0
            || length as usize != size_of::<libc::sockaddr_ctl>()
            || address.sc_family != libc::AF_SYSTEM as u8
            || address.ss_sysaddr != libc::AF_SYS_CONTROL as u16
        {
            continue;
        }
        if info.ctl_id == 0 && unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } != 0 {
            continue;
        }
        if address.sc_id != info.ctl_id
            || !matches!(name(fd).as_deref(), Ok(actual) if actual == expected_name)
        {
            continue;
        }
        // SAFETY: fcntl creates a fresh owned descriptor, leaving the original open.
        let copy = check(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) })?;
        let owned = unsafe { OwnedFd::from_raw_fd(copy) };
        // Revalidate the duplicate before any mutation, guarding descriptor reuse.
        if name(copy)? != expected_name {
            return Err(io::Error::other("utun changed during lookup"));
        }
        return Ok(owned);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Network Extension utun descriptor not found",
    ))
}

fn integer(fd: RawFd, level: i32, option: i32) -> io::Result<i32> {
    let mut value = 0i32;
    let mut length = size_of::<i32>() as libc::socklen_t;
    check(unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut i32).cast(),
            &mut length,
        )
    })?;
    if length as usize != size_of::<i32>() {
        return Err(io::Error::other("invalid option length"));
    }
    Ok(value)
}

fn set_integer(fd: RawFd, level: i32, option: i32, value: i32) -> io::Result<()> {
    check(unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const i32).cast(),
            size_of::<i32>() as _,
        )
    })?;
    Ok(())
}

fn snapshot(fd: RawFd) -> serde_json::Value {
    let mut values = serde_json::Map::new();
    for (key, level, option) in [
        ("receive_bytes", libc::SOL_SOCKET, libc::SO_RCVBUF),
        ("send_bytes", libc::SOL_SOCKET, libc::SO_SNDBUF),
        ("receive_low_water", libc::SOL_SOCKET, libc::SO_RCVLOWAT),
        ("send_low_water", libc::SOL_SOCKET, libc::SO_SNDLOWAT),
        ("dont_truncate", libc::SOL_SOCKET, libc::SO_DONTTRUNC),
        ("flags", libc::SYSPROTO_CONTROL, 1),
        ("external_stats", libc::SYSPROTO_CONTROL, 3),
        ("pending_packets", libc::SYSPROTO_CONTROL, MAX_PENDING),
        ("channels", libc::SYSPROTO_CONTROL, 17),
        ("flowswitch_enabled", libc::SYSPROTO_CONTROL, 19),
        ("netif_enabled", libc::SYSPROTO_CONTROL, 20),
        ("slot_size", libc::SYSPROTO_CONTROL, 21),
        ("netif_ring_size", libc::SYSPROTO_CONTROL, 22),
        ("tx_flowswitch_ring_size", libc::SYSPROTO_CONTROL, 23),
        ("rx_flowswitch_ring_size", libc::SYSPROTO_CONTROL, 24),
        ("tx_kernel_pipe_ring_size", libc::SYSPROTO_CONTROL, 25),
        ("rx_kernel_pipe_ring_size", libc::SYSPROTO_CONTROL, 26),
    ] {
        values.insert(
            key.into(),
            match integer(fd, level, option) {
                Ok(value) => serde_json::json!(value),
                Err(error) => serde_json::json!({ "error": error.to_string() }),
            },
        );
    }
    serde_json::Value::Object(values)
}

/// Zero requests inspection only. Only the receive byte capacity and packet
/// threshold may be raised, never lowered; no low-water/timer/global knobs change.
pub fn inspect_and_tune(
    expected_name: &str,
    receive_bytes: u32,
    pending: u32,
) -> io::Result<serde_json::Value> {
    if receive_bytes > 8 * 1024 * 1024 || pending > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "utun queue request exceeds experiment bounds",
        ));
    }
    let fd = find(expected_name)?;
    let raw = fd.as_raw_fd();
    let before = snapshot(raw);
    for (level, option, requested) in [
        (libc::SOL_SOCKET, libc::SO_RCVBUF, receive_bytes),
        (libc::SYSPROTO_CONTROL, MAX_PENDING, pending),
    ] {
        if requested == 0 {
            continue;
        }
        let current = integer(raw, level, option)?;
        if current < requested as i32 {
            set_integer(raw, level, option, requested as i32)?;
        }
        if integer(raw, level, option)? < requested as i32 {
            return Err(io::Error::other("utun queue setting was clamped"));
        }
    }
    Ok(serde_json::json!({ "interface": expected_name, "before": before, "after": snapshot(raw) }))
}

/// Use the existing descriptor directly, with one Rust reader. The provider
/// must never also start NEPacketTunnelFlow reads/writes for this session.
pub fn dataplane(expected_name: &str) -> io::Result<super::Tunnel> {
    let fd = find(expected_name)?;
    let raw = fd.as_raw_fd();
    // The existing batched implementation expects the ordinary four-byte AF
    // prefix. Refuse disabled directions or a process-UUID prefix, rather than
    // modifying a creation-time flag on a framework-owned interface.
    if integer(raw, libc::SYSPROTO_CONTROL, 1)? != 0 {
        return Err(io::Error::other("unsupported utun framing flags"));
    }
    if integer(raw, libc::SOL_SOCKET, libc::SO_DONTTRUNC)? != 0 {
        return Err(io::Error::other(
            "utun SO_DONTTRUNC is incompatible with batched reads",
        ));
    }
    let flags = check(unsafe { libc::fcntl(raw, libc::F_GETFL) })?;
    check(unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) })?;
    Ok(super::Tunnel::from_ne_fd(fd, expected_name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_names_and_oversized_requests_without_opening_a_tunnel() {
        assert_eq!(find("en0").unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            inspect_and_tune("utun4", 16 * 1024 * 1024, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
