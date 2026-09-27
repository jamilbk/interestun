//! Dynamically loaded Wintun 0.14 API. The session owns all ring and event handles.
use libloading::os::windows::Library;
use std::{ffi::c_void, io, path::Path, ptr, time::Duration};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_MORE_ITEMS, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    NetworkManagement::{
        IpHelper::{
            GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
            SetIpInterfaceEntry,
        },
        Ndis::NET_LUID_LH,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::Threading::WaitForSingleObject,
};

/// Raw IP packets, without utun's address-family prefix. Implementations must be
/// safe for concurrent writes; the runtime uses one receive/wait thread.
pub trait PacketIo: Send + Sync {
    fn name(&self) -> &str;
    /// Nonblocking read. Oversized packets must be consumed and rejected.
    fn receive(&self, buffer: &mut [u8]) -> io::Result<usize>;
    fn send(&self, packet: &[u8]) -> io::Result<()>;
    /// Wait at most `timeout`; readiness can be spurious.
    fn wait_readable(&self, timeout: Duration) -> io::Result<()>;
}

type Handle = *mut c_void;
struct Api {
    create:
        unsafe extern "system" fn(*const u16, *const u16, *const windows_sys::core::GUID) -> Handle,
    close: unsafe extern "system" fn(Handle),
    luid: unsafe extern "system" fn(Handle, *mut NET_LUID_LH),
    start: unsafe extern "system" fn(Handle, u32) -> Handle,
    end: unsafe extern "system" fn(Handle),
    event: unsafe extern "system" fn(Handle) -> HANDLE,
    receive: unsafe extern "system" fn(Handle, *mut u32) -> *mut u8,
    release: unsafe extern "system" fn(Handle, *const u8),
    allocate: unsafe extern "system" fn(Handle, u32) -> *mut u8,
    send: unsafe extern "system" fn(Handle, *const u8),
    _library: Library,
}
impl Api {
    fn load(path: &Path) -> io::Result<Self> {
        // Resolve before loading and exclude the working directory/PATH from
        // dependency lookup. Only a caller-selected DLL or the executable's DLL is used.
        let path = path.canonicalize()?;
        // SAFETY: The caller supplies a trusted native Wintun DLL. Symbol types
        // match api/wintun.h; the library stays loaded until after all handles close.
        unsafe {
            let library =
                Library::load_with_flags(path, 0x100 | 0x800).map_err(io::Error::other)?;
            Ok(Self {
                create: *library
                    .get(b"WintunCreateAdapter\0")
                    .map_err(io::Error::other)?,
                close: *library
                    .get(b"WintunCloseAdapter\0")
                    .map_err(io::Error::other)?,
                luid: *library
                    .get(b"WintunGetAdapterLUID\0")
                    .map_err(io::Error::other)?,
                start: *library
                    .get(b"WintunStartSession\0")
                    .map_err(io::Error::other)?,
                end: *library
                    .get(b"WintunEndSession\0")
                    .map_err(io::Error::other)?,
                event: *library
                    .get(b"WintunGetReadWaitEvent\0")
                    .map_err(io::Error::other)?,
                receive: *library
                    .get(b"WintunReceivePacket\0")
                    .map_err(io::Error::other)?,
                release: *library
                    .get(b"WintunReleaseReceivePacket\0")
                    .map_err(io::Error::other)?,
                allocate: *library
                    .get(b"WintunAllocateSendPacket\0")
                    .map_err(io::Error::other)?,
                send: *library
                    .get(b"WintunSendPacket\0")
                    .map_err(io::Error::other)?,
                _library: library,
            })
        }
    }
}

pub struct Wintun {
    api: Api,
    adapter: Handle,
    session: Handle,
    pub name: String,
}
// SAFETY: Wintun documents packet operations as thread-safe. Handles are only
// destroyed with exclusive ownership in Drop, after all Arc users have gone.
unsafe impl Send for Wintun {}
unsafe impl Sync for Wintun {}

pub(crate) fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.encode_utf16().count() >= 128
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | '/' | ':'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Windows adapter name",
        ));
    }
    Ok(())
}

impl Wintun {
    /// Windows interface identity for address/route configuration by a caller.
    pub fn interface_luid(&self) -> u64 {
        // SAFETY: The adapter is live and Wintun initializes the complete LUID.
        unsafe {
            let mut luid: NET_LUID_LH = std::mem::zeroed();
            (self.api.luid)(self.adapter, &mut luid);
            luid.Value
        }
    }

    /// Creates a temporary adapter (Administrator required). Never adopts an
    /// existing adapter. Drop ends its session and removes the created adapter.
    pub fn open(name: &str, mtu: u32, dll: &Path) -> io::Result<Self> {
        validate_name(name)?;
        if !(1280..=2000).contains(&mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MTU must be 1280..=2000",
            ));
        }
        let api = Api::load(dll)?;
        let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: NUL-terminated strings and live API pointers; null GUID asks
        // Wintun to generate a fresh adapter identity.
        let adapter = unsafe {
            (api.create)(
                wide.as_ptr(),
                windows_sys::core::w!("interestun"),
                ptr::null(),
            )
        };
        if adapter.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut tun = Self {
            api,
            adapter,
            session: ptr::null_mut(),
            name: name.into(),
        };
        tun.set_mtu(mtu)?;
        // SAFETY: Adapter is live; 4 MiB is a valid power-of-two ring capacity.
        tun.session = unsafe { (tun.api.start)(tun.adapter, 4 * 1024 * 1024) };
        if tun.session.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(tun)
    }

    fn set_mtu(&self, mtu: u32) -> io::Result<()> {
        // SAFETY: Structures are initialized by the IP Helper API. Each row is
        // selected by family and the adapter's LUID before changing its MTU.
        unsafe {
            let mut luid = std::mem::zeroed();
            (self.api.luid)(self.adapter, &mut luid);
            for family in [AF_INET, AF_INET6] {
                let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
                InitializeIpInterfaceEntry(&mut row);
                row.Family = family;
                row.InterfaceLuid = luid;
                let status = GetIpInterfaceEntry(&mut row);
                if status != 0 {
                    return Err(io::Error::from_raw_os_error(status as i32));
                }
                row.NlMtu = mtu;
                if family == AF_INET {
                    row.SitePrefixLength = 0;
                }
                let status = SetIpInterfaceEntry(&mut row);
                if status != 0 {
                    return Err(io::Error::from_raw_os_error(status as i32));
                }
            }
        }
        Ok(())
    }
}
impl PacketIo for Wintun {
    fn name(&self) -> &str {
        &self.name
    }
    fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut len = 0;
        // SAFETY: Session stays alive through &self. Every acquired packet is
        // released exactly once, including when the caller's buffer is too small.
        unsafe {
            let packet = (self.api.receive)(self.session, &mut len);
            if packet.is_null() {
                let error = io::Error::last_os_error();
                return Err(
                    if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                        io::ErrorKind::WouldBlock.into()
                    } else {
                        error
                    },
                );
            }
            let len = len as usize;
            let result = if len > buffer.len() {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "oversized Wintun packet",
                ))
            } else {
                ptr::copy_nonoverlapping(packet, buffer.as_mut_ptr(), len);
                Ok(len)
            };
            (self.api.release)(self.session, packet);
            result
        }
    }
    fn send(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > 65535 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: Allocation has the requested size and is always committed;
        // nothing fallible occurs between allocate and send.
        unsafe {
            let target = (self.api.allocate)(self.session, packet.len() as u32);
            if target.is_null() {
                let error = io::Error::last_os_error();
                return Err(
                    if error.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW as i32) {
                        io::ErrorKind::WouldBlock.into()
                    } else {
                        error
                    },
                );
            }
            ptr::copy_nonoverlapping(packet.as_ptr(), target, packet.len());
            (self.api.send)(self.session, target);
        }
        Ok(())
    }
    fn wait_readable(&self, timeout: Duration) -> io::Result<()> {
        // SAFETY: This borrowed event is owned by the live session. Never close
        // or reset it; receive performs Wintun's race-safe event reset.
        match unsafe {
            WaitForSingleObject(
                (self.api.event)(self.session),
                timeout.as_millis().min(u32::MAX as u128 - 1) as u32,
            )
        } {
            WAIT_OBJECT_0 | WAIT_TIMEOUT => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }
}
impl Drop for Wintun {
    fn drop(&mut self) {
        // SAFETY: No borrowed ring packets escape the methods. Drop is exclusive
        // and unloads the DLL only after destroying the session and adapter.
        unsafe {
            if !self.session.is_null() {
                (self.api.end)(self.session);
            }
            (self.api.close)(self.adapter);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_invalid_parameters_before_loading_dll() {
        for name in ["", "bad\\name", "bad/name", "bad\0name", &"a".repeat(128)] {
            assert_eq!(
                Wintun::open(name, 1420, Path::new("missing.dll"))
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            Wintun::open("test", 1279, Path::new("missing.dll"))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(validate_name("Office VPN").is_ok());
    }
}
