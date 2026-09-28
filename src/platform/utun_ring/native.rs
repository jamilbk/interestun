//! Private os_channel SPI, pinned to the audited XNU contract. No layout/cursor
//! arithmetic on mapped rings; only slot properties returned by the library.
use super::engine::{Direction, Slots};
use crate::packet::BATCH;
use std::{
    ffi::{CStr, c_void},
    fs::{File, OpenOptions},
    io::{self, Write},
    mem::{offset_of, size_of},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::fs::OpenOptionsExt,
    },
    ptr::NonNull,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

type Handle = *mut c_void;
const RING_SLOTS: i32 = 256;
const SLOT_BYTES: i32 = 2048;
const CLIENT_PORT: u16 = 0;
const TX_RX: i32 = 0;
const ANY_RING: u32 = u32::MAX;
const FIRST_TX: i32 = 0;
const FIRST_RX: i32 = 2;
const ATTR_USER_POOL: i32 = 24;
const ATTR_DEFUNCT_OK: i32 = 26;

#[repr(C, align(8))]
#[derive(Default, Clone, Copy)]
struct Properties {
    flags: u16,
    len: u16,
    index: u32,
    external: u64,
    buffer: u64,
    metadata: u64,
    padding: [u32; 8],
}
const _: () = {
    assert!(size_of::<Properties>() == 64);
    assert!(offset_of!(Properties, buffer) == 16);
    assert!(offset_of!(Properties, metadata) == 24);
};

macro_rules! channel_api {
    ($($field:ident: $symbol:literal => $ty:ty),+ $(,)?) => {
        struct Api { $($field: $ty),+ }
        impl Api {
            fn load() -> io::Result<&'static Self> {
                static API: OnceLock<Result<Api, &'static str>> = OnceLock::new();
                API.get_or_init(|| {
                    $(
                        // SAFETY: NUL-terminated symbol; the typed signature is
                        // from XNU os_channel.h (nexus_port_t is uint16_t).
                        let $field = unsafe {
                            let p = libc::dlsym(libc::RTLD_DEFAULT, concat!($symbol, "\0").as_ptr().cast());
                            if p.is_null() { return Err($symbol); }
                            std::mem::transmute::<*mut c_void, $ty>(p)
                        };
                    )+
                    Ok(Self { $($field),+ })
                }).as_ref().map_err(|symbol| io::Error::new(io::ErrorKind::Unsupported,
                    format!("Skywalk symbol unavailable: {symbol}")))
            }
        }
    }
}
channel_api! {
    attr_create: "os_channel_attr_create" => unsafe extern "C" fn() -> Handle,
    attr_destroy: "os_channel_attr_destroy" => unsafe extern "C" fn(Handle),
    attr_set: "os_channel_attr_set" => unsafe extern "C" fn(Handle, i32, u64) -> i32,
    attr_get: "os_channel_attr_get" => unsafe extern "C" fn(Handle, i32, *mut u64) -> i32,
    read_attr: "os_channel_read_attr" => unsafe extern "C" fn(Handle, Handle) -> i32,
    create: "os_channel_create_extended" => unsafe extern "C" fn(*const u8, u16, i32, u32, Handle) -> Handle,
    destroy: "os_channel_destroy" => unsafe extern "C" fn(Handle),
    fd: "os_channel_get_fd" => unsafe extern "C" fn(Handle) -> i32,
    ring_id: "os_channel_ring_id" => unsafe extern "C" fn(Handle, i32) -> u32,
    tx_ring: "os_channel_tx_ring" => unsafe extern "C" fn(Handle, u32) -> Handle,
    rx_ring: "os_channel_rx_ring" => unsafe extern "C" fn(Handle, u32) -> Handle,
    available: "os_channel_available_slot_count" => unsafe extern "C" fn(Handle) -> u32,
    next: "os_channel_get_next_slot" => unsafe extern "C" fn(Handle, Handle, *mut Properties) -> Handle,
    set_properties: "os_channel_set_slot_properties" => unsafe extern "C" fn(Handle, Handle, *const Properties),
    advance: "os_channel_advance_slot" => unsafe extern "C" fn(Handle, Handle) -> i32,
    sync: "os_channel_sync" => unsafe extern "C" fn(Handle, i32) -> i32,
    defunct: "os_channel_is_defunct" => unsafe extern "C" fn(Handle) -> i32,
}

fn syscall(result: i32) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn status(result: i32) -> io::Result<()> {
    match result {
        0 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        error => Err(io::Error::from_raw_os_error(error)),
    }
}

struct Attributes {
    api: &'static Api,
    handle: NonNull<c_void>,
}
impl Attributes {
    fn new(api: &'static Api) -> io::Result<Self> {
        // SAFETY: returns a new owned attribute object.
        let handle =
            NonNull::new(unsafe { (api.attr_create)() }).ok_or_else(io::Error::last_os_error)?;
        Ok(Self { api, handle })
    }
    fn set(&self, kind: i32, value: u64) -> io::Result<()> {
        // SAFETY: live owned attributes, documented enum and value.
        status(unsafe { (self.api.attr_set)(self.handle.as_ptr(), kind, value) })
    }
    fn get(&self, kind: i32) -> io::Result<u64> {
        let mut value = 0;
        // SAFETY: live handle and writable u64 output.
        status(unsafe { (self.api.attr_get)(self.handle.as_ptr(), kind, &mut value) })?;
        Ok(value)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: sole owner; no dependent call is running.
        unsafe { (self.api.attr_destroy)(self.handle.as_ptr()) };
    }
}

struct Journal(File);
impl Journal {
    fn new() -> io::Result<Self> {
        let path = format!("/var/tmp/interestun-skywalk-{}.log", std::process::id());
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)?;
        eprintln!("Skywalk setup journal: {path}");
        Ok(Self(file))
    }
    fn record(&mut self, text: &str) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        writeln!(self.0, "{}.{:09} {text}", now.as_secs(), now.subsec_nanos())?;
        self.0.sync_all()?;
        // fsync alone need not flush a device's volatile write cache on Darwin.
        // SAFETY: live file descriptor; F_FULLFSYNC has no additional argument.
        syscall(unsafe { libc::fcntl(self.0.as_raw_fd(), libc::F_FULLFSYNC) })?;
        // Mirror only setup metadata into the daemon's captured stderr. The
        // durable journal remains private when the daemon runs as root.
        let _ = writeln!(io::stderr().lock(), "Skywalk {text}");
        Ok(())
    }
    fn step<T>(&mut self, stage: &str, call: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        self.record(&format!("BEGIN {stage}"))?;
        let result = call();
        self.record(&match &result {
            Ok(_) => format!("OK {stage}"),
            Err(error) => format!("ERROR {stage}: {error}"),
        })?;
        result
    }
}

struct Control {
    fd: Option<OwnedFd>,
    journal: Journal,
}
impl Control {
    fn new() -> io::Result<Self> {
        let mut journal = Journal::new()?;
        let fd = journal.step("control-socket", || {
            // SAFETY: creates a new descriptor, owned immediately on success.
            let raw =
                unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
            syscall(raw)?;
            Ok(unsafe { OwnedFd::from_raw_fd(raw) })
        })?;
        Ok(Self {
            fd: Some(fd),
            journal,
        })
    }
    fn raw(&self) -> RawFd {
        self.fd.as_ref().unwrap().as_raw_fd()
    }
    fn set(&mut self, option: i32, value: i32) -> io::Result<()> {
        let fd = self.raw();
        self.journal
            .step(&format!("pre-option={option} value={value}"), || {
                // SAFETY: initialized 32-bit option and exact size; descriptor live.
                syscall(unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SYSPROTO_CONTROL,
                        option,
                        (&value as *const i32).cast(),
                        size_of::<i32>() as _,
                    )
                })?;
                // ATTACH_FLOWSWITCH is set-only in the audited XNU source.
                // Reading it back would fail with ENOPROTOOPT before connect.
                if option == 27 {
                    return Ok(());
                }
                let mut actual = [0; 4];
                if get(fd, option, &mut actual)? != actual.len()
                    || i32::from_ne_bytes(actual) != value
                {
                    return Err(io::Error::other("utun preconnect option readback mismatch"));
                }
                Ok(())
            })
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        // Cleanup must still happen if logging fails (e.g. full filesystem).
        let _ = self.journal.record("BEGIN control-close");
        drop(self.fd.take());
        let _ = self.journal.record("OK control-close");
    }
}

fn get(fd: i32, option: i32, output: &mut [u8]) -> io::Result<usize> {
    let mut len = output.len() as libc::socklen_t;
    // SAFETY: valid writable output with matching capacity, live control fd.
    syscall(unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            option,
            output.as_mut_ptr().cast(),
            &mut len,
        )
    })?;
    if len as usize > output.len() {
        return Err(io::Error::other("utun option exceeds output capacity"));
    }
    Ok(len as usize)
}

#[derive(Clone, Copy)]
pub(super) struct Cursor {
    handle: NonNull<c_void>,
    properties: Properties,
    direction: Direction,
}

pub(super) struct Channel {
    api: &'static Api,
    handle: NonNull<c_void>,
    rx: Option<NonNull<c_void>>,
    tx: Option<NonNull<c_void>>,
    slot_bytes: usize,
    control: Control,
}
// SAFETY: pointers refer to owned channel mappings, not thread-local memory.
// Adapter serializes all slot operations through one Mutex; views never escape
// an operation. Last owner destroys the channel before closing its utun.
unsafe impl Send for Channel {}

impl Channel {
    pub(super) fn attach(name: &str, mtu: u32) -> io::Result<(Self, String)> {
        let unit = super::super::utun::unit(name)?;
        if !(1280..=2000).contains(&mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Skywalk MTU must be 1280..=2000",
            ));
        }
        let api = Api::load()?;
        let attributes = Attributes::new(api)?;
        attributes.set(ATTR_USER_POOL, 0)?;
        attributes.set(ATTR_DEFUNCT_OK, 1)?;
        let mut control = Control::new()?;
        let fd = control.raw();
        control.journal.step("control-flags", || {
            // SAFETY: descriptor is live and flags are supported fcntl values.
            unsafe {
                syscall(libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC))?;
                syscall(libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK))
            }
        })?;
        let address = control.journal.step("resolve-control", || {
            // SAFETY: zeroed ctl_info; initialized name and Darwin ioctl layout.
            unsafe {
                let mut info: libc::ctl_info = std::mem::zeroed();
                for (dst, src) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
                    *dst = *src as i8;
                }
                syscall(libc::ioctl(fd, 0xc0644e03, &mut info))?;
                Ok(libc::sockaddr_ctl {
                    sc_len: size_of::<libc::sockaddr_ctl>() as u8,
                    sc_family: libc::AF_SYSTEM as u8,
                    ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                    sc_id: info.ctl_id,
                    sc_unit: unit,
                    sc_reserved: [0; 5],
                })
            }
        })?;
        control.journal.step(&format!("bind unit={unit}"), || {
            // SAFETY: initialized address and exact ABI size.
            syscall(unsafe {
                libc::bind(
                    fd,
                    (&address as *const libc::sockaddr_ctl).cast(),
                    size_of::<libc::sockaddr_ctl>() as _,
                )
            })
        })?;
        // One fixed configuration, one connect, no retry/sweep. No undocumented
        // user-pool, flow-steering, power, or process-UUID options are enabled.
        for (option, value) in [
            (20, 1),
            (17, 1),
            (27, 0),
            (21, SLOT_BYTES),
            (22, RING_SLOTS),
            (25, RING_SLOTS),
            (26, RING_SLOTS),
        ] {
            control.set(option, value)?;
        }
        control.journal.step("connect", || {
            // SAFETY: same bound control descriptor, initialized address.
            syscall(unsafe {
                libc::connect(
                    fd,
                    (&address as *const libc::sockaddr_ctl).cast(),
                    size_of::<libc::sockaddr_ctl>() as _,
                )
            })
        })?;
        let name = control.journal.step("interface-name", || {
            let mut bytes = [0; libc::IFNAMSIZ];
            let len = get(fd, 2, &mut bytes)?;
            let name = CStr::from_bytes_until_nul(&bytes[..len]).map_err(io::Error::other)?;
            Ok(name.to_str().map_err(io::Error::other)?.to_owned())
        })?;
        control
            .journal
            .step(&format!("set-mtu interface={name} mtu={mtu}"), || {
                super::super::utun::set_mtu(&name, mtu)
            })?;
        let uuid = control.journal.step("channel-uuid", || {
            let mut uuid = [0; 16];
            if get(fd, 18, &mut uuid)? != uuid.len() {
                return Err(io::Error::other("unexpected channel UUID count"));
            }
            Ok(uuid)
        })?;
        // Record completion after constructing Channel, so a logging failure
        // after successful creation still destroys the channel before control.
        control.journal.record("BEGIN channel-open")?;
        // SAFETY: exact os_channel signature and live UUID/attributes.
        let raw = unsafe {
            (api.create)(
                uuid.as_ptr(),
                CLIENT_PORT,
                TX_RX,
                ANY_RING,
                attributes.handle.as_ptr(),
            )
        };
        let Some(handle) = NonNull::new(raw) else {
            let error = io::Error::last_os_error();
            control
                .journal
                .record(&format!("ERROR channel-open: {error}"))?;
            return Err(error);
        };
        let mut channel = Self {
            api,
            handle,
            rx: None,
            tx: None,
            slot_bytes: 0,
            control,
        };
        channel.control.journal.record("OK channel-open")?;
        channel.initialize(mtu as usize)?;
        Ok((channel, name))
    }

    fn initialize(&mut self, mtu: usize) -> io::Result<()> {
        self.control.journal.record("BEGIN channel-attributes")?;
        let attributes = Attributes::new(self.api)?;
        // SAFETY: both handles remain live and exclusively owned here.
        status(unsafe { (self.api.read_attr)(self.handle.as_ptr(), attributes.handle.as_ptr()) })?;
        let mut values = Vec::new();
        for (name, kind) in [
            ("tx_rings", 0),
            ("rx_rings", 1),
            ("tx_slots", 2),
            ("rx_slots", 3),
            ("slot_bytes", 4),
            ("metadata_type", 21),
            ("user_pool", 24),
            ("max_fragments", 29),
        ] {
            values.push((name, attributes.get(kind)?));
        }
        self.control
            .journal
            .record(&format!("attributes {values:?}"))?;
        if values[0].1 != 1
            || values[1].1 != 1
            || values[2].1 <= BATCH as u64
            || values[3].1 <= BATCH as u64
            || values[4].1 < (mtu + 4) as u64
            || values[4].1 > SLOT_BYTES as u64
            || values[5].1 != 2
            || values[6].1 != 0
            || values[7].1 != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unexpected Skywalk channel geometry/metadata; see setup journal",
            ));
        }
        self.slot_bytes = values[4].1 as usize;
        // SAFETY: owned channel; query actual IDs, never assume ring zero.
        unsafe {
            let tx = (self.api.ring_id)(self.handle.as_ptr(), FIRST_TX);
            let rx = (self.api.ring_id)(self.handle.as_ptr(), FIRST_RX);
            self.tx = NonNull::new((self.api.tx_ring)(self.handle.as_ptr(), tx));
            self.rx = NonNull::new((self.api.rx_ring)(self.handle.as_ptr(), rx));
        }
        if self.tx.is_none() || self.rx.is_none() || self.fd() < 0 {
            return Err(io::Error::other(
                "Skywalk channel lacks required rings or descriptor",
            ));
        }
        self.check()?;
        self.control.journal.record("OK channel-attributes; ready")
    }

    pub(super) fn fd(&self) -> RawFd {
        // SAFETY: borrowed guarded descriptor; never close/duplicate it directly.
        unsafe { (self.api.fd)(self.handle.as_ptr()) }
    }
    fn ring(&self, direction: Direction) -> Handle {
        match direction {
            Direction::Rx => self.rx,
            Direction::Tx => self.tx,
        }
        .expect("validated ring")
        .as_ptr()
    }
    fn next(
        &mut self,
        direction: Direction,
        previous: Option<Cursor>,
    ) -> io::Result<Option<Cursor>> {
        self.check()?;
        if previous.is_some_and(|p| p.direction != direction) {
            return Err(io::Error::other("Skywalk cursor direction mismatch"));
        }
        let mut properties = Properties::default();
        // SAFETY: ring is live and exclusively used; previous cursor came from
        // this same direction/batch. Properties has the audited layout.
        let raw = unsafe {
            (self.api.next)(
                self.ring(direction),
                previous.map_or(std::ptr::null_mut(), |p| p.handle.as_ptr()),
                &mut properties,
            )
        };
        self.check()?;
        let Some(handle) = NonNull::new(raw) else {
            return Ok(None);
        };
        if properties.buffer == 0 || properties.len as usize > self.slot_bytes {
            return Err(io::Error::other("Skywalk returned invalid slot storage"));
        }
        Ok(Some(Cursor {
            handle,
            properties,
            direction,
        }))
    }
}

impl Slots for Channel {
    type Cursor = Cursor;
    fn check(&self) -> io::Result<()> {
        // SAFETY: live channel; defunct-OK keeps mappings valid until destroy.
        if unsafe { (self.api.defunct)(self.handle.as_ptr()) } != 0 {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Skywalk channel is defunct",
            ))
        } else {
            Ok(())
        }
    }
    fn available(&self, direction: Direction) -> usize {
        // SAFETY: live ring, queried under Adapter's channel lock.
        unsafe { (self.api.available)(self.ring(direction)) as usize }
    }
    fn rx_next(&mut self, previous: Option<Cursor>) -> io::Result<Option<(Cursor, &[u8])>> {
        let Some(cursor) = self.next(Direction::Rx, previous)? else {
            return Ok(None);
        };
        // SAFETY: library-provided mapped slot with checked length; the buffer
        // remains reserved until advance. Borrow prevents mutation/destruction.
        let data = unsafe {
            std::slice::from_raw_parts(
                cursor.properties.buffer as *const u8,
                cursor.properties.len as usize,
            )
        };
        Ok(Some((cursor, data)))
    }
    fn tx_next(&mut self, previous: Option<Cursor>) -> io::Result<Option<(Cursor, &mut [u8])>> {
        let Some(cursor) = self.next(Direction::Tx, previous)? else {
            return Ok(None);
        };
        // SAFETY: this free TX slot is exclusively owned until publication.
        // No mapped references survive the next call or leave the adapter lock.
        let data = unsafe {
            std::slice::from_raw_parts_mut(
                cursor.properties.buffer as *mut u8,
                cursor.properties.len as usize,
            )
        };
        Ok(Some((cursor, data)))
    }
    fn tx_len(&mut self, slot: Cursor, len: usize) -> io::Result<()> {
        if slot.direction != Direction::Tx || len > slot.properties.len as usize {
            return Err(io::Error::other("invalid Skywalk slot length"));
        }
        let properties = Properties {
            len: len as u16,
            ..slot.properties
        };
        // SAFETY: same slot, only length changes; immutable properties preserved.
        unsafe {
            (self.api.set_properties)(self.ring(Direction::Tx), slot.handle.as_ptr(), &properties)
        };
        self.check()
    }
    fn advance(&mut self, direction: Direction, last: Cursor) -> io::Result<()> {
        if last.direction != direction {
            return Err(io::Error::other("invalid Skywalk advance direction"));
        }
        // SAFETY: completed last slot in the same batch/direction, payload work
        // finished before publishing this head. No borrowed storage escapes.
        status(unsafe { (self.api.advance)(self.ring(direction), last.handle.as_ptr()) })
    }
    fn sync(&mut self, direction: Direction) -> io::Result<()> {
        let mode = match direction {
            Direction::Tx => 0,
            Direction::Rx => 1,
        };
        // SAFETY: valid sync enum (not flags), serialized channel operation.
        status(unsafe { (self.api.sync)(self.handle.as_ptr(), mode) })
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.control.journal.record("BEGIN channel-destroy");
        // SAFETY: last owner, all workers have released their adapter Arcs.
        unsafe { (self.api.destroy)(self.handle.as_ptr()) };
        let _ = self.control.journal.record("OK channel-destroy");
        // Control's Drop closes the utun after channel destruction.
    }
}
