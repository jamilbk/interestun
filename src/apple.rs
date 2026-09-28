//! C ABI for the macOS packet tunnel provider. Swift serializes session calls;
//! worker callbacks may run concurrently. No operation here creates a utun.
use crate::{
    config::{Cipher, Config},
    packet::BATCH,
    platform::{
        Tunnel,
        packet_flow::{Adapter, OutputBatch, WriteBatch},
        udp::Backend,
    },
    runtime::Runtime,
};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{Arc, atomic::Ordering},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketView {
    pub bytes: *const u8,
    pub len: usize,
    pub family: u32,
}

pub type WriteCallback =
    unsafe extern "C" fn(*mut c_void, *const PacketView, usize, *const c_void) -> bool;
pub type ReleaseCallback = unsafe extern "C" fn(*mut c_void);
struct Writer {
    context: *mut c_void,
    write: WriteCallback,
    release: ReleaseCallback,
}
// SAFETY: the caller supplies a thread-safe writer context whose lifetime is
// transferred to this object. Swift's writer holds only a thread-safe packetFlow.
unsafe impl Send for Writer {}
unsafe impl Sync for Writer {}
impl Drop for Writer {
    fn drop(&mut self) {
        unsafe { (self.release)(self.context) }
    }
}
impl WriteBatch for Writer {
    fn write(&self, batch: &Arc<OutputBatch>) -> bool {
        let mut views = [PacketView {
            bytes: ptr::null(),
            len: 0,
            family: 0,
        }; BATCH];
        for (view, packet) in views.iter_mut().zip(&batch.packets) {
            *view = PacketView {
                bytes: packet.data().as_ptr(),
                len: packet.len,
                family: if packet.data()[0] >> 4 == 4 {
                    libc::AF_INET as u32
                } else {
                    libc::AF_INET6 as u32
                },
            };
        }
        // The callback borrows the batch. Any retained NSData must retain its
        // batch lease before returning and release it only after final use.
        unsafe {
            (self.write)(
                self.context,
                views.as_ptr(),
                batch.packets.len(),
                Arc::as_ptr(batch).cast(),
            )
        }
    }
}

pub struct Session {
    runtime: Runtime,
    adapter: Option<Arc<Adapter>>,
    cipher: Cipher,
    name: String,
}

unsafe fn string<'a>(text: *const c_char) -> anyhow::Result<&'a str> {
    anyhow::ensure!(!text.is_null(), "missing text argument");
    Ok(unsafe { CStr::from_ptr(text) }.to_str()?)
}
fn configure(text: &str, cipher: u32) -> anyhow::Result<(Config, Cipher)> {
    anyhow::ensure!(text.len() <= 1024 * 1024, "configuration too large");
    let config = Config::default().apply(text)?;
    anyhow::ensure!(config.private_key != [0; 32], "PrivateKey is required");
    anyhow::ensure!(!config.peers.is_empty(), "at least one peer is required");
    anyhow::ensure!(
        config
            .peers
            .values()
            .all(|p| p.endpoint.is_some() && !p.allowed_ips.is_empty()),
        "each peer requires a numeric Endpoint and AllowedIPs"
    );
    let cipher = match cipher {
        0 => Cipher::Aes256Gcm,
        1 => Cipher::Chacha20Poly1305,
        _ => anyhow::bail!("unknown cipher"),
    };
    Ok((config, cipher))
}
unsafe fn error(output: *mut *mut c_char, message: String) {
    if !output.is_null() {
        unsafe { *output = CString::new(message.replace('\0', "?")).unwrap().into_raw() };
    }
}
unsafe fn result<T>(
    output: *mut *mut c_char,
    failure: T,
    action: impl FnOnce() -> anyhow::Result<T>,
) -> T {
    if !output.is_null() {
        unsafe { *output = ptr::null_mut() };
    }
    match catch_unwind(AssertUnwindSafe(action)) {
        Ok(Ok(value)) => value,
        Ok(Err(err)) => {
            unsafe { error(output, format!("{err:#}")) };
            failure
        }
        Err(_) => {
            unsafe { error(output, "Rust engine panicked".into()) };
            failure
        }
    }
}

/// Parse only; never starts sockets, threads, or interfaces.
/// # Safety
/// `config` is NUL-terminated; `out_error` is null or writable. Free returned errors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_validate(
    config: *const c_char,
    cipher: u32,
    out_error: *mut *mut c_char,
) -> bool {
    unsafe {
        result(out_error, false, || {
            configure(string(config)?, cipher)?;
            Ok(true)
        })
    }
}

/// Inspect and optionally raise queue limits on the provider's existing utun.
/// # Safety
/// Name is NUL-terminated, out_error is null or writable. Free returned strings.
/// Call before starting packet-flow reads, while the provider owns the interface.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_utun_options(
    name: *const c_char,
    receive_bytes: u32,
    pending: u32,
    out_error: *mut *mut c_char,
) -> *mut c_char {
    unsafe {
        result(out_error, ptr::null_mut(), || {
            let options =
                crate::platform::ne_utun::inspect_and_tune(string(name)?, receive_bytes, pending)?;
            Ok(CString::new(options.to_string())?.into_raw())
        })
    }
}

/// Takes ownership of `context` even on failure. Does not create an interface.
/// # Safety
/// Strings are valid NUL-terminated UTF-8. Callbacks are thread-safe and remain
/// valid until `release(context)`. Session operations must be serialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_start(
    config: *const c_char,
    cipher: u32,
    mtu: u32,
    name: *const c_char,
    context: *mut c_void,
    write: WriteCallback,
    release: ReleaseCallback,
    out_error: *mut *mut c_char,
) -> *mut Session {
    let writer = Writer {
        context,
        write,
        release,
    };
    unsafe {
        result(out_error, ptr::null_mut(), || {
            let (config, cipher) = configure(string(config)?, cipher)?;
            let name = string(name)?.to_owned();
            anyhow::ensure!(
                name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "invalid interface label"
            );
            let adapter = Arc::new(Adapter::new(mtu as usize, Box::new(writer))?);
            let tun = Arc::new(Tunnel::from_packet_flow(adapter.clone(), name.clone()));
            // The extension always uses Network.framework, independent of default features.
            let runtime = Runtime::start_with_backend(&config, cipher, tun, Backend::Network)?;
            Ok(Box::into_raw(Box::new(Session {
                runtime,
                adapter: Some(adapter),
                cipher,
                name,
            })))
        })
    }
}

/// Start on the utun Network Extension already owns, duplicating its descriptor.
/// No interface/channel is created. The outer UDP backend is Network.framework.
/// # Safety
/// Strings are valid NUL-terminated UTF-8; error is null or writable. Provider
/// owns the interface until stop completes and must not start packet-flow I/O.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_start_utun(
    config: *const c_char,
    cipher: u32,
    name: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut Session {
    unsafe {
        result(out_error, ptr::null_mut(), || {
            let (config, cipher) = configure(string(config)?, cipher)?;
            let name = string(name)?.to_owned();
            let tun = Arc::new(crate::platform::ne_utun::dataplane(&name)?);
            let runtime = Runtime::start_with_backend(&config, cipher, tun, Backend::Network)?;
            Ok(Box::into_raw(Box::new(Session {
                runtime,
                adapter: None,
                cipher,
                name,
            })))
        })
    }
}

/// Copy a borrowed input batch into bounded preallocated storage. Returns accepted packets.
/// # Safety
/// Session is live and calls serialized; views and bytes live through this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_receive(
    session: *mut Session,
    packets: *const PacketView,
    count: usize,
) -> usize {
    if session.is_null() || packets.is_null() || count == 0 || count > BATCH {
        return 0;
    }
    // Invalid ABI metadata fails closed before making payload slices.
    let views = unsafe { std::slice::from_raw_parts(packets, count) };
    if views.iter().any(|p| p.bytes.is_null() || p.len > 65535) {
        return 0;
    }
    let session = unsafe { &*session };
    let Some(adapter) = &session.adapter else {
        return 0;
    };
    adapter.feed(views.iter().map(|p| {
        (
            unsafe { std::slice::from_raw_parts(p.bytes, p.len) },
            p.family,
        )
    }))
}

/// Perform housekeeping and detect failed workers.
/// # Safety
/// Session is live and calls serialized.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_tick(session: *mut Session) -> bool {
    if session.is_null() {
        return false;
    }
    let session = unsafe { &*session };
    session.runtime.housekeeping();
    !session.runtime.failed.load(Ordering::Acquire)
}

/// Public status only; never includes private or preshared keys.
/// # Safety
/// Session is live and calls serialized. Release returned text with string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_status(session: *mut Session) -> *mut c_char {
    if session.is_null() {
        return ptr::null_mut();
    }
    let session = unsafe { &*session };
    let peers: Vec<_> = session.runtime.peers.iter().map(|(key, peer)| {
        let snapshot = peer.stats.lock().unwrap_or_else(|p| p.into_inner());
        serde_json::json!({ "public_key_hex": hex::encode(key), "tx_bytes": snapshot.tx, "rx_bytes": snapshot.rx,
            "latest_handshake_unix_seconds": snapshot.handshake.as_secs(), "endpoint": snapshot.endpoint.map(|a| a.to_string()),
            "drops": peer.drops.load(Ordering::Relaxed), "tx_queue_drops": peer.tx_queue_drops.load(Ordering::Relaxed) })
    }).collect();
    let backend = if session.adapter.is_some() {
        "NEPacketTunnelFlow"
    } else {
        "Network Extension utun descriptor"
    };
    let mut value = serde_json::json!({ "interface": session.name, "tun_backend": backend, "skywalk": "unverified",
        "udp_backend": "Network.framework", "cipher": format!("{:?}", session.cipher), "listen_port": session.runtime.port,
        "failed": session.runtime.failed.load(Ordering::Acquire), "peers": peers });
    if let Some(adapter) = &session.adapter {
        let m = adapter.metrics();
        value.as_object_mut().unwrap().extend(serde_json::json!({
            "input_batches": m.input_batches, "input_packets": m.input_packets, "input_drops": m.input_drops,
            "output_batches": m.output_batches, "output_packets": m.output_packets, "output_failures": m.output_failures
        }).as_object().unwrap().clone());
    }
    CString::new(value.to_string()).unwrap().into_raw()
}

/// Stops and joins all peer workers before releasing the writer context.
/// # Safety
/// Call once for a live session, after stopping input/timer/status calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_stop(session: *mut Session) {
    if !session.is_null() {
        drop(unsafe { Box::from_raw(session) });
    }
}

/// # Safety
/// `batch` is a live borrowed or retained lease supplied to the write callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_batch_retain(batch: *const c_void) {
    unsafe { Arc::increment_strong_count(batch.cast::<OutputBatch>()) };
}
/// # Safety
/// Balances exactly one batch_retain; the caller no longer accesses its payloads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_batch_release(batch: *const c_void) {
    unsafe { Arc::decrement_strong_count(batch.cast::<OutputBatch>()) };
}
/// # Safety
/// Text is null or returned by this ABI, and is freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn interestun_ne_string_free(text: *mut c_char) {
    if !text.is_null() {
        drop(unsafe { CString::from_raw(text) });
    }
}
