//! Ownership wrapper around the bounded Network.framework bridge.
use super::batch::{Received, Receiver};
use super::readiness::Waker;
use crate::packet::{BATCH, Packet};
use std::{
    collections::VecDeque,
    ffi::{CString, c_void},
    io,
    net::SocketAddr,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

const _: () = assert!(crate::packet::CAPACITY == 2048);

/// Relaxed diagnostic snapshot. Matches INTxStats in network_flow.m.
#[repr(C)]
#[derive(Default, Debug)]
pub struct TxStats {
    pub accepted: u64,
    pub partial: u64,
    pub blocked: u64,
    pub blocked_ns: u64,
    pub wakes: u64,
    pub batches: [u64; 9],
    pub occupancy: [u64; 12],
}

#[cfg(feature = "io-metrics")]
pub(crate) mod metrics;
#[cfg(feature = "io-profile")]
use super::profile::{Span, Stage};

unsafe extern "C" {
    fn in_flow_open(
        host: *const i8,
        port: *const i8,
        local_host: *const i8,
        local_port: *const i8,
        context: *mut c_void,
        wake: unsafe extern "C" fn(*mut c_void, bool),
        release: unsafe extern "C" fn(*mut c_void),
    ) -> *mut c_void;
    fn in_flow_send(
        handle: *mut c_void,
        buffers: *const *const u8,
        lengths: *const usize,
        count: usize,
    ) -> i32;
    fn in_flow_receive(
        handle: *mut c_void,
        buffers: *const *mut u8,
        lengths: *mut usize,
        count: usize,
    ) -> i32;
    fn in_flow_close(handle: *mut c_void);
    fn in_flow_tx_stats(handle: *mut c_void, out: *mut TxStats);
    #[cfg(feature = "network-bench")]
    fn in_flow_tx_pending(handle: *mut c_void) -> i32;
}

pub struct Socket {
    handle: NonNull<c_void>,
    endpoint: SocketAddr,
    receiving: AtomicBool,
}
struct ReceiveGuard<'a>(&'a AtomicBool);
impl Drop for ReceiveGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
// SAFETY: C publishes its SPSC ring with atomics; the receive guard enforces one
// consumer even if callers use different Receiver instances concurrently.
// Async callbacks retain immutable framework buffers, never Rust pointers.
// Arc ownership prevents close racing a Rust call; RX scratch belongs to its worker.
unsafe impl Send for Socket {}
unsafe impl Sync for Socket {}

struct Signals {
    rx: Waker,
    tx: Waker,
}
unsafe extern "C" fn wake(context: *mut c_void, tx: bool) {
    // SAFETY: C owns this Box until the final retained flow is released.
    let signals = unsafe { &*context.cast::<Signals>() };
    let signal = if tx { &signals.tx } else { &signals.rx };
    // Only EBADF/invalid registration can fail; Arc owns the registered queue.
    if let Err(error) = signal.wake() {
        eprintln!("worker wake failed: {error}");
    }
}
unsafe extern "C" fn release(context: *mut c_void) {
    // SAFETY: Called exactly once by flow deallocation, including open failure.
    drop(unsafe { Box::from_raw(context.cast::<Signals>()) });
}
fn count(n: i32) -> io::Result<usize> {
    if n < 0 {
        Err(io::Error::from_raw_os_error(-n))
    } else {
        Ok(n as usize)
    }
}
impl Socket {
    /// Benchmark setup/drain snapshot. Idle fences callbacks and checks errors;
    /// it says nothing about delivery to the remote receiver. One TX caller only.
    #[cfg(feature = "network-bench")]
    pub fn pending_sends(&self) -> io::Result<usize> {
        // SAFETY: live handle; C only observes atomics and fences its queue.
        count(unsafe { in_flow_tx_pending(self.handle.as_ptr()) })
    }
    pub fn tx_stats(&self) -> TxStats {
        let mut stats = TxStats::default();
        // SAFETY: live handle, matching C layout, atomic snapshot only.
        unsafe { in_flow_tx_stats(self.handle.as_ptr(), &mut stats) };
        stats
    }
    pub fn connect(port: u16, endpoint: SocketAddr, rx: Waker, tx: Waker) -> io::Result<Self> {
        // Host strings preserve an IPv6 scope identifier when present.
        let host = CString::new(match endpoint {
            SocketAddr::V4(a) => a.ip().to_string(),
            SocketAddr::V6(a) if a.scope_id() != 0 => format!("{}%{}", a.ip(), a.scope_id()),
            SocketAddr::V6(a) => a.ip().to_string(),
        })
        .unwrap();
        let remote_port = CString::new(endpoint.port().to_string()).unwrap();
        let local = if endpoint.is_ipv4() {
            c"0.0.0.0"
        } else {
            c"::"
        };
        let local_port = CString::new(port.to_string()).unwrap();
        let context = Box::into_raw(Box::new(Signals { rx, tx })).cast();
        // SAFETY: C consumes the signal Box on all paths; callbacks own it.
        let handle = unsafe {
            in_flow_open(
                host.as_ptr(),
                remote_port.as_ptr(),
                local.as_ptr(),
                local_port.as_ptr(),
                context,
                wake,
                release,
            )
        };
        let handle = NonNull::new(handle).ok_or_else(io::Error::last_os_error)?;
        Ok(Self {
            handle,
            endpoint,
            receiving: AtomicBool::new(false),
        })
    }
    pub fn flush(&self, queue: &mut VecDeque<Packet>) -> io::Result<usize> {
        if queue.is_empty() {
            return Ok(0);
        }
        let n = queue.len().min(BATCH);
        let mut pointers = [std::ptr::null(); BATCH];
        let mut lengths = [0; BATCH];
        for (i, packet) in queue.iter().take(n).enumerate() {
            pointers[i] = packet.data().as_ptr();
            lengths[i] = packet.len;
        }
        // SAFETY: C copies a prefix synchronously and never retains Rust pointers.
        #[cfg(feature = "io-profile")]
        let span = Span::new(Stage::NetworkSend);
        let result = count(unsafe {
            in_flow_send(self.handle.as_ptr(), pointers.as_ptr(), lengths.as_ptr(), n)
        });
        #[cfg(feature = "io-profile")]
        drop(span);
        #[cfg(feature = "io-metrics")]
        metrics::record(true, 0, &result);
        let sent = result?;
        assert!(sent <= n);
        queue.drain(..sent);
        Ok(sent)
    }
    pub fn receive(
        &self,
        receiver: &mut Receiver,
        mut consume: impl FnMut(Received),
    ) -> io::Result<usize> {
        if self.receiving.swap(true, Ordering::Acquire) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let _guard = ReceiveGuard(&self.receiving);
        #[cfg(feature = "io-profile")]
        let setup = Span::new(Stage::ReceiveSetup);
        let packets = receiver.receive_buffers();
        let n = packets.len();
        if n == 0 {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        let mut pointers = [std::ptr::null_mut(); BATCH];
        let mut lengths = [0; BATCH];
        for i in 0..n {
            pointers[i] = packets[i].buffer().as_mut_ptr();
        }
        #[cfg(feature = "io-profile")]
        drop(setup);
        // SAFETY: Each pointer has CAPACITY writable bytes, matching C's ring
        // slot size; C fills at most n slots and does not retain pointers.
        #[cfg(feature = "io-profile")]
        let span = Span::new(Stage::NetworkReceive);
        let result = count(unsafe {
            in_flow_receive(
                self.handle.as_ptr(),
                pointers.as_ptr(),
                lengths.as_mut_ptr(),
                n,
            )
        });
        #[cfg(feature = "io-profile")]
        drop(span);
        #[cfg(feature = "io-metrics")]
        metrics::record(false, 0, &result);
        let received = result?;
        assert!(received <= n);
        for (i, mut packet) in packets.drain(..received).enumerate() {
            packet.len = lengths[i];
            consume(Received {
                packet,
                source: Some(self.endpoint),
            });
        }
        Ok(received)
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        // SAFETY: Last Rust owner; bridge serializes cancellation. Callback
        // storage and signal ownership live until callbacks end.
        unsafe { in_flow_close(self.handle.as_ptr()) };
    }
}
