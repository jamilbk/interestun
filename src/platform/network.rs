//! Safe ownership wrapper around the serial-queue Network.framework bridge.
use super::batch::Received;
use crate::packet::{BATCH, Packet, Pool};
use std::{
    collections::VecDeque,
    ffi::{CString, c_void},
    io::{self, Read},
    net::SocketAddr,
    os::{fd::AsRawFd, unix::net::UnixStream},
    ptr::NonNull,
};

const _: () = assert!(crate::packet::CAPACITY == 2048);

unsafe extern "C" {
    fn in_flow_open(
        host: *const i8,
        port: *const i8,
        local_host: *const i8,
        local_port: *const i8,
        rx: i32,
        tx: i32,
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
}

pub struct Socket {
    handle: NonNull<c_void>,
    rx: UnixStream,
    tx: UnixStream,
    endpoint: SocketAddr,
}
// SAFETY: Every bridge operation serializes mutable flow state on its dispatch
// queue. Async callbacks own their buffers and never access Rust pointers.
// Arc ownership prevents close racing any Rust send/receive call.
unsafe impl Send for Socket {}
unsafe impl Sync for Socket {}

fn drain(mut stream: &UnixStream) -> io::Result<()> {
    let mut bytes = [0; 256];
    loop {
        match stream.read(&mut bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}
fn count(n: i32) -> io::Result<usize> {
    if n < 0 {
        Err(io::Error::from_raw_os_error(-n))
    } else {
        Ok(n as usize)
    }
}
impl Socket {
    pub fn connect(port: u16, endpoint: SocketAddr) -> io::Result<Self> {
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
        let (rx, rx_write) = UnixStream::pair()?;
        let (tx, tx_write) = UnixStream::pair()?;
        for s in [&rx, &rx_write, &tx, &tx_write] {
            s.set_nonblocking(true)?;
        }
        // SAFETY: Arguments remain valid throughout open; bridge duplicates the
        // notification writers and consumes endpoint strings synchronously.
        let handle = unsafe {
            in_flow_open(
                host.as_ptr(),
                remote_port.as_ptr(),
                local.as_ptr(),
                local_port.as_ptr(),
                rx_write.as_raw_fd(),
                tx_write.as_raw_fd(),
            )
        };
        let handle = NonNull::new(handle).ok_or_else(io::Error::last_os_error)?;
        Ok(Self {
            handle,
            rx,
            tx,
            endpoint,
        })
    }
    pub fn rx_fd(&self) -> i32 {
        self.rx.as_raw_fd()
    }
    pub fn tx_fd(&self) -> i32 {
        self.tx.as_raw_fd()
    }
    pub fn flush(&self, queue: &mut VecDeque<Packet>) -> io::Result<usize> {
        if queue.is_empty() {
            return Ok(0);
        }
        drain(&self.tx)?;
        let n = queue.len().min(BATCH);
        let mut pointers = [std::ptr::null(); BATCH];
        let mut lengths = [0; BATCH];
        for (i, packet) in queue.iter().take(n).enumerate() {
            pointers[i] = packet.data().as_ptr();
            lengths[i] = packet.len;
        }
        // SAFETY: C copies a prefix synchronously and never retains Rust pointers.
        let sent = count(unsafe {
            in_flow_send(self.handle.as_ptr(), pointers.as_ptr(), lengths.as_ptr(), n)
        })?;
        assert!(sent <= n);
        queue.drain(..sent);
        Ok(sent)
    }
    pub fn receive(&self, pool: &Pool, mut consume: impl FnMut(Received)) -> io::Result<usize> {
        drain(&self.rx)?;
        let mut packets: [Option<Packet>; BATCH] = std::array::from_fn(|_| Packet::new(pool));
        let n = packets.iter().take_while(|p| p.is_some()).count();
        if n == 0 {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        let mut pointers = [std::ptr::null_mut(); BATCH];
        let mut lengths = [0; BATCH];
        for i in 0..n {
            pointers[i] = packets[i].as_mut().unwrap().buffer().as_mut_ptr();
        }
        // SAFETY: Each pointer has CAPACITY writable bytes, matching C's ring
        // slot size; C fills at most n slots and does not retain pointers.
        let received = count(unsafe {
            in_flow_receive(
                self.handle.as_ptr(),
                pointers.as_ptr(),
                lengths.as_mut_ptr(),
                n,
            )
        })?;
        assert!(received <= n);
        for i in 0..received {
            let mut packet = packets[i].take().unwrap();
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
        // storage and duplicate notification writers live until callbacks end.
        unsafe { in_flow_close(self.handle.as_ptr()) };
    }
}
