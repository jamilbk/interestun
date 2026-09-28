//! macOS worker readiness: native kqueue for descriptors, atomic callback signals.
//! A producer enters the kernel only while the consumer has armed its sleep.
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Token(pub usize);
#[derive(Clone, Copy)]
pub enum Interest {
    Readable,
    Writable,
}
impl Interest {
    pub const READABLE: Self = Self::Readable;
    pub const WRITABLE: Self = Self::Writable;
    fn filter(self) -> i16 {
        match self {
            Self::Readable => libc::EVFILT_READ,
            Self::Writable => libc::EVFILT_WRITE,
        }
    }
}
#[derive(Clone, Copy)]
pub struct Event {
    token: Token,
    filter: i16,
    flags: u16,
}
impl Event {
    pub fn token(&self) -> Token {
        self.token
    }
    pub fn is_readable(&self) -> bool {
        self.filter != libc::EVFILT_WRITE
    }
    pub fn is_writable(&self) -> bool {
        self.filter == libc::EVFILT_WRITE
    }
    pub fn is_error(&self) -> bool {
        self.flags & libc::EV_ERROR != 0
    }
    pub fn is_read_closed(&self) -> bool {
        self.flags & libc::EV_EOF != 0
    }
    pub fn is_write_closed(&self) -> bool {
        self.is_read_closed()
    }
}
pub type Events = Vec<Event>;
struct State {
    fd: OwnedFd,
    pending: AtomicUsize,
    sleeping: AtomicBool,
}
#[derive(Clone)]
pub struct Waker {
    state: Arc<State>,
    token: Token,
}
pub struct Poll {
    state: Arc<State>,
    active_polls: u32,
}
fn event(ident: usize, filter: i16, flags: u16, fflags: u32, token: usize) -> libc::kevent {
    libc::kevent {
        ident,
        filter,
        flags,
        fflags,
        data: 0,
        udata: token as *mut _,
    }
}
fn change(fd: i32, e: &libc::kevent) -> io::Result<()> {
    loop {
        // SAFETY: Valid input event, no output storage requested.
        if unsafe { libc::kevent(fd, e, 1, std::ptr::null_mut(), 0, std::ptr::null()) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
impl Poll {
    pub fn new() -> io::Result<Self> {
        // SAFETY: Returns a fresh owned descriptor on success.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        change(
            fd.as_raw_fd(),
            &event(0, libc::EVFILT_USER, libc::EV_ADD | libc::EV_CLEAR, 0, 0),
        )?;
        Ok(Self {
            active_polls: 0,
            state: Arc::new(State {
                fd,
                pending: AtomicUsize::new(0),
                sleeping: AtomicBool::new(false),
            }),
        })
    }
    pub fn register(&self, fd: i32, token: Token, interest: Interest) -> io::Result<()> {
        change(
            self.state.fd.as_raw_fd(),
            &event(
                fd as usize,
                interest.filter(),
                libc::EV_ADD | libc::EV_CLEAR,
                0,
                token.0,
            ),
        )
    }
    pub fn deregister(&self, fd: i32, interest: Interest) -> io::Result<()> {
        change(
            self.state.fd.as_raw_fd(),
            &event(fd as usize, interest.filter(), libc::EV_DELETE, 0, 0),
        )
    }
    pub fn notifications(&self, events: &mut Events) {
        events.clear();
        self.collect(events);
    }
    fn collect(&self, events: &mut Events) {
        let mut bits = self.state.pending.swap(0, Ordering::SeqCst);
        while bits != 0 {
            let bit = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            events.push(Event {
                token: Token(bit),
                filter: libc::EVFILT_USER,
                flags: 0,
            });
        }
    }
    /// During bounded active work, consume callbacks without a syscall. Probe
    /// descriptor edges every 32 batches so other sources cannot starve.
    pub fn poll_active(
        &mut self,
        events: &mut Events,
        timeout: Option<Duration>,
    ) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            self.active_polls = self.active_polls.wrapping_add(1);
            if !self.active_polls.is_multiple_of(32) {
                self.notifications(events);
                return Ok(());
            }
        } else {
            self.active_polls = 0;
        }
        self.poll(events, timeout)
    }
    pub fn poll(&mut self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.clear();
        // SeqCst pairs arming with producer publication: either collect sees
        // pending work or the producer sees sleeping and triggers EVFILT_USER.
        self.state.sleeping.store(true, Ordering::SeqCst);
        self.collect(events);
        let timeout = if events.is_empty() {
            timeout
        } else {
            Some(Duration::ZERO)
        };
        let ts = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as _,
            tv_nsec: d.subsec_nanos() as _,
        });
        let mut output = [event(0, 0, 0, 0, 0); 8];
        // SAFETY: Output array and optional timeout live for this call.
        let n = unsafe {
            libc::kevent(
                self.state.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                output.as_mut_ptr(),
                output.len() as _,
                ts.as_ref().map_or(std::ptr::null(), |t| t),
            )
        };
        self.state.sleeping.store(false, Ordering::SeqCst);
        if n < 0 {
            let error = io::Error::last_os_error();
            // Do not discard callback tokens collected before an interrupted wait.
            if error.kind() == io::ErrorKind::Interrupted && !events.is_empty() {
                return Ok(());
            }
            return Err(error);
        }
        for e in output.iter().take(n as usize) {
            if e.filter != libc::EVFILT_USER {
                events.push(Event {
                    token: Token(e.udata as usize),
                    filter: e.filter,
                    flags: e.flags,
                });
            }
        }
        self.collect(events);
        Ok(())
    }
}
impl Waker {
    pub fn new(poll: &Poll, token: Token) -> io::Result<Self> {
        assert!(token.0 < usize::BITS as usize);
        Ok(Self {
            state: poll.state.clone(),
            token,
        })
    }
    pub fn with_token(&self, token: Token) -> Self {
        assert!(token.0 < usize::BITS as usize);
        Self {
            state: self.state.clone(),
            token,
        }
    }
    pub fn wake(&self) -> io::Result<()> {
        let bit = 1 << self.token.0;
        if self.state.pending.fetch_or(bit, Ordering::SeqCst) & bit == 0
            && self.state.sleeping.load(Ordering::SeqCst)
        {
            change(
                self.state.fd.as_raw_fd(),
                &event(0, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER, 0),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        sync::mpsc,
        thread,
    };
    #[test]
    fn coalesces_callbacks_and_preserves_descriptor_edges() {
        let mut poll = Poll::new().unwrap();
        let wake = Waker::new(&poll, Token(1)).unwrap();
        let (mut read, mut write) = UnixStream::pair().unwrap();
        read.set_nonblocking(true).unwrap();
        poll.register(read.as_raw_fd(), Token(2), Interest::READABLE)
            .unwrap();
        for _ in 0..100 {
            wake.wake().unwrap();
        }
        write.write_all(&[1]).unwrap();
        let mut events = Events::with_capacity(8);
        poll.poll(&mut events, Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(events.iter().filter(|e| e.token() == Token(1)).count(), 1);
        assert!(events.iter().any(|e| e.token() == Token(2)));
        let mut byte = [0];
        read.read_exact(&mut byte).unwrap();
        poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.is_empty());
        write.write_all(&[2]).unwrap();
        poll.poll(&mut events, Some(Duration::from_secs(1)))
            .unwrap();
        assert!(events.iter().any(|e| e.token() == Token(2)));
        poll.deregister(read.as_raw_fd(), Interest::READABLE)
            .unwrap();
    }
    #[test]
    fn active_work_still_probes_descriptors_and_observes_callbacks() {
        let mut poll = Poll::new().unwrap();
        let wake = Waker::new(&poll, Token(1)).unwrap();
        let (read, mut write) = UnixStream::pair().unwrap();
        poll.register(read.as_raw_fd(), Token(2), Interest::READABLE)
            .unwrap();
        write.write_all(&[1]).unwrap();
        wake.wake().unwrap();
        let mut events = Events::with_capacity(8);
        poll.poll_active(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(events.iter().any(|e| e.token() == Token(1)));
        let mut descriptor_seen = events.iter().any(|e| e.token() == Token(2));
        for _ in 0..31 {
            poll.poll_active(&mut events, Some(Duration::ZERO)).unwrap();
            descriptor_seen |= events.iter().any(|e| e.token() == Token(2));
        }
        assert!(
            descriptor_seen,
            "active packet processing starved a descriptor"
        );
    }
    #[test]
    fn callback_racing_sleep_is_never_lost() {
        let mut poll = Poll::new().unwrap();
        let wake = Waker::new(&poll, Token(1)).unwrap();
        let (go, start) = mpsc::sync_channel(0);
        let producer = thread::spawn(move || {
            for i in 0..10000 {
                start.recv().unwrap();
                if i % 2 == 0 {
                    thread::yield_now();
                }
                wake.wake().unwrap();
            }
        });
        let mut events = Events::with_capacity(8);
        for _ in 0..10000 {
            go.send(()).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            loop {
                poll.poll(
                    &mut events,
                    Some(deadline.saturating_duration_since(std::time::Instant::now())),
                )
                .unwrap();
                if events.iter().any(|e| e.token() == Token(1)) {
                    break;
                }
                assert!(std::time::Instant::now() < deadline, "lost callback wake");
            }
        }
        producer.join().unwrap();
    }
}
