#[cfg(target_os = "macos")]
use crate::platform::batch::{self, Receiver};
use crate::{
    config::{Cipher, Config},
    packet::{self, BATCH, Packet, Pool},
    platform::Tunnel,
};
use anyhow::{Context, Result};
use boringtun::{
    noise::{
        Index, Packet as WirePacket, Tunn, TunnResult, handshake::parse_handshake_anon_with_cipher,
        rate_limiter::RateLimiter,
    },
    x25519,
};
use crossbeam_queue::ArrayQueue;
#[cfg(windows)]
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(target_os = "macos")]
use {
    mio::unix::SourceFd,
    std::{net::UdpSocket, os::fd::AsRawFd},
};

const QUEUE: usize = 256;
#[cfg(target_os = "macos")]
const UDP: Token = Token(1);
#[cfg(target_os = "macos")]
const TUN: Token = Token(2);
const WILDCARD4: Token = Token(3);
const WILDCARD6: Token = Token(4);
const WAKE: Token = Token(5);

#[derive(Default, Clone)]
pub struct Snapshot {
    pub tx: usize,
    pub rx: usize,
    pub handshake: Duration,
    pub endpoint: Option<SocketAddr>,
}
pub struct SharedPeer {
    inbox: ArrayQueue<Input>,
    waker: Waker,
    notified: AtomicBool,
    pub stats: Mutex<Snapshot>,
    pub drops: AtomicU64,
}
enum Input {
    Plain(Packet),
    Wire(Packet, SocketAddr),
}
impl SharedPeer {
    fn send(&self, packet: Input) {
        if self.inbox.push(packet).is_err() {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !self.notified.swap(true, Ordering::AcqRel) {
            let _ = self.waker.wake();
        }
    }
}
struct Routing {
    routes: ip_network_table::IpNetworkTable<usize>,
    keys: BTreeMap<[u8; 32], usize>,
    peers: Vec<Arc<SharedPeer>>,
}
impl Routing {
    fn lookup(&self, address: IpAddr) -> Option<usize> {
        self.routes.longest_match(address).map(|(_, i)| *i)
    }
}

pub struct Runtime {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    pub peers: BTreeMap<[u8; 32], Arc<SharedPeer>>,
    pub port: u16,
    pub failed: Arc<AtomicBool>,
    limiter: Arc<RateLimiter>,
    // Keep listeners alive even when there are no peers; main never reads packet I/O.
    _wildcards: Arc<[UdpSocket; 2]>,
}
fn bind_udp(local: SocketAddr, endpoint: Option<SocketAddr>) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        if local.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if local.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    #[cfg(target_os = "macos")]
    {
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOL_SOCKET, WSAGetLastError, setsockopt,
        };
        let enabled: i32 = 1;
        // SAFETY: Live socket and a correctly sized BOOL option. Exclusive bind
        // prevents another Windows socket from stealing the shared listen port.
        if unsafe {
            setsockopt(
                socket.as_raw_socket() as _,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&enabled as *const i32).cast(),
                4,
            )
        } != 0
        {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    socket.set_nonblocking(true)?;
    // macOS caps these per host; retain kernel defaults if larger buffers are rejected.
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    socket.bind(&local.into())?;
    if let Some(endpoint) = endpoint {
        socket.connect(&endpoint.into())?;
    }
    #[cfg(target_os = "macos")]
    {
        Ok(socket.into())
    }
    #[cfg(windows)]
    {
        Ok(UdpSocket::from_std(socket.into()))
    }
}
#[cfg(target_os = "macos")]
fn flow(port: u16, endpoint: SocketAddr) -> io::Result<UdpSocket> {
    bind_udp(
        SocketAddr::new(
            if endpoint.is_ipv4() {
                "0.0.0.0".parse().unwrap()
            } else {
                "::".parse().unwrap()
            },
            port,
        ),
        Some(endpoint),
    )
}
#[cfg(target_os = "macos")]
fn register(poll: &Poll, fd: i32, token: Token, interest: Interest) -> io::Result<()> {
    poll.registry()
        .register(&mut SourceFd(&fd), token, interest)
}

impl Runtime {
    pub fn start(config: &Config, cipher: Cipher, tun: Arc<Tunnel>) -> Result<Self> {
        let v4 = bind_udp(([0, 0, 0, 0], config.listen_port).into(), None)?;
        let port = v4.local_addr()?.port();
        let v6 = bind_udp((std::net::Ipv6Addr::UNSPECIFIED, port).into(), None)?;
        let wildcards = [v4, v6];
        #[cfg(windows)]
        let mut wildcards = wildcards;
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let private = x25519::StaticSecret::from(config.private_key);
        let public = x25519::PublicKey::from(&private);
        let limiter = Arc::new(RateLimiter::new_at(&public, 100, Instant::now()));
        let mut prepared = Vec::new();
        let mut peers = BTreeMap::new();
        // All fallible resource setup happens before spawning any worker.
        if config.private_key != [0; 32] {
            for (key, peer) in &config.peers {
                let poll = Poll::new()?;
                let shared = Arc::new(SharedPeer {
                    inbox: ArrayQueue::new(QUEUE),
                    notified: AtomicBool::new(false),
                    waker: Waker::new(poll.registry(), WAKE)?,
                    stats: Mutex::new(Snapshot {
                        endpoint: peer.endpoint,
                        ..Snapshot::default()
                    }),
                    drops: AtomicU64::new(0),
                });
                #[cfg(target_os = "macos")]
                let socket = peer
                    .endpoint
                    .map(|endpoint| flow(port, endpoint))
                    .transpose()?;
                #[cfg(target_os = "macos")]
                if let Some(socket) = &socket {
                    register(&poll, socket.as_raw_fd(), UDP, Interest::READABLE)?;
                }
                #[cfg(windows)]
                let socket: Option<UdpSocket> = None;
                peers.insert(*key, shared.clone());
                prepared.push((peer.clone(), poll, shared, socket));
            }
        }
        // Mio's Windows sockets must be registered before sharing ownership.
        #[cfg(windows)]
        if let Some((_, poll, _, _)) = prepared.first() {
            for (socket, token) in wildcards.iter_mut().zip([WILDCARD4, WILDCARD6]) {
                poll.registry()
                    .register(socket, token, Interest::READABLE)?;
            }
        }
        let wildcards = Arc::new(wildcards);
        let mut routing = Routing {
            routes: ip_network_table::IpNetworkTable::new(),
            keys: BTreeMap::new(),
            peers: Vec::new(),
        };
        for (i, (peer, _, shared, _)) in prepared.iter().enumerate() {
            routing.keys.insert(peer.public_key, i);
            routing.peers.push(shared.clone());
            for net in &peer.allowed_ips {
                routing.routes.insert(
                    ip_network::IpNetwork::new_truncate(net.addr(), net.prefix_len())
                        .expect("validated network"),
                    i,
                );
            }
        }
        let routing = Arc::new(routing);
        let pool = packet::pool((prepared.len() * (QUEUE * 3 + BATCH * 3)).clamp(128, 16384));
        let mut runtime = Self {
            stop: stop.clone(),
            threads: Vec::new(),
            peers,
            port,
            failed: failed.clone(),
            limiter: limiter.clone(),
            _wildcards: wildcards.clone(),
        };
        for (id, (peer, poll, shared, socket)) in prepared.into_iter().enumerate() {
            let now = Instant::now();
            let unix = SystemTime::now().duration_since(UNIX_EPOCH)?;
            let tunnel = Tunn::new_with_cipher_at(
                private.clone(),
                x25519::PublicKey::from(peer.public_key),
                Some(x25519::StaticSecret::from(peer.preshared_key)),
                Some(peer.keepalive),
                Index::new_local(id as u32 + 1),
                Some(limiter.clone()),
                rand::random(),
                now,
                now,
                unix,
                cipher.into(),
            );
            let mut worker = Worker {
                id,
                tunnel,
                poll,
                shared,
                #[cfg(target_os = "macos")]
                socket,
                endpoint: peer.endpoint,
                #[cfg(target_os = "macos")]
                port,
                tun: tun.clone(),
                routing: routing.clone(),
                pool: pool.clone(),
                wildcards: wildcards.clone(),
                stop: stop.clone(),
                private: private.clone(),
                public,
                cipher,
                limiter: limiter.clone(),
                plain: VecDeque::with_capacity(QUEUE),
                network: VecDeque::with_capacity(QUEUE),
                injection: VecDeque::with_capacity(QUEUE),
                #[cfg(target_os = "macos")]
                tun_registered: false,
                #[cfg(target_os = "macos")]
                udp_writable: false,
                #[cfg(target_os = "macos")]
                tun_writable: false,
                #[cfg(target_os = "macos")]
                readable: [false; 5],
                #[cfg(target_os = "macos")]
                udp_blocked: false,
            };
            #[cfg(windows)]
            let _ = socket;
            let failed = failed.clone();
            let handle = thread::Builder::new()
                .name(format!("peer-{id}"))
                .spawn(move || {
                    if let Err(error) = worker.run() {
                        eprintln!("peer-{id} stopped: {error:#}");
                        failed.store(true, Ordering::Release);
                    }
                })
                .context("spawn peer worker")?;
            runtime.threads.push(handle);
        }
        #[cfg(windows)]
        if !routing.peers.is_empty() {
            // Wintun exposes a waitable event rather than a socket that Mio can
            // register. One reader dispatches raw IP packets to bounded inboxes.
            let handle = thread::Builder::new()
                .name("wintun-reader".into())
                .spawn(move || {
                    if let Err(error) = read_wintun(&tun, &routing, &pool, &stop) {
                        eprintln!("Wintun reader stopped: {error:#}");
                        failed.store(true, Ordering::Release);
                    }
                })
                .context("spawn Wintun reader")?;
            runtime.threads.push(handle);
        }
        Ok(runtime)
    }
    pub fn housekeeping(&self) {
        self.limiter.reset_count_at(Instant::now());
        if self.threads.iter().any(JoinHandle::is_finished) {
            self.failed.store(true, Ordering::Release);
        }
    }
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for peer in self.peers.values() {
            let _ = peer.waker.wake();
        }
        for thread in self.threads.drain(..) {
            if thread.join().is_err() {
                self.failed.store(true, Ordering::Release);
            }
        }
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(windows)]
fn read_wintun(
    tun: &Arc<Tunnel>,
    routing: &Routing,
    pool: &Pool,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut scratch = [0; packet::CAPACITY];
    while !stop.load(Ordering::Acquire) {
        match tun.receive(&mut scratch) {
            Ok(len) => {
                if let Some(id) =
                    packet::addresses(&scratch[..len]).and_then(|(_, dst)| routing.lookup(dst))
                {
                    if let Some(mut packet) = Packet::new(pool) {
                        packet.buffer()[..len].copy_from_slice(&scratch[..len]);
                        packet.len = len;
                        routing.peers[id].send(Input::Plain(packet));
                    } else {
                        routing.peers[id].drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                tun.wait_readable(Duration::from_millis(100))?
            }
            Err(e)
                if e.kind() == io::ErrorKind::Interrupted
                    || (e.kind() == io::ErrorKind::InvalidData && e.raw_os_error().is_none()) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

struct Worker {
    id: usize,
    tunnel: Tunn,
    poll: Poll,
    shared: Arc<SharedPeer>,
    #[cfg(target_os = "macos")]
    socket: Option<UdpSocket>,
    endpoint: Option<SocketAddr>,
    #[cfg(target_os = "macos")]
    port: u16,
    tun: Arc<Tunnel>,
    routing: Arc<Routing>,
    pool: Pool,
    wildcards: Arc<[UdpSocket; 2]>,
    stop: Arc<AtomicBool>,
    private: x25519::StaticSecret,
    public: x25519::PublicKey,
    cipher: Cipher,
    limiter: Arc<RateLimiter>,
    plain: VecDeque<Packet>,
    network: VecDeque<Packet>,
    injection: VecDeque<Packet>,
    #[cfg(target_os = "macos")]
    tun_registered: bool,
    #[cfg(target_os = "macos")]
    udp_writable: bool,
    #[cfg(target_os = "macos")]
    tun_writable: bool,
    #[cfg(target_os = "macos")]
    readable: [bool; 5],
    #[cfg(target_os = "macos")]
    udp_blocked: bool,
}
impl Worker {
    #[cfg(windows)]
    fn receive_windows(&mut self) -> io::Result<bool> {
        let mut more = false;
        let mut scratch = [0; packet::CAPACITY];
        for family in 0..2 {
            for index in 0..BATCH * 4 {
                match self.wildcards[family].recv_from(&mut scratch) {
                    Ok((len, source)) => {
                        more |= index == BATCH * 4 - 1;
                        // Reject full buffers conservatively, including truncation.
                        if len == scratch.len() {
                            self.drop_packet();
                            continue;
                        }
                        if let Some(mut packet) = Packet::new(&self.pool) {
                            packet.buffer()[..len].copy_from_slice(&scratch[..len]);
                            packet.len = len;
                            self.dispatch_wire(packet, source);
                        } else {
                            self.drop_packet();
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    // WSAEMSGSIZE consumes an oversized datagram. ICMP errors
                    // must not terminate the shared listener for every peer.
                    Err(e)
                        if e.raw_os_error() == Some(10040)
                            || matches!(
                                e.kind(),
                                io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::ConnectionRefused
                                    | io::ErrorKind::Interrupted
                            ) =>
                    {
                        self.drop_packet();
                        more |= index == BATCH * 4 - 1;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(more)
    }

    #[cfg(windows)]
    fn flush_windows(&mut self) -> io::Result<()> {
        if let Some(endpoint) = self.endpoint {
            let socket = &self.wildcards[usize::from(endpoint.is_ipv6())];
            for _ in 0..BATCH * 4 {
                let Some(packet) = self.network.front() else {
                    break;
                };
                match socket.send_to(packet.data(), endpoint) {
                    Ok(n) if n == packet.len => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    _ => self.drop_packet(),
                }
                self.network.pop_front();
            }
        }
        for _ in 0..BATCH * 4 {
            let Some(packet) = self.injection.front() else {
                break;
            };
            match self.tun.send(packet.data()) {
                Ok(()) => {
                    self.injection.pop_front();
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn drop_packet(&self) {
        self.shared.drops.fetch_add(1, Ordering::Relaxed);
    }
    fn enqueue_plain(&mut self, p: Packet) {
        if self.plain.len() < QUEUE {
            self.plain.push_back(p);
        } else {
            self.drop_packet();
        }
    }
    #[cfg(target_os = "macos")]
    fn new_endpoint(&mut self, endpoint: SocketAddr) -> io::Result<()> {
        if self.endpoint == Some(endpoint) && self.socket.is_some() {
            return Ok(());
        }
        let socket = flow(self.port, endpoint)?;
        register(&self.poll, socket.as_raw_fd(), UDP, Interest::READABLE)?;
        if let Some(old) = &self.socket {
            self.poll
                .registry()
                .deregister(&mut SourceFd(&old.as_raw_fd()))?;
        }
        self.socket = Some(socket);
        self.endpoint = Some(endpoint);
        self.udp_writable = false;
        self.udp_blocked = false;
        self.readable[UDP.0] = true;
        Ok(())
    }
    #[cfg(windows)]
    fn new_endpoint(&mut self, endpoint: SocketAddr) -> io::Result<()> {
        self.endpoint = Some(endpoint);
        Ok(())
    }
    fn wire(&mut self, input: Packet, source: SocketAddr) {
        let Some(mut output) = Packet::new(&self.pool) else {
            self.drop_packet();
            return;
        };
        let kind = input.data().first().copied();
        let result = self.tunnel.decapsulate_at(
            Some(source.ip()),
            input.data(),
            output.buffer(),
            Instant::now(),
        );
        let authenticated;
        let mut inject = false;
        let len = match result {
            TunnResult::WriteToNetwork(data) => {
                // Cookie replies are not proof of possession and must never move an endpoint.
                authenticated = matches!(
                    (kind, data.first()),
                    (Some(1), Some(2)) | (Some(2), Some(4))
                );
                data.len()
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                authenticated = true;
                inject = true;
                data.len()
            }
            TunnResult::Done => {
                authenticated = kind == Some(4);
                0
            }
            TunnResult::Err(_) => {
                self.drop_packet();
                return;
            }
        };
        if authenticated && self.new_endpoint(source).is_err() {
            self.drop_packet();
            return;
        }
        if len == 0 {
            return;
        }
        output.len = len;
        if inject {
            // Inbound source validation must use the same global longest-prefix lookup as outbound routing.
            if packet::addresses(output.data())
                .is_some_and(|(src, _)| self.routing.lookup(src) == Some(self.id))
                && self.injection.len() < QUEUE
            {
                self.injection.push_back(output);
            } else {
                self.drop_packet();
            }
        } else if authenticated {
            if self.network.len() < QUEUE {
                self.network.push_back(output);
            } else {
                self.drop_packet();
            }
        } else {
            // Unauthenticated cookie replies go only to the requesting address.
            let socket = &self.wildcards[usize::from(source.is_ipv6())];
            let _ = socket.send_to(output.data(), source);
        }
    }
    fn dispatch_wire(&mut self, packet: Packet, source: SocketAddr) {
        let mut cookie = [0u8; 64];
        let id = match Tunn::parse_incoming_packet(packet.data()) {
            Ok(WirePacket::HandshakeInit(_)) => {
                match self.limiter.verify_packet_at(
                    Some(source.ip()),
                    packet.data(),
                    &mut cookie,
                    Instant::now(),
                ) {
                    Ok(WirePacket::HandshakeInit(init)) => parse_handshake_anon_with_cipher(
                        &self.private,
                        &self.public,
                        &init,
                        self.cipher.into(),
                    )
                    .ok()
                    .and_then(|half| self.routing.keys.get(&half.peer_static_public).copied()),
                    Err(TunnResult::WriteToNetwork(reply)) => {
                        let _ =
                            self.wildcards[usize::from(source.is_ipv6())].send_to(reply, source);
                        None
                    }
                    _ => None,
                }
            }
            Ok(_) => {
                let bytes = packet.data();
                let offset = if bytes[0] == 2 { 8 } else { 4 };
                bytes.get(offset..offset + 4).and_then(|b| {
                    let index = u32::from_le_bytes(b.try_into().ok()?) >> 8;
                    index
                        .checked_sub(1)
                        .map(|i| i as usize)
                        .filter(|i| *i < self.routing.peers.len())
                })
            }
            Err(_) => None,
        };
        if let Some(id) = id {
            if id == self.id {
                self.wire(packet, source);
            } else {
                self.routing.peers[id].send(Input::Wire(packet, source));
            }
        } else {
            self.drop_packet();
        }
    }
    fn plaintext(&mut self) -> bool {
        let mut processed = 0;
        while processed < BATCH * 4 && self.network.len() < QUEUE {
            let Some(input) = self.plain.front() else {
                break;
            };
            if self.endpoint.is_none() {
                break;
            }
            let Some(mut output) = Packet::new(&self.pool) else {
                break;
            };
            match self
                .tunnel
                .encapsulate_data_at(input.data(), output.buffer(), Instant::now())
            {
                Ok(len) => {
                    output.len = len;
                    self.network.push_back(output);
                    self.plain.pop_front();
                    processed += 1;
                }
                Err(boringtun::noise::errors::WireGuardError::NoCurrentSession) => {
                    if let TunnResult::WriteToNetwork(data) = self
                        .tunnel
                        .format_handshake_initiation_at(output.buffer(), false, Instant::now())
                    {
                        output.len = data.len();
                        self.network.push_back(output);
                    }
                    break;
                }
                Err(_) => {
                    self.plain.pop_front();
                    self.drop_packet();
                    processed += 1;
                }
            }
        }
        processed == BATCH * 4
    }
    #[cfg(target_os = "macos")]
    fn interests(&mut self) -> io::Result<()> {
        if let Some(socket) = &self.socket {
            let writable = !self.network.is_empty();
            if writable != self.udp_writable {
                self.poll.registry().reregister(
                    &mut SourceFd(&socket.as_raw_fd()),
                    UDP,
                    if writable {
                        Interest::READABLE | Interest::WRITABLE
                    } else {
                        Interest::READABLE
                    },
                )?;
                self.udp_writable = writable;
            }
        }
        let writable = !self.injection.is_empty();
        let needed = self.id == 0 || writable;
        let interest = match (self.id == 0, writable) {
            (true, true) => Interest::READABLE | Interest::WRITABLE,
            (true, false) => Interest::READABLE,
            _ => Interest::WRITABLE,
        };
        let mut fd = SourceFd(&self.tun.fd.as_raw_fd());
        if needed && !self.tun_registered {
            self.poll.registry().register(&mut fd, TUN, interest)?;
        } else if needed && writable != self.tun_writable {
            self.poll.registry().reregister(&mut fd, TUN, interest)?;
        } else if !needed && self.tun_registered {
            self.poll.registry().deregister(&mut fd)?;
        }
        self.tun_registered = needed;
        self.tun_writable = writable;
        Ok(())
    }
    fn run(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        if self.id == 0 {
            register(
                &self.poll,
                self.wildcards[0].as_raw_fd(),
                WILDCARD4,
                Interest::READABLE,
            )?;
            register(
                &self.poll,
                self.wildcards[1].as_raw_fd(),
                WILDCARD6,
                Interest::READABLE,
            )?;
        }
        #[cfg(target_os = "macos")]
        self.interests()?;
        #[cfg(target_os = "macos")]
        let mut tun_rx = Receiver::new(self.pool.clone());
        #[cfg(target_os = "macos")]
        let mut udp_rx = Receiver::new(self.pool.clone());
        let mut events = Events::with_capacity(16);
        let mut snapshot_at = Instant::now();
        #[cfg(target_os = "macos")]
        let mut tun_blocked = false;
        // Probe once at startup, then retain readiness until WouldBlock. Mio is
        // edge-triggered: hitting our fairness budget must not lose a ready fd.
        #[cfg(target_os = "macos")]
        {
            self.readable[UDP.0] = self.socket.is_some();
            for token in [TUN, WILDCARD4, WILDCARD6] {
                self.readable[token.0] = self.id == 0;
            }
        }
        while !self.stop.load(Ordering::Acquire) {
            let mut more = false;
            // Bounded draining keeps timers and other directions live under continuous traffic.
            #[cfg(target_os = "macos")]
            if self.id == 0 {
                for _ in 0..4 {
                    if !self.readable[TUN.0] {
                        break;
                    }
                    let fd = self.tun.fd.as_raw_fd();
                    match tun_rx.receive(fd, true, |received| {
                        if let Some(id) = packet::addresses(received.packet.data())
                            .and_then(|(_, dst)| self.routing.lookup(dst))
                        {
                            if id == self.id {
                                self.enqueue_plain(received.packet);
                            } else {
                                self.routing.peers[id].send(Input::Plain(received.packet));
                            }
                        } else {
                            self.drop_packet();
                        }
                    }) {
                        Ok(n) => {
                            if n == 0 {
                                anyhow::bail!("utun closed");
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            self.readable[TUN.0] = false;
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) if e.kind() == io::ErrorKind::OutOfMemory => break,
                        Err(e) => return Err(e.into()),
                    }
                }
                for family in 0..2 {
                    let token = [WILDCARD4, WILDCARD6][family];
                    for _ in 0..4 {
                        if !self.readable[token.0] {
                            break;
                        }
                        let fd = self.wildcards[family].as_raw_fd();
                        match udp_rx.receive(fd, false, |received| {
                            if let Some(source) = received.source {
                                self.dispatch_wire(received.packet, source);
                            }
                        }) {
                            Ok(n) => {
                                if n == 0 {
                                    self.readable[token.0] = false;
                                    break;
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                self.readable[token.0] = false;
                                break;
                            }
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) if e.kind() == io::ErrorKind::OutOfMemory => break,
                            Err(_) => {
                                // A socket error does not prove the receive queue is drained.
                                self.drop_packet();
                                break;
                            }
                        }
                    }
                }
            }
            #[cfg(target_os = "macos")]
            if let Some(fd) = self.socket.as_ref().map(AsRawFd::as_raw_fd) {
                for _ in 0..4 {
                    if !self.readable[UDP.0]
                        || self.socket.as_ref().map(AsRawFd::as_raw_fd) != Some(fd)
                    {
                        break;
                    }
                    match udp_rx.receive(fd, false, |received| {
                        if let Some(source) = received.source {
                            self.wire(received.packet, source);
                        }
                    }) {
                        Ok(n) => {
                            if n == 0 {
                                self.readable[UDP.0] = false;
                                break;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            self.readable[UDP.0] = false;
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) if e.kind() == io::ErrorKind::OutOfMemory => break,
                        Err(_) => {
                            self.drop_packet();
                            break;
                        }
                    }
                }
            }
            #[cfg(windows)]
            if self.id == 0 {
                more |= self.receive_windows()?;
            }
            self.shared.notified.store(false, Ordering::Release);
            for _ in 0..BATCH * 4 {
                match self.shared.inbox.pop() {
                    Some(Input::Plain(p)) => self.enqueue_plain(p),
                    Some(Input::Wire(p, source)) => self.wire(p, source),
                    None => break,
                }
            }
            more |= !self.shared.inbox.is_empty();
            more |= self.plaintext();
            let now = Instant::now();
            if self
                .tunnel
                .next_timer_update()
                .is_some_and(|(deadline, _)| deadline <= now)
            {
                // Timers must progress even if congestion exhausts the packet pool.
                let mut scratch = [0u8; packet::CAPACITY];
                if let TunnResult::WriteToNetwork(data) =
                    self.tunnel.update_timers_at(&mut scratch, now)
                    && self.endpoint.is_some()
                    && self.network.len() < QUEUE
                    && let Some(mut output) = Packet::new(&self.pool)
                {
                    output.buffer()[..data.len()].copy_from_slice(data);
                    output.len = data.len();
                    self.network.push_back(output);
                }
            }

            #[cfg(target_os = "macos")]
            if let Some(socket) = &self.socket
                && !self.udp_blocked
            {
                for _ in 0..4 {
                    match batch::flush(socket.as_raw_fd(), false, &mut self.network) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            self.udp_blocked = true;
                            break;
                        }
                        Err(_) => {
                            self.drop_packet();
                            break;
                        }
                    }
                }
            }
            #[cfg(target_os = "macos")]
            for _ in 0..4 {
                if tun_blocked {
                    break;
                }
                match batch::flush(self.tun.fd.as_raw_fd(), true, &mut self.injection) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        tun_blocked = true;
                        break;
                    }
                    Err(_) => {
                        self.drop_packet();
                        break;
                    }
                }
            }
            #[cfg(windows)]
            self.flush_windows()?;
            if now >= snapshot_at {
                let (elapsed, tx, rx, _, _) = self.tunnel.stats_at(now);
                let handshake = elapsed
                    .and_then(|d| SystemTime::now().checked_sub(d))
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .unwrap_or_default();
                *self.shared.stats.lock().unwrap() = Snapshot {
                    tx,
                    rx,
                    handshake,
                    endpoint: self.endpoint,
                };
                snapshot_at = now + Duration::from_millis(250);
            }
            #[cfg(target_os = "macos")]
            {
                more |= self.readable.iter().any(|ready| *ready)
                    || (self.socket.is_some() && !self.network.is_empty() && !self.udp_blocked)
                    || (!self.injection.is_empty() && !tun_blocked);
                self.interests()?;
            }
            let deadline = self
                .tunnel
                .next_timer_update()
                .map(|(d, _)| d)
                .unwrap_or(snapshot_at)
                .min(snapshot_at);
            let timeout = if more {
                Duration::ZERO
            } else {
                deadline.saturating_duration_since(Instant::now())
            };
            // Wintun has no writable event. Retry ring/UDP congestion with a
            // bounded delay rather than spinning or waiting for a handshake timer.
            #[cfg(windows)]
            let timeout = if !self.injection.is_empty() || !self.network.is_empty() {
                timeout.min(Duration::from_millis(2))
            } else {
                timeout
            };
            match self.poll.poll(&mut events, Some(timeout)) {
                Ok(()) =>
                {
                    #[cfg(target_os = "macos")]
                    for event in &events {
                        let token = event.token();
                        if matches!(token, UDP | TUN | WILDCARD4 | WILDCARD6)
                            && (event.is_readable() || event.is_read_closed() || event.is_error())
                            && (token == UDP || self.id == 0)
                        {
                            self.readable[token.0] = true;
                        }
                        if event.is_writable() || event.is_write_closed() || event.is_error() {
                            match token {
                                UDP => self.udp_blocked = false,
                                TUN => tun_blocked = false,
                                _ => {}
                            }
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
