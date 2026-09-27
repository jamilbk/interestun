//! Windows duplex peer workers with a shared IOCP listener and Wintun reader.
use crate::{
    config::{Cipher, Config},
    packet::{self, BATCH, Packet, Pool},
    platform::{Tunnel, coalesce::Injector},
};
use anyhow::{Context, Result};
use boringtun::{
    noise::{
        Index, Packet as WirePacket, TransportSender, Tunn, TunnResult,
        handshake::parse_handshake_anon_with_cipher, rate_limiter::RateLimiter,
    },
    x25519,
};
use crossbeam_queue::ArrayQueue;
use mio::{Events, Interest, Poll, Token, Waker, net::UdpSocket};
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

const QUEUE: usize = 256;
const WILDCARD4: Token = Token(3);
const WILDCARD6: Token = Token(4);
const WAKE: Token = Token(5);
const CONTROL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Default, Clone)]
pub struct Snapshot {
    pub tx: usize,
    pub rx: usize,
    pub handshake: Duration,
    pub endpoint: Option<SocketAddr>,
    pub injection: crate::platform::coalesce::Stats,
}
struct Inbox<T> {
    queue: ArrayQueue<T>,
    waker: Waker,
    notified: AtomicBool,
}
impl<T> Inbox<T> {
    fn new(poll: &Poll) -> io::Result<Self> {
        Ok(Self {
            queue: ArrayQueue::new(QUEUE),
            waker: Waker::new(poll.registry(), WAKE)?,
            notified: AtomicBool::new(false),
        })
    }
    fn wake(&self) {
        if !self.notified.swap(true, Ordering::AcqRel) {
            let _ = self.waker.wake();
        }
    }
    fn push(&self, value: T) -> bool {
        if self.queue.push(value).is_err() {
            return false;
        }
        self.wake();
        true
    }
}
#[derive(Default)]
struct TxControl {
    endpoint: Option<SocketAddr>,
    sender: Option<TransportSender>,
    packets: VecDeque<Packet>,
    keepalive: bool,
}
#[derive(Default)]
struct Activity {
    bytes: usize,
    last_packet: Option<Instant>,
    first_data: Option<Instant>,
    last_data: Option<Instant>,
}
impl Activity {
    fn sent(&mut self, bytes: usize, now: Instant) {
        self.bytes += bytes;
        self.last_packet = Some(now);
        if bytes != 0 {
            self.first_data.get_or_insert(now);
            self.last_data = Some(now);
        }
    }
    fn merge(&mut self, other: Self) {
        self.bytes += other.bytes;
        if other.last_packet.is_some() {
            self.last_packet = other.last_packet;
        }
        if self.first_data.is_none() {
            self.first_data = other.first_data;
        }
        if other.last_data.is_some() {
            self.last_data = other.last_data;
        }
    }
}
pub struct SharedPeer {
    tx: Inbox<Packet>,
    rx: Inbox<(Packet, SocketAddr)>,
    control: Mutex<TxControl>,
    control_pending: AtomicBool,
    activity: Mutex<Activity>,
    needs_handshake: AtomicBool,
    pub stats: Mutex<Snapshot>,
    pub drops: AtomicU64,
}
impl SharedPeer {
    fn drop_packet(&self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
    fn plain(&self, p: Packet) {
        if !self.tx.push(p) {
            self.drop_packet();
        }
    }
    fn wire(&self, p: Packet, source: SocketAddr) {
        if !self.rx.push((p, source)) {
            self.drop_packet();
        }
    }
    fn control(&self, update: impl FnOnce(&mut TxControl)) {
        update(&mut self.control.lock().unwrap());
        self.control_pending.store(true, Ordering::Release);
        self.tx.wake();
    }
    fn request_handshake(&self) {
        if !self.needs_handshake.swap(true, Ordering::AcqRel) {
            self.rx.wake();
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
    // Retain kernel defaults if larger buffers are rejected.
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    socket.bind(&local.into())?;
    if let Some(endpoint) = endpoint {
        socket.connect(&endpoint.into())?;
    }
    Ok(UdpSocket::from_std(socket.into()))
}

impl Runtime {
    pub fn start(config: &Config, cipher: Cipher, tun: Arc<Tunnel>) -> Result<Self> {
        let v4 = bind_udp(([0, 0, 0, 0], config.listen_port).into(), None)?;
        let port = v4.local_addr()?.port();
        let v6 = bind_udp((std::net::Ipv6Addr::UNSPECIFIED, port).into(), None)?;
        let mut wildcards = [v4, v6];
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let private = x25519::StaticSecret::from(config.private_key);
        let public = x25519::PublicKey::from(&private);
        let limiter = Arc::new(RateLimiter::new_at(&public, 100, Instant::now()));
        let mut prepared = Vec::new();
        let mut peers = BTreeMap::new();
        if config.private_key != [0; 32] {
            for (key, peer) in &config.peers {
                let rx_poll = Poll::new()?;
                let tx_poll = Poll::new()?;
                let shared = Arc::new(SharedPeer {
                    rx: Inbox::new(&rx_poll)?,
                    tx: Inbox::new(&tx_poll)?,
                    control: Mutex::new(TxControl::default()),
                    control_pending: AtomicBool::new(false),
                    activity: Mutex::new(Activity::default()),
                    needs_handshake: AtomicBool::new(false),
                    stats: Mutex::new(Snapshot {
                        endpoint: peer.endpoint,
                        ..Snapshot::default()
                    }),
                    drops: AtomicU64::new(0),
                });
                peers.insert(*key, shared.clone());
                prepared.push((peer.clone(), rx_poll, tx_poll, shared));
            }
        }
        // Register IOCP sockets before sharing them with direction workers.
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
        for (id, (peer, _, _, shared)) in prepared.iter().enumerate() {
            routing.keys.insert(peer.public_key, id);
            routing.peers.push(shared.clone());
            for net in &peer.allowed_ips {
                routing.routes.insert(
                    ip_network::IpNetwork::new_truncate(net.addr(), net.prefix_len())
                        .expect("validated network"),
                    id,
                );
            }
        }
        let routing = Arc::new(routing);
        let pool = packet::pool((prepared.len() * (QUEUE * 5 + BATCH * 3)).clamp(BATCH * 3, 16384));
        let mut runtime = Self {
            stop: stop.clone(),
            threads: Vec::new(),
            peers,
            port,
            failed: failed.clone(),
            limiter: limiter.clone(),
            _wildcards: wildcards.clone(),
        };
        for (id, (peer, rx_poll, tx_poll, shared)) in prepared.into_iter().enumerate() {
            let now = Instant::now();
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
                SystemTime::now().duration_since(UNIX_EPOCH)?,
                cipher.into(),
            );
            let mut tx = SendWorker {
                #[cfg(feature = "io-profile")]
                id,
                poll: tx_poll,
                shared: shared.clone(),
                endpoint: peer.endpoint,
                wildcards: wildcards.clone(),
                sender: None,
                pool: pool.clone(),
                stop: stop.clone(),
                plain: VecDeque::with_capacity(QUEUE),
                network: VecDeque::with_capacity(QUEUE),
            };
            let mut rx = ReceiveWorker {
                id,
                tunnel,
                poll: rx_poll,
                shared,
                endpoint: peer.endpoint,
                tun: tun.clone(),
                routing: routing.clone(),
                pool: pool.clone(),
                wildcards: wildcards.clone(),
                stop: stop.clone(),
                private: private.clone(),
                public,
                cipher,
                limiter: limiter.clone(),
                injector: Injector::new(tun.tcp_coalescing()),
                injection: VecDeque::with_capacity(QUEUE),
                udp_readable: [id == 0; 2],
            };
            for (name, task) in [
                (
                    format!("peer-{id}-tx"),
                    Box::new(move || tx.run()) as Box<dyn FnOnce() -> Result<()> + Send>,
                ),
                (
                    format!("peer-{id}-rx"),
                    Box::new(move || rx.run()) as Box<dyn FnOnce() -> Result<()> + Send>,
                ),
            ] {
                let failed = failed.clone();
                let handle = thread::Builder::new()
                    .name(name.clone())
                    .spawn(move || {
                        if let Err(error) = task() {
                            eprintln!("{name} stopped: {error:#}");
                            failed.store(true, Ordering::Release);
                        }
                    })
                    .context("spawn peer direction worker")?;
                runtime.threads.push(handle);
            }
        }
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
        for p in self.peers.values() {
            let _ = p.tx.waker.wake();
            let _ = p.rx.waker.wake();
        }
        for t in self.threads.drain(..) {
            if t.join().is_err() {
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

fn read_wintun(
    tun: &Arc<Tunnel>,
    routing: &Routing,
    pool: &Pool,
    stop: &AtomicBool,
) -> io::Result<()> {
    let mut scratch = [0; packet::CAPACITY];
    while !stop.load(Ordering::Acquire) {
        let mut received = Packet::new(pool);
        // Receive plaintext after the transport-header reservation, leaving
        // room for in-place encryption without a scratch-to-pool copy.
        let buffer = received
            .as_mut()
            .map_or(&mut scratch[..], |p| &mut p.buffer()[packet::HEADROOM..]);
        #[cfg(feature = "io-profile")]
        let span = crate::platform::profile::Span::syscall(true, false);
        let result = tun.receive(buffer);
        #[cfg(feature = "io-profile")]
        {
            drop(span);
            crate::platform::profile::report(0, Instant::now());
        }
        match result {
            // The transport adds a 16-byte header and 16-byte authentication tag.
            Ok(len) if len > packet::CAPACITY - packet::HEADROOM - 16 => continue,
            Ok(len) => {
                if let Some(packet) = received.as_mut() {
                    packet.start = packet::HEADROOM;
                    packet.len = len;
                }
                let bytes = received.as_ref().map_or(&scratch[..len], Packet::data);
                if let Some(id) = packet::addresses(bytes).and_then(|(_, dst)| routing.lookup(dst))
                {
                    if let Some(mut packet) = received {
                        packet.len = len;
                        routing.peers[id].plain(packet);
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

struct SendWorker {
    #[cfg(feature = "io-profile")]
    id: usize,
    poll: Poll,
    shared: Arc<SharedPeer>,
    endpoint: Option<SocketAddr>,
    wildcards: Arc<[UdpSocket; 2]>,
    sender: Option<TransportSender>,
    pool: Pool,
    stop: Arc<AtomicBool>,
    plain: VecDeque<Packet>,
    network: VecDeque<Packet>,
}
impl SendWorker {
    fn enqueue(&mut self, p: Packet) {
        if self.plain.len() < QUEUE {
            self.plain.push_back(p);
        } else {
            self.shared.drop_packet();
        }
    }
    fn run(&mut self) -> Result<()> {
        let mut events = Events::with_capacity(8);
        let mut handshake_after = Instant::now();
        while !self.stop.load(Ordering::Acquire) {
            self.shared.tx.notified.store(false, Ordering::Release);
            if self.shared.control_pending.swap(false, Ordering::AcqRel) {
                let control = std::mem::take(&mut *self.shared.control.lock().unwrap());
                if let Some(endpoint) = control.endpoint {
                    self.endpoint = Some(endpoint);
                }
                if let Some(sender) = control.sender {
                    self.sender = Some(sender);
                    handshake_after = Instant::now();
                }
                for p in control.packets {
                    if self.network.len() < QUEUE {
                        self.network.push_back(p);
                    } else {
                        self.shared.drop_packet();
                    }
                }
                if control.keepalive
                    && let Some(mut p) = Packet::new(&self.pool)
                {
                    p.start = packet::HEADROOM;
                    self.enqueue(p);
                }
            }
            if self
                .sender
                .as_ref()
                .is_some_and(|s| !s.is_valid_at(Instant::now()))
            {
                self.sender = None;
            }
            while self.plain.len() < QUEUE {
                let Some(p) = self.shared.tx.queue.pop() else {
                    break;
                };
                self.plain.push_back(p);
            }
            let mut activity = Activity::default();
            #[cfg(feature = "io-profile")]
            let encrypt_span =
                crate::platform::profile::Span::new(crate::platform::profile::Stage::Encrypt);
            // Flush between batches instead of draining an unbounded producer.
            for _ in 0..BATCH {
                if self.network.len() == QUEUE || self.endpoint.is_none() {
                    break;
                }
                let Some(mut p) = self.plain.pop_front() else {
                    break;
                };
                let now = Instant::now();
                let result = self
                    .sender
                    .as_mut()
                    .ok_or(boringtun::noise::errors::WireGuardError::NoCurrentSession)
                    .and_then(|s| s.encapsulate_in_place_at(p.len, p.buffer(), now));
                match result {
                    Ok(len) => {
                        activity.sent(p.len, now);
                        p.start = 0;
                        p.len = len;
                        self.network.push_back(p);
                    }
                    Err(boringtun::noise::errors::WireGuardError::NoCurrentSession) => {
                        self.sender = None;
                        self.plain.push_front(p);
                        if now >= handshake_after {
                            self.shared.request_handshake();
                            handshake_after = now + Duration::from_secs(1);
                        }
                        break;
                    }
                    Err(_) => self.shared.drop_packet(),
                }
            }
            #[cfg(feature = "io-profile")]
            drop(encrypt_span);
            if activity.last_packet.is_some() {
                self.shared.activity.lock().unwrap().merge(activity);
            }
            let blocked = self.flush_network();
            #[cfg(feature = "io-profile")]
            crate::platform::profile::report(self.id, Instant::now());
            let can_encrypt =
                self.sender.is_some() && self.endpoint.is_some() && self.network.len() < QUEUE;
            let more = self.shared.control_pending.load(Ordering::Acquire)
                || (!blocked && self.endpoint.is_some() && !self.network.is_empty())
                || (can_encrypt && (!self.plain.is_empty() || !self.shared.tx.queue.is_empty()));
            // The shared IOCP sockets belong to the receive poll. Retry blocked
            // sends with a bounded delay rather than registering them twice.
            let timeout = if more {
                Duration::ZERO
            } else if blocked {
                Duration::from_millis(2)
            } else {
                CONTROL_INTERVAL
            };
            match self.poll.poll(&mut events, Some(timeout)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    /// True when the queue's head must be retried without dropping it.
    fn flush_network(&mut self) -> bool {
        #[cfg(feature = "io-profile")]
        let _span = crate::platform::profile::Span::syscall(false, true);
        let Some(endpoint) = self.endpoint else {
            return false;
        };
        let socket = &self.wildcards[usize::from(endpoint.is_ipv6())];
        for _ in 0..BATCH {
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
                    return true;
                }
                _ => self.shared.drop_packet(),
            }
            self.network.pop_front();
        }
        false
    }
}
struct ReceiveWorker {
    id: usize,
    tunnel: Tunn,
    poll: Poll,
    shared: Arc<SharedPeer>,
    endpoint: Option<SocketAddr>,
    tun: Arc<Tunnel>,
    routing: Arc<Routing>,
    pool: Pool,
    wildcards: Arc<[UdpSocket; 2]>,
    stop: Arc<AtomicBool>,
    private: x25519::StaticSecret,
    public: x25519::PublicKey,
    cipher: Cipher,
    limiter: Arc<RateLimiter>,
    injector: Injector,
    injection: VecDeque<Packet>,
    udp_readable: [bool; 2],
}
impl ReceiveWorker {
    fn output(&self, packet: Packet) {
        self.shared.control(|c| {
            if c.packets.len() < QUEUE {
                c.packets.push_back(packet);
            } else {
                self.shared.drop_packet();
            }
        });
    }
    fn new_endpoint(&mut self, endpoint: SocketAddr) -> io::Result<()> {
        if self.endpoint != Some(endpoint) {
            self.endpoint = Some(endpoint);
            self.shared.control(|c| c.endpoint = Some(endpoint));
        }
        Ok(())
    }
    fn wire(&mut self, mut input: Packet, source: SocketAddr) {
        if input.data().first() == Some(&4) {
            let len = match self
                .tunnel
                .decapsulate_data_in_place_at(input.data_mut(), Instant::now())
            {
                TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                    data.len()
                }
                TunnResult::Done => 0,
                _ => {
                    self.shared.drop_packet();
                    return;
                }
            };
            if self.new_endpoint(source).is_err() {
                self.shared.drop_packet();
                return;
            }
            if len != 0 {
                input.start += packet::HEADROOM;
                input.len = len;
                self.inject(input);
            }
            return;
        }
        let Some(mut output) = Packet::new(&self.pool) else {
            self.shared.drop_packet();
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
                self.shared.drop_packet();
                return;
            }
        };
        if authenticated && self.new_endpoint(source).is_err() {
            self.shared.drop_packet();
            return;
        }
        if len == 0 {
            return;
        }
        output.len = len;
        if inject {
            self.inject(output);
        } else if authenticated {
            self.output(output);
        } else {
            // Unauthenticated cookie replies go only to the requesting address.
            let socket = &self.wildcards[usize::from(source.is_ipv6())];
            let _ = socket.send_to(output.data(), source);
        }
    }
    fn inject(&mut self, packet: Packet) {
        // Validate against the global longest-prefix route before injection.
        if packet::addresses(packet.data())
            .is_some_and(|(src, _)| self.routing.lookup(src) == Some(self.id))
            && self.injection.len() < QUEUE
        {
            self.injection.push_back(packet);
        } else {
            self.shared.drop_packet();
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
                self.routing.peers[id].wire(packet, source);
            }
        } else {
            self.shared.drop_packet();
        }
    }

    fn control(&mut self, snapshot_at: &mut Instant) {
        let now = Instant::now();
        let activity = std::mem::take(&mut *self.shared.activity.lock().unwrap());
        if let Some(last) = activity.last_packet {
            self.tunnel.record_external_send(
                activity.bytes,
                last,
                activity.first_data,
                activity.last_data,
            );
        }
        if let Some(sender) = self.tunnel.take_transport_sender() {
            self.shared.control(|c| c.sender = Some(sender));
        }
        let handshake = self.shared.needs_handshake.swap(false, Ordering::AcqRel);
        let mut scratch = [0; packet::CAPACITY];
        if handshake
            && let TunnResult::WriteToNetwork(data) =
                self.tunnel
                    .format_handshake_initiation_at(&mut scratch, false, now)
            && let Some(mut p) = Packet::new(&self.pool)
        {
            p.len = data.len();
            p.buffer()[..data.len()].copy_from_slice(data);
            self.output(p);
        }
        if self
            .tunnel
            .next_timer_update()
            .is_some_and(|(at, _)| at <= now)
        {
            if let TunnResult::WriteToNetwork(data) =
                self.tunnel.update_timers_at(&mut scratch, now)
                && let Some(mut p) = Packet::new(&self.pool)
            {
                p.len = data.len();
                p.buffer()[..data.len()].copy_from_slice(data);
                self.output(p);
            }
            if self.tunnel.take_external_keepalive() {
                self.shared.control(|c| c.keepalive = true);
            }
        }
        if now >= *snapshot_at {
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
                injection: self.injector.stats,
            };
            *snapshot_at = now + CONTROL_INTERVAL;
        }
    }
    fn receive_windows(&mut self) -> io::Result<bool> {
        let mut scratch = [0; packet::CAPACITY];
        for family in 0..2 {
            if !self.udp_readable[family] {
                continue;
            }
            for _ in 0..BATCH {
                if self.injection.len() == QUEUE {
                    break;
                }
                let mut received = Packet::new(&self.pool);
                let buffer = received.as_mut().map_or(&mut scratch[..], Packet::buffer);
                #[cfg(feature = "io-profile")]
                let span = crate::platform::profile::Span::syscall(false, false);
                let result = self.wildcards[family].recv_from(buffer);
                #[cfg(feature = "io-profile")]
                drop(span);
                match result {
                    Ok((len, source)) => {
                        // Reject full buffers conservatively, including truncation.
                        if len == scratch.len() {
                            self.shared.drop_packet();
                            continue;
                        }
                        if let Some(mut packet) = received {
                            packet.len = len;
                            self.dispatch_wire(packet, source);
                        } else {
                            self.shared.drop_packet();
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.udp_readable[family] = false;
                        break;
                    }
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
                        self.shared.drop_packet();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        // Retain readiness across a fairness-budget boundary, clearing it only
        // after an actual WouldBlock, not after a short batch or pool pressure.
        Ok(self.udp_readable.iter().any(|ready| *ready))
    }

    fn run(&mut self) -> Result<()> {
        let mut events = Events::with_capacity(8);
        let mut snapshot_at = Instant::now();
        while !self.stop.load(Ordering::Acquire) {
            self.shared.rx.notified.store(false, Ordering::Release);
            self.control(&mut snapshot_at);
            if self.id == 0 {
                self.receive_windows()?;
            }
            for _ in 0..BATCH {
                if self.injection.len() == QUEUE {
                    break;
                }
                let Some((p, source)) = self.shared.rx.queue.pop() else {
                    break;
                };
                self.wire(p, source);
            }
            // The receive owner publishes promoted sessions; only TX owns the
            // resulting sender and advances its transport nonce.
            if let Some(sender) = self.tunnel.take_transport_sender() {
                self.shared.control(|c| c.sender = Some(sender));
            }
            #[cfg(feature = "io-profile")]
            let span = crate::platform::profile::Span::syscall(true, true);
            let injection_more = self
                .injector
                .flush(&mut self.injection, |p| self.tun.send(p))?;
            #[cfg(feature = "io-profile")]
            drop(span);
            #[cfg(feature = "io-profile")]
            crate::platform::profile::report(self.id, Instant::now());
            let more = (self.udp_readable.iter().any(|r| *r) && self.injection.len() < QUEUE)
                || (!self.shared.rx.queue.is_empty() && self.injection.len() < QUEUE)
                || injection_more
                || self.shared.needs_handshake.load(Ordering::Acquire);
            let now = Instant::now();
            let deadline = self
                .tunnel
                .next_timer_update()
                .map(|(at, _)| at)
                .unwrap_or(snapshot_at)
                .min(snapshot_at);
            let timeout = if more {
                Duration::ZERO
            } else {
                deadline
                    .saturating_duration_since(now)
                    .min(if self.injection.is_empty() {
                        CONTROL_INTERVAL
                    } else {
                        Duration::from_millis(2)
                    })
            };
            match self.poll.poll(&mut events, Some(timeout)) {
                Ok(()) => {
                    for e in &events {
                        if matches!(e.token(), WILDCARD4 | WILDCARD6)
                            && (e.is_readable() || e.is_read_closed() || e.is_error())
                        {
                            self.udp_readable[usize::from(e.token() == WILDCARD6)] = true;
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
