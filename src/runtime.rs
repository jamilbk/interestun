use crate::platform::readiness::{Events, Interest, Poll, Token, Waker};
use crate::{
    config::{Cipher, Config},
    packet::{self, BATCH, Packet, Pool},
    platform::{
        Tunnel,
        batch::{self, Receiver},
        udp::{Backend, PeerSocket, bind as bind_udp},
    },
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
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const QUEUE: usize = 256;
const UDP: Token = Token(1);
const TUN: Token = Token(2);
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
            waker: Waker::new(poll, WAKE)?,
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
    socket: Option<Arc<PeerSocket>>,
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
    pub tx_queue_drops: AtomicU64,
    // Network.framework uses a fixed configured endpoint. This weak reference
    // exposes diagnostics without extending the connection's worker lifetime.
    #[cfg(all(target_os = "macos", feature = "apple-packet-tunnel"))]
    pub network_socket: Option<std::sync::Weak<PeerSocket>>,
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
    _wildcards: Arc<Vec<UdpSocket>>,
}
fn register(poll: &Poll, fd: i32, token: Token, interest: Interest) -> io::Result<()> {
    poll.register(fd, token, interest)
}

impl Runtime {
    pub fn start(config: &Config, cipher: Cipher, tun: Arc<Tunnel>) -> Result<Self> {
        Self::start_with_backend(config, cipher, tun, Backend::default())
    }
    pub fn start_with_backend(
        config: &Config,
        cipher: Cipher,
        tun: Arc<Tunnel>,
        backend: Backend,
    ) -> Result<Self> {
        let (port, wildcards) = match backend {
            Backend::Bsd => {
                let v4 = bind_udp(([0, 0, 0, 0], config.listen_port).into(), None)?;
                let port = v4.local_addr()?.port();
                let v6 = bind_udp((std::net::Ipv6Addr::UNSPECIFIED, port).into(), None)?;
                (port, vec![v4, v6])
            }
            #[cfg(feature = "apple-network")]
            Backend::Network => {
                anyhow::ensure!(
                    config.private_key == [0; 32]
                        || config.peers.values().all(|peer| peer.endpoint.is_some()),
                    "Network.framework experiment requires a configured endpoint for every peer"
                );
                (config.listen_port, Vec::new())
            }
        };
        let wildcards = Arc::new(wildcards);
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
                let socket = peer
                    .endpoint
                    .map(|e| {
                        PeerSocket::connect(
                            backend,
                            port,
                            e,
                            Waker::new(&rx_poll, UDP)?,
                            Waker::new(&tx_poll, UDP)?,
                        )
                        .map(Arc::new)
                    })
                    .transpose()?;
                if let Some(s) = &socket {
                    s.register_rx(&rx_poll, UDP)?;
                }
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
                    tx_queue_drops: AtomicU64::new(0),
                    #[cfg(all(target_os = "macos", feature = "apple-packet-tunnel"))]
                    network_socket: socket
                        .as_ref()
                        .filter(|s| s.is_network())
                        .map(Arc::downgrade),
                });
                peers.insert(*key, shared.clone());
                prepared.push((peer.clone(), rx_poll, tx_poll, shared, socket));
            }
        }
        let mut routing = Routing {
            routes: ip_network_table::IpNetworkTable::new(),
            keys: BTreeMap::new(),
            peers: Vec::new(),
        };
        for (id, (peer, _, _, shared, _)) in prepared.iter().enumerate() {
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
        let injection_gate = (routing.peers.len() > 1).then(|| Arc::new(Mutex::new(())));
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
        for (id, (peer, rx_poll, tx_poll, shared, socket)) in prepared.into_iter().enumerate() {
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
                id,
                poll: tx_poll,
                shared: shared.clone(),
                socket: socket.clone(),
                sender: None,
                tun: tun.clone(),
                routing: routing.clone(),
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
                socket,
                endpoint: peer.endpoint,
                port,
                backend,
                tun: tun.clone(),
                routing: routing.clone(),
                pool: pool.clone(),
                wildcards: wildcards.clone(),
                stop: stop.clone(),
                private: private.clone(),
                public,
                cipher,
                limiter: limiter.clone(),
                injection_gate: injection_gate.clone(),
                injection: VecDeque::with_capacity(QUEUE),
                readable: [false; 5],
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

struct SendWorker {
    id: usize,
    poll: Poll,
    shared: Arc<SharedPeer>,
    socket: Option<Arc<PeerSocket>>,
    sender: Option<TransportSender>,
    tun: Arc<Tunnel>,
    routing: Arc<Routing>,
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
            self.shared.tx_queue_drops.fetch_add(1, Ordering::Relaxed);
            self.shared.drop_packet();
        }
    }
    fn can_read_tun(&self) -> bool {
        // With one peer every packet goes into this queue. Reserve room for a
        // complete read before draining utun, and retain readiness while paused.
        // A shared dispatcher still drains for other peers when its own peer
        // is congested; those per-peer queues retain their existing drop policy.
        self.routing.peers.len() > 1 || self.plain.len() <= QUEUE - BATCH
    }
    fn run(&mut self) -> Result<()> {
        let mut receiver = Receiver::new(self.pool.clone());
        let tun = self.tun.clone();
        let mut writer = batch::Sender::new();
        let mut events = Events::with_capacity(8);
        let mut readable = self.id == 0;
        let mut blocked = false;
        let mut registered = false;
        let mut handshake_after = Instant::now();
        if self.id == 0 {
            self.tun.register_readable(&self.poll, TUN)?;
        }
        while !self.stop.load(Ordering::Acquire) {
            self.shared.tx.notified.store(false, Ordering::Release);
            if self.shared.control_pending.swap(false, Ordering::AcqRel) {
                let control = std::mem::take(&mut *self.shared.control.lock().unwrap());
                if let Some(socket) = control.socket {
                    if registered {
                        self.socket.as_ref().unwrap().deregister_tx(&self.poll)?;
                        registered = false;
                    }
                    self.socket = Some(socket);
                    blocked = false;
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
            if readable && self.can_read_tun() {
                match tun.receive(&mut receiver, |r| {
                    if let Some(id) = packet::addresses(r.packet.data())
                        .and_then(|(_, dst)| self.routing.lookup(dst))
                    {
                        if id == self.id {
                            self.enqueue(r.packet);
                        } else {
                            self.routing.peers[id].plain(r.packet);
                        }
                    } else {
                        self.shared.drop_packet();
                    }
                }) {
                    Ok(0) => anyhow::bail!("utun closed"),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => readable = false,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::OutOfMemory
                        ) => {}
                    Err(e) => return Err(e.into()),
                }
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
                if self.network.len() == QUEUE || self.socket.is_none() {
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
            if !blocked && let Some(socket) = &self.socket {
                match socket.flush(&mut writer, &mut self.network) {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => blocked = true,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if socket.is_network() => return Err(e.into()),
                    Err(_) => {
                        // flush already discarded the ambiguous attempted prefix.
                        self.shared.drop_packet();
                    }
                }
            }
            if let Some(socket) = &self.socket {
                if blocked && !registered {
                    socket.register_tx(&self.poll, UDP)?;
                    registered = true;
                } else if !blocked && registered {
                    socket.deregister_tx(&self.poll)?;
                    registered = false;
                }
            }
            #[cfg(feature = "io-metrics")]
            batch::report_metrics(self.id, Instant::now());
            let can_encrypt =
                self.sender.is_some() && self.socket.is_some() && self.network.len() < QUEUE;
            let more = self.shared.control_pending.load(Ordering::Acquire)
                || (!blocked && self.socket.is_some() && !self.network.is_empty())
                || (can_encrypt && (!self.plain.is_empty() || !self.shared.tx.queue.is_empty()))
                || (readable && self.can_read_tun());
            // A bounded retry handles temporary global pool exhaustion without
            // sleeping forever on an edge that was already consumed.
            #[cfg(feature = "io-profile")]
            let poll_span =
                crate::platform::profile::Span::new(crate::platform::profile::Stage::Poll);
            let result = self.poll.poll_active(
                &mut events,
                Some(if more {
                    Duration::ZERO
                } else {
                    CONTROL_INTERVAL
                }),
            );
            #[cfg(feature = "io-profile")]
            drop(poll_span);
            match result {
                Ok(()) => {
                    #[cfg(all(feature = "io-metrics", feature = "apple-network"))]
                    crate::platform::network::metrics::poll(!more, &events, UDP);
                    for e in &events {
                        if e.token() == TUN
                            && (e.is_readable() || e.is_error() || e.is_read_closed())
                        {
                            readable = true;
                        }
                        if e.token() == UDP
                            && (e.is_writable()
                                || e.is_readable()
                                || e.is_error()
                                || e.is_write_closed()
                                || e.is_read_closed())
                        {
                            blocked = false;
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
struct ReceiveWorker {
    id: usize,
    tunnel: Tunn,
    poll: Poll,
    shared: Arc<SharedPeer>,
    socket: Option<Arc<PeerSocket>>,
    endpoint: Option<SocketAddr>,
    port: u16,
    backend: Backend,
    tun: Arc<Tunnel>,
    routing: Arc<Routing>,
    pool: Pool,
    wildcards: Arc<Vec<UdpSocket>>,
    stop: Arc<AtomicBool>,
    private: x25519::StaticSecret,
    public: x25519::PublicKey,
    cipher: Cipher,
    limiter: Arc<RateLimiter>,
    // XNU sendmsg_x can misreport progress on nonblocking send-lock
    // contention. Serialize shared-fd writes, never cryptographic work.
    injection_gate: Option<Arc<Mutex<()>>>,
    injection: VecDeque<Packet>,
    readable: [bool; 5],
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
        if self.endpoint == Some(endpoint) && self.socket.is_some() {
            return Ok(());
        }
        let socket = Arc::new(PeerSocket::connect(
            self.backend,
            self.port,
            endpoint,
            Waker::new(&self.poll, UDP)?,
            self.shared.tx.waker.with_token(UDP),
        )?);
        socket.register_rx(&self.poll, UDP)?;
        if let Some(old) = &self.socket {
            old.deregister_rx(&self.poll)?;
        }
        self.socket = Some(socket.clone());
        self.endpoint = Some(endpoint);
        self.readable[UDP.0] = true;
        self.shared.control(|c| c.socket = Some(socket));
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
            if let Some(socket) = self.wildcards.get(usize::from(source.is_ipv6())) {
                let _ = socket.send_to(output.data(), source);
            } else {
                // In the Network.framework experiment, connected callbacks
                // can only deliver the already configured peer endpoint.
                self.output(output);
            }
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
            };
            *snapshot_at = now + CONTROL_INTERVAL;
        }
    }
    fn run(&mut self) -> Result<()> {
        if self.id == 0 {
            for (s, t) in self.wildcards.iter().zip([WILDCARD4, WILDCARD6]) {
                register(&self.poll, s.as_raw_fd(), t, Interest::READABLE)?;
                self.readable[t.0] = true;
            }
        }
        self.readable[UDP.0] = self.socket.is_some();
        let mut receiver = Receiver::new(self.pool.clone());
        let mut writer = batch::Sender::new();
        #[cfg(feature = "apple-coalesce")]
        // Preserve original packets for adapters using rings or packet objects.
        let mut coalescer = self
            .tun
            .supports_socket_coalescing()
            .then(crate::platform::coalesce_macos::Coalescer::default);
        let mut events = Events::with_capacity(8);
        let mut snapshot_at = Instant::now();
        let mut blocked = false;
        let mut registered = false;
        while !self.stop.load(Ordering::Acquire) {
            self.shared.rx.notified.store(false, Ordering::Release);
            self.control(&mut snapshot_at);
            for token in [UDP, WILDCARD4, WILDCARD6] {
                if !self.readable[token.0] || self.injection.len() > QUEUE - BATCH {
                    continue;
                }
                let connected = self.socket.clone();
                let socket = if token == UDP {
                    connected.as_ref().map(|s| s.rx_fd())
                } else {
                    self.wildcards
                        .get(usize::from(token == WILDCARD6))
                        .map(|s| s.as_raw_fd())
                };
                let Some(fd) = socket else {
                    continue;
                };
                let pool = self.pool.clone();
                let consume = |r: batch::Received| {
                    if let Some(source) = r.source {
                        if token == UDP {
                            self.wire(r.packet, source);
                        } else {
                            self.dispatch_wire(r.packet, source);
                        }
                    }
                };
                let result = if token == UDP {
                    connected
                        .as_ref()
                        .unwrap()
                        .receive(&mut receiver, &pool, consume)
                } else {
                    receiver.receive(fd, false, consume)
                };
                match result {
                    Ok(0) => self.readable[token.0] = false,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        // A roaming update may have installed a different fd during dispatch.
                        if token != UDP || self.socket.as_ref().map(|s| s.rx_fd()) == Some(fd) {
                            self.readable[token.0] = false;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::OutOfMemory
                        ) => {}
                    Err(e)
                        if token == UDP && connected.as_ref().is_some_and(|s| s.is_network()) =>
                    {
                        return Err(e.into());
                    }
                    Err(_) => {
                        self.shared.drop_packet();
                    }
                }
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
            // Publish newly established/promoted transmit sessions before sleeping.
            if let Some(sender) = self.tunnel.take_transport_sender() {
                self.shared.control(|c| c.sender = Some(sender));
            }
            if !blocked && !self.injection.is_empty() {
                let _guard = self
                    .injection_gate
                    .as_ref()
                    .map(|gate| gate.lock().unwrap());
                #[cfg(feature = "apple-coalesce")]
                let result = match &mut coalescer {
                    Some(coalescer) => coalescer.flush(
                        &mut writer,
                        self.tun
                            .io_fd()
                            .expect("socket coalescer requires a descriptor"),
                        &mut self.injection,
                    ),
                    None => self.tun.flush(&mut writer, &mut self.injection),
                };
                #[cfg(not(feature = "apple-coalesce"))]
                let result = self.tun.flush(&mut writer, &mut self.injection);
                match result {
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => blocked = true,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e.into()),
                }
            }
            if blocked && !registered {
                let fd = self.tun.io_fd().context(
                    "callback adapter returned WouldBlock without a writable notification",
                )?;
                register(&self.poll, fd, TUN, Interest::WRITABLE)?;
                registered = true;
            } else if !blocked && registered {
                self.poll.deregister(
                    self.tun
                        .io_fd()
                        .context("missing registered adapter descriptor")?,
                    Interest::WRITABLE,
                )?;
                registered = false;
            }
            #[cfg(feature = "io-metrics")]
            batch::report_metrics(self.id, Instant::now());
            let more = (self.readable.iter().any(|r| *r) && self.injection.len() <= QUEUE - BATCH)
                || (!self.shared.rx.queue.is_empty() && self.injection.len() < QUEUE)
                || (!blocked && !self.injection.is_empty())
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
                    .min(CONTROL_INTERVAL)
            };
            #[cfg(feature = "io-profile")]
            let poll_span =
                crate::platform::profile::Span::new(crate::platform::profile::Stage::Poll);
            let result = self.poll.poll_active(&mut events, Some(timeout));
            #[cfg(feature = "io-profile")]
            drop(poll_span);
            match result {
                Ok(()) => {
                    #[cfg(all(feature = "io-metrics", feature = "apple-network"))]
                    crate::platform::network::metrics::poll(!timeout.is_zero(), &events, UDP);
                    for e in &events {
                        if matches!(e.token(), UDP | WILDCARD4 | WILDCARD6)
                            && (e.is_readable() || e.is_read_closed() || e.is_error())
                        {
                            self.readable[e.token().0] = true;
                        }
                        if e.token() == TUN
                            && (e.is_writable() || e.is_write_closed() || e.is_error())
                        {
                            blocked = false;
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
