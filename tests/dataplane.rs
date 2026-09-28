#![cfg(any(target_os = "macos", windows))]
use boringtun::x25519::{PublicKey, StaticSecret};
use interestun::{
    config::{Cipher, Config, Peer},
    platform::Tunnel as Utun,
    runtime::Runtime,
};
use std::{net::UdpSocket, sync::Arc, time::Duration};
fn key(n: u8) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from([n; 32])).as_bytes()
}
fn fake_tun() -> (Arc<Utun>, UdpSocket) {
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    let kernel = UdpSocket::bind("127.0.0.1:0").unwrap();
    // The fake adapter must hold concurrent peer bursts; small OS defaults
    // otherwise drop packets before the test's consumer gets scheduled.
    for socket in [&app, &kernel] {
        socket2::SockRef::from(socket)
            .set_recv_buffer_size(1024 * 1024)
            .unwrap();
        socket2::SockRef::from(socket)
            .set_send_buffer_size(1024 * 1024)
            .unwrap();
    }
    app.connect(kernel.local_addr().unwrap()).unwrap();
    kernel.connect(app.local_addr().unwrap()).unwrap();
    app.set_nonblocking(true).unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    #[cfg(target_os = "macos")]
    let tun = Arc::new(Utun::from_fd(app.into(), "utun-test".into()));
    #[cfg(windows)]
    let tun = Arc::new(FakeWintun(app));
    (tun, kernel)
}
#[cfg(windows)]
struct FakeWintun(UdpSocket);
#[cfg(windows)]
impl interestun::platform::wintun::PacketIo for FakeWintun {
    fn tcp_coalescing(&self) -> bool {
        true
    }
    fn name(&self) -> &str {
        "wintun-test"
    }
    fn receive(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buffer)
    }
    fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        self.0.send(packet).map(|_| ())
    }
    fn wait_readable(&self, timeout: Duration) -> std::io::Result<()> {
        std::thread::sleep(timeout.min(Duration::from_millis(1)));
        Ok(())
    }
}
fn payload(packet: &[u8]) -> &[u8] {
    #[cfg(target_os = "macos")]
    {
        &packet[4..]
    }
    #[cfg(windows)]
    {
        packet
    }
}
fn ip(src: u8, dst: u8, marker: u8) -> Vec<u8> {
    let mut p = vec![0; 32];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&32u16.to_be_bytes());
    p[12..16].copy_from_slice(&[10, 0, 0, src]);
    p[16..20].copy_from_slice(&[10, 0, 0, dst]);
    p[20] = marker;
    #[cfg(target_os = "macos")]
    {
        [&(libc::AF_INET as u32).to_be_bytes()[..], &p].concat()
    }
    #[cfg(windows)]
    {
        p
    }
}
#[test]
fn two_peers_share_adapter_and_use_their_own_workers() {
    exercise_two_peers(bsd_fixture);
}

fn bsd_fixture(config: &Config, cipher: Cipher, tun: Arc<Utun>) -> anyhow::Result<Runtime> {
    #[cfg(target_os = "macos")]
    {
        Runtime::start_with_backend(config, cipher, tun, interestun::platform::udp::Backend::Bsd)
    }
    #[cfg(windows)]
    {
        Runtime::start(config, cipher, tun)
    }
}

#[cfg(all(target_os = "macos", feature = "apple-network"))]
#[test]
fn network_framework_configured_peers_against_wireguard_fixtures() {
    exercise_two_peers(|config, cipher, tun| {
        Runtime::start_with_backend(
            config,
            cipher,
            tun,
            if config.private_key == [1; 32] {
                interestun::platform::udp::Backend::Network
            } else {
                interestun::platform::udp::Backend::Bsd
            },
        )
    });
}

#[cfg(all(target_os = "macos", feature = "apple-network"))]
#[test]
fn network_framework_rejects_unknown_endpoint_without_fallback() {
    let (tun, _kernel) = fake_tun();
    let mut config = Config {
        private_key: [1; 32],
        ..Config::default()
    };
    config.peers.insert(
        key(2),
        Peer {
            public_key: key(2),
            ..Peer::default()
        },
    );
    let error = match Runtime::start(&config, Cipher::Aes256Gcm, tun) {
        Ok(_) => panic!("Network.framework unexpectedly accepted an unknown endpoint"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("requires a configured endpoint"));
}

fn exercise_two_peers(start: fn(&Config, Cipher, Arc<Utun>) -> anyhow::Result<Runtime>) {
    for cipher in [Cipher::Aes256Gcm, Cipher::Chacha20Poly1305] {
        let (tun_a, kernel_a) = fake_tun();
        let (tun_b, kernel_b) = fake_tun();
        let (tun_c, kernel_c) = fake_tun();
        let peer_a = Peer {
            public_key: key(1),
            allowed_ips: vec![
                "10.0.0.1/32".parse().unwrap(),
                "fd00::1/128".parse().unwrap(),
            ],
            ..Peer::default()
        };
        let mut b = Config {
            private_key: [2; 32],
            ..Config::default()
        };
        b.peers.insert(key(1), peer_a.clone());
        let mut c = Config {
            private_key: [3; 32],
            ..Config::default()
        };
        c.peers.insert(key(1), peer_a);
        let rb = start(&b, cipher, tun_b).unwrap();
        let rc = start(&c, cipher, tun_c).unwrap();
        let mut a = Config {
            private_key: [1; 32],
            ..Config::default()
        };
        for (n, port) in [(2, rb.port), (3, rc.port)] {
            a.peers.insert(
                key(n),
                Peer {
                    public_key: key(n),
                    endpoint: Some(if n == 2 {
                        ([127, 0, 0, 1], port).into()
                    } else {
                        (std::net::Ipv6Addr::LOCALHOST, port).into()
                    }),
                    allowed_ips: vec![
                        if n == 2 {
                            "10.0.0.0/24".parse().unwrap()
                        } else {
                            format!("10.0.0.{n}/32").parse().unwrap()
                        },
                        format!("fd00::{n}/128").parse().unwrap(),
                    ],
                    ..Peer::default()
                },
            );
        }
        let ra = start(&a, cipher, tun_a).unwrap();
        assert_eq!(ra.peers.len(), 2);
        let mut output = [0u8; 2048];
        for (n, kernel) in [(2, &kernel_b), (3, &kernel_c)] {
            let sent = ip(1, n, n);
            kernel_a.send(&sent).unwrap();
            let len = kernel.recv(&mut output).unwrap();
            assert_eq!(&output[..len], sent);
            let sent = ip(n, 1, n + 10);
            kernel.send(&sent).unwrap();
            let len = kernel_a.recv(&mut output).unwrap();
            assert_eq!(&output[..len], sent);
        }
        for (n, kernel) in [(2, &kernel_b), (3, &kernel_c)] {
            let sent = ip6(1, n);
            kernel_a.send(&sent).unwrap();
            let len = kernel.recv(&mut output).unwrap();
            assert_eq!(&output[..len], sent);
            let sent = ip6(n, 1);
            kernel.send(&sent).unwrap();
            let len = kernel_a.recv(&mut output).unwrap();
            assert_eq!(&output[..len], sent);
        }
        // More than one worker drain budget, followed by idle and a fresh edge.
        // Exercise both the dispatcher-owned flow and the other peer's worker.
        for round in 0..2 {
            for (n, kernel) in [(2, &kernel_b), (3, &kernel_c)] {
                for marker in 0..192 {
                    kernel_a.send(&ip(1, n, marker)).unwrap();
                }
                for marker in 0..192 {
                    let len = kernel.recv(&mut output).unwrap();
                    assert_eq!(&output[..len], ip(1, n, marker));
                }
                for marker in 0..192 {
                    kernel.send(&ip(n, 1, marker)).unwrap();
                }
                for marker in 0..192 {
                    let len = kernel_a.recv(&mut output).unwrap();
                    assert_eq!(&output[..len], ip(n, 1, marker));
                }
            }
            if round == 0 {
                std::thread::sleep(Duration::from_millis(300));
            }
        }
        // Concurrent duplex traffic through both peers. Bounded rounds keep
        // the fake UDP adapter below its receive capacity; scoped joins also
        // let a socket timeout fail the test rather than deadlock a barrier.
        for round in 0..8 {
            std::thread::scope(|scope| {
                for (n, kernel) in [(2, &kernel_b), (3, &kernel_c)] {
                    scope.spawn(move || {
                        let mut out = [0; 2048];
                        for marker in round * 16..(round + 1) * 16 {
                            kernel.send(&ip(n, 1, marker)).unwrap();
                        }
                        for marker in round * 16..(round + 1) * 16 {
                            let len = kernel.recv(&mut out).unwrap();
                            assert_eq!(&out[..len], ip(1, n, marker));
                        }
                    });
                }
                for marker in round * 16..(round + 1) * 16 {
                    kernel_a.send(&ip(1, 2, marker)).unwrap();
                    kernel_a.send(&ip(1, 3, marker)).unwrap();
                }
                let mut seen = std::collections::BTreeSet::new();
                for _ in 0..32 {
                    let len = kernel_a.recv(&mut output).unwrap_or_else(|e| {
                        eprintln!("round={round} seen={seen:?}");
                        for (name, runtime) in [("a", &ra), ("b", &rb), ("c", &rc)] {
                            for (key, peer) in &runtime.peers {
                                let stats = peer.stats.lock().unwrap();
                                eprintln!(
                                    "{name} key={} drops={} tx={} rx={}",
                                    key[0],
                                    peer.drops.load(std::sync::atomic::Ordering::Relaxed),
                                    stats.tx,
                                    stats.rx
                                );
                            }
                        }
                        panic!("{e}")
                    });
                    let p = payload(&output[..len]);
                    assert!((round * 16..(round + 1) * 16).contains(&p[20]));
                    assert!(seen.insert((p[15], p[20])));
                }
                assert_eq!(seen.len(), 32);
            });
        }
        // Maximum configured MTU must leave room for both the in-place header
        // and tag, and expose only plaintext again after decryption.
        for (n, kernel) in [(2, &kernel_b), (3, &kernel_c)] {
            for reverse in [false, true] {
                let (src, dst, send, recv) = if reverse {
                    (n, 1, kernel, &kernel_a)
                } else {
                    (1, n, &kernel_a, kernel)
                };
                let mut sent = ip(src, dst, 77);
                let prefix = sent.len() - payload(&sent).len();
                sent.resize(prefix + 2000, 0x5a);
                sent[prefix + 2..prefix + 4].copy_from_slice(&2000u16.to_be_bytes());
                send.send(&sent).unwrap();
                let len = recv.recv(&mut output).unwrap();
                assert_eq!(&output[..len], sent);
            }
        }
        #[cfg(windows)]
        {
            // An oversized but otherwise valid IP packet must not be truncated
            // into the reserved tag space or kill the Wintun reader.
            let mut oversized = ip(1, 2, 88);
            oversized.resize(2017, 0);
            oversized[2..4].copy_from_slice(&2017u16.to_be_bytes());
            kernel_a.send(&oversized).unwrap();
            let sent = ip(1, 2, 89);
            kernel_a.send(&sent).unwrap();
            let len = kernel_b.recv(&mut output).unwrap();
            assert_eq!(&output[..len], sent);
        }
        // Authenticated peer B is not allowed to inject peer C's source address.
        kernel_a
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        kernel_b.send(&ip(3, 1, 99)).unwrap();
        assert!(kernel_a.recv(&mut output).is_err());
        assert!(!ra.failed.load(std::sync::atomic::Ordering::Acquire));
        drop((ra, rb, rc));
    }
}

fn ip6(src: u8, dst: u8) -> Vec<u8> {
    let mut p = vec![0; 52];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&12u16.to_be_bytes());
    p[8..24].copy_from_slice(
        &format!("fd00::{src}")
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    p[24..40].copy_from_slice(
        &format!("fd00::{dst}")
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    #[cfg(target_os = "macos")]
    {
        [&(libc::AF_INET6 as u32).to_be_bytes()[..], &p].concat()
    }
    #[cfg(windows)]
    {
        p
    }
}

#[test]
fn only_authenticated_packets_roam_the_udp_endpoint() {
    exercise_roaming(bsd_fixture);
}

fn exercise_roaming(start: fn(&Config, Cipher, Arc<Utun>) -> anyhow::Result<Runtime>) {
    use boringtun::noise::{Index, Tunn, TunnResult, cipher::CipherSuite};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};
    let (tun, kernel) = fake_tun();
    let mut config = Config {
        private_key: [2; 32],
        ..Config::default()
    };
    config.peers.insert(
        key(1),
        Peer {
            public_key: key(1),
            allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
            ..Peer::default()
        },
    );
    let runtime = start(&config, Cipher::Aes256Gcm, tun).unwrap();
    let socket = || {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.connect((std::net::Ipv4Addr::LOCALHOST, runtime.port))
            .unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s
    };
    let old = socket();
    let new = socket();
    let now = Instant::now();
    let mut peer = Tunn::new_with_cipher_at(
        StaticSecret::from([1; 32]),
        PublicKey::from(key(2)),
        None,
        None,
        Index::new_local(9),
        None,
        1,
        now,
        now,
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
        CipherSuite::Aes256Gcm,
    );
    let mut x = [0; 2048];
    let mut y = [0; 2048];
    let init = match peer.format_handshake_initiation_at(&mut x, false, Instant::now()) {
        TunnResult::WriteToNetwork(p) => p,
        r => panic!("{r:?}"),
    };
    old.send(init).unwrap();
    let n = old.recv(&mut y).unwrap();
    let confirm = match peer.decapsulate_at(
        Some("127.0.0.1".parse().unwrap()),
        &y[..n],
        &mut x,
        Instant::now(),
    ) {
        TunnResult::WriteToNetwork(p) => p,
        r => panic!("{r:?}"),
    };
    old.send(confirm).unwrap();
    // A data packet on the new port with a corrupt tag must not move the endpoint.
    let inner = ip(1, 2, 41);
    let n = peer
        .encapsulate_data_at(payload(&inner), &mut x, Instant::now())
        .unwrap();
    let valid = x[..n].to_vec();
    x[n - 1] ^= 1;
    new.send(&x[..n]).unwrap();
    // A valid packet through the old endpoint provides a processing barrier.
    old.send(&valid).unwrap();
    let n = kernel.recv(&mut y).unwrap();
    assert_eq!(&y[..n], inner);
    kernel.send(&ip(2, 1, 42)).unwrap();
    let n = old.recv(&mut y).unwrap();
    assert!(matches!(
        peer.decapsulate_at(None, &y[..n], &mut x, Instant::now()),
        TunnResult::WriteToTunnelV4(_, _)
    ));
    let inner = ip(1, 2, 43);
    let n = peer
        .encapsulate_data_at(payload(&inner), &mut x, Instant::now())
        .unwrap();
    new.send(&x[..n]).unwrap();
    let n = kernel.recv(&mut y).unwrap();
    assert_eq!(&y[..n], inner);
    kernel.send(&ip(2, 1, 44)).unwrap();
    let n = new.recv(&mut y).unwrap();
    assert!(matches!(
        peer.decapsulate_at(None, &y[..n], &mut x, Instant::now()),
        TunnResult::WriteToTunnelV4(_, _)
    ));
    drop(runtime);
}

#[cfg(windows)]
#[test]
fn windows_ring_backpressure_oversized_udp_and_shutdown() {
    use interestun::platform::wintun::PacketIo;
    use std::{
        io,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        time::Instant,
    };
    struct Congested {
        inner: Arc<Utun>,
        blocked: AtomicBool,
        failed: AtomicBool,
        attempts: AtomicUsize,
    }
    impl PacketIo for Congested {
        fn name(&self) -> &str {
            "congested"
        }
        fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.failed.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            self.inner.receive(buffer)
        }
        fn send(&self, packet: &[u8]) -> io::Result<()> {
            if self.blocked.load(Ordering::Relaxed) {
                self.attempts.fetch_add(1, Ordering::Relaxed);
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.inner.send(packet)
        }
        fn wait_readable(&self, timeout: Duration) -> io::Result<()> {
            self.inner.wait_readable(timeout)
        }
    }
    let (tun_a, kernel_a) = fake_tun();
    let (tun_b, kernel_b) = fake_tun();
    let tun_b = Arc::new(Congested {
        inner: tun_b,
        blocked: AtomicBool::new(true),
        failed: AtomicBool::new(false),
        attempts: AtomicUsize::new(0),
    });
    let mut b = Config {
        private_key: [2; 32],
        ..Config::default()
    };
    b.peers.insert(
        key(1),
        Peer {
            public_key: key(1),
            allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
            ..Peer::default()
        },
    );
    let mut rb = Runtime::start(&b, Cipher::Aes256Gcm, tun_b.clone()).unwrap();
    // A second runtime cannot share/steal a Windows listener's bound port.
    b.listen_port = rb.port;
    assert!(Runtime::start(&b, Cipher::Aes256Gcm, tun_b.clone()).is_err());
    let mut a = Config {
        private_key: [1; 32],
        ..Config::default()
    };
    a.peers.insert(
        key(2),
        Peer {
            public_key: key(2),
            endpoint: Some(([127, 0, 0, 1], rb.port).into()),
            allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
            ..Peer::default()
        },
    );
    let mut ra = Runtime::start(&a, Cipher::Aes256Gcm, tun_a).unwrap();
    let junk = UdpSocket::bind("127.0.0.1:0").unwrap();
    junk.send_to(&[0; 8192], ("127.0.0.1", rb.port)).unwrap();
    for marker in 0..20 {
        kernel_a.send(&ip(1, 2, marker)).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while tun_b.attempts.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    // Receive-side adapter pressure must not prevent the independent sender
    // from encrypting and delivering traffic in the opposite direction.
    let mut buffer = [0; 2048];
    for marker in 0..20 {
        kernel_b.send(&ip(2, 1, marker)).unwrap();
    }
    for marker in 0..20 {
        let len = kernel_a.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], ip(2, 1, marker));
    }
    assert!(tun_b.blocked.load(Ordering::Relaxed));
    tun_b.blocked.store(false, Ordering::Relaxed);
    for marker in 0..20 {
        let len = kernel_b.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], ip(1, 2, marker));
    }
    // A fatal adapter failure is surfaced to control/housekeeping.
    tun_b.failed.store(true, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !rb.failed.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    let start = Instant::now();
    ra.stop();
    rb.stop();
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[cfg(windows)]
#[test]
fn encrypted_tcp_burst_coalesces_after_ring_pressure_without_losing_bytes() {
    use interestun::platform::wintun::PacketIo;
    use std::{
        io,
        sync::atomic::{AtomicBool, Ordering},
        time::Instant,
    };
    struct Gated {
        inner: Arc<Utun>,
        blocked: AtomicBool,
    }
    impl PacketIo for Gated {
        fn tcp_coalescing(&self) -> bool {
            true
        }
        fn name(&self) -> &str {
            "gated"
        }
        fn receive(&self, p: &mut [u8]) -> io::Result<usize> {
            self.inner.receive(p)
        }
        fn send(&self, p: &[u8]) -> io::Result<()> {
            if self.blocked.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.inner.send(p)
        }
        fn wait_readable(&self, d: Duration) -> io::Result<()> {
            self.inner.wait_readable(d)
        }
    }
    fn sum(bytes: &[u8]) -> u32 {
        bytes
            .chunks(2)
            .map(|b| ((b[0] as u32) << 8) + b.get(1).copied().unwrap_or(0) as u32)
            .sum()
    }
    fn finish(mut value: u32) -> u16 {
        while value > 65535 {
            value = (value & 65535) + (value >> 16);
        }
        !(value as u16)
    }
    let (tun_a, kernel_a) = fake_tun();
    let (tun_b, kernel_b) = fake_tun();
    let gated = Arc::new(Gated {
        inner: tun_b,
        blocked: AtomicBool::new(true),
    });
    let mut b = Config {
        private_key: [2; 32],
        ..Config::default()
    };
    b.peers.insert(
        key(1),
        Peer {
            public_key: key(1),
            allowed_ips: vec!["10.0.0.1/32".parse().unwrap()],
            ..Peer::default()
        },
    );
    let rb = Runtime::start(&b, Cipher::Aes256Gcm, gated.clone()).unwrap();
    let mut a = Config {
        private_key: [1; 32],
        ..Config::default()
    };
    a.peers.insert(
        key(2),
        Peer {
            public_key: key(2),
            endpoint: Some(([127, 0, 0, 1], rb.port).into()),
            allowed_ips: vec!["10.0.0.2/32".parse().unwrap()],
            ..Peer::default()
        },
    );
    let _ra = Runtime::start(&a, Cipher::Aes256Gcm, tun_a).unwrap();
    for i in 0..32u32 {
        let mut p = vec![0; 1040];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&1040u16.to_be_bytes());
        p[6] = 0x40;
        p[8] = 64;
        p[9] = 6;
        p[12..20].copy_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        p[20..24].copy_from_slice(&[0x12, 0x34, 0x14, 0x51]);
        p[24..28].copy_from_slice(&(i * 1000).to_be_bytes());
        p[31] = 1;
        p[32] = 0x50;
        p[33] = if i == 31 { 0x18 } else { 0x10 };
        p[34] = 0x80;
        p[40..].fill(i as u8);
        let check = finish(sum(&p[..20]));
        p[10..12].copy_from_slice(&check.to_be_bytes());
        let check = finish(sum(&p[12..20]) + 6 + 1020 + sum(&p[20..]));
        p[36..38].copy_from_slice(&check.to_be_bytes());
        kernel_a.send(&p).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while rb.peers[&key(1)].stats.lock().unwrap().rx < 32 * 1040 {
        assert!(Instant::now() < deadline, "burst not received/decrypted");
        std::thread::sleep(Duration::from_millis(5));
    }
    gated.blocked.store(false, Ordering::Relaxed);
    let mut buf = [0; 65535];
    let mut stream = Vec::new();
    let mut writes = 0;
    while stream.len() < 32000 {
        let n = kernel_b.recv(&mut buf).unwrap();
        let p = &buf[..n];
        assert_eq!(u16::from_be_bytes([p[2], p[3]]) as usize, n);
        assert_eq!(finish(sum(&p[..20])), 0);
        assert_eq!(
            finish(sum(&p[12..20]) + 6 + (n - 20) as u32 + sum(&p[20..])),
            0
        );
        assert_eq!(
            u32::from_be_bytes(p[24..28].try_into().unwrap()) as usize,
            stream.len()
        );
        stream.extend_from_slice(&p[40..]);
        writes += 1;
    }
    let expected: Vec<u8> = (0..32u8)
        .flat_map(|i| std::iter::repeat_n(i, 1000))
        .collect();
    assert_eq!(stream, expected);
    assert!(writes < 32, "coalescing must reduce adapter writes");
}
