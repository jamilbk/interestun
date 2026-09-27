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
    let tun = Arc::new(Utun {
        fd: app.into(),
        name: "utun-test".into(),
    });
    #[cfg(windows)]
    let tun = Arc::new(FakeWintun(app));
    (tun, kernel)
}
#[cfg(windows)]
struct FakeWintun(UdpSocket);
#[cfg(windows)]
impl interestun::platform::wintun::PacketIo for FakeWintun {
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
        let rb = Runtime::start(&b, cipher, tun_b).unwrap();
        let rc = Runtime::start(&c, cipher, tun_c).unwrap();
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
        let ra = Runtime::start(&a, cipher, tun_a).unwrap();
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
        #[cfg(target_os = "macos")]
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
        #[cfg(target_os = "macos")]
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
    let runtime = Runtime::start(&config, Cipher::Aes256Gcm, tun).unwrap();
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
    tun_b.blocked.store(false, Ordering::Relaxed);
    let mut buffer = [0; 2048];
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
