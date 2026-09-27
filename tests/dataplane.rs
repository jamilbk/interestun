#![cfg(target_os = "macos")]
use boringtun::x25519::{PublicKey, StaticSecret};
use interestun::{
    config::{Cipher, Config, Peer},
    platform::utun::Utun,
    runtime::Runtime,
};
use std::{net::UdpSocket, sync::Arc, time::Duration};
fn key(n: u8) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from([n; 32])).as_bytes()
}
fn fake_tun() -> (Arc<Utun>, UdpSocket) {
    let app = UdpSocket::bind("127.0.0.1:0").unwrap();
    let kernel = UdpSocket::bind("127.0.0.1:0").unwrap();
    app.connect(kernel.local_addr().unwrap()).unwrap();
    kernel.connect(app.local_addr().unwrap()).unwrap();
    app.set_nonblocking(true).unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    (
        Arc::new(Utun {
            fd: app.into(),
            name: "utun-test".into(),
        }),
        kernel,
    )
}
fn ip(src: u8, dst: u8, marker: u8) -> Vec<u8> {
    let mut p = vec![0; 32];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&32u16.to_be_bytes());
    p[12..16].copy_from_slice(&[10, 0, 0, src]);
    p[16..20].copy_from_slice(&[10, 0, 0, dst]);
    p[20] = marker;
    [&(libc::AF_INET as u32).to_be_bytes()[..], &p].concat()
}
#[test]
fn two_peers_share_utun_and_use_their_own_workers() {
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
    [&(libc::AF_INET6 as u32).to_be_bytes()[..], &p].concat()
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
        .encapsulate_data_at(&inner[4..], &mut x, Instant::now())
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
        .encapsulate_data_at(&inner[4..], &mut x, Instant::now())
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
