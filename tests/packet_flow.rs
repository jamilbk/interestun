#![cfg(all(target_os = "macos", feature = "apple-packet-tunnel"))]
use boringtun::x25519::{PublicKey, StaticSecret};
use interestun::{
    config::{Cipher, Config, Peer},
    platform::{
        Tunnel,
        packet_flow::{Adapter, OutputBatch, WriteBatch},
        udp::Backend,
    },
    runtime::Runtime,
};
use std::{
    net::UdpSocket,
    sync::{Arc, mpsc},
    time::Duration,
};

struct Output(mpsc::SyncSender<Arc<OutputBatch>>);
impl WriteBatch for Output {
    fn write(&self, batch: &Arc<OutputBatch>) -> bool {
        self.0.try_send(batch.clone()).is_ok()
    }
}
fn ip(source: u8, destination: u8) -> Vec<u8> {
    let mut p = vec![0u8; 1420];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&1420u16.to_be_bytes());
    p[12..16].copy_from_slice(&[10, 20, 0, source]);
    p[16..20].copy_from_slice(&[10, 20, 0, destination]);
    for (i, b) in p[20..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    p
}

#[test]
fn callback_adapters_exchange_encrypted_packets_in_both_directions() {
    for cipher in [Cipher::Aes256Gcm, Cipher::Chacha20Poly1305] {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let ports = [
            a.local_addr().unwrap().port(),
            b.local_addr().unwrap().port(),
        ];
        drop((a, b));
        let private = [[41; 32], [42; 32]];
        let public = private.map(|k| *PublicKey::from(&StaticSecret::from(k)).as_bytes());
        let mut runtimes = Vec::new();
        let mut adapters = Vec::new();
        let mut outputs = Vec::new();
        for i in 0..2 {
            let (output, receiver) = mpsc::sync_channel(16);
            let adapter = Arc::new(Adapter::new(1420, Box::new(Output(output))).unwrap());
            let mut config = Config {
                private_key: private[i],
                listen_port: ports[i],
                ..Config::default()
            };
            config.peers.insert(
                public[1 - i],
                Peer {
                    public_key: public[1 - i],
                    endpoint: Some(([127, 0, 0, 1], ports[1 - i]).into()),
                    allowed_ips: vec![format!("10.20.0.{}/32", 2 - i).parse().unwrap()],
                    ..Peer::default()
                },
            );
            let tun = Arc::new(Tunnel::from_packet_flow(
                adapter.clone(),
                format!("flow-{i}"),
            ));
            assert!(tun.io_fd().is_none());
            assert!(!tun.supports_socket_coalescing());
            runtimes
                .push(Runtime::start_with_backend(&config, cipher, tun, Backend::Network).unwrap());
            adapters.push(adapter);
            outputs.push(receiver);
        }
        let outbound = ip(1, 2);
        assert_eq!(
            adapters[0].feed([(outbound.as_slice(), libc::AF_INET as u32)]),
            1
        );
        let retained = outputs[1].recv_timeout(Duration::from_secs(8)).unwrap();
        assert_eq!(retained.packets[0].data(), outbound);
        let inbound = ip(2, 1);
        assert_eq!(
            adapters[1].feed([(inbound.as_slice(), libc::AF_INET as u32)]),
            1
        );
        assert_eq!(
            outputs[0]
                .recv_timeout(Duration::from_secs(8))
                .unwrap()
                .packets[0]
                .data(),
            inbound
        );
        for runtime in &runtimes {
            runtime.housekeeping();
            assert!(!runtime.failed.load(std::sync::atomic::Ordering::Acquire));
        }
        drop(runtimes);
        drop(adapters);
        // Framework-style deferred releases remain valid after both engines stop.
        assert_eq!(retained.packets[0].data(), outbound);
    }
}
