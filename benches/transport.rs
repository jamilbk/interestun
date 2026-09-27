//! CSV benchmark: a full Tunn seal/open roundtrip, excluding key setup and socket I/O.
use boringtun::{
    noise::{Index, Tunn, TunnResult, cipher::CipherSuite},
    x25519::{PublicKey, StaticSecret},
};
use std::{
    hint::black_box,
    sync::{Arc, Barrier, OnceLock},
    thread,
    time::{Duration, Instant},
};
fn env_number(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}
fn main() {
    let in_place = env_number("IN_PLACE", 0) != 0;
    let count = env_number("PACKETS", 200_000).clamp(1, 8_000_000);
    let samples = env_number("SAMPLES", 5);
    let max_workers = env_number("MAX_WORKERS", 1).clamp(1, 64) as usize;
    println!("suite,bytes,workers,sample,packets,seconds,ns_per_packet,payload_gbps");
    for workers in 1..=max_workers {
        for sample in 0..samples {
            // Alternate suite order between samples to reduce systematic thermal/order bias.
            let suites = if sample % 2 == 0 {
                [CipherSuite::Aes256Gcm, CipherSuite::ChaCha20Poly1305]
            } else {
                [CipherSuite::ChaCha20Poly1305, CipherSuite::Aes256Gcm]
            };
            for suite in suites {
                for size in [64usize, 1420] {
                    let ready = Arc::new(Barrier::new(workers + 1));
                    let go = Arc::new(Barrier::new(workers + 1));
                    let start = Arc::new(OnceLock::<Instant>::new());
                    let mut threads = Vec::new();
                    for id in 0..workers {
                        let ready = ready.clone();
                        let go = go.clone();
                        let start = start.clone();
                        threads.push(thread::spawn(move || {
                            let now = Instant::now();
                            let make = |a, b| {
                                Tunn::new_with_cipher_at(
                                    StaticSecret::from([a; 32]),
                                    PublicKey::from(&StaticSecret::from([b; 32])),
                                    None,
                                    None,
                                    Index::new_local(a as u32),
                                    None,
                                    1,
                                    now,
                                    now,
                                    Duration::from_secs(1_700_000_000),
                                    suite,
                                )
                            };
                            let ka = (id * 2 + 1) as u8;
                            let kb = ka + 1;
                            let mut a = make(ka, kb);
                            let mut b = make(kb, ka);
                            let mut x = [0; 2048];
                            let mut y = [0; 2048];
                            let init = match a.format_handshake_initiation_at(&mut x, false, now) {
                                TunnResult::WriteToNetwork(p) => p,
                                _ => panic!(),
                            };
                            let response = match b.decapsulate_at(None, init, &mut y, now) {
                                TunnResult::WriteToNetwork(p) => p,
                                _ => panic!(),
                            };
                            let confirm = match a.decapsulate_at(None, response, &mut x, now) {
                                TunnResult::WriteToNetwork(p) => p,
                                _ => panic!(),
                            };
                            assert!(matches!(
                                b.decapsulate_at(None, confirm, &mut y, now),
                                TunnResult::Done
                            ));
                            let mut ip = vec![0; size];
                            ip[0] = 0x45;
                            ip[2..4].copy_from_slice(&(size as u16).to_be_bytes());
                            x[16..16 + size].copy_from_slice(&ip);
                            let mut roundtrip = || {
                                if in_place {
                                    let n = a
                                        .encapsulate_data_in_place_at(size, black_box(&mut x), now)
                                        .unwrap();
                                    assert!(matches!(
                                        black_box(b.decapsulate_data_in_place_at(&mut x[..n], now)),
                                        TunnResult::WriteToTunnelV4(_, _)
                                    ));
                                } else {
                                    let n =
                                        a.encapsulate_data_at(black_box(&ip), &mut x, now).unwrap();
                                    assert!(matches!(
                                        black_box(b.decapsulate_at(None, &x[..n], &mut y, now)),
                                        TunnResult::WriteToTunnelV4(_, _)
                                    ));
                                }
                            };
                            for _ in 0..10_000 {
                                roundtrip();
                            }
                            ready.wait();
                            go.wait();
                            for _ in 0..count {
                                roundtrip();
                            }
                            start.get().unwrap().elapsed()
                        }));
                    }
                    ready.wait();
                    start.set(Instant::now()).unwrap();
                    go.wait();
                    let elapsed = threads
                        .into_iter()
                        .map(|t| t.join().unwrap())
                        .max()
                        .unwrap()
                        .as_secs_f64();
                    let packets = count * workers as u64;
                    println!(
                        "{suite:?},{size},{workers},{sample},{packets},{elapsed:.6},{:.1},{:.3}",
                        elapsed * 1e9 / packets as f64,
                        packets as f64 * size as f64 * 8.0 / elapsed / 1e9
                    );
                }
            }
        }
    }
}
