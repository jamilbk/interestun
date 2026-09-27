//! Userspace cost and adapter-write count only, not real Wintun throughput.
#[cfg(windows)]
fn main() {
    use interestun::{
        packet::{self, Packet},
        platform::coalesce::Injector,
    };
    use std::{collections::VecDeque, hint::black_box, time::Instant};
    fn sum(bytes: &[u8]) -> u32 {
        bytes
            .chunks(2)
            .map(|b| ((b[0] as u32) << 8) + b.get(1).copied().unwrap_or(0) as u32)
            .sum()
    }
    fn finish(mut sum: u32) -> u16 {
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        !(sum as u16)
    }
    let templates: Vec<_> = (0..32u32)
        .map(|i| {
            let mut p = vec![0u8; 1400];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&1400u16.to_be_bytes());
            p[6] = 0x40;
            p[8] = 64;
            p[9] = 6;
            p[12..20].copy_from_slice(&[10, 20, 0, 2, 10, 20, 0, 1]);
            p[20..24].copy_from_slice(&[0x12, 0x34, 0x14, 0x51]);
            p[24..28].copy_from_slice(&(i * 1360).to_be_bytes());
            p[31] = 1;
            p[32] = 0x50;
            p[33] = if i == 31 { 0x18 } else { 0x10 };
            p[34] = 0x80;
            p[40..].fill(i as u8);
            let ip_checksum = finish(sum(&p[..20]));
            p[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
            let tcp_checksum = finish(sum(&p[12..20]) + 6 + 1380 + sum(&p[20..]));
            p[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());
            p
        })
        .collect();
    let iterations = 10000;
    println!("coalescing,input_packets,adapter_writes,merged_segments,elapsed_ms,input_mpps");
    for enabled in [false, true] {
        let pool = packet::pool(32);
        let mut queue = VecDeque::with_capacity(32);
        let mut injector = Injector::new(enabled);
        let start = Instant::now();
        for _ in 0..iterations {
            for bytes in &templates {
                let mut p = Packet::new(&pool).unwrap();
                p.buffer()[..bytes.len()].copy_from_slice(bytes);
                p.len = bytes.len();
                queue.push_back(p);
            }
            injector
                .flush(&mut queue, |packet| {
                    black_box(packet);
                    Ok(())
                })
                .unwrap();
        }
        let elapsed = start.elapsed();
        println!(
            "{enabled},{},{},{},{:.2},{:.3}",
            iterations * 32,
            injector.stats.writes,
            injector.stats.merged,
            elapsed.as_secs_f64() * 1000.0,
            iterations as f64 * 32.0 / elapsed.as_secs_f64() / 1e6
        );
        assert_eq!(
            injector.stats.writes,
            iterations * if enabled { 1 } else { 32 }
        );
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("The injection benchmark currently targets Windows.");
}
