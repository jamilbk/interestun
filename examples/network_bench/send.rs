use anyhow::{Context, Result, bail, ensure};
use boringtun::{
    noise::{Index, TransportSender, Tunn, TunnResult, cipher::CipherSuite},
    x25519::{PublicKey, StaticSecret},
};
use clap::ValueEnum;
use interestun::{
    packet::{self, BATCH, CAPACITY, Packet},
    platform::{
        network::Socket,
        readiness::{Poll, Token, Waker},
    },
};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Raw,
    Aes,
    Chacha,
}

#[derive(clap::Args)]
pub struct Args {
    #[arg(long)]
    target: SocketAddr,
    /// Use an existing iperf3 UDP receiver (target port usually 5201).
    #[arg(long)]
    iperf: bool,
    /// Save sender diagnostics and the unmodified iperf3 receiver report.
    #[arg(long, requires = "iperf")]
    json: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "raw")]
    mode: Mode,
    /// Inner IP bytes; both raw and encrypted modes send size + 32 UDP bytes.
    #[arg(long, default_value_t = 1420)]
    size: usize,
    #[arg(long, default_value_t = 128)]
    batch: usize,
    /// Optional payload bits/second; zero offers as fast as the bridge accepts.
    #[arg(long, default_value_t = 0)]
    bitrate: u64,
    #[arg(long, default_value_t = 5)]
    seconds: u64,
    /// Fixed packet count instead of a duration, for correctness checks.
    #[arg(long, default_value_t = 0)]
    packets: u64,
}

struct Crypto {
    suite: CipherSuite,
    // Keeps the sender lease alive; dropping this session revokes it.
    _session: Tunn,
    verifier: Tunn,
    sender: TransportSender,
}
impl Crypto {
    fn new(suite: CipherSuite) -> Result<Self> {
        let a = StaticSecret::from(rand::random::<[u8; 32]>());
        let b = StaticSecret::from(rand::random::<[u8; 32]>());
        let ap = PublicKey::from(&a);
        let bp = PublicKey::from(&b);
        let now = Instant::now();
        let wall = SystemTime::now().duration_since(UNIX_EPOCH)?;
        let make = |key, peer, index| {
            Tunn::new_with_cipher_at(
                key,
                peer,
                None,
                None,
                Index::new_local(index),
                None,
                1,
                now,
                now,
                wall,
                suite,
            )
        };
        let mut a = make(a, bp, 1);
        let mut b = make(b, ap, 2);
        let mut x = [0; CAPACITY];
        let mut y = [0; CAPACITY];
        let TunnResult::WriteToNetwork(init) = a.format_handshake_initiation_at(&mut x, false, now)
        else {
            bail!("initiation failed")
        };
        let TunnResult::WriteToNetwork(response) = b.decapsulate_at(None, init, &mut y, now) else {
            bail!("response failed")
        };
        let TunnResult::WriteToNetwork(confirm) = a.decapsulate_at(None, response, &mut x, now)
        else {
            bail!("confirmation failed")
        };
        ensure!(
            matches!(
                b.decapsulate_at(None, confirm, &mut y, now),
                TunnResult::Done
            ),
            "handshake failed"
        );
        let sender = a.take_transport_sender().context("sender handoff failed")?;
        Ok(Self {
            suite,
            _session: a,
            verifier: b,
            sender,
        })
    }
    fn encrypt(&mut self, ip: &[u8], packet: &mut Packet) -> Result<()> {
        if !self.sender.is_valid_at(Instant::now()) {
            // New random keys and a local handshake; never bypass counter or
            // lifetime limits, including a limit reached inside a batch.
            *self = Self::new(self.suite)?;
        }
        packet.buffer()[16..16 + ip.len()].copy_from_slice(ip);
        packet.len = self
            .sender
            .encapsulate_in_place_at(ip.len(), packet.buffer(), Instant::now())
            .map_err(|e| anyhow::anyhow!("encryption: {e:?}"))?;
        Ok(())
    }
}

fn cpu() -> (f64, f64) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: rusage is writable and read only on syscall success.
    unsafe {
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()), 0);
        let usage = usage.assume_init();
        let seconds = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
        (seconds(usage.ru_utime), seconds(usage.ru_stime))
    }
}

pub fn run(args: Args) -> Result<()> {
    ensure!(
        !args.iperf || matches!(args.mode, Mode::Raw),
        "iperf mode requires --mode raw"
    );
    ensure!(
        !args.iperf || args.packets == 0,
        "iperf mode uses --seconds, not --packets"
    );
    ensure!(
        (20..=CAPACITY - 32).contains(&args.size),
        "size must be 20..={}",
        CAPACITY - 32
    );
    ensure!(
        (1..=BATCH).contains(&args.batch),
        "batch must be 1..={BATCH}"
    );
    ensure!(
        args.seconds > 0 && args.seconds <= 120,
        "seconds must be 1..=120"
    );
    let pool = packet::pool(BATCH);
    let mut packets = VecDeque::with_capacity(BATCH);
    let mut ip = vec![0u8; args.size];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(args.size as u16).to_be_bytes());
    ip[12..16].copy_from_slice(&[10, 20, 0, 2]);
    ip[16..20].copy_from_slice(&[10, 20, 0, 1]);
    let suite = match args.mode {
        Mode::Raw => None,
        Mode::Aes => Some(CipherSuite::Aes256Gcm),
        Mode::Chacha => Some(CipherSuite::ChaCha20Poly1305),
    };
    let mut crypto = suite.map(Crypto::new).transpose()?;
    if let Some(crypto) = &mut crypto {
        let mut packet = Packet::new(&pool).unwrap();
        crypto.encrypt(&ip, &mut packet)?;
        let mut plain = [0; CAPACITY];
        match crypto
            .verifier
            .decapsulate_at(None, packet.data(), &mut plain, Instant::now())
        {
            TunnResult::WriteToTunnelV4(data, _) => ensure!(data == ip, "plaintext mismatch"),
            other => bail!("local crypto validation failed: {other:?}"),
        }
    }
    // The tunnel's actual bridge, pool, partial-send handling and callback
    // readiness. One connection, fixed 1024 packet credits; no benchmark shim.
    let mut control = if args.iperf {
        Some(super::iperf::Control::connect(
            args.target,
            args.seconds,
            args.size + 32,
            args.bitrate,
        )?)
    } else {
        None
    };
    let mut poll = Poll::new()?;
    let mut events = Vec::with_capacity(2);
    let network = Socket::connect(
        0,
        args.target,
        Waker::new(&poll, Token(0))?,
        Waker::new(&poll, Token(1))?,
    )?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match network.pending_sends() {
            Ok(0) => break,
            Ok(_) => bail!("unexpected send during setup"),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        ensure!(
            Instant::now() < deadline,
            "Network.framework connection timed out"
        );
        poll.poll(
            &mut events,
            Some(deadline.saturating_duration_since(Instant::now())),
        )?;
    }
    eprintln!(
        "production Network.framework bridge ready; batch={} credits=1024",
        args.batch
    );
    if let Some(control) = &mut control {
        control.start(&network, &mut poll, &mut events)?;
    }
    let setup_accepted = network.tx_stats().accepted;
    let mut submitted = 0u64;
    let mut waits = 0u64;
    let start_cpu = cpu();
    let start = Instant::now();
    while if args.packets > 0 {
        submitted < args.packets
    } else {
        start.elapsed() < Duration::from_secs(args.seconds)
    } {
        let n = if args.packets > 0 {
            (args.packets - submitted).min(args.batch as u64) as usize
        } else {
            args.batch
        };
        let timestamp = if args.iperf {
            Some(SystemTime::now().duration_since(UNIX_EPOCH)?)
        } else {
            None
        };
        for i in 0..n {
            let mut packet = Packet::new(&pool).unwrap();
            if let Some(c) = &mut crypto {
                c.encrypt(&ip, &mut packet)?;
            } else {
                // Pool contents start zero and raw payloads remain immutable.
                // Only the sequence/header changes; no per-packet memset.
                packet.len = args.size + 32;
                if let Some(timestamp) = timestamp {
                    packet.buffer()[..4]
                        .copy_from_slice(&(timestamp.as_secs() as u32).to_be_bytes());
                    packet.buffer()[4..8].copy_from_slice(&timestamp.subsec_micros().to_be_bytes());
                    packet.buffer()[8..16]
                        .copy_from_slice(&(submitted + i as u64 + 1).to_be_bytes());
                } else {
                    packet.buffer()[..4].copy_from_slice(b"INB1");
                    packet.buffer()[8..16].copy_from_slice(&(submitted + i as u64).to_le_bytes());
                }
            }
            packets.push_back(packet);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !packets.is_empty() {
            match network.flush(&mut packets) {
                Ok(n) => submitted += n as u64,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    waits += 1;
                    ensure!(Instant::now() < deadline, "Network.framework send stalled");
                    // Same callback-driven full-window wakeup as the tunnel.
                    // The deadline detects failure, never periodically retries.
                    poll.poll(
                        &mut events,
                        Some(deadline.saturating_duration_since(Instant::now())),
                    )?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        if args.bitrate != 0 {
            // Explicit offered-rate control, once per application batch. This
            // branch is absent from the unlimited throughput measurement.
            let due = start
                + Duration::from_secs_f64(
                    submitted as f64 * (args.size + 32) as f64 * 8.0 / args.bitrate as f64,
                );
            let remaining = due.saturating_duration_since(Instant::now());
            if !remaining.is_zero() {
                std::thread::sleep(remaining);
            }
        }
    }
    let submit_seconds = start.elapsed().as_secs_f64();
    let drain = Instant::now();
    while network.pending_sends()? != 0 {
        ensure!(
            drain.elapsed() < Duration::from_secs(5),
            "send completions did not drain"
        );
        // The production bridge wakes at full -> nonfull, not on idle. Poll
        // only AFTER submission ends; include this drain in the reported rate.
        poll.poll(&mut events, Some(Duration::from_millis(1)))?;
    }
    let seconds = start.elapsed().as_secs_f64();
    let end_cpu = cpu();
    let stats = network.tx_stats();
    ensure!(
        stats.accepted - setup_accepted == submitted,
        "bridge acceptance count mismatch"
    );
    eprintln!(
        "tx={stats:?}; readiness_waits={waits}; submit_seconds={submit_seconds:.6}; drain_seconds={:.6}",
        drain.elapsed().as_secs_f64()
    );
    println!(
        "backend,mode,inner_bytes,udp_bytes,batch,credits,packets,seconds,accepted_payload_gbps,user_cpu_seconds,system_cpu_seconds"
    );
    println!(
        "NetworkProduction,{:?},{},{},{},1024,{},{:.6},{:.6},{:.6},{:.6}",
        args.mode,
        args.size,
        args.size + 32,
        args.batch,
        submitted,
        seconds,
        submitted as f64 * (args.size + 32) as f64 * 8.0 / seconds / 1e9,
        end_cpu.0 - start_cpu.0,
        end_cpu.1 - start_cpu.1
    );
    if let Some(control) = control {
        // TCP test-end can overtake the last UDP datagrams. Allow a fixed tail
        // settlement outside the active send/CPU interval, and retain the
        // receiver's own (longer) interval as a separate denominator.
        std::thread::sleep(Duration::from_millis(100));
        let receiver = control.finish(
            submitted,
            args.size + 32,
            seconds,
            end_cpu.0 - start_cpu.0,
            end_cpu.1 - start_cpu.1,
        )?;
        let streams = receiver["streams"]
            .as_array()
            .context("missing receiver streams")?;
        ensure!(
            streams.len() == 1 && streams[0]["id"] == 1,
            "expected one receiver stream"
        );
        let received_bytes = streams[0]["bytes"]
            .as_u64()
            .context("missing receiver bytes")?;
        let received_packets = received_bytes / (args.size + 32) as u64;
        ensure!(
            received_bytes.is_multiple_of((args.size + 32) as u64) && received_packets <= submitted,
            "inconsistent receiver byte count"
        );
        let receiver_seconds = streams[0]["end_time"]
            .as_f64()
            .zip(streams[0]["start_time"].as_f64())
            .map(|(end, start)| end - start);
        let report = serde_json::json!({
            "backend": "production Network.framework", "target": args.target.to_string(),
            "udp_bytes": args.size + 32, "batch": args.batch, "credits": 1024,
            "offered_bitrate": args.bitrate, "submitted_packets": submitted,
            "receiver_buffer_requested": 4 * 1024 * 1024, "tail_settle_ms": 100,
            "seconds": seconds, "submit_seconds": submit_seconds,
            "accepted_payload_gbps": submitted as f64 * (args.size + 32) as f64 * 8.0 / seconds / 1e9,
            "received_packets": received_packets, "missing_packets": submitted - received_packets,
            "loss_percent": (submitted - received_packets) as f64 * 100.0 / submitted as f64,
            "received_gbps_sender_interval": received_bytes as f64 * 8.0 / seconds / 1e9,
            "received_gbps_receiver_interval": receiver_seconds.filter(|s| *s > 0.0).map(|s| received_bytes as f64 * 8.0 / s / 1e9),
            "user_cpu_seconds": end_cpu.0 - start_cpu.0, "system_cpu_seconds": end_cpu.1 - start_cpu.1,
            "cpu_cores": (end_cpu.0 + end_cpu.1 - start_cpu.0 - start_cpu.1) / seconds,
            "readiness_waits": waits,
            "tx": {"accepted_including_setup": stats.accepted, "blocked": stats.blocked,
                "blocked_ns": stats.blocked_ns, "partial": stats.partial, "wakes": stats.wakes,
                "batches": stats.batches, "occupancy": stats.occupancy},
            "receiver": receiver,
        });
        let json = serde_json::to_string_pretty(&report)?;
        if let Some(path) = args.json {
            std::fs::write(path, format!("{json}\n"))?;
        }
        eprintln!("{json}");
    }
    Ok(())
}
