//! Production UDP transport control, with a counting sink or iperf3 receiver.
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    net::UdpSocket,
    time::{Duration, Instant},
};

#[cfg(target_os = "macos")]
mod iperf;
#[cfg(target_os = "macos")]
mod send;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Portable counting sink. Does not decrypt or inject into a TUN.
    Receive {
        #[arg(long, default_value = "0.0.0.0:5202")]
        bind: String,
        /// Exit after this much inactivity (also limits the initial wait).
        #[arg(long, default_value_t = 10000)]
        idle_ms: u64,
        /// Optional count for a finite correctness test; zero means wait for idle.
        #[arg(long, default_value_t = 0)]
        packets: u64,
    },
    /// macOS production Network.framework sender; counting sink or --iperf.
    #[cfg(target_os = "macos")]
    Send(send::Args),
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::Receive {
            bind,
            idle_ms,
            packets,
        } => receive(&bind, idle_ms, packets),
        #[cfg(target_os = "macos")]
        Command::Send(args) => send::run(args),
    }
}

fn receive(bind: &str, idle_ms: u64, limit: u64) -> Result<()> {
    ensure!(idle_ms > 0, "idle timeout must be positive");
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(Duration::from_millis(idle_ms)))?;
    let sock = socket2::SockRef::from(&socket);
    sock.set_recv_buffer_size(4 * 1024 * 1024)
        .context("set receive buffer")?;
    eprintln!(
        "sink ready on {}; rcvbuf={}",
        socket.local_addr()?,
        sock.recv_buffer_size()?
    );
    let mut buffer = vec![0; 65536];
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut first = None;
    let mut last = Instant::now();
    let mut source = None;
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((n, peer)) => {
                ensure!(
                    n >= 32 && (&buffer[..4] == b"INB1" || buffer[..4] == [4, 0, 0, 0]),
                    "unexpected benchmark datagram"
                );
                if let Some(expected) = source {
                    ensure!(
                        expected == peer,
                        "multiple senders: run separate sinks/ports"
                    );
                }
                source = Some(peer);
                last = Instant::now();
                first.get_or_insert(last);
                packets += 1;
                bytes += n as u64;
                if limit != 0 && packets >= limit {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }
    let seconds = first.map_or(0.0, |start| last.duration_since(start).as_secs_f64());
    println!("role,packets,udp_payload_bytes,arrival_span_seconds,udp_payload_gbps");
    println!(
        "receiver,{packets},{bytes},{seconds:.6},{:.6}",
        if seconds > 0.0 {
            bytes as f64 * 8.0 / seconds / 1e9
        } else {
            0.0
        }
    );
    ensure!(packets > 0, "no packets received");
    ensure!(
        limit == 0 || packets == limit,
        "received {packets} of {limit} expected packets"
    );
    Ok(())
}
