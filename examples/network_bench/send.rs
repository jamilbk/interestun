use anyhow::{Context, Result, bail, ensure};
use boringtun::{
    noise::{Index, TransportSender, Tunn, TunnResult, cipher::CipherSuite},
    x25519::{PublicKey, StaticSecret},
};
use clap::ValueEnum;
use interestun::{
    packet::{self, BATCH, CAPACITY, Packet},
    platform::batch,
};
use std::{
    collections::VecDeque,
    ffi::{CString, c_void},
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Backend {
    Bsd,
    Network,
}
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
    #[arg(long, value_enum, default_value = "network")]
    backend: Backend,
    #[arg(long, value_enum, default_value = "aes")]
    mode: Mode,
    /// Inner IP bytes; both raw and encrypted modes send size + 32 UDP bytes.
    #[arg(long, default_value_t = 1420)]
    size: usize,
    #[arg(long, default_value_t = 128)]
    batch: usize,
    /// Maximum Network.framework batches in flight; copied data stays bounded.
    #[arg(long, default_value_t = 8)]
    window: usize,
    #[arg(long, default_value_t = 5)]
    seconds: u64,
    /// Fixed packet count instead of a duration, for correctness checks.
    #[arg(long, default_value_t = 0)]
    packets: u64,
}

unsafe extern "C" {
    fn in_nw_open(host: *const i8, port: *const i8, error: *mut i32) -> *mut c_void;
    fn in_nw_submit(
        handle: *mut c_void,
        buffers: *const *const u8,
        lengths: *const usize,
        count: usize,
    ) -> *mut c_void;
    fn in_nw_wait(handle: *mut c_void) -> i32;
    fn in_nw_close(handle: *mut c_void);
}

struct Network {
    handle: *mut c_void,
    pending: VecDeque<(*mut c_void, usize)>,
}
impl Network {
    fn new(target: SocketAddr) -> Result<Self> {
        ensure!(
            target.is_ipv4(),
            "initial Network.framework stub requires an IPv4 target"
        );
        let host = CString::new(target.ip().to_string())?;
        let port = CString::new(target.port().to_string())?;
        let mut error = 0;
        // SAFETY: NUL-terminated strings and error pointer live through this call.
        let handle = unsafe { in_nw_open(host.as_ptr(), port.as_ptr(), &mut error) };
        ensure!(
            !handle.is_null(),
            "Network.framework connection failed: {error}"
        );
        Ok(Self {
            handle,
            pending: VecDeque::new(),
        })
    }
    fn submit(&mut self, packets: &VecDeque<Packet>) {
        let mut pointers = [std::ptr::null(); BATCH];
        let mut lengths = [0; BATCH];
        for (i, packet) in packets.iter().enumerate() {
            pointers[i] = packet.data().as_ptr();
            lengths[i] = packet.len;
        }
        // SAFETY: The bridge synchronously copies these buffers, never retains
        // their pointers, and returns an owned batch handle consumed by wait.
        let handle = unsafe {
            in_nw_submit(
                self.handle,
                pointers.as_ptr(),
                lengths.as_ptr(),
                packets.len(),
            )
        };
        self.pending.push_back((handle, packets.len()));
    }
    fn wait(&mut self) -> Result<u64> {
        let (handle, count) = self.pending.pop_front().unwrap();
        // SAFETY: Each retained batch handle is consumed exactly once.
        let error = unsafe { in_nw_wait(handle) };
        ensure!(
            error == 0,
            "Network.framework send completion failed: {error}"
        );
        Ok(count as u64)
    }
}
impl Drop for Network {
    fn drop(&mut self) {
        // Cancel first; pending callbacks own their data and batch state.
        unsafe { in_nw_close(self.handle) };
        while !self.pending.is_empty() {
            let _ = self.wait();
        }
    }
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
        (20..=CAPACITY - 32).contains(&args.size),
        "size must be 20..={}",
        CAPACITY - 32
    );
    ensure!(
        (1..=BATCH).contains(&args.batch),
        "batch must be 1..={BATCH}"
    );
    ensure!((1..=64).contains(&args.window), "window must be 1..=64");
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
    let mut network = match args.backend {
        Backend::Network => Some(Network::new(args.target)?),
        _ => None,
    };
    let socket = if network.is_none() {
        let s = UdpSocket::bind(if args.target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        s.connect(args.target)?;
        s.set_nonblocking(true)?;
        socket2::SockRef::from(&s).set_send_buffer_size(4 * 1024 * 1024)?;
        eprintln!("BSD connected; sendmsg_x={}", batch::available());
        Some(s)
    } else {
        None
    };
    let mut sender = batch::Sender::new();
    let mut submitted = 0u64;
    let mut completed = 0u64;
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
        for i in 0..n {
            let mut packet = Packet::new(&pool).unwrap();
            if let Some(c) = &mut crypto {
                c.encrypt(&ip, &mut packet)?;
            } else {
                packet.len = args.size + 32;
                packet.buffer()[..args.size + 32].fill(0);
                packet.buffer()[..4].copy_from_slice(b"INB1");
                packet.buffer()[8..16].copy_from_slice(&(submitted + i as u64).to_le_bytes());
            }
            packets.push_back(packet);
        }
        if let Some(network) = &mut network {
            network.submit(&packets);
            packets.clear();
            if network.pending.len() >= args.window {
                completed += network.wait()?;
            }
        } else {
            let fd = socket.as_ref().unwrap().as_raw_fd();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !packets.is_empty() {
                match sender.flush(fd, false, &mut packets) {
                    Ok(n) => completed += n as u64,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        let mut poll = libc::pollfd {
                            fd,
                            events: libc::POLLOUT,
                            revents: 0,
                        };
                        // SAFETY: one valid pollfd, no other thread closes fd.
                        let result = unsafe { libc::poll(&mut poll, 1, 100) };
                        if result < 0 {
                            return Err(std::io::Error::last_os_error().into());
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
                ensure!(Instant::now() < deadline, "BSD send stalled");
            }
        }
        submitted += n as u64;
    }
    if let Some(network) = &mut network {
        while !network.pending.is_empty() {
            completed += network.wait()?;
        }
    }
    let seconds = start.elapsed().as_secs_f64();
    let end_cpu = cpu();
    ensure!(completed == submitted, "incomplete sends");
    println!(
        "backend,mode,inner_bytes,udp_bytes,batch,window,packets,seconds,udp_payload_gbps,user_cpu_seconds,system_cpu_seconds"
    );
    println!(
        "{:?},{:?},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6}",
        args.backend,
        args.mode,
        args.size,
        args.size + 32,
        args.batch,
        args.window,
        completed,
        seconds,
        completed as f64 * (args.size + 32) as f64 * 8.0 / seconds / 1e9,
        end_cpu.0 - start_cpu.0,
        end_cpu.1 - start_cpu.1
    );
    Ok(())
}
