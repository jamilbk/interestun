//! Opt-in real-utun test. Only the daemon and OS configuration commands run as root.
//! The remote peers are unprivileged BoringTun UDP echo responders, not OS interfaces.
#![cfg(target_os = "macos")]
use anyhow::{Context, Result, bail, ensure};
use boringtun::{
    noise::{Index, Tunn, TunnResult, cipher::CipherSuite},
    x25519::{PublicKey, StaticSecret},
};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const LOCAL4: &str = "198.18.254.1";
const LOCAL6: &str = "fd7a:115c:a1::1";
const WG: &str = "/opt/homebrew/bin/wg";
fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    ensure!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn root(program: &str, args: &[&str]) -> Result<String> {
    let mut all = vec!["-n", program];
    all.extend_from_slice(args);
    command("sudo", &all)
}
fn base64(bytes: &[u8]) -> Result<String> {
    let mut child = Command::new("/usr/bin/base64")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(bytes)?;
    let output = child.wait_with_output()?;
    ensure!(output.status.success(), "base64 failed");
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
struct Fixture {
    dir: PathBuf,
    child: Option<Child>,
    routes: Vec<(bool, String)>,
    interface: Option<String>,
}
impl Fixture {
    fn new() -> Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "interestun-live-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(Self {
            dir,
            child: None,
            routes: Vec::new(),
            interface: None,
        })
    }
    fn start(&mut self, binary: &Path, cipher: &str) -> Result<String> {
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.dir.join("daemon.log"))?;
        self.child = Some(
            Command::new("sudo")
                .args(["-n"])
                .arg(binary)
                .args(["utun", "--cipher", cipher])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(log)
                .spawn()?,
        );
        let start = Instant::now();
        loop {
            let log = fs::read_to_string(self.dir.join("daemon.log"))?;
            if let Some(name) = log
                .lines()
                .find_map(|l| l.split_once(" ready; UAPI ").map(|(name, _)| name))
            {
                self.interface = Some(name.to_owned());
                return Ok(name.to_owned());
            }
            ensure!(
                self.child.as_mut().unwrap().try_wait()?.is_none(),
                "daemon exited: {log}"
            );
            ensure!(
                start.elapsed() < Duration::from_secs(5),
                "daemon startup timed out: {log}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn route(&mut self, destination: &str, ipv6: bool, interface: &str) -> Result<()> {
        let family = if ipv6 { "-inet6" } else { "-inet" };
        root(
            "/sbin/route",
            &[
                "-n",
                "add",
                family,
                "-host",
                destination,
                "-interface",
                interface,
            ],
        )?;
        self.routes.push((ipv6, destination.into()));
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for (ipv6, destination) in self.routes.iter().rev() {
            if let Err(e) = root(
                "/sbin/route",
                &[
                    "-n",
                    "delete",
                    if *ipv6 { "-inet6" } else { "-inet" },
                    "-host",
                    destination,
                ],
            ) {
                eprintln!("route cleanup: {e:#}");
            }
        }
        if let Some(mut child) = self.child.take() {
            // sudo normally forks the daemon. Stop the exact child first, then reap sudo.
            if child.try_wait().ok().flatten().is_none() {
                let pid = child.id().to_string();
                let descendants = command("/usr/bin/pgrep", &["-P", &pid]).unwrap_or_default();
                if descendants.trim().is_empty() {
                    let _ = root("/bin/kill", &["-TERM", &pid]);
                } else {
                    for descendant in descendants.split_whitespace() {
                        let _ = root("/bin/kill", &["-TERM", descendant]);
                    }
                }
                let deadline = Instant::now() + Duration::from_secs(5);
                while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(20));
                }
                if child.try_wait().ok().flatten().is_none() {
                    eprintln!("daemon cleanup timed out for sudo PID {pid}");
                }
            }
        }
        if let Some(name) = &self.interface
            && Path::new(&format!("/var/run/wireguard/{name}.sock")).exists()
        {
            eprintln!("UAPI socket remains after shutdown: {name}");
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in bytes.chunks(2) {
        sum += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn echo(packet: &[u8]) -> Option<Vec<u8>> {
    let mut p = packet.to_vec();
    let offset = match p.first()? >> 4 {
        4 if p.len() >= 28 && p[9] == 17 => {
            let ihl = (p[0] as usize & 15) * 4;
            if ihl < 20 || p.len() < ihl + 8 {
                return None;
            }
            for i in 0..4 {
                p.swap(12 + i, 16 + i);
            }
            p[10..12].fill(0);
            let check = checksum(&p[..ihl]);
            p[10..12].copy_from_slice(&check.to_be_bytes());
            ihl
        }
        6 if p.len() >= 48 && p[6] == 17 => {
            for i in 0..16 {
                p.swap(8 + i, 24 + i);
            }
            40
        }
        _ => return None,
    };
    for i in 0..2 {
        p.swap(offset + i, offset + 2 + i);
    }
    p[offset + 6..offset + 8].fill(0);
    if offset == 40 {
        let mut pseudo = p[8..40].to_vec();
        pseudo.extend_from_slice(&((p.len() - 40) as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]);
        pseudo.extend_from_slice(&p[40..]);
        let check = checksum(&pseudo);
        let check = if check == 0 { u16::MAX } else { check };
        p[46..48].copy_from_slice(&check.to_be_bytes());
    }
    Some(p)
}
fn peer(
    socket: UdpSocket,
    secret: [u8; 32],
    public: PublicKey,
    suite: CipherSuite,
    stop: Arc<AtomicBool>,
    id: u32,
) -> Result<usize> {
    socket.set_read_timeout(Some(Duration::from_millis(20)))?;
    let now = Instant::now();
    let mut tunnel = Tunn::new_with_cipher_at(
        StaticSecret::from(secret),
        public,
        None,
        None,
        Index::new_local(id),
        None,
        rand::random(),
        now,
        now,
        SystemTime::now().duration_since(UNIX_EPOCH)?,
        suite,
    );
    let mut input = [0; 2048];
    let mut output = [0; 2048];
    let mut endpoint = None;
    let mut echoed = 0;
    while !stop.load(Ordering::Acquire) {
        match socket.recv_from(&mut input) {
            Ok((n, source)) => {
                endpoint = Some(source);
                let response = match tunnel.decapsulate_at(
                    Some(source.ip()),
                    &input[..n],
                    &mut output,
                    Instant::now(),
                ) {
                    TunnResult::WriteToNetwork(p) => {
                        socket.send_to(p, source)?;
                        None
                    }
                    TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                        echo(p)
                    }
                    TunnResult::Done => None,
                    TunnResult::Err(e) => bail!("peer decapsulation: {e:?}"),
                };
                if let Some(response) = response {
                    let n = tunnel
                        .encapsulate_data_at(&response, &mut output, Instant::now())
                        .map_err(|e| anyhow::anyhow!("echo encapsulation: {e:?}"))?;
                    socket.send_to(&output[..n], source)?;
                    echoed += 1;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.into()),
        }
        if let Some(endpoint) = endpoint
            && let TunnResult::WriteToNetwork(p) =
                tunnel.update_timers_at(&mut output, Instant::now())
        {
            socket.send_to(p, endpoint)?;
        }
    }
    Ok(echoed)
}
struct Peers {
    stop: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<Result<usize>>>,
}
impl Drop for Peers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for t in self.threads.drain(..) {
            if let Ok(Err(e)) = t.join() {
                eprintln!("peer failed: {e:#}");
            }
        }
    }
}
fn exercise(source: IpAddr, destination: IpAddr) -> Result<()> {
    let socket = UdpSocket::bind(SocketAddr::new(source, 0))?;
    socket.connect(SocketAddr::new(destination, 7777))?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut output = [0; 2048];
    for size in [0, 1, 63, 64, 511, 1372] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        socket.send(&payload)?;
        let n = socket
            .recv(&mut output)
            .with_context(|| format!("echo {source} -> {destination}, payload={size}"))?;
        ensure!(output[..n] == payload, "echo payload mismatch");
    }
    for start in [0u32, 64] {
        for i in start..start + 64 {
            let mut p = [0xa5; 512];
            p[..4].copy_from_slice(&i.to_be_bytes());
            socket.send(&p)?;
        }
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let n = socket.recv(&mut output)?;
            ensure!(
                n == 512 && output[4..n].iter().all(|b| *b == 0xa5),
                "burst payload damaged"
            );
            seen.insert(u32::from_be_bytes(output[..4].try_into()?));
        }
        ensure!(
            seen == (start..start + 64).collect(),
            "burst lost/duplicated packets"
        );
    }
    println!("PASS {source} -> {destination}: 6 packet sizes + 128 burst packets");
    Ok(())
}
#[test]
#[ignore = "creates real utun and temporary test routes; requires configured noninteractive sudo"]
fn real_utun_two_peers_ipv4_ipv6_both_ciphers() -> Result<()> {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release/interestun");
    ensure!(
        binary.exists(),
        "build using CARGO_TARGET_DIR=target cargo build --release --locked"
    );
    let interfaces = command("/sbin/ifconfig", &["-a"])?;
    ensure!(
        !interfaces.contains(LOCAL4) && !interfaces.contains(LOCAL6),
        "test addresses already assigned"
    );
    let routes = command("/usr/sbin/netstat", &["-rn"])?;
    for address in [
        "198.18.254.2",
        "198.18.254.3",
        "fd7a:115c:a1::2",
        "fd7a:115c:a1::3",
    ] {
        ensure!(
            !routes.contains(address),
            "test route already exists for {address}"
        );
    }
    for (name, suite) in [
        ("aes256-gcm", CipherSuite::Aes256Gcm),
        ("chacha20-poly1305", CipherSuite::ChaCha20Poly1305),
    ] {
        let mut fixture = Fixture::new()?;
        let interface = fixture.start(&binary, name)?;
        println!("Testing {name} on {interface}");
        let local_secret = rand::random::<[u8; 32]>();
        let local_public = PublicKey::from(&StaticSecret::from(local_secret));
        let path = fixture.dir.join("private.key");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        writeln!(file, "{}", base64(&local_secret)?)?;
        drop(file);
        let mut args = vec![
            "set".to_owned(),
            interface.clone(),
            "private-key".into(),
            path.to_string_lossy().into_owned(),
            "listen-port".into(),
            "0".into(),
        ];
        let mut peers = Peers {
            stop: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        };
        for id in [2, 3] {
            let secret = rand::random::<[u8; 32]>();
            let public = PublicKey::from(&StaticSecret::from(secret));
            let socket = UdpSocket::bind(if id == 2 {
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
            } else {
                SocketAddr::from((Ipv6Addr::LOCALHOST, 0))
            })?;
            args.extend([
                "peer".into(),
                base64(public.as_bytes())?,
                "endpoint".into(),
                socket.local_addr()?.to_string(),
                "allowed-ips".into(),
                format!("198.18.254.{id}/32,fd7a:115c:a1::{id}/128"),
            ]);
            let stop = peers.stop.clone();
            peers.threads.push(thread::spawn(move || {
                peer(socket, secret, local_public, suite, stop, id)
            }));
        }
        root(WG, &args.iter().map(String::as_str).collect::<Vec<_>>())?;
        root(
            "/sbin/ifconfig",
            &[&interface, "inet", LOCAL4, "198.18.254.2", "up"],
        )?;
        root(
            "/sbin/ifconfig",
            &[&interface, "inet6", LOCAL6, "prefixlen", "128", "alias"],
        )?;
        // The point-to-point IPv4 destination already has a route from ifconfig.
        fixture.route("198.18.254.3", false, &interface)?;
        for destination in ["fd7a:115c:a1::2", "fd7a:115c:a1::3"] {
            fixture.route(destination, true, &interface)?;
        }
        thread::sleep(Duration::from_millis(1200)); // IPv6 duplicate-address detection.
        for id in [2, 3] {
            exercise(LOCAL4.parse()?, format!("198.18.254.{id}").parse()?)?;
            exercise(LOCAL6.parse()?, format!("fd7a:115c:a1::{id}").parse()?)?;
        }
        // UAPI snapshots update every 250 ms; allow the final handshake to be published.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let stats = root(WG, &["show", &interface, "latest-handshakes"])?;
            if stats.lines().count() == 2
                && stats
                    .lines()
                    .all(|l| l.split_whitespace().nth(1).is_some_and(|t| t != "0"))
            {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "both peers must report handshakes"
            );
            thread::sleep(Duration::from_millis(50));
        }
        println!(
            "PASS wg reports both handshakes; {}",
            command("/sbin/ifconfig", &[&interface])?
                .lines()
                .next()
                .unwrap_or_default()
        );
        peers.stop.store(true, Ordering::Release);
        for worker in peers.threads.drain(..) {
            ensure!(
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("peer panicked"))??
                    >= 268,
                "missing echoed packets"
            );
        }
        drop(peers);
        drop(fixture);
        ensure!(
            !Path::new(&format!("/var/run/wireguard/{interface}.sock")).exists(),
            "UAPI not removed"
        );
        ensure!(
            !Command::new("/sbin/ifconfig")
                .arg(&interface)
                .output()?
                .status
                .success(),
            "utun not removed"
        );
    }
    Ok(())
}
