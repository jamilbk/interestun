//! WireGuard userspace IPC. The main thread owns configuration and bounded clients.
use crate::{
    config::{Cipher, Config},
    platform::Tunnel,
    runtime::Runtime,
};
#[cfg(target_os = "macos")]
use anyhow::ensure;
use anyhow::{Context, Result};
use std::{
    fmt::Write as _,
    sync::{Arc, atomic::AtomicBool},
};
#[cfg(target_os = "macos")]
use std::{
    fs,
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub static STOP: AtomicBool = AtomicBool::new(false);
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{install_signals, serve};
#[cfg(target_os = "macos")]
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
#[cfg(target_os = "macos")]
pub fn install_signals() -> io::Result<()> {
    // SAFETY: The handler only stores to a lock-free atomic. sigaction is initialized and has no borrowed state.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = stop as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        for signal in [libc::SIGINT, libc::SIGTERM] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}
#[cfg(target_os = "macos")]
struct SocketPath {
    path: PathBuf,
    inode: u64,
}
#[cfg(target_os = "macos")]
impl Drop for SocketPath {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.inode) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
#[cfg(target_os = "macos")]
struct Client {
    stream: UnixStream,
    input: Vec<u8>,
    output: Vec<u8>,
    offset: usize,
    deadline: Instant,
}
fn show(config: &Config, runtime: &Runtime) -> String {
    let mut out = String::new();
    if config.private_key != [0; 32] {
        writeln!(out, "private_key={}", hex::encode(config.private_key)).unwrap();
    }
    writeln!(out, "listen_port={}\nfwmark=0", runtime.port).unwrap();
    for (key, peer) in &config.peers {
        writeln!(
            out,
            "public_key={}\npreshared_key={}",
            hex::encode(key),
            hex::encode(peer.preshared_key)
        )
        .unwrap();
        let snapshot = runtime
            .peers
            .get(key)
            .map(|p| p.stats.lock().unwrap().clone())
            .unwrap_or_default();
        if let Some(endpoint) = snapshot.endpoint.or(peer.endpoint) {
            writeln!(out, "endpoint={endpoint}").unwrap();
        }
        writeln!(out, "last_handshake_time_sec={}\nlast_handshake_time_nsec={}\ntx_bytes={}\nrx_bytes={}\npersistent_keepalive_interval={}\nprotocol_version=1", snapshot.handshake.as_secs(), snapshot.handshake.subsec_nanos(), snapshot.tx, snapshot.rx, peer.keepalive).unwrap();
        for net in &peer.allowed_ips {
            writeln!(out, "allowed_ip={net}").unwrap();
        }
    }
    out.push_str("errno=0\n\n");
    out
}
fn request(
    input: &[u8],
    config: &mut Config,
    runtime: &mut Option<Runtime>,
    tun: &Arc<Tunnel>,
    cipher: Cipher,
    backend: crate::platform::udp::Backend,
) -> Result<String> {
    let input = match std::str::from_utf8(input) {
        Ok(s) => s,
        Err(_) => return Ok(format!("errno={}\n\n", libc::EINVAL)),
    };
    if input == "get=1\n\n" {
        return Ok(show(config, runtime.as_ref().unwrap()));
    }
    #[cfg(windows)]
    if input == "stats=1\n\n" {
        let mut out = format!("tcp_coalescing={}\n", u8::from(tun.tcp_coalescing()));
        for (key, peer) in &runtime.as_ref().unwrap().peers {
            let stats = peer.stats.lock().unwrap().injection;
            writeln!(out, "public_key={}\nwintun_writes={}\ncoalesced_segments={}\nring_full_retries={}\ndrops={}", hex::encode(key), stats.writes, stats.merged, stats.blocked, peer.drops.load(std::sync::atomic::Ordering::Relaxed)).unwrap();
        }
        out.push_str("errno=0\n\n");
        return Ok(out);
    }
    let mut base = config.clone();
    // Preserve authenticated endpoint roaming across unrelated configuration requests.
    for (key, shared) in &runtime.as_ref().unwrap().peers {
        if let Some(peer) = base.peers.get_mut(key) {
            peer.endpoint = shared.stats.lock().unwrap().endpoint.or(peer.endpoint);
        }
    }
    let next = match base.apply(input) {
        Ok(next) => next,
        Err(_) => return Ok(format!("errno={}\n\n", libc::EINVAL)),
    };
    // Initial implementation uses a coordinated restart for set. No data-plane locks or partially applied settings.
    drop(runtime.take());
    match Runtime::start_with_backend(&next, cipher, tun.clone(), backend) {
        Ok(new_runtime) => {
            *config = next;
            config.listen_port = new_runtime.port;
            *runtime = Some(new_runtime);
            Ok("errno=0\n\n".into())
        }
        Err(error) => {
            eprintln!("configuration resource setup failed: {error:#}");
            *runtime = Some(
                Runtime::start_with_backend(&base, cipher, tun.clone(), backend)
                    .context("restore previous configuration")?,
            );
            Ok(format!("errno={}\n\n", libc::EIO))
        }
    }
}
#[cfg(target_os = "macos")]
pub fn serve(tun: Arc<Tunnel>, directory: &Path, cipher: Cipher) -> Result<()> {
    serve_with_backend(
        tun,
        directory,
        cipher,
        crate::platform::udp::Backend::default(),
    )
}
#[cfg(target_os = "macos")]
pub fn serve_with_backend(
    tun: Arc<Tunnel>,
    directory: &Path,
    cipher: Cipher,
    backend: crate::platform::udp::Backend,
) -> Result<()> {
    if !directory.exists() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(directory)?;
    }
    let metadata = fs::symlink_metadata(directory)?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "UAPI directory must be owned by this user and not writable by group/others"
    );
    let path = directory.join(format!("{}.sock", tun.name));
    // Never unlink a pre-existing socket: it may belong to a live daemon.
    // SAFETY: Startup is single-threaded; restore umask immediately after bind.
    let old_mask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(&path);
    unsafe { libc::umask(old_mask) };
    let listener = listener.context("bind UAPI socket (remove stale socket manually if needed)")?;
    let _path_guard = SocketPath {
        inode: fs::symlink_metadata(&path)?.ino(),
        path: path.clone(),
    };
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let mut config = Config::default();
    let mut runtime = Some(Runtime::start_with_backend(
        &config,
        cipher,
        tun.clone(),
        backend,
    )?);
    config.listen_port = runtime.as_ref().unwrap().port;
    let mut clients: Vec<Client> = Vec::new();
    eprintln!(
        "{} ready; UAPI {}; cipher {:?}; UDP backend {:?}; batch syscalls {}",
        tun.name,
        path.display(),
        cipher,
        backend,
        crate::platform::batch::available()
    );
    while !STOP.load(Ordering::Relaxed) {
        let active = runtime.as_ref().unwrap();
        ensure!(!active.failed.load(Ordering::Acquire), "peer worker failed");
        active.housekeeping();
        // Poll control connections on the main thread; no runtime, acceptor, or signal threads.
        let mut fds = Vec::with_capacity(clients.len() + 1);
        fds.push(libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        for client in &clients {
            fds.push(libc::pollfd {
                fd: client.stream.as_raw_fd(),
                events: if client.output.is_empty() {
                    libc::POLLIN
                } else {
                    libc::POLLOUT
                },
                revents: 0,
            });
        }
        // SAFETY: fds contains initialized pollfd entries and remains live for the call.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 250) };
        if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error().into());
        }
        for _ in 0..16 {
            match listener.accept() {
                Ok((stream, _)) if clients.len() < 32 => {
                    stream.set_nonblocking(true)?;
                    clients.push(Client {
                        stream,
                        input: Vec::new(),
                        output: Vec::new(),
                        offset: 0,
                        deadline: Instant::now() + Duration::from_secs(5),
                    });
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let mut i = 0;
        while i < clients.len() {
            let client = &mut clients[i];
            let mut close = Instant::now() > client.deadline;
            if client.output.is_empty() && !close {
                let mut buf = [0; 8192];
                for _ in 0..8 {
                    match client.stream.read(&mut buf) {
                        Ok(0) => {
                            close = true;
                            break;
                        }
                        Ok(n) => {
                            client.input.extend_from_slice(&buf[..n]);
                            if client.input.len() > 1024 * 1024 {
                                close = true;
                                break;
                            }
                            if client.input.windows(2).any(|w| w == b"\n\n") {
                                if !client.input.ends_with(b"\n\n") {
                                    client.output =
                                        format!("errno={}\n\n", libc::EINVAL).into_bytes();
                                } else {
                                    client.output = request(
                                        &client.input,
                                        &mut config,
                                        &mut runtime,
                                        &tun,
                                        cipher,
                                        backend,
                                    )?
                                    .into_bytes();
                                }
                                break;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            close = true;
                            break;
                        }
                    }
                }
            }
            if !client.output.is_empty() && !close {
                match client.stream.write(&client.output[client.offset..]) {
                    Ok(0) => close = true,
                    Ok(n) => {
                        client.offset += n;
                        close = client.offset == client.output.len();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => close = true,
                }
            }
            if close {
                clients.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }
    drop(runtime);
    Ok(())
}
