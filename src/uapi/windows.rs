//! Bounded, nonblocking named-pipe control server. No packet I/O on this thread.
use super::{STOP, request};
use crate::{
    config::{Cipher, Config},
    platform::Tunnel,
    runtime::Runtime,
};
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
    System::{
        Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler},
        Pipes::{ConnectNamedPipe, CreateNamedPipeW, PIPE_NOWAIT, PIPE_REJECT_REMOTE_CLIENTS},
    },
};

unsafe extern "system" fn console(signal: u32) -> i32 {
    if matches!(signal, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        STOP.store(true, Ordering::Relaxed);
        1
    } else {
        0
    }
}
pub fn install_signals() -> io::Result<()> {
    // SAFETY: Static handler only stores an atomic flag.
    if unsafe { SetConsoleCtrlHandler(Some(console), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct Security(*mut std::ffi::c_void);
impl Security {
    fn new(sddl: &[u16]) -> io::Result<Self> {
        let mut descriptor = ptr::null_mut();
        // SAFETY: Valid constant SDDL; Windows allocates the descriptor. The
        // protected DACL grants access only to SYSTEM and elevated Administrators.
        // Running as LocalSystem also supplies the owner expected by stock wg.exe.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}
impl Drop for Security {
    fn drop(&mut self) {
        // SAFETY: Descriptor was allocated by the conversion function above.
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn create_pipe(path: &[u16], security: &Security, first: bool) -> io::Result<File> {
    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    // SAFETY: Path is NUL terminated and security descriptor remains live. The
    // first-instance flag refuses to take over a live daemon's endpoint.
    let handle = unsafe {
        CreateNamedPipeW(
            path.as_ptr(),
            PIPE_ACCESS_DUPLEX
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                },
            PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            33,
            65536,
            65536,
            0,
            &attrs,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Newly created handle is uniquely owned.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}
struct Client {
    pipe: File,
    input: Vec<u8>,
    output: Vec<u8>,
    offset: usize,
    deadline: Instant,
}
fn pending(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_NO_DATA as i32) || error.kind() == io::ErrorKind::WouldBlock
}

pub fn serve(tun: Arc<Tunnel>, cipher: Cipher) -> Result<()> {
    crate::platform::wintun::validate_name(tun.name())?;
    let name = format!(
        r"\\.\pipe\ProtectedPrefix\Administrators\WireGuard\{}",
        tun.name()
    );
    let security = Security::new(
        &"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>(),
    )?;
    serve_at(tun, cipher, &name, security)
}

fn serve_at(tun: Arc<Tunnel>, cipher: Cipher, name: &str, security: Security) -> Result<()> {
    let path: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
    let mut listener = create_pipe(&path, &security, true)
        .context("create protected UAPI pipe (requires an elevated account)")?;
    let mut config = Config::default();
    let mut runtime = Some(Runtime::start(&config, cipher, tun.clone())?);
    config.listen_port = runtime.as_ref().unwrap().port;
    let mut clients: Vec<Client> = Vec::new();
    eprintln!("{} ready; UAPI {name}; cipher {cipher:?}", tun.name());
    while !STOP.load(Ordering::Relaxed) {
        let active = runtime.as_ref().unwrap();
        active.housekeeping();
        ensure!(
            !active.failed.load(Ordering::Acquire),
            "packet worker failed"
        );
        if clients.len() < 32 {
            // SAFETY: Nonblocking pipe, no OVERLAPPED structure required.
            let connected = unsafe { ConnectNamedPipe(listener.as_raw_handle(), ptr::null_mut()) };
            let error = if connected == 0 {
                Some(io::Error::last_os_error())
            } else {
                None
            };
            match error.as_ref().and_then(io::Error::raw_os_error) {
                Some(code) if code == ERROR_PIPE_CONNECTED as i32 => {
                    let next = create_pipe(&path, &security, false)?;
                    clients.push(Client {
                        pipe: std::mem::replace(&mut listener, next),
                        input: Vec::new(),
                        output: Vec::new(),
                        offset: 0,
                        deadline: Instant::now() + Duration::from_secs(5),
                    });
                }
                Some(code) if code == ERROR_PIPE_LISTENING as i32 => {}
                // A client can connect and close before we accept it.
                Some(code) if code == ERROR_NO_DATA as i32 => {
                    listener = create_pipe(&path, &security, false)?;
                }
                Some(_) => return Err(error.unwrap().into()),
                // PIPE_NOWAIT returns success on the initial transition into
                // listening; connection is reported as PIPE_CONNECTED later.
                None => {}
            }
        }
        let mut i = 0;
        while i < clients.len() {
            let client = &mut clients[i];
            let mut close = Instant::now() >= client.deadline;
            if !close && client.output.is_empty() {
                let mut buffer = [0; 8192];
                for _ in 0..8 {
                    match client.pipe.read(&mut buffer) {
                        Ok(0) => {
                            close = true;
                            break;
                        }
                        Ok(n) => {
                            client.input.extend_from_slice(&buffer[..n]);
                            if client.input.len() > 1024 * 1024 {
                                close = true;
                                break;
                            }
                            if client.input.windows(2).any(|w| w == b"\n\n") {
                                client.output = request(
                                    &client.input,
                                    &mut config,
                                    &mut runtime,
                                    &tun,
                                    cipher,
                                )?
                                .into_bytes();
                                break;
                            }
                        }
                        Err(e) if pending(&e) => break,
                        Err(_) => {
                            close = true;
                            break;
                        }
                    }
                }
            }
            if !close && !client.output.is_empty() {
                if client.offset < client.output.len() {
                    match client.pipe.write(&client.output[client.offset..]) {
                        Ok(n) => client.offset += n, // Zero means the nonblocking pipe is full.
                        Err(e) if pending(&e) => {}
                        Err(_) => close = true,
                    }
                } else {
                    // Retain the server handle until the client consumes the
                    // response and disconnects; never block on FlushFileBuffers.
                    match client.pipe.read(&mut [0; 1]) {
                        Err(e) if pending(&e) => {}
                        _ => close = true,
                    }
                }
            }
            if close {
                clients.swap_remove(i);
            } else {
                i += 1;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(runtime);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use windows_sys::Win32::System::Pipes::SetNamedPipeHandleState;

    struct EmptyTun;
    impl crate::platform::wintun::PacketIo for EmptyTun {
        fn name(&self) -> &str {
            "test"
        }
        fn receive(&self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
        fn send(&self, _: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn wait_readable(&self, timeout: Duration) -> io::Result<()> {
            std::thread::sleep(timeout);
            Ok(())
        }
    }
    fn connect(path: &str) -> File {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(file) => {
                    // SAFETY: Live pipe handle and valid mode pointer.
                    assert_ne!(
                        unsafe {
                            SetNamedPipeHandleState(
                                file.as_raw_handle(),
                                &PIPE_NOWAIT,
                                ptr::null(),
                                ptr::null(),
                            )
                        },
                        0
                    );
                    return file;
                }
                Err(error) => {
                    assert!(Instant::now() < deadline, "connect: {error}");
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
    }
    fn exchange(path: &str, input: &[u8]) -> String {
        let mut pipe = connect(path);
        pipe.write_all(input).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut output = Vec::new();
        while !output.ends_with(b"\n\n") {
            let mut buffer = [0; 1024];
            match pipe.read(&mut buffer) {
                Ok(n) => output.extend_from_slice(&buffer[..n]),
                Err(e) if pending(&e) => {}
                Err(e) => panic!("read: {e}"),
            }
            assert!(Instant::now() < deadline, "response timed out");
            std::thread::sleep(Duration::from_millis(5));
        }
        String::from_utf8(output).unwrap()
    }
    #[test]
    fn named_pipe_transactions_idle_client_and_exclusive_ownership() {
        // Exercise real Windows pipes without requiring elevation. Production
        // always uses the protected namespace and SYSTEM/Administrator-only ACL.
        let name = format!(r"\\.\pipe\interestun-test-{}", std::process::id());
        let server_name = name.clone();
        STOP.store(false, Ordering::Relaxed);
        let server = std::thread::spawn(move || {
            let sddl: Vec<_> = "D:P(A;;GA;;;OW)".encode_utf16().chain(Some(0)).collect();
            serve_at(
                Arc::new(EmptyTun),
                Cipher::Aes256Gcm,
                &server_name,
                Security::new(&sddl).unwrap(),
            )
        });
        struct StopOnDrop;
        impl Drop for StopOnDrop {
            fn drop(&mut self) {
                STOP.store(true, Ordering::Relaxed);
            }
        }
        let stop = StopOnDrop;
        let idle = connect(&name);
        assert!(exchange(&name, b"get=1\n\n").ends_with("errno=0\n\n"));
        let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let sddl: Vec<_> = "D:P(A;;GA;;;OW)".encode_utf16().chain(Some(0)).collect();
        assert!(create_pipe(&wide, &Security::new(&sddl).unwrap(), true).is_err());
        let peer = "02".repeat(32);
        assert_eq!(
            exchange(
                &name,
                format!(
                    "set=1\nprivate_key={}\npublic_key={peer}\nallowed_ip=10.0.0.2/32\n\n",
                    "01".repeat(32)
                )
                .as_bytes()
            ),
            "errno=0\n\n"
        );
        let before = exchange(&name, b"get=1\n\n");
        assert!(before.contains("allowed_ip=10.0.0.2/32"));
        for malformed in [
            b"set=1\nlisten_port=bad\n\n".as_slice(),
            b"get=1\n\ntrailing",
            b"\xff\n\n",
        ] {
            assert_eq!(
                exchange(&name, malformed),
                format!("errno={}\n\n", libc::EINVAL)
            );
        }
        assert_eq!(exchange(&name, b"get=1\n\n"), before);
        drop(idle);
        drop(stop);
        server.join().unwrap().unwrap();
        assert!(OpenOptions::new().read(true).open(&name).is_err());
    }
}
