#![cfg(target_os = "macos")]
use interestun::{config::Cipher, platform::utun::Utun, uapi};
use std::{
    fs,
    io::{Read, Write},
    net::UdpSocket,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    process::Command,
    sync::{Arc, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};

fn exchange(path: &std::path::Path, request: &str) -> String {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut output = String::new();
    stream.read_to_string(&mut output).unwrap();
    output
}
#[test]
fn ipc_get_set_invalid_request_and_optional_real_wg() {
    // INTERESTUN_TEST_UAPI_DIR must match wg's compile-time RUNSTATEDIR/wireguard.
    let directory = std::env::var_os("INTERESTUN_TEST_UAPI_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("interestun-uapi-{}", std::process::id()))
        });
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let tun = Arc::new(Utun {
        fd: socket.into(),
        name: "utun-test".into(),
    });
    let dir = directory.clone();
    let daemon = thread::spawn(move || uapi::serve(tun, &dir, Cipher::Aes256Gcm));
    let path = directory.join("utun-test.sock");
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < Duration::from_secs(3));
        thread::sleep(Duration::from_millis(10));
    }
    // An idle client must not block other control requests or housekeeping.
    let idle = UnixStream::connect(&path).unwrap();
    let peer = "02".repeat(32);
    assert_eq!(
        exchange(
            &path,
            &format!(
                "set=1\npublic_key={peer}\nallowed_ip=10.0.0.0/24\npersistent_keepalive_interval=25\n\n"
            )
        ),
        "errno=0\n\n"
    );
    let get = exchange(&path, "get=1\n\n");
    assert!(
        get.contains(&format!("public_key={peer}\n")) && get.contains("allowed_ip=10.0.0.0/24\n")
    );
    assert_eq!(
        exchange(&path, "set=1\nlisten_port=invalid\n\n"),
        format!("errno={}\n\n", libc::EINVAL)
    );
    assert_eq!(exchange(&path, "get=1\n\n"), get);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    if let Some(wg) = std::env::var_os("INTERESTUN_TEST_WG") {
        let output = Command::new(&wg)
            .args(["show", "utun-test", "dump"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("10.0.0.0/24"));
        let output = Command::new(&wg)
            .args(["set", "utun-test", "listen-port", "0"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(&wg)
            .args(["showconf", "utun-test"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("PersistentKeepalive = 25"));
        let config_file = directory.join("test.conf");
        fs::write(&config_file, &output.stdout).unwrap();
        for operation in ["setconf", "syncconf"] {
            let output = Command::new(&wg)
                .args([operation, "utun-test"])
                .arg(&config_file)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        fs::remove_file(config_file).unwrap();
    }
    drop(idle);
    uapi::STOP.store(true, Ordering::Relaxed);
    daemon.join().unwrap().unwrap();
    assert!(!path.exists());
    fs::remove_dir(directory).unwrap();
}
