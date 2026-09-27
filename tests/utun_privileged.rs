#![cfg(target_os = "macos")]
use interestun::platform::utun::Utun;
#[test]
#[ignore = "requires root and creates a real temporary BSD utun"]
fn open_real_utun_and_verify_mtu() {
    let tun = Utun::open("utun", 1420).expect("run this test executable with sudo");
    assert!(tun.name.starts_with("utun"));
    let output = std::process::Command::new("/sbin/ifconfig")
        .arg(&tun.name)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("mtu 1420"), "{text}");
    println!(
        "created {} and verified MTU 1420; closing owned fd",
        tun.name
    );
}
