#![cfg(windows)]
use interestun::platform::wintun::{PacketIo, Wintun};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

#[test]
#[ignore = "requires Administrator and INTERESTUN_WINTUN_DLL; creates a temporary adapter"]
fn real_wintun_lifecycle_and_dual_stack_mtu() {
    let dll = std::env::var_os("INTERESTUN_WINTUN_DLL")
        .expect("set INTERESTUN_WINTUN_DLL to the trusted Wintun DLL");
    let tun = Wintun::open(
        &format!("interestun-test-{}", std::process::id()),
        1420,
        std::path::Path::new(&dll),
    )
    .unwrap();
    let luid = tun.interface_luid();
    for family in [AF_INET, AF_INET6] {
        // SAFETY: Initialized IP Helper row selected by this temporary adapter.
        unsafe {
            let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
            InitializeIpInterfaceEntry(&mut row);
            row.InterfaceLuid.Value = luid;
            row.Family = family;
            assert_eq!(GetIpInterfaceEntry(&mut row), 0);
            assert_eq!(row.NlMtu, 1420);
        }
    }
    assert_eq!(
        tun.send(&[]).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    let start = std::time::Instant::now();
    tun.wait_readable(std::time::Duration::from_millis(10))
        .unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
    // Windows can generate initial IPv6 control packets. Drain a bounded number.
    for _ in 0..256 {
        match tun.receive(&mut [0; 65535]) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("receive: {e}"),
        }
    }
    drop(tun);
    // The adapter/session must be released, allowing another create/open cycle.
    drop(
        Wintun::open(
            &format!("interestun-test-{}", std::process::id()),
            1500,
            std::path::Path::new(&dll),
        )
        .unwrap(),
    );
}
