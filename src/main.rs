use clap::Parser;

#[derive(Parser)]
#[command(
    version,
    about = "Peer-threaded userspace tunnel. Configure with the standard wg tool."
)]
struct Args {
    /// Adapter name. On macOS, utun allocates the next available unit.
    #[cfg_attr(windows, arg(default_value = "interestun"))]
    #[cfg_attr(not(windows), arg(default_value = "utun"))]
    interface: String,
    /// AES is a custom protocol; use chacha20-poly1305 to talk to standard WireGuard.
    #[arg(long, value_enum, default_value = "aes256-gcm")]
    cipher: interestun::config::Cipher,
    #[arg(long, default_value_t = 1420, value_parser = clap::value_parser!(u32).range(1280..=2000))]
    mtu: u32,
    #[cfg(target_os = "macos")]
    #[arg(long, default_value = "/var/run/wireguard")]
    uapi_dir: std::path::PathBuf,
    /// Trusted Wintun DLL. Defaults to wintun.dll beside this executable.
    #[cfg(windows)]
    #[arg(long)]
    wintun_dll: Option<std::path::PathBuf>,
    /// Accepted for userspace implementation / wg-quick conventions. Always runs in foreground.
    #[arg(short, long)]
    foreground: bool,
}
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    #[cfg(target_os = "macos")]
    {
        interestun::uapi::install_signals()?;
        let tun = std::sync::Arc::new(interestun::platform::utun::Utun::open(
            &args.interface,
            args.mtu,
        )?);
        interestun::uapi::serve(tun, &args.uapi_dir, args.cipher)
    }
    #[cfg(windows)]
    {
        use anyhow::Context;
        interestun::uapi::install_signals()?;
        let dll = match args.wintun_dll {
            Some(path) => path,
            None => std::env::current_exe()?.with_file_name("wintun.dll"),
        };
        let tun = std::sync::Arc::new(
            interestun::platform::wintun::Wintun::open(&args.interface, args.mtu, &dll)
                .with_context(|| {
                    format!(
                        "create Wintun adapter using {} (requires Administrator)",
                        dll.display()
                    )
                })?,
        );
        interestun::uapi::serve(tun, args.cipher)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = args;
        anyhow::bail!("supported adapter backends are macOS utun and Windows Wintun")
    }
}
