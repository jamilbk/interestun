use clap::Parser;

#[derive(Parser)]
#[command(
    version,
    about = "Peer-threaded userspace tunnel. Configure with the standard wg tool."
)]
struct Args {
    /// BSD interface name: utun allocates the next available unit.
    #[arg(default_value = "utun")]
    interface: String,
    /// AES is a custom protocol; use chacha20-poly1305 to talk to standard WireGuard.
    #[arg(long, value_enum, default_value = "aes256-gcm")]
    cipher: interestun::config::Cipher,
    #[arg(long, default_value_t = 1420, value_parser = clap::value_parser!(u32).range(1280..=2000))]
    mtu: u32,
    #[arg(long, default_value = "/var/run/wireguard")]
    uapi_dir: std::path::PathBuf,
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
    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        anyhow::bail!("macOS is currently the only implemented adapter backend")
    }
}
