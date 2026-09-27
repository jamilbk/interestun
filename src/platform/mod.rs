#[cfg(target_os = "macos")]
pub mod batch;
#[cfg(any(windows, test))]
pub mod coalesce;
#[cfg(all(any(windows, target_os = "macos"), feature = "io-profile"))]
pub mod profile;
#[cfg(target_os = "macos")]
pub mod utun;
#[cfg(windows)]
pub mod wintun;

#[cfg(target_os = "macos")]
pub use utun::Utun as Tunnel;
#[cfg(windows)]
pub type Tunnel = dyn wintun::PacketIo;
