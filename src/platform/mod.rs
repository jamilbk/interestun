#[cfg(target_os = "macos")]
pub mod batch;
#[cfg(target_os = "macos")]
pub mod utun;
#[cfg(windows)]
pub mod wintun;

#[cfg(target_os = "macos")]
pub use utun::Utun as Tunnel;
#[cfg(windows)]
pub type Tunnel = dyn wintun::PacketIo;
