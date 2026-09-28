//! Experimental mapped utun backend. Live attachment is disabled after EPERM
//! left an interface behind; see docs/utun-ring-backend.md.
//! Packet batches own their payloads; no mapped buffer escapes a channel lock.

mod engine;
mod native;
#[cfg(test)]
mod tests;

use super::batch::Received;
use crate::packet::Packet;
use engine::Engine;
use std::{collections::VecDeque, io, os::fd::RawFd, sync::Mutex};

// The authorized 2026-09-28 attempt attached utun64, then the kernel denied
// channel privilege 12001 and left the interface present after process exit.
// Do not repeat attachment until that permission/failure path is resolved.
// Unit tests must never attach, including when this production gate is armed.
const LIVE_ATTACH_ENABLED: bool = false;

pub struct Adapter {
    channel: Mutex<Engine<native::Channel>>,
    fd: RawFd,
}

impl Adapter {
    pub(crate) fn open(name: &str, mtu: u32) -> io::Result<(Self, String)> {
        if !LIVE_ATTACH_ENABLED {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Skywalk attachment is disabled after a kernel privilege denial left an interface behind; no interface was opened",
            ));
        }
        let (channel, name) = native::Channel::attach(name, mtu)?;
        let fd = channel.fd();
        Ok((
            Self {
                channel: Mutex::new(Engine::new(channel, mtu as usize)),
                fd,
            },
            name,
        ))
    }

    pub(crate) fn fd(&self) -> RawFd {
        self.fd
    }

    pub(crate) fn receive(
        &self,
        buffers: &mut Vec<Packet>,
        consume: impl FnMut(Received),
    ) -> io::Result<usize> {
        self.channel
            .lock()
            .map_err(|_| io::Error::other("Skywalk channel lock poisoned"))?
            .receive(buffers, consume)
    }

    pub(crate) fn flush(&self, queue: &mut VecDeque<Packet>) -> io::Result<usize> {
        self.channel
            .lock()
            .map_err(|_| io::Error::other("Skywalk channel lock poisoned"))?
            .flush(queue)
    }
}

/// Refuse the experimental probe before loading APIs or opening any sockets.
pub fn probe() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "utun ring probe disabled: it triggered macOS kernel panics during connect(); see docs/utun-ring-panic.md",
    ))
}
