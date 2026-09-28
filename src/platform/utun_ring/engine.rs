//! Shared by the native channel and the memory-backed tests. No syscalls here.
use crate::{
    packet::{BATCH, CAPACITY, HEADROOM, Packet},
    platform::batch::Received,
};
use std::{collections::VecDeque, io};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Direction {
    Rx,
    Tx,
}

/// Slot views are borrowed only until the next channel operation. Implementors
/// must keep the current slot reserved until advance; only TX views are mutable.
/// Cursors are opaque, valid within one batch/direction, and never persisted.
pub(super) trait Slots {
    type Cursor: Copy;
    fn check(&self) -> io::Result<()>;
    fn available(&self, direction: Direction) -> usize;
    fn rx_next(
        &mut self,
        previous: Option<Self::Cursor>,
    ) -> io::Result<Option<(Self::Cursor, &[u8])>>;
    fn tx_next(
        &mut self,
        previous: Option<Self::Cursor>,
    ) -> io::Result<Option<(Self::Cursor, &mut [u8])>>;
    fn tx_len(&mut self, slot: Self::Cursor, len: usize) -> io::Result<()>;
    fn advance(&mut self, direction: Direction, last: Self::Cursor) -> io::Result<()>;
    fn sync(&mut self, direction: Direction) -> io::Result<()>;
}

pub(super) struct Engine<C> {
    pub(super) channel: C,
    mtu: usize,
    failed: bool,
}

impl<C: Slots> Engine<C> {
    pub(super) fn new(channel: C, mtu: usize) -> Self {
        Self {
            channel,
            mtu,
            failed: false,
        }
    }

    fn check(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Skywalk channel stopped after an I/O failure",
            ));
        }
        let result = self.channel.check();
        self.fatal(result)
    }

    // After an advance/sync error, progress can be ambiguous. Never let the
    // runtime retry EINTR/WouldBlock against possibly published slot contents.
    fn fatal<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        result.map_err(|error| {
            self.failed = true;
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("Skywalk channel failed: {error}"),
            )
        })
    }

    fn ready(&mut self, direction: Direction) -> io::Result<usize> {
        self.check()?;
        if self.channel.available(direction) == 0 {
            let result = self.channel.sync(direction);
            self.fatal(result)?;
            self.check()?;
        }
        let count = self.channel.available(direction).min(BATCH);
        if count == 0 {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            Ok(count)
        }
    }

    pub(super) fn receive(
        &mut self,
        buffers: &mut Vec<Packet>,
        mut consume: impl FnMut(Received),
    ) -> io::Result<usize> {
        // Retain readiness on pool exhaustion: no ring operation occurred.
        if buffers.is_empty() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        let limit = self.ready(Direction::Rx)?.min(buffers.len());
        let mut previous = None;
        let mut consumed = 0;
        let mut copied = 0;
        for _ in 0..limit {
            let result = self.channel.rx_next(previous);
            let next = match result {
                Ok(next) => next,
                Err(error) => return self.fatal(Err(error)),
            };
            let Some((cursor, frame)) = next else {
                break;
            };
            previous = Some(cursor);
            consumed += 1;
            // Malformed slots are consumed without allocating or delivering.
            if let Some(ip) = decode(frame, self.mtu) {
                let packet = &mut buffers[copied];
                packet.start = HEADROOM;
                packet.len = ip.len();
                packet.buffer()[HEADROOM..HEADROOM + ip.len()].copy_from_slice(ip);
                copied += 1;
            }
        }
        let Some(last) = previous else {
            self.check()?;
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let result = self.channel.advance(Direction::Rx, last);
        self.fatal(result)?;
        let result = self.channel.sync(Direction::Rx);
        self.fatal(result)?;
        self.check()?;
        // The kernel may now reuse every RX slot. Deliver only owned buffers.
        for packet in buffers.drain(..copied) {
            consume(Received {
                packet,
                source: None,
            });
        }
        Ok(consumed)
    }

    pub(super) fn flush(&mut self, queue: &mut VecDeque<Packet>) -> io::Result<usize> {
        if queue.is_empty() {
            return Ok(0);
        }
        self.check()?;
        // Validate the entire attempted prefix before modifying shared storage.
        for packet in queue.iter().take(BATCH) {
            let ip = packet.data();
            if ip.len() > self.mtu || crate::packet::addresses(ip).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid or oversized IP packet for Skywalk slot",
                ));
            }
        }
        let limit = self.ready(Direction::Tx)?.min(queue.len());
        let mut previous = None;
        let mut sent = 0;
        for packet in queue.iter().take(limit) {
            let result = self.channel.tx_next(previous);
            let next = match result {
                Ok(next) => next,
                Err(error) => return self.fatal(Err(error)),
            };
            let Some((cursor, storage)) = next else {
                break;
            };
            let ip = packet.data();
            let len = ip.len() + 4;
            if storage.len() < len {
                return self.fatal(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Skywalk slot smaller than validated MTU",
                )));
            }
            let family = if ip[0] >> 4 == 6 {
                libc::AF_INET6
            } else {
                libc::AF_INET
            };
            storage[..4].copy_from_slice(&(family as u32).to_be_bytes());
            storage[4..len].copy_from_slice(ip);
            let result = self.channel.tx_len(cursor, len);
            self.fatal(result)?;
            previous = Some(cursor);
            sent += 1;
        }
        let Some(last) = previous else {
            self.check()?;
            return Err(io::ErrorKind::WouldBlock.into());
        };
        let result = self.channel.advance(Direction::Tx, last);
        self.fatal(result)?;
        // Ownership has transferred. A sync failure must not resend this prefix.
        queue.drain(..sent);
        let result = self.channel.sync(Direction::Tx);
        self.fatal(result)?;
        self.check()?;
        Ok(sent)
    }
}

fn decode(frame: &[u8], mtu: usize) -> Option<&[u8]> {
    let family = u32::from_be_bytes(frame.get(..4)?.try_into().ok()?);
    let ip = &frame[4..];
    if ip.len() > mtu || ip.len() > CAPACITY - HEADROOM {
        return None;
    }
    let expected = match family as i32 {
        libc::AF_INET => 4,
        libc::AF_INET6 => 6,
        _ => return None,
    };
    (ip.first()? >> 4 == expected && crate::packet::addresses(ip).is_some()).then_some(ip)
}
