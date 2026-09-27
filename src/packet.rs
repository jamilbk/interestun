use crossbeam_queue::ArrayQueue;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
pub const CAPACITY: usize = 2048;
pub const BATCH: usize = 128;
pub const HEADROOM: usize = 16;
pub type Pool = Arc<ArrayQueue<Box<[u8; CAPACITY]>>>;
pub struct Packet {
    buffer: Option<Box<[u8; CAPACITY]>>,
    pub len: usize,
    pub start: usize,
    pool: Pool,
}
impl Packet {
    pub fn new(pool: &Pool) -> Option<Self> {
        Some(Self {
            buffer: Some(pool.pop()?),
            len: 0,
            start: 0,
            pool: pool.clone(),
        })
    }
    pub fn data(&self) -> &[u8] {
        &self.buffer.as_ref().unwrap()[self.start..self.start + self.len]
    }
    pub fn data_mut(&mut self) -> &mut [u8] {
        let end = self.start + self.len;
        &mut self.buffer.as_mut().unwrap()[self.start..end]
    }
    pub fn buffer(&mut self) -> &mut [u8] {
        self.buffer.as_mut().unwrap().as_mut_slice()
    }
}
impl Drop for Packet {
    fn drop(&mut self) {
        let _ = self.pool.push(self.buffer.take().unwrap());
    }
}
pub fn pool(size: usize) -> Pool {
    let pool = Arc::new(ArrayQueue::new(size));
    for _ in 0..size {
        pool.push(Box::new([0; CAPACITY])).unwrap();
    }
    pool
}
/// Validate the IP length before routing or injecting. Return (source, destination).
pub fn addresses(p: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match p.first()? >> 4 {
        4 if p.len() >= 20 => {
            let ihl = (p[0] as usize & 15) * 4;
            let len = u16::from_be_bytes([p[2], p[3]]) as usize;
            if ihl < 20 || ihl > len || len > p.len() {
                return None;
            }
            Some((
                Ipv4Addr::new(p[12], p[13], p[14], p[15]).into(),
                Ipv4Addr::new(p[16], p[17], p[18], p[19]).into(),
            ))
        }
        6 if p.len() >= 40 => {
            let len = 40 + u16::from_be_bytes([p[4], p[5]]) as usize;
            if len > p.len() {
                return None;
            }
            Some((
                Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).ok()?).into(),
                Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?).into(),
            ))
        }
        _ => None,
    }
}
