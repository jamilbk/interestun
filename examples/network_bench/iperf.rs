//! Minimal iperf3 forward-UDP control protocol; TCP carries metadata only.
//! Protocol reference: esnet/iperf 3.21 src/iperf_{api,udp,client_api}.c.
//! No reverse, parallel streams, authentication, warmup omission, or TCP data.
use anyhow::{Context, Result, bail, ensure};
use interestun::{
    packet::{self, BATCH, Packet},
    platform::{
        batch::Receiver,
        network::Socket,
        readiness::{Events, Poll},
    },
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub struct Control(TcpStream);
impl Control {
    pub fn connect(target: SocketAddr, seconds: u64, size: usize, bitrate: u64) -> Result<Self> {
        let stream = TcpStream::connect_timeout(&target, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.set_nodelay(true)?;
        let mut control = Self(stream);
        let cookie = format!("{}\0", hex::encode(rand::random::<[u8; 18]>()));
        control.0.write_all(cookie.as_bytes())?;
        control.expect(9)?; // PARAM_EXCHANGE
        control.write_json(&json!({"udp": true, "omit": 0, "time": seconds,
            "num": 0, "blockcount": 0, "parallel": 1, "len": size, "window": 4 * 1024 * 1024,
            "bandwidth": bitrate, "udp_counters_64bit": 1,
            "get_server_output": 1, "client_version": "interestun-network-bench"}))?;
        control.expect(10)?; // CREATE_STREAMS
        Ok(control)
    }
    fn expect(&mut self, expected: u8) -> Result<()> {
        let mut state = [0];
        self.0
            .read_exact(&mut state)
            .context("iperf control state")?;
        if state[0] == 254 {
            // SERVER_ERROR
            let mut errors = [0; 8];
            self.0.read_exact(&mut errors)?;
            bail!(
                "iperf server error={} errno={}",
                u32::from_be_bytes(errors[..4].try_into()?),
                u32::from_be_bytes(errors[4..].try_into()?)
            );
        }
        ensure!(
            state[0] == expected,
            "iperf state {}, expected {expected}",
            state[0] as i8
        );
        Ok(())
    }
    fn write_json(&mut self, value: &Value) -> Result<()> {
        let data = serde_json::to_vec(value)?;
        self.0.write_all(&(data.len() as u32).to_be_bytes())?;
        self.0.write_all(&data)?;
        Ok(())
    }
    fn read_json(&mut self) -> Result<Value> {
        let mut header = [0; 4];
        self.0.read_exact(&mut header)?;
        let len = u32::from_be_bytes(header) as usize;
        ensure!(len <= 4 * 1024 * 1024, "oversized iperf results");
        let mut data = vec![0; len];
        self.0.read_exact(&mut data)?;
        Ok(serde_json::from_slice(&data)?)
    }
    pub fn start(&mut self, socket: &Socket, poll: &mut Poll, events: &mut Events) -> Result<()> {
        let pool = packet::pool(BATCH + 1);
        let mut packet = Packet::new(&pool).unwrap();
        packet.len = 4;
        packet.buffer()[..4].copy_from_slice(b"9876");
        let mut queue = VecDeque::from([packet]);
        ensure!(
            socket.flush(&mut queue)? == 1,
            "iperf UDP connect was not accepted"
        );
        let mut receiver = Receiver::new(pool);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut valid = false;
            match socket.receive(&mut receiver, |received| {
                let data = received.packet.data();
                valid = data == b"6789" || data == 987654321u32.to_le_bytes();
            }) {
                Ok(_) => {
                    ensure!(valid, "invalid iperf UDP connect reply");
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            ensure!(
                Instant::now() < deadline,
                "iperf UDP connect reply timed out"
            );
            poll.poll(
                events,
                Some(deadline.saturating_duration_since(Instant::now())),
            )?;
        }
        self.expect(1)?; // TEST_START
        self.expect(2)?; // TEST_RUNNING
        Ok(())
    }
    pub fn finish(
        mut self,
        packets: u64,
        size: usize,
        seconds: f64,
        user: f64,
        system: f64,
    ) -> Result<Value> {
        self.0.write_all(&[4])?; // TEST_END
        self.expect(13)?; // EXCHANGE_RESULTS
        self.write_json(&json!({
            "cpu_util_total": (user + system) * 100.0 / seconds,
            "cpu_util_user": user * 100.0 / seconds,
            "cpu_util_system": system * 100.0 / seconds,
            "sender_has_retransmits": 0,
            "streams": [{"id": 1, "bytes": packets * size as u64,
                "retransmits": -1, "jitter": 0, "errors": 0, "packets": packets,
                "start_time": 0, "end_time": seconds}]
        }))?;
        let result = self.read_json()?;
        self.expect(14)?; // DISPLAY_RESULTS
        self.0.write_all(&[16])?; // IPERF_DONE
        Ok(result)
    }
}
