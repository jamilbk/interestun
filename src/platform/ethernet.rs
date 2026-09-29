//! IPv4 Ethernet edge for the public NEEthernetTunnelProvider packet flow.
//! The encrypted wire format remains IP. No interfaces or sockets are opened here.
use crate::packet::Packet;
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

pub const HOST: [u8; 6] = [0x02, 0x49, 0x54, 0, 0, 1];
pub const ROUTER: [u8; 6] = [0x02, 0x49, 0x54, 0, 0, 2];
pub struct Ethernet {
    pub routes: Vec<Ipv4Net>,
    pub local: Vec<Ipv4Addr>,
}
pub enum Input<'a> {
    Ip(&'a [u8]),
    Arp([u8; 60]),
    Drop,
}
impl Ethernet {
    pub fn input<'a>(&self, frame: &'a [u8]) -> Input<'a> {
        if frame.len() < 14 || frame[6..12] != HOST {
            return Input::Drop;
        }
        match &frame[12..14] {
            [8, 0] if frame[..6] == ROUTER => {
                let ip = &frame[14..];
                if ip.len() < 20 || ip[0] >> 4 != 4 {
                    return Input::Drop;
                }
                let len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
                if len > ip.len() || crate::packet::addresses(&ip[..len]).is_none() {
                    return Input::Drop;
                }
                Input::Ip(&ip[..len]) // Exclude Ethernet padding from encryption.
            }
            [8, 6] if frame.len() >= 42 => {
                let a = &frame[14..42];
                if (frame[..6] != [255; 6] && frame[..6] != ROUTER)
                    || a[..8] != [0, 1, 8, 0, 6, 4, 0, 1]
                    || a[8..14] != HOST
                {
                    return Input::Drop;
                }
                let source = Ipv4Addr::new(a[14], a[15], a[16], a[17]);
                let target = Ipv4Addr::new(a[24], a[25], a[26], a[27]);
                // Never answer probes for our own address or proxy unrelated routes.
                if !self.local.contains(&source)
                    || self.local.contains(&target)
                    || target.is_unspecified()
                    || target.is_multicast()
                    || target.is_broadcast()
                    || !self.routes.iter().any(|r| r.contains(&target))
                {
                    return Input::Drop;
                }
                let mut reply = [0; 60];
                reply[..6].copy_from_slice(&HOST);
                reply[6..12].copy_from_slice(&ROUTER);
                reply[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
                reply[22..28].copy_from_slice(&ROUTER);
                reply[28..32].copy_from_slice(&target.octets());
                reply[32..38].copy_from_slice(&HOST);
                reply[38..42].copy_from_slice(&source.octets());
                Input::Arp(reply)
            }
            _ => Input::Drop,
        }
    }
    pub fn wrap(&self, packet: &mut Packet) {
        // Transport receive normally leaves 16 bytes of headroom. Handshake
        // fallback packets may start at zero; only that slow path moves payload.
        if packet.start < 14 {
            let start = packet.start;
            let len = packet.len;
            packet.buffer().copy_within(start..start + len, 14);
            packet.start = 14;
        }
        packet.start -= 14;
        packet.len += 14;
        let unpadded = packet.len;
        packet.len = packet.len.max(60);
        packet.data_mut()[unpadded..].fill(0);
        let frame = packet.data_mut();
        frame[..6].copy_from_slice(&HOST);
        frame[6..12].copy_from_slice(&ROUTER);
        frame[12..14].copy_from_slice(&[8, 0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn edge() -> Ethernet {
        Ethernet {
            local: vec!["10.20.0.2".parse().unwrap()],
            routes: vec!["10.20.0.1/32".parse().unwrap()],
        }
    }
    pub fn ip() -> Vec<u8> {
        let mut ip = vec![0; 1420];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&1420u16.to_be_bytes());
        ip[12..16].copy_from_slice(&[10, 20, 0, 2]);
        ip[16..20].copy_from_slice(&[10, 20, 0, 1]);
        ip
    }
    #[test]
    fn ipv4_padding_truncation_and_protocol_validation() {
        let mut frame = vec![0; 14];
        frame[..6].copy_from_slice(&ROUTER);
        frame[6..12].copy_from_slice(&HOST);
        frame[12..14].copy_from_slice(&[8, 0]);
        frame.extend(ip());
        frame.extend([0; 32]);
        assert!(matches!(edge().input(&frame), Input::Ip(p) if p == ip()));
        for len in 0..1434 {
            assert!(matches!(edge().input(&frame[..len]), Input::Drop));
        }
        frame[12..14].copy_from_slice(&[0x81, 0]); // VLAN unsupported.
        assert!(matches!(edge().input(&frame), Input::Drop));
        frame[12..14].copy_from_slice(&[0x86, 0xdd]);
        assert!(matches!(edge().input(&frame), Input::Drop));
    }
    #[test]
    fn arp_is_local_and_scoped_to_peer_routes() {
        let mut request = [0; 42];
        request[..6].fill(255);
        request[6..12].copy_from_slice(&HOST);
        request[12..22].copy_from_slice(&[8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
        request[22..28].copy_from_slice(&HOST);
        request[28..32].copy_from_slice(&[10, 20, 0, 2]);
        request[38..42].copy_from_slice(&[10, 20, 0, 1]);
        let Input::Arp(reply) = edge().input(&request) else {
            panic!("missing ARP reply")
        };
        assert_eq!(&reply[..6], &HOST);
        assert_eq!(&reply[20..22], &[0, 2]);
        assert_eq!(&reply[22..28], &ROUTER);
        assert_eq!(&reply[28..32], &[10, 20, 0, 1]);
        assert_eq!(&reply[38..42], &[10, 20, 0, 2]);
        for target in [2, 3] {
            request[41] = target;
            assert!(matches!(edge().input(&request), Input::Drop));
        }
        request[41] = 1;
        request[28..32].fill(0); // DAD probe is not a request to route traffic.
        assert!(matches!(edge().input(&request), Input::Drop));
    }
    #[test]
    fn injection_preserves_payload_address_with_headroom_and_handles_fallback() {
        let pool = crate::packet::pool(1);
        for start in [0, 16] {
            let mut p = Packet::new(&pool).unwrap();
            p.start = start;
            p.len = 1420;
            p.data_mut().copy_from_slice(&ip());
            let pointer = p.data().as_ptr();
            edge().wrap(&mut p);
            assert_eq!(&p.data()[14..], ip());
            assert_eq!(&p.data()[..6], &HOST);
            assert_eq!(&p.data()[6..12], &ROUTER);
            if start == 16 {
                assert_eq!(p.data()[14..].as_ptr(), pointer);
            }
        }
    }
}
