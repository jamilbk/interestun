use anyhow::{Result, bail, ensure};
use boringtun::noise::cipher::CipherSuite;
use ipnet::IpNet;
use std::{collections::BTreeMap, net::SocketAddr};

#[derive(Clone, Default)]
pub struct Config {
    pub private_key: [u8; 32],
    pub listen_port: u16,
    pub peers: BTreeMap<[u8; 32], Peer>,
}

#[derive(Clone, Default)]
pub struct Peer {
    pub public_key: [u8; 32],
    pub preshared_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub keepalive: u16,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Cipher {
    Aes256Gcm,
    Chacha20Poly1305,
}
impl From<Cipher> for CipherSuite {
    fn from(value: Cipher) -> Self {
        match value {
            Cipher::Aes256Gcm => Self::Aes256Gcm,
            Cipher::Chacha20Poly1305 => Self::ChaCha20Poly1305,
        }
    }
}

fn key(value: &str) -> Result<[u8; 32]> {
    let mut key = [0; 32];
    hex::decode_to_slice(value, &mut key)?;
    Ok(key)
}

impl Config {
    /// Apply to a clone: a malformed request never partially changes live configuration.
    pub fn apply(&self, request: &str) -> Result<Self> {
        let mut next = self.clone();
        let mut current = None;
        let mut current_existed = false;
        let mut skip = false;
        ensure!(request.starts_with("set=1\n"), "expected set=1");
        ensure!(
            !request.trim_end_matches('\n').contains("\n\n"),
            "multiple requests in one frame"
        );
        for line in request.lines().skip(1).filter(|s| !s.is_empty()) {
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid line"))?;
            match name {
                "private_key" if current.is_none() => next.private_key = key(value)?,
                "listen_port" if current.is_none() => next.listen_port = value.parse()?,
                "fwmark" if current.is_none() => {
                    ensure!(value == "0", "fwmark unsupported")
                }
                "replace_peers" if current.is_none() => {
                    ensure!(value == "true", "invalid boolean");
                    next.peers.clear();
                }
                "public_key" => {
                    let public = key(value)?;
                    ensure!(public != [0; 32], "zero peer key");
                    current = Some(public);
                    current_existed = next.peers.contains_key(&public);
                    skip = false;
                    next.peers.entry(public).or_insert_with(|| Peer {
                        public_key: public,
                        ..Peer::default()
                    });
                }
                "remove" => {
                    ensure!(value == "true", "invalid boolean");
                    next.peers
                        .remove(&current.ok_or_else(|| anyhow::anyhow!("missing public key"))?);
                    skip = true;
                }
                "update_only" => {
                    ensure!(value == "true", "invalid boolean");
                    let k = current.ok_or_else(|| anyhow::anyhow!("missing public key"))?;
                    if !current_existed {
                        next.peers.remove(&k);
                        skip = true;
                    }
                }
                "preshared_key"
                | "endpoint"
                | "persistent_keepalive_interval"
                | "replace_allowed_ips"
                | "allowed_ip"
                | "protocol_version" => {
                    let k = current.ok_or_else(|| anyhow::anyhow!("missing public key"))?;
                    if skip {
                        continue;
                    }
                    let peer = next.peers.get_mut(&k).unwrap();
                    match name {
                        "preshared_key" => peer.preshared_key = key(value)?,
                        "endpoint" => peer.endpoint = Some(value.parse()?),
                        "persistent_keepalive_interval" => peer.keepalive = value.parse()?,
                        "replace_allowed_ips" => {
                            ensure!(value == "true", "invalid boolean");
                            peer.allowed_ips.clear();
                        }
                        "allowed_ip" => {
                            let net: IpNet = value.parse()?;
                            let net = net.trunc();
                            // WireGuard transfers an identical prefix to the latest peer.
                            for p in next.peers.values_mut() {
                                p.allowed_ips.retain(|n| *n != net);
                            }
                            next.peers.get_mut(&k).unwrap().allowed_ips.push(net);
                        }
                        "protocol_version" => ensure!(value == "1", "unsupported protocol version"),
                        _ => unreachable!(),
                    }
                }
                _ => bail!("unknown or misplaced UAPI field"),
            }
        }
        ensure!(next.peers.len() <= 4096, "peer limit exceeded");
        let mut endpoints = std::collections::HashSet::new();
        for peer in next.peers.values() {
            if let Some(endpoint) = peer.endpoint {
                ensure!(
                    endpoint.port() != 0
                        && !endpoint.ip().is_unspecified()
                        && !endpoint.ip().is_multicast(),
                    "invalid endpoint"
                );
                ensure!(
                    endpoints.insert(endpoint),
                    "duplicate connected UDP endpoint"
                );
            }
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transactional_and_prefix_transfer() {
        let a = "01".repeat(32);
        let b = "02".repeat(32);
        let initial = Config::default()
            .apply(&format!("set=1\npublic_key={a}\nallowed_ip=10.0.0.9/24\n"))
            .unwrap();
        assert!(
            initial
                .apply("set=1\nlisten_port=42\nprivate_key=bad\n")
                .is_err()
        );
        assert_eq!(initial.listen_port, 0);
        let next = initial
            .apply(&format!("set=1\npublic_key={b}\nallowed_ip=10.0.0.0/24\n"))
            .unwrap();
        assert!(next.peers[&[1; 32]].allowed_ips.is_empty());
        assert_eq!(next.peers[&[2; 32]].allowed_ips.len(), 1);
        let next = next
            .apply(&format!(
                "set=1\npublic_key={}\nupdate_only=true\nallowed_ip=::/0\n",
                "03".repeat(32)
            ))
            .unwrap();
        assert_eq!(next.peers.len(), 2);
        let replaced = next
            .apply(&format!(
                "set=1\nreplace_peers=true\npublic_key={a}\nupdate_only=true\nallowed_ip=::/0\n"
            ))
            .unwrap();
        assert!(replaced.peers.is_empty());
    }
}
