//! Connected peer transport. The daemon selects one backend at build time.
use super::batch::{Received, Receiver, Sender};
use crate::packet::Packet;
use mio::Interest;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::VecDeque,
    io,
    net::{SocketAddr, UdpSocket},
    os::fd::AsRawFd,
};

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
pub enum Backend {
    #[cfg_attr(not(feature = "apple-network"), default)]
    Bsd,
    #[cfg(feature = "apple-network")]
    #[default]
    Network,
}

pub fn bind(local: SocketAddr, endpoint: Option<SocketAddr>) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        if local.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if local.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    socket.bind(&local.into())?;
    if let Some(endpoint) = endpoint {
        socket.connect(&endpoint.into())?;
    }
    Ok(socket.into())
}

pub enum PeerSocket {
    Bsd(UdpSocket),
    #[cfg(feature = "apple-network")]
    Network(super::network::Socket),
}
impl PeerSocket {
    pub fn connect(backend: Backend, port: u16, endpoint: SocketAddr) -> io::Result<Self> {
        match backend {
            Backend::Bsd => {
                let local = SocketAddr::new(
                    if endpoint.is_ipv4() {
                        std::net::Ipv4Addr::UNSPECIFIED.into()
                    } else {
                        std::net::Ipv6Addr::UNSPECIFIED.into()
                    },
                    port,
                );
                Ok(Self::Bsd(bind(local, Some(endpoint))?))
            }
            #[cfg(feature = "apple-network")]
            Backend::Network => Ok(Self::Network(super::network::Socket::connect(
                port, endpoint,
            )?)),
        }
    }
    pub fn rx_fd(&self) -> i32 {
        match self {
            Self::Bsd(s) => s.as_raw_fd(),
            #[cfg(feature = "apple-network")]
            Self::Network(s) => s.rx_fd(),
        }
    }
    pub fn tx_fd(&self) -> i32 {
        match self {
            Self::Bsd(s) => s.as_raw_fd(),
            #[cfg(feature = "apple-network")]
            Self::Network(s) => s.tx_fd(),
        }
    }
    pub fn tx_interest(&self) -> Interest {
        match self {
            Self::Bsd(_) => Interest::WRITABLE,
            #[cfg(feature = "apple-network")]
            Self::Network(_) => Interest::READABLE,
        }
    }
    pub fn is_network(&self) -> bool {
        match self {
            Self::Bsd(_) => false,
            #[cfg(feature = "apple-network")]
            Self::Network(_) => true,
        }
    }
    pub fn flush(&self, writer: &mut Sender, queue: &mut VecDeque<Packet>) -> io::Result<usize> {
        match self {
            Self::Bsd(s) => writer.flush(s.as_raw_fd(), false, queue),
            #[cfg(feature = "apple-network")]
            Self::Network(s) => s.flush(queue),
        }
    }
    pub fn receive(
        &self,
        receiver: &mut Receiver,
        pool: &crate::packet::Pool,
        consume: impl FnMut(Received),
    ) -> io::Result<usize> {
        let _ = pool;
        match self {
            Self::Bsd(s) => receiver.receive(s.as_raw_fd(), false, consume),
            #[cfg(feature = "apple-network")]
            Self::Network(s) => s.receive(receiver, consume),
        }
    }
}
