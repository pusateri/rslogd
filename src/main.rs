//! Stage 2 - syslog server rslogd
//!
//! MUST run as root or use sudo
//!
//! ```
//! sudo cargo run
//! ```
//!
//! # panics
//!
//! If socket cannot bind to syslog UDP port 514 (permissions or already in use)
//! sudo allows the program to bind to a port < 1024
//!

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

mod syslog;

const SYSLOG_UDP_PORT: u16 = 514;
const SERVER4: Token = Token(0);
const SERVER6: Token = Token(1);

fn main() -> Result<(), Error> {
    let mut events = Events::with_capacity(256);
    let poll = Poll::new()?;
    let mut buffer = [0; 4096];

    // listen to anyone
    let udp4_server_s = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;
    let sa4 = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), SYSLOG_UDP_PORT);

    #[cfg(unix)]
    udp4_server_s.set_reuse_address(true)?;
    udp4_server_s.set_reuse_port(true)?;
    udp4_server_s.bind(&sa4.into())?;
    let udp4_server_mio = UdpSocket::from_socket(udp4_server_s.into_udp_socket())?;

    // listen over IPv6 too
    let udp6_server_s = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;
    let sa6 = SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        SYSLOG_UDP_PORT,
    );

    #[cfg(unix)]
    udp6_server_s.set_reuse_address(true)?;
    udp6_server_s.set_reuse_port(true)?;
    udp6_server_s.set_only_v6(true)?;
    udp6_server_s.bind(&sa6.into())?;
    let udp6_server_mio = UdpSocket::from_socket(udp6_server_s.into_udp_socket())?;

    // edge triggering
    poll.register(
        &udp4_server_mio,
        SERVER4,
        Ready::readable(),
        PollOpt::edge(),
    )?;
    poll.register(
        &udp6_server_mio,
        SERVER6,
        Ready::readable(),
        PollOpt::edge(),
    )?;

    let mut shutdown = false;
    while !shutdown {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            match event.token() {
                SERVER4 => match receive(&udp4_server_mio, &mut buffer) {
                    Ok(()) => continue,
                    Err(e) => {
                        eprintln!("IPv4 receive {}", e);
                        shutdown = true;
                    }
                },
                SERVER6 => match receive(&udp4_server_mio, &mut buffer) {
                    Ok(()) => continue,
                    Err(e) => {
                        eprintln!("IPv6 receive {}", e);
                        shutdown = true;
                    }
                },
                _ => shutdown = true,
            }
        }
    }
    Ok(())
}

// common receive routine
fn receive(sock: &UdpSocket, buf: &mut [u8]) -> Result<(), Error> {
    loop {
        let (len, from) = match sock.recv_from(buf) {
            Ok((len, from)) => (len, from),
            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted {
                    return Ok(());
                } else {
                    return Err(e);
                }
            }
        };

        if let Some(msg) = syslog::parse(from, len, buf) {
            println!("{:?}", msg);
        } else {
            match std::str::from_utf8(buf) {
                Ok(s) => eprintln!("error parsing: {}", s),
                Err(e) => eprintln!("received message not parseable and not UTF-8: {}", e),
            }
        }
    }
}
