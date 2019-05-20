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
//!

use bytes::BytesMut;
use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

const SYSLOG_UDP_PORT: u16 = 514;
const SERVER4: Token = Token(0);
const SERVER6: Token = Token(1);

fn main() {
    let mut events = Events::with_capacity(1024);
    let poll = Poll::new().expect("Poll::new() failed");
    let mut buffer = [0; 4096];

    // listen to anyone
    let udp4_server_s =
        Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp())).expect("Socket::new");
    let sa4 = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), SYSLOG_UDP_PORT);

    #[cfg(unix)]
    udp4_server_s
        .set_reuse_port(true)
        .expect("v4 set_reuse_port");
    udp4_server_s.bind(&sa4.into()).expect("v4 bind");
    let udp4_server_mio =
        UdpSocket::from_socket(udp4_server_s.into_udp_socket()).expect("mio v4 from_socket");

    // listen over IPv6 too
    let udp6_server_s =
        Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp())).expect("Socket::new");
    let sa6 = SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        SYSLOG_UDP_PORT,
    );

    #[cfg(unix)]
    udp6_server_s.set_reuse_port(true).expect("set_reuse_port");
    udp6_server_s.set_only_v6(true).expect("set_only_v6");
    udp6_server_s.bind(&sa6.into()).expect("v6 bind");
    let udp6_server_mio =
        UdpSocket::from_socket(udp6_server_s.into_udp_socket()).expect("mio v6 from_socket");

    // edge triggering
    poll.register(
        &udp4_server_mio,
        SERVER4,
        Ready::readable(),
        PollOpt::edge(),
    )
    .expect("poll.register failed");
    poll.register(
        &udp6_server_mio,
        SERVER6,
        Ready::readable(),
        PollOpt::edge(),
    )
    .expect("poll.register failed");

    loop {
        poll.poll(&mut events, None).expect("poll.poll failed");
        for event in events.iter() {
            match event.token() {
                SERVER4 => receive(&udp4_server_mio, &mut buffer),
                SERVER6 => receive(&udp6_server_mio, &mut buffer),
                _ => (),
            }
        }
    }
}

// common receive routine
fn receive(sock: &UdpSocket, buf: &mut [u8]) {
    let (len, from) = sock
        .recv_from(buf.as_mut().into())
        .expect("recvfrom errors");
    let mut bytes = BytesMut::from(buf.as_ref());
    bytes.truncate(len);
    parse_msg(from, &mut bytes);
}

// decode packet
fn parse_msg(from: SocketAddr, bytes: &mut BytesMut) {
    println!("recv {} bytes from {:?}", bytes.len(), from);
}
