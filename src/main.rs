//! Stage 3 - syslog server rslogd
//!
//! MUST run as root or use sudo
//!
//! ```
//! cargo build
//! sudo target/debug/rslogd
//! ```
//!
//! # panics
//!
//! If socket cannot bind to syslog UDP port 514 (permissions or already in use)
//!

use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Poll, PollOpt, Ready, Token};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

mod syslog;

const SYSLOG_UDP_PORT: u16 = 514;
const SYSLOG_TCP_PORT: u16 = 601;
const UDP4: Token = Token(0);
const UDP6: Token = Token(1);
const TCP4: Token = Token(2);
const TCP6: Token = Token(3);

struct TcpConn {
    stream: TcpStream,
    sa: SocketAddr,
}

fn main() {
    let mut events = Events::with_capacity(1024);
    let poll = Poll::new().expect("Poll::new() failed");
    let mut buffer = [0; 4096];

    // listen to anyone
    let udp4_server_s =
        Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp())).expect("Socket::new");
    let sa_udp4 = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), SYSLOG_UDP_PORT);

    #[cfg(unix)]
    udp4_server_s
        .set_reuse_port(true)
        .expect("v4 set_reuse_port");
    udp4_server_s.bind(&sa_udp4.into()).expect("v4 bind");
    let udp4_server_mio =
        UdpSocket::from_socket(udp4_server_s.into_udp_socket()).expect("mio v4 from_socket");

    poll.register(&udp4_server_mio, UDP4, Ready::readable(), PollOpt::edge())
        .expect("poll.register udp4 failed");

    // listen over IPv6 too
    let udp6_server_s =
        Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp())).expect("udp6 Socket::new");
    let sa6 = SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        SYSLOG_UDP_PORT,
    );

    #[cfg(unix)]
    udp6_server_s.set_reuse_port(true).expect("udp set_reuse_port");
    udp6_server_s.set_only_v6(true).expect("udp set_only_v6");
    udp6_server_s.bind(&sa6.into()).expect("v6 bind");
    let udp6_server_mio =
        UdpSocket::from_socket(udp6_server_s.into_udp_socket()).expect("mio v6 from_socket");

    poll.register(&udp6_server_mio, UDP6, Ready::readable(), PollOpt::edge())
        .expect("poll.register udp6 failed");

// TCP IPv4
    let tcp4_server_s = Socket::new(Domain::ipv4(), Type::stream(), Some(Protocol::tcp()))
        .expect("tcp4 Socket::new");
    let sa_tcp4 = SocketAddr::new(
        Ipv4Addr::new(0, 0, 0, 0).into(),
        SYSLOG_TCP_PORT,
    );
    tcp4_server_s
        .set_reuse_address(true)
        .expect("tcp v4 set_reuse_address");
    #[cfg(unix)]
    tcp4_server_s
        .set_reuse_port(true)
        .expect("tcp v4 set_reuse_port");
    tcp4_server_s.bind(&sa_tcp4.into()).expect("tcp v4 bind");
    tcp4_server_s.listen(128).expect("tcp v4 listen");
    let tcp4_listener =
        TcpListener::from_std(tcp4_server_s.into_tcp_listener()).expect("tcp mio v4 from_socket");
    poll.register(&tcp4_listener, TCP4, Ready::readable(), PollOpt::edge())
        .expect("poll.register tcp4 failed");

    // TCP IPv6
    let tcp6_server_s = Socket::new(Domain::ipv6(), Type::stream(), Some(Protocol::tcp()))
        .expect("tcp6 Socket::new");
    let sa_tcp6 = SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        SYSLOG_TCP_PORT,
    );
    tcp6_server_s
        .set_reuse_address(true)
        .expect("tcp v6 set_reuse_address");
    #[cfg(unix)]
    tcp6_server_s
        .set_reuse_port(true)
        .expect("tcp set_reuse_port");
    tcp6_server_s.set_only_v6(true).expect("tcp set_only_v6");
    tcp6_server_s.bind(&sa_tcp6.into()).expect("tcp v6 bind");
    tcp6_server_s.listen(128).expect("tcp v6 listen");
    let tcp6_listener =
        TcpListener::from_std(tcp6_server_s.into_tcp_listener()).expect("mio v6 from_socket");
    poll.register(&tcp6_listener, TCP6, Ready::readable(), PollOpt::edge())
.expect("poll.register tcp6 failed");

    let mut tok_dyn = 10;
    let mut tcp_tokens: HashMap<Token, TcpConn> = HashMap::new();
    loop {
        poll.poll(&mut events, None).expect("poll.poll failed");
        for event in events.iter() {
            match event.token() {
                UDP4 => receive_udp(&udp4_server_mio, &mut buffer),
                UDP6 => receive_udp(&udp6_server_mio, &mut buffer),
                TCP4 => match tcp4_listener.accept() {
                    Ok((stream, sa)) => {
                        let key = Token(tok_dyn);
                        let stream_clone = stream.try_clone().expect("tcp4 stream clone");
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())
                            .expect("poll.register tcp4 dynamic failed");
                        let conn = TcpConn {
                            stream: stream_clone,
                            sa: sa,
                        };
                        tcp_tokens.insert(key, conn);
                        tok_dyn += 1;
                    }
                    Err(_e) => eprintln!("tcp4 connection error"),
                },
                TCP6 => match tcp6_listener.accept() {
                    Ok((stream, sa)) => {
                        let key = Token(tok_dyn);
                        let stream_clone = stream.try_clone().expect("tcp6 stream clone");
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())
                            .expect("poll.register tcp6 dynamic failed");
                        let conn = TcpConn {
                            stream: stream_clone,
                            sa: sa,
                        };
                        tcp_tokens.insert(key, conn);
                        tok_dyn += 1;
                    }
                    Err(_e) => eprintln!("tcp6 connection error"),
                },
                tok => {
                    let conn_ref = tcp_tokens.get_mut(&tok).expect("missing stream");
                    if receive_tcp(conn_ref, &mut buffer) {
                        poll.deregister(&conn_ref.stream).expect("deregister tcp"); // not necessary
                        tcp_tokens.remove(&tok);
                    }
                }
            }
        }
    }
}

// common receive routine
fn receive_udp(sock: &UdpSocket, buf: &mut [u8]) {
    let (len, from) = sock.recv_from(buf).expect("recvfrom errors");

    if let Some(msg) = syslog::parse(from, len, buf) {
        println!("{:?}", msg);
    } else {
        println!(
            "error parsing: {:?}",
            String::from_utf8(buf[0..len].to_vec())
        );
    }
}

fn receive_tcp(conn_ref: &mut TcpConn, buf: &mut [u8]) -> bool {
    match conn_ref.stream.read(buf) {
        Ok(0) => true,
        Ok(len) => {
            if let Some(msg) = syslog::parse(conn_ref.sa, len, buf) {
                println!("{:?}", msg);
            } else {
                println!(
                    "error parsing: {:?}",
                    String::from_utf8(buf[0..len].to_vec())
                );
            }
            false
        }
        Err(e) => {
            eprintln!("read error: {}", e);
            true
        }
    }
}
