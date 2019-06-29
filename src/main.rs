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
use std::io::{Error, ErrorKind};
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

fn main() -> Result<(), Error> {
    let mut events = Events::with_capacity(256);
    let poll = Poll::new()?;
    let mut buffer = [0; 4096];

    // listen to anyone
    let udp4_server_s = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;
    let sa_udp4 = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), SYSLOG_UDP_PORT);

    #[cfg(unix)]
    udp4_server_s.set_reuse_port(true)?;
    udp4_server_s.set_reuse_address(true)?;
    udp4_server_s.bind(&sa_udp4.into())?;
    let udp4_server_mio = UdpSocket::from_socket(udp4_server_s.into_udp_socket())?;

    poll.register(&udp4_server_mio, UDP4, Ready::readable(), PollOpt::edge())?;

    // listen over IPv6 too
    let udp6_server_s = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;
    let sa6 = SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        SYSLOG_UDP_PORT,
    );

    #[cfg(unix)]
    udp6_server_s.set_reuse_port(true)?;
    udp6_server_s.set_reuse_address(true)?;
    udp6_server_s.set_only_v6(true)?;
    udp6_server_s.bind(&sa6.into())?;
    let udp6_server_mio = UdpSocket::from_socket(udp6_server_s.into_udp_socket())?;

    poll.register(&udp6_server_mio, UDP6, Ready::readable(), PollOpt::edge())?;

    // TCP IPv4
    let tcp4_server_s = Socket::new(Domain::ipv4(), Type::stream(), Some(Protocol::tcp()))?;
    let sa_tcp4 = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), SYSLOG_TCP_PORT);
    tcp4_server_s.set_reuse_address(true)?;

    #[cfg(unix)]
    tcp4_server_s.set_reuse_port(true)?;
    tcp4_server_s.bind(&sa_tcp4.into())?;
    tcp4_server_s.listen(128)?;
    let tcp4_listener = TcpListener::from_std(tcp4_server_s.into_tcp_listener())?;
    poll.register(&tcp4_listener, TCP4, Ready::readable(), PollOpt::edge())?;

    // TCP IPv6
    let tcp6_server_s = Socket::new(Domain::ipv6(), Type::stream(), Some(Protocol::tcp()))?;
    let sa_tcp6 = SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        SYSLOG_TCP_PORT,
    );
    tcp6_server_s.set_reuse_address(true)?;

    #[cfg(unix)]
    tcp6_server_s.set_reuse_port(true)?;
    tcp6_server_s.set_only_v6(true)?;
    tcp6_server_s.bind(&sa_tcp6.into())?;
    tcp6_server_s.listen(128)?;
    let tcp6_listener = TcpListener::from_std(tcp6_server_s.into_tcp_listener())?;
    poll.register(&tcp6_listener, TCP6, Ready::readable(), PollOpt::edge())?;

    let mut tok_dyn = 10;
    let mut tcp_tokens: HashMap<Token, TcpConn> = HashMap::new();
    let mut shutdown = false;
    while !shutdown {
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            match event.token() {
                UDP4 => match receive_udp(&udp4_server_mio, &mut buffer) {
                    Ok(()) => continue,
                    Err(e) => {
                        eprintln!("IPv4 receive {}", e);
                        shutdown = true;
                    }
                },
                UDP6 => match receive_udp(&udp6_server_mio, &mut buffer) {
                    Ok(()) => continue,
                    Err(e) => {
                        eprintln!("IPv6 receive {}", e);
                        shutdown = true;
                    }
                },
                TCP4 => match tcp4_listener.accept() {
                    Ok((stream, sa)) => {
                        let key = Token(tok_dyn);
                        let stream_clone = stream.try_clone()?;
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())?;
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
                        let stream_clone = stream.try_clone()?;
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())?;
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
                    if let Some(conn_ref) = tcp_tokens.get_mut(&tok) {
                        if receive_tcp(conn_ref, &mut buffer) {
                            poll.deregister(&conn_ref.stream)?;
                            tcp_tokens.remove(&tok);
                        }
                    } else {
                        eprintln!("stream for token {:?} missing", tok);
                    }
                }
            }
        }
    }
    Ok(())
}

// common receive routine
fn receive_udp(sock: &UdpSocket, buf: &mut [u8]) -> Result<(), Error> {
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
