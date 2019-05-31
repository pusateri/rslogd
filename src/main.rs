//! Stage 4 - syslog server rslogd
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
// TLS
use rustls;
use rustls::Session;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;

mod syslog;

const SYSLOG_UDP_PORT: u16 = 514;
const SYSLOG_TCP_PORT: u16 = 601;
const SYSLOG_TLS_PORT: u16 = 6514;

const UDP4: Token = Token(0);
const UDP6: Token = Token(1);
const TCP4: Token = Token(2);
const TCP6: Token = Token(3);
const TLS4: Token = Token(4);

struct ClientConnection {
    stream: TcpStream,
    session: Option<rustls::ServerSession>,
    sa: SocketAddr,
}

// from https://github.com/ctz/rustls/blob/master/rustls-mio/examples/tlsserver.rs
fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

// from https://github.com/ctz/rustls/blob/master/rustls-mio/examples/tlsserver.rs
fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn main() {
    let mut events = Events::with_capacity(1024);
    let poll = Poll::new().expect("Poll::new() failed");
    let mut buffer = [0; 4096];

    // UDP
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

    let udp6_server_s = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))
        .expect("udp6 Socket::new");
    let sa6 = SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        SYSLOG_UDP_PORT,
    );

    #[cfg(unix)]
    udp6_server_s
        .set_reuse_port(true)
        .expect("udp set_reuse_port");
    udp6_server_s.set_only_v6(true).expect("udp set_only_v6");
    udp6_server_s.bind(&sa6.into()).expect("v6 bind");
    let udp6_server_mio =
        UdpSocket::from_socket(udp6_server_s.into_udp_socket()).expect("mio v6 from_socket");

    poll.register(&udp6_server_mio, UDP6, Ready::readable(), PollOpt::edge())
        .expect("poll.register udp6 failed");

    // TCP
    let sa_tcp4 = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), SYSLOG_TCP_PORT);
    let listener4 = TcpListener::bind(&sa_tcp4).expect("TcpListener4");
    poll.register(&listener4, TCP4, Ready::readable(), PollOpt::edge())
        .expect("poll.register tcp4 failed");

    let sa_tcp6 = SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        SYSLOG_TCP_PORT,
    );
    let listener6 = TcpListener::bind(&sa_tcp6).expect("TcpListener6");
    poll.register(&listener6, TCP6, Ready::readable(), PollOpt::edge())
        .expect("poll.register tcp6 failed");

    // general TLS setup
    let mut tls_conf = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    let certs = load_certs("./nstest.org/cert.pem");
    let privkey = load_private_key("./nstest.org/privkey.pem");
    tls_conf
        .set_single_cert(certs, privkey)
        .expect("bad certificates/private key");
    let tls_config = Arc::new(tls_conf);

    // TLS IPv4
    let sa_tls4 = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), SYSLOG_TLS_PORT);
    let tls_listener4 = TcpListener::bind(&sa_tls4).expect("TlsListener4");
    poll.register(&tls_listener4, TLS4, Ready::readable(), PollOpt::edge())
        .expect("poll.register tls4 failed");

    let mut tok_dyn = 10;
    let mut tokens: HashMap<Token, ClientConnection> = HashMap::new();
    loop {
        poll.poll(&mut events, None).expect("poll.poll failed");
        for event in events.iter() {
            match event.token() {
                UDP4 => receive_udp(&udp4_server_mio, &mut buffer),
                UDP6 => receive_udp(&udp6_server_mio, &mut buffer),
                TCP4 => match listener4.accept() {
                    Ok((stream, sa)) => {
                        let key = Token(tok_dyn);
                        let stream_clone = stream.try_clone().expect("tcp4 stream clone");
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())
                            .expect("poll.register tcp4 dynamic failed");
                        let conn = ClientConnection {
                            stream: stream_clone,
                            session: None,
                            sa: sa,
                        };
                        tokens.insert(key, conn);
                        tok_dyn += 1;
                    }
                    Err(_e) => eprintln!("tcp4 connection error"),
                },
                TCP6 => match listener6.accept() {
                    Ok((stream, sa)) => {
                        let key = Token(tok_dyn);
                        let stream_clone = stream.try_clone().expect("tcp6 stream clone");
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())
                            .expect("poll.register tcp6 dynamic failed");
                        let conn = ClientConnection {
                            stream: stream_clone,
                            session: None,
                            sa: sa,
                        };
                        tokens.insert(key, conn);
                        tok_dyn += 1;
                    }
                    Err(_e) => eprintln!("tcp6 connection error"),
                },
                TLS4 => match tls_listener4.accept() {
                    Ok((stream, sa)) => {
                        println!("accepted TLS");
                        let tls_session = rustls::ServerSession::new(&tls_config);
                        println!("created new tls session");
                        let key = Token(tok_dyn);
                        let stream_clone = stream.try_clone().expect("tls4 stream clone");
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())
                            .expect("poll.register tls4 dynamic failed");
                        let conn = ClientConnection {
                            stream: stream_clone,
                            session: Some(tls_session),
                            sa: sa,
                        };
                        tokens.insert(key, conn);
                        tok_dyn += 1;
                    }
                    Err(_e) => eprintln!("tls4 connection error"),
                },
                tok => {
                    match tokens.get_mut(&tok) {
                        Some(conn_ref) => {
                            if let Some(ref mut session) = conn_ref.session {
                                if session.is_handshaking() {
                                    if session.wants_read() {
                                        let rc = session.read_tls(&mut conn_ref.stream);
                                        if rc.is_err() {
                                            continue;
                                        }
                                        if rc.unwrap() == 0 {
                                            continue;
                                        }
                                        let rc2 = session.process_new_packets();
                                        if rc2.is_err() {
                                            continue;
                                        }
                                    }
                                    while session.wants_write() {
                                        let rc = session.write_tls(&mut conn_ref.stream);
                                        if rc.is_err() {
                                            continue;
                                        }
                                        if rc.unwrap() == 0 {
                                            continue;
                                        }
                                    }
                                    continue;
                                }
                                // finished TLS handshake
                                if receive_tls(conn_ref, &mut buffer) {
                                    poll.deregister(&conn_ref.stream).expect("deregister tls"); // not necessary
                                    tokens.remove(&tok);
                                }
                            } else {
                                if receive_tcp(conn_ref, &mut buffer) {
                                    poll.deregister(&conn_ref.stream).expect("deregister tcp"); // not necessary
                                    tokens.remove(&tok);
                                }
                            }
                        }
                        None => eprintln!("missing stream for Token {:?}", tok),
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
            "error parsing {} bytes over UDP: {:?}",
            len,
            String::from_utf8(buf[0..len].to_vec())
        );
    }
}

fn receive_tcp(conn_ref: &mut ClientConnection, buf: &mut [u8]) -> bool {
    match conn_ref.stream.read(buf) {
        Ok(0) => {
            println!("read returned 0");
            true
        }
        Ok(len) => {
            if let Some(msg) = syslog::parse(conn_ref.sa, len, buf) {
                println!("{:?}", msg);
            } else {
                println!(
                    "error parsing {} bytes over TCP: {:?}",
                    len,
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

fn receive_tls(conn_ref: &mut ClientConnection, buf: &mut [u8]) -> bool {
    if let Some(ref mut session) = conn_ref.session {
        let rc = session.read_tls(&mut conn_ref.stream);
        if rc.is_err() {
            return true;
        }
        if rc.unwrap() == 0 {
            return true;
        }
        let processed = session.process_new_packets();
        if processed.is_err() {
            return true;
        }
        let rc = session.read(&mut buf[..2048]);
        match rc {
            Ok(0) => return true,
            Ok(len) => {
                if let Some(msg) = syslog::parse(conn_ref.sa, len, buf) {
                    println!("{:?}", msg);
                } else {
                    println!(
                        "error parsing {} bytes over TLS: {:?}",
                        len,
                        String::from_utf8(buf[0..len].to_vec())
                    );
                }
                return false;
            }
            Err(e) => {
                eprintln!("read_to_end error: {}", e);
                return true;
            }
        };
    } else {
        true
    }
}
