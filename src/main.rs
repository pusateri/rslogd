//! Stage 5 - syslog server rslogd
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

use docopt::Docopt;
use index_pool::IndexPool;
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::{Events, Poll, PollOpt, Ready, Token};
use rustls;
use rustls::Session;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

#[macro_use]
extern crate serde_derive;

mod syslog;

const SYSLOG_UDP_PORT: u16 = 514;
const SYSLOG_TCP_PORT: u16 = 601;
const SYSLOG_TLS_PORT: u16 = 6514;

const UDP4: Token = Token(0);
const UDP6: Token = Token(1);
const TCP4: Token = Token(2);
const TCP6: Token = Token(3);
const TLS4: Token = Token(4);
const TLS6: Token = Token(5);

struct ClientConnection {
    stream: TcpStream,
    session: Option<rustls::ServerSession>,
    sa: SocketAddr,
    token_index: usize,
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

const USAGE: &'static str = "
Syslog server that supports UDP, TCP (deprecated), and TLS over IPv4 and IPv6.

`--certs' names the full certificate chain,
`--key' provides the RSA private key.

Usage:
  rslogd [--verbose] --certs CERTFILE --key KEYFILE 
  rslogd (--version | -v)
  rslogd (--help | -h)

Options:
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE. This should be a RSA
                        private key or PKCS8-encoded private key in PEM format.
    --verbose           Monitor progress.
    --version, -v       Show version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_verbose: bool,
    flag_certs: Option<String>,
    flag_key: Option<String>,
}

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| Ok(d.help(true)))
        .and_then(|d| Ok(d.version(Some(version))))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

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
    udp6_server_s.bind(&sa6.into()).expect("udp v6 bind");
    let udp6_server_mio =
        UdpSocket::from_socket(udp6_server_s.into_udp_socket()).expect("mio v6 from_socket");

    poll.register(&udp6_server_mio, UDP6, Ready::readable(), PollOpt::edge())
        .expect("poll.register udp6 failed");

    // TCP IPv4
    let tcp4_server_s = Socket::new(Domain::ipv4(), Type::stream(), Some(Protocol::tcp()))
        .expect("tcp4 Socket::new");
    let sa_tcp4 = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), SYSLOG_TCP_PORT);
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

    // general TLS setup
    let mut tls_conf = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    let certs = load_certs(args.flag_certs.as_ref().expect("--certs option missing"));
    let privkey = load_private_key(args.flag_key.as_ref().expect("--key option missing"));
    tls_conf
        .set_single_cert(certs, privkey)
        .expect("bad certificates/private key");
    let tls_config = Arc::new(tls_conf);

    // TLS IPv4
    let tls4_server_s = Socket::new(Domain::ipv4(), Type::stream(), Some(Protocol::tcp()))
        .expect("tls4 Socket::new");
    let sa_tls4 = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), SYSLOG_TLS_PORT);
    tls4_server_s
        .set_reuse_address(true)
        .expect("tls v4 set_reuse_address");
    #[cfg(unix)]
    tls4_server_s
        .set_reuse_port(true)
        .expect("tls v4 set_reuse_port");
    tls4_server_s.bind(&sa_tls4.into()).expect("tls v4 bind");
    tls4_server_s.listen(128).expect("tls v4 listen");
    let tls4_listener =
        TcpListener::from_std(tls4_server_s.into_tcp_listener()).expect("tls mio v4 from_socket");
    poll.register(&tls4_listener, TLS4, Ready::readable(), PollOpt::edge())
        .expect("poll.register tls4 failed");

    // TLS IPv6
    let tls6_server_s = Socket::new(Domain::ipv6(), Type::stream(), Some(Protocol::tcp()))
        .expect("tls6 Socket::new");
    let sa_tls6 = SocketAddr::new(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0).into(),
        SYSLOG_TLS_PORT,
    );
    tls6_server_s
        .set_reuse_address(true)
        .expect("tls v6 set_reuse_address");
    #[cfg(unix)]
    tls6_server_s
        .set_reuse_port(true)
        .expect("tls v6 set_reuse_port");
    tls6_server_s.bind(&sa_tls6.into()).expect("tls v6 bind");
    tls6_server_s.listen(128).expect("tls v6 listen");
    let tls6_listener =
        TcpListener::from_std(tls6_server_s.into_tcp_listener()).expect("tls mio v6 from_socket");
    poll.register(&tls6_listener, TLS6, Ready::readable(), PollOpt::edge())
        .expect("poll.register tls6 failed");

    // begin main event loop
    let mut tokens: HashMap<Token, ClientConnection> = HashMap::new();
    let mut pool = IndexPool::with_initial_index(6);    // allocate unused index for accepted sockets
    loop {
        poll.poll(&mut events, None).expect("poll.poll failed");
        for event in events.iter() {
            match event.token() {
                UDP4 => receive_udp(&udp4_server_mio, &mut buffer),
                UDP6 => receive_udp(&udp6_server_mio, &mut buffer),
                TCP4 => match tcp4_listener.accept() {
                    Ok((stream, sa)) => {
                        let idx = pool.new_id();
                        let key = Token(idx);
                        let stream_clone = stream.try_clone().expect("tcp4 stream clone");
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())
                            .expect("poll.register tcp4 dynamic failed");
                        let conn = ClientConnection {
                            stream: stream_clone,
                            session: None,
                            sa: sa,
                            token_index: idx,
                        };
                        tokens.insert(key, conn);
                    }
                    Err(_e) => eprintln!("tcp4 connection error"),
                },
                TCP6 => match tcp6_listener.accept() {
                    Ok((stream, sa)) => {
                        let idx = pool.new_id();
                        let key = Token(idx);
                        let stream_clone = stream.try_clone().expect("tcp6 stream clone");
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())
                            .expect("poll.register tcp6 dynamic failed");
                        let conn = ClientConnection {
                            stream: stream_clone,
                            session: None,
                            sa: sa,
                            token_index: idx,
                        };
                        tokens.insert(key, conn);
                    }
                    Err(_e) => eprintln!("tcp6 connection error"),
                },
                TLS4 => match tls4_listener.accept() {
                    Ok((stream, sa)) => {
                        let tls_session = rustls::ServerSession::new(&tls_config);
                        let idx = pool.new_id();
                        let key = Token(idx);
                        let stream_clone = stream.try_clone().expect("tls4 stream clone");
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())
                            .expect("poll.register tls4 dynamic failed");
                        let conn = ClientConnection {
                            stream: stream_clone,
                            session: Some(tls_session),
                            sa: sa,
                            token_index: idx,
                        };
                        tokens.insert(key, conn);
                    }
                    Err(_e) => eprintln!("tls4 connection error"),
                },
                TLS6 => match tls6_listener.accept() {
                    Ok((stream, sa)) => {
                        let tls_session = rustls::ServerSession::new(&tls_config);
                        let idx = pool.new_id();
                        let key = Token(idx);
                        let stream_clone = stream.try_clone().expect("tls4 stream clone");
                        poll.register(&stream_clone, key, Ready::readable(), PollOpt::edge())
                            .expect("poll.register tls6 dynamic failed");
                        let conn = ClientConnection {
                            stream: stream_clone,
                            session: Some(tls_session),
                            sa: sa,
                            token_index: idx,
                        };
                        tokens.insert(key, conn);
                    }
                    Err(_e) => eprintln!("tls6 connection error"),
                },
                tok => {
                    match tokens.get_mut(&tok) {
                        Some(conn_ref) => {
                            // if we have a TLS session, use TLS methods
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
                                    pool.return_id(conn_ref.token_index)
                                        .expect("tls pool return id");
                                    tokens.remove(&tok);
                                }
                            } else {
                                // it's TCP (no session)
                                if receive_tcp(conn_ref, &mut buffer) {
                                    poll.deregister(&conn_ref.stream).expect("deregister tcp"); // not necessary
                                    pool.return_id(conn_ref.token_index)
                                        .expect("tcp pool return id");
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
                eprintln!("read error: {}", e);
                return true;
            }
        };
    } else {
        true
    }
}
