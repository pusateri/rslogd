//! Stage 1 - syslog server rslogd
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
use std::io::ErrorKind;

const SERVER: Token = Token(0);

fn main() -> Result<(), std::io::Error> {
    let mut events = Events::with_capacity(256);
    let poll = Poll::new()?;
    let mut buffer = [0u8; 4096];

    // create listen socket
    let udp_server_socket = UdpSocket::bind(&"127.0.0.1:514".parse().expect("parse failed"))?;
    // tell mio about the socket
    poll.register(
        &udp_server_socket,
        SERVER,
        Ready::readable(),
        PollOpt::level(),
    )?;

    // main event loop
    let mut shutdown = false;
    while !shutdown {
        // wait for an event to occur
        poll.poll(&mut events, None)?;
        for event in events.iter() {
            // find token of matching event
            match event.token() {
                SERVER => {
                    // read from the socket
                    match udp_server_socket.recv(&mut buffer) {
                        Ok(len) => println!("recv {} bytes", len),
                        Err(e) => {
                            if e.kind() == ErrorKind::WouldBlock
                                || e.kind() == ErrorKind::Interrupted
                            {
                                continue;
                            } else {
                                shutdown = true;
                            }
                        }
                    }
                }
                _ => (),
            }
        }
    }
    Ok(())
}
