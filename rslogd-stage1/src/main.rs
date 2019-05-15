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
//!

use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};

const SERVER: Token = Token(0);

fn main() {
    let mut events = Events::with_capacity(1024);
    let poll = Poll::new().expect("Poll::new() failed");
    let mut buffer = [0u8; 4096];

    // create listen socket
    let udp_server_socket = match UdpSocket::bind(&"127.0.0.1:514".parse().expect("parse failed")) {
        Ok(new_socket) => new_socket,
        Err(fail) => {
            panic!("Failed to bind socket. {:?}", fail);
        }
    };
    // tell mio about the socket
    poll.register(
        &udp_server_socket,
        SERVER,
        Ready::readable(),
        PollOpt::level(),
    )
    .expect("poll.register failed");

    // main event loop
    loop {
        // wait for an event to occur
        poll.poll(&mut events, None).expect("poll.poll failed");
        for event in events.iter() {
            // find token of matching event
            match event.token() {
                SERVER => {
                    // read from the socket
                    let len = udp_server_socket.recv(&mut buffer).expect("recv errors");
                    println!("recv {} bytes", len);
                }
                _ => (),
            }
        }
    }
}
