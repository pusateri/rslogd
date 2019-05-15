

use mio::net::UdpSocket;
use mio::{Events, Ready, Poll, PollOpt, Token};

const SERVER: Token = Token(0);

fn main() {
	let udp_server_socket = match UdpSocket::bind(&"127.0.0.1:514".parse().expect("parse failed")) {
	    Ok(new_socket) => new_socket,
	    Err(fail) => {
	        panic!("Failed to bind socket. {:?}", fail);
	    }
	};
    let mut events = Events::with_capacity(1024);
    let poll = Poll::new().expect("Poll::new() failed");
    let mut buffer = [0u8; 4096];
    poll.register(&udp_server_socket,SERVER, Ready::readable(), PollOpt::level()).expect("poll.register failed");

    // main event loop
    loop {
        poll.poll(&mut events, None).expect("poll.poll failed");
        for event in events.iter() {
            match event.token() {
                SERVER => {
                    let len = udp_server_socket.recv(&mut buffer).expect("recv errors");
                    println!("recv {} bytes", len);
                },
                _ => (),
            }
        }
    }
}
