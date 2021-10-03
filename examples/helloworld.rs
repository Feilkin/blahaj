//! Serving Hello, world!'s

use blahaj::{ParseError, Request, Response, Socket};

fn main() -> () {
    let socket = Socket::bind_and_listen("127.0.0.1:8081").expect("failed to create socket");

    let mut buffer = [0; 2 << 15];
    let mut offset;
    while let Ok((peer_socket, peer_address)) = socket.accept() {
        println!("Got connection from {}", peer_address);

        offset = 0;
        while let Ok(count) = peer_socket.read(&mut buffer[offset..]) {
            if count == 0 {
                break;
            }
            offset += count;

            match Request::parse(&buffer[0..offset]) {
                Ok(req) => {
                    println!("{}", req);

                    let resp = Response::new(200, "OK".as_bytes(), "Hello, World!".as_bytes());

                    resp.send(&peer_socket).unwrap();
                    break;
                }
                Err(ParseError::Incomplete) => {}
                Err(ParseError::Malformed) => break,
            }
        }

        println!("--------------------------")
    }
}
