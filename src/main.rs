use std::{
    io::{Read, Write},
    net::TcpStream
};
use sha2::{Sha256, Digest};

fn main() {
    let mut hasher = Sha256::new();

    let range_increment = 64 * 1024;
    let mut range = range_increment;
    loop {
        let mut stream = TcpStream::connect("localhost:8080").expect("error connecting to the buggy server");
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Range: bytes={}-{}\r\n\
             Connection: close\r\n\
             \r\n",
             range - range_increment, range
        );
        stream.write_all(request.as_bytes()).expect("error sending request");

        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).expect("reading reply");

        // find the blank line
        let blank_line_idx = buffer
            .windows(4)
            .enumerate()
            .find(|(_idx, bytes)| {
                if  bytes[0] == b'\r' &&
                    bytes[1] == b'\n' &&
                    bytes[2] == b'\r' &&
                    bytes[3] == b'\n' { true }
                else { false }
            });

        let payload_start_idx = if let Some((blank_line_idx, _)) = blank_line_idx {
            // the returned index is the start of the window, therefore add +4 to get payload start idx
            blank_line_idx + 4
        } else {
            println!("Malformed response form the server, exiting...");
            return;
        };

        hasher.update(&buffer[payload_start_idx..]);

        // if the lenght of the received payload is not equal to the expected - data has been read in its entirety
        if buffer.len() < range_increment { break }

        range += range_increment;
    }

    println!("SHA-256 hash of the data: {:x}", hasher.finalize());
}
