use std::{
    io::{Read, Write},
    net::TcpStream
};
use sha2::{Sha256, Digest};

fn get_content_len(headers: &[u8]) -> u64 {
    String::from_utf8_lossy(headers)
        .split("\r\n")
        .find(|line|{ line.contains("Content-Length") })
        .expect("missing Contenet-Lenght header")
        .split(": ")
        .nth(1)
        .expect("malformed Content-Length header")
        .parse::<u64>()
        .expect("malformed Content-Length value")
}

fn main() {
    let mut hasher = Sha256::new();

    let mut total_len = 1024*1024;
    let mut confirmed_total_len = false;
    let mut start = 0;

    while start < total_len {
        let mut stream = TcpStream::connect("localhost:8080").expect("error connecting to the buggy server");
        let request = format!(
            "GET / HTTP/1.1\r\n\
             Host: localhost\r\n\
             Range: bytes={}-{}\r\n\
             Connection: close\r\n\
             \r\n",
             start, total_len
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

        if !confirmed_total_len {
            total_len = get_content_len(&buffer[..payload_start_idx]);
            confirmed_total_len = true;
        }
        start += buffer[payload_start_idx..].len() as u64;
    }

    println!("SHA-256 hash of the data: {:x}", hasher.finalize());
}
