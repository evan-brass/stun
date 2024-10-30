use std::net::UdpSocket;
use std::{time::{Instant, Duration}, thread::sleep};
use rand::random;

mod server;
use server::Server;

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = UdpSocket::bind("[::]:3478")?;
	let mut buffer = [0; 2048];
	let mut server = Server::new()?;

	loop {
		let (len, sender) = sock.recv_from(&mut buffer)?;
		let start = Instant::now();

		// Handle the packet:
		let Some((out_len, receiver)) = server.handle(&mut buffer, len, sender) else { continue };

		// Prevent amplification attacks by dropping ~50% of responses that are larger than the request
		if out_len > len && random() {
			continue;
		}

		let _ = sock.send_to(&buffer[..out_len], receiver);
		
		// Sleep ~1 ms per 40 bytes sent:
		let wait = Duration::from_millis(1 + out_len as u64 / 40).saturating_sub(start.elapsed());
		sleep(wait);
	}
}
