use rand::random;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::{
	thread::sleep,
	time::{Duration, Instant},
};

mod server;
use server::Server;
use stun::Stun;

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = UdpSocket::bind("[::]:3478")?;
	let mut buffer = [0; 2048];
	let mut server = Server::new()?;

	loop {
		let (len, sender) = sock.recv_from(&mut buffer)?;

		// We bind a v6 Socket so we should only be receiving from v6 addresses (v4 peers will appear in the v6-mapped range)
		let SocketAddr::V6(sender) = sender else {
			continue;
		};

		// Check that the message has an expected length:
		let mut msg = Stun::new(buffer.as_mut_slice());
		if msg.len() != len {
			continue;
		}

		// Handle the packet:
		let start = Instant::now();
		let Some(receiver) = server.handle_turn(&mut msg, sender) else {
			continue;
		};

		// Prevent amplification attacks by dropping ~50% of responses that are larger than the request
		let out_len = msg.len();
		if out_len > len && random() {
			continue;
		}

		// Try to send the response, ignoring errors (could happen with multi-cast peer addresses for instance.)
		let Ok(_) = sock.send_to(&buffer[..out_len], receiver) else {
			continue;
		};

		// Sleep ~1 ms per 40 bytes sent:
		let wait = Duration::from_millis(1 + out_len as u64 / 40).saturating_sub(start.elapsed());
		sleep(wait);
	}
}
