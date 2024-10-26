use std::net::UdpSocket;
use std::{time::{Instant, Duration}, thread::sleep};
use openssl::rand::rand_bytes;

mod server;
use server::Server;

#[derive(Debug, Default)]
struct Stats {
	n_packets_recv: usize,
	n_packets_sent: usize,
	n_packets_drop: usize,

	bytes_recv: usize,
	bytes_sent: usize,
}

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = UdpSocket::bind("[::]:3478")?;
	let mut server = Server::new()?;
	let mut stats = Stats::default();

	let mut stamp = Instant::now();

	let mut buffer = [0; 2048];
	loop {
		let now = Instant::now();
		let dur = now.duration_since(stamp);
		if dur.as_secs() > 3600 {
			println!("{dur:?} {:?}", std::mem::take(&mut stats));
			stamp = now;
		}

		let (len, sender) = sock.recv_from(&mut buffer)?;
		stats.n_packets_recv += 1;
		stats.bytes_recv += len;

		// Handle the packet:
		let Some((out_len, receiver)) = server.handle(&mut buffer, len, sender) else { continue };

		// Prevent amplification attacks by dropping ~50% of responses that are larger than the request
		if out_len > len {
			let mut drop_test = [0];
			rand_bytes(&mut drop_test)?;
			if (0..u8::MAX/2).contains(&drop_test[0]) {
				stats.n_packets_drop += 1;
				continue
			}
		}

		let _ = sock.send_to(&buffer[..out_len], receiver);
		stats.n_packets_sent += 1;
		stats.bytes_sent += out_len;

		// Sleep ~1 ms per 40 bytes sent:
		sleep(Duration::from_millis(1 + out_len as u64 / 40));
	}
}
