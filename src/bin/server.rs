use std::net::{SocketAddr, UdpSocket};

use stun::attr::{self, parse::AttrIter as _};

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = UdpSocket::bind("[::]:3478")?;

	let mut stun = stun::Stun { buffer: [0; 2048] };
	loop {
		let (len, sender) = sock.recv_from(&mut stun.buffer)?;
		if stun.decode(len).is_err() {
			continue;
		}

		let sender = SocketAddr::new(sender.ip().to_canonical(), sender.port());

		let mut username = None;

		println!("{sender} {stun:?}");
		let unknown = stun.into_iter()
			.parse::<{attr::USERNAME}, &str>(&mut username)
			.collect_unknown::<4>();

		println!("Username: {username:?}");
		println!("Unknown Attributes: {unknown:?}");
	}
}
