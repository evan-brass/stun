use std::net::{UdpSocket, SocketAddr};

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = UdpSocket::bind("[::]:3478")?;

	let mut stun = stun::Stun { buffer: [0; 2048] };
	loop {
		let (len, sender) = sock.recv_from(&mut stun.buffer)?;
		if stun.decode(len).is_err() { continue }

		let sender = SocketAddr::new(sender.ip().to_canonical(), sender.port());

		println!("{sender} {stun:?}");
		for (_, typ, value) in &stun {
			println!(" - {typ}: {value:?}");
		}
	}
}
