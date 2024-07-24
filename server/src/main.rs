use std::{net::UdpSocket, rc::Rc};

mod stun;
mod dtls;

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = Rc::new(UdpSocket::bind("[::]:3478")?);

	let mut stun_server = stun::Server::new();
	let mut dtls_server = dtls::Server::new(sock.clone())?;

	let mut buffer = [0; 2048];
	loop {
		let (len, sender) = sock.recv_from(&mut buffer)?;
		if len < 1 { continue }

		match buffer[0] {
			0..=3 => stun_server.handle(&sock, sender, &mut buffer, len)?,
			20..=63 => dtls_server.handle(sender, &mut buffer, len)?,
			_ => continue
		}
	}
}
