use std::net::{SocketAddr, UdpSocket};

use stun::attr::integrity::IntegritySha1;
use stun::attr::{MESSAGE_INTEGRITY, USERNAME};
use stun::{attr::parse::AttrIter as _, Class, Method};

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
		let mut integrity = None;

		let unknown = stun
			.into_iter()
			.parse::<USERNAME, &str>(&mut username)
			.parse::<MESSAGE_INTEGRITY, IntegritySha1>(&mut integrity)
			.collect_unknown::<4>();

		println!("{sender} {stun:?} {unknown:?}");
		println!("username: {username:?}");
		println!(
			"integrity: {integrity:?} - {}",
			integrity.is_some_and(
				|r| r.is_ok_and(|mut i| i.verify("the/ice/password/constant".as_bytes()))
			)
		);

		if let Some(_unknown) = unknown {
			// Notify the peer which attributes we didn't understand.
			// NOTICE: we are reusing the recv buffer for our response, and therefore the method, txid, cookie, etc are already correctly set
			stun.set_class(Class::Error);
			stun.set_length(0);
		} else {
			match (stun.class(), stun.method()) {
				(Class::Request, Method::Binding) => {
					stun.set_class(Class::Success);
					stun.set_length(0); // Clear the attributes
					continue;
				}
				_ => continue,
			}
		}
		sock.send_to(&stun.buffer[..stun.len()], sender)?;
	}
}
