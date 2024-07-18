use std::net::{SocketAddr, UdpSocket};

use stun::attr::fingerprint::Fingerprint;
use stun::attr::integrity::IntegritySha1;
use stun::attr::{ICE_CONTROLLED, ICE_CONTROLLING, MESSAGE_INTEGRITY, NONCE, PRIORITY, REALM, USERNAME, FINGERPRINT, USE_CANDIDATE, DATA, XOR_MAPPED_ADDRESS};
use stun::{attr::parse::AttrIter as _, Class, Method};

const LONG_KEY: &[u8] = &[1, 92, 138, 151, 62, 164, 180, 169, 201, 69, 246, 144, 20, 43, 243, 173];
const SHORT_KEY: &[u8] = "the/ice/password/constant".as_bytes();

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = UdpSocket::bind("[::]:3478")?;

	let mut stun = stun::Stun { buffer: [0; 2048] };
	loop {
		let (len, sender) = sock.recv_from(&mut stun.buffer)?;
		if stun.decode(len).is_err() {
			continue;
		}

		let mapped = SocketAddr::new(sender.ip().to_canonical(), sender.port());

		let mut username = None;
		let mut integrity = None;
		let mut realm = None;
		let mut nonce = None;
		let mut priority = None;
		let mut ice_controlled = None;
		let mut ice_controlling = None;
		let mut fingerprint = None;
		let mut use_candidate = None;
		let mut data = None;

		let unknown = stun
			.into_iter()
			.parse::<USERNAME, &str>(&mut username)
			.parse::<MESSAGE_INTEGRITY, IntegritySha1>(&mut integrity)
			.parse::<REALM, &str>(&mut realm)
			.parse::<NONCE, &str>(&mut nonce)
			.parse::<PRIORITY, u32>(&mut priority)
			.parse::<ICE_CONTROLLED, u64>(&mut ice_controlled)
			.parse::<ICE_CONTROLLING, u64>(&mut ice_controlling)
			.parse::<FINGERPRINT, Fingerprint>(&mut fingerprint)
			.parse::<USE_CANDIDATE, ()>(&mut use_candidate)
			.parse::<DATA, &[u8]>(&mut data)
			.collect_unknown::<4>();

		println!("{sender} {stun:?} {unknown:?}");
		println!("username: {username:?}");
		println!("fingerprint: {}", fingerprint.is_some_and(|v| v.is_ok()));

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
					let _ = stun.append::<XOR_MAPPED_ADDRESS, _>(&mapped);
				}
				_ => continue,
			}
		}
		sock.send_to(&stun.buffer[..stun.len()], sender)?;
	}
}
