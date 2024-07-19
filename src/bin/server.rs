use std::net::{SocketAddr, UdpSocket};

use integrity::IntegritySha1;
use parse::AttrIter;
use stun::attr::*;
use stun::{Stun, Class, Method};

const LONG_KEY: &[u8] = &[1, 92, 138, 151, 62, 164, 180, 169, 201, 69, 246, 144, 20, 43, 243, 173];
const SHORT_KEY: &[u8] = "the/ice/password/constant".as_bytes();

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = UdpSocket::bind("[::]:3478")?;

	let mut stun = Stun { buffer: [0; 2048] };
	loop {
		let (len, sender) = sock.recv_from(&mut stun.buffer)?;
		if stun.decode(len).is_err() {
			continue;
		}

		let mapped = SocketAddr::new(sender.ip().to_canonical(), sender.port());

		println!("{sender} {stun:?}");

		// We set these in every codepath to tell what integrity to use, and what IPv6 addr to send the response message to
		let key;
		let mut send_to = sender;

		// Common Attributes:
		let mut username = None;
		let mut fingerprint = None;
		let mut integrity = None;
		// ICE attributes
		let mut priority = None;
		let mut ice_controlled = None;
		let mut ice_controlling = None;
		let mut use_candidate = None;

		let common_attrs = stun.into_iter()
			.parse::<USERNAME, &str>(&mut username)
			.parse::<FINGERPRINT, ()>(&mut fingerprint)
			.parse::<MESSAGE_INTEGRITY, IntegritySha1>(&mut integrity);

		// Decide which attributes to decode and which key to use for integrity
		let unknown: Option<[u16; 4]> = match (stun.class(), stun.method()) {
			(Class::Request, Method::Binding) => {
				key = SHORT_KEY;

				common_attrs
					.parse::<PRIORITY, u32>(&mut priority)
					.parse::<ICE_CONTROLLED, u64>(&mut ice_controlled)
					.parse::<ICE_CONTROLLING, u64>(&mut ice_controlling)
					.parse::<USE_CANDIDATE, ()>(&mut use_candidate)
					.collect_unknown()
			}
			// (Class::Request, Method::Allocate | Method::Refresh | Method::CreatePermission) => {
			// 	key = LONG_KEY;
			// 	common_attrs
			// }
			_ => continue
		};

		// Verify integrity
		let set_integrity = integrity.and_then(|i| i.verify(key));

		// Handle Unknown Attributes
		if let Some(unknown) = unknown {
			stun.set_class(Class::Error);
			stun.set_length(0);
			stun.append::<ERROR_CODE, _>(&(420, "")).unwrap();
			stun.append::<UNKNOWN_ATTRIBUTES, _>(&unknown).unwrap();
		}
		// Handle authentication failure
		else if integrity.is_some() && set_integrity.is_none() {
			stun.set_class(Class::Error);
			stun.set_length(0);
			stun.append(&(403, "")).unwrap();
		}
		// Handle specific method cases
		else {
			match (stun.class(), stun.method()) {
				(Class::Request, Method::Binding) if ice_controlled.is_some() => {
					stun.set_class(Class::Error);
					stun.set_length(0);
					stun.append::<ERROR_CODE, _>(&(487, "")).unwrap();
				}
				(Class::Request, Method::Binding) => {
					stun.set_class(Class::Success);
					stun.set_length(0);
					stun.append::<XOR_MAPPED_ADDRESS, _>(&mapped).unwrap();
				}
				_ => continue
			}
		}

		// Append the integrity and fingerprint
		if let Some(int) = set_integrity {
			stun.append::<MESSAGE_INTEGRITY, _>(&int).unwrap();
		}
		if fingerprint.is_some() {
			stun.append::<FINGERPRINT, _>(&()).unwrap();
		}

		// Send the message
		sock.send_to(&stun.buffer[..stun.len()], send_to)?;
	}
}
