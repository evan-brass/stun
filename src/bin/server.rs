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

		// The key to use when checking integrity
		let key;

		// Common Attributes:
		let mut username = None;
		let mut fingerprint = None;
		let mut integrity = None;
		let mut software = None;
		// ICE attributes
		let mut priority = None;
		let mut ice_controlled = None;
		let mut ice_controlling = None;
		let mut use_candidate = None;
		// TURN attributes
		// let mut channel_number = None;
		let mut lifetime = None;
		let mut xor_peer = None;
		let mut data = None;
		let mut realm = None;
		let mut nonce = None;
		let mut requested_family = None;
		let mut even_port = None;
		let mut requested_transport = None;
		let mut dont_fragment = None;


		let common_attrs = stun.into_iter()
			.parse::<USERNAME, &str>(&mut username)
			.parse::<REALM, &str>(&mut realm)
			.parse::<NONCE, &str>(&mut nonce)
			.parse::<FINGERPRINT, ()>(&mut fingerprint)
			.parse::<MESSAGE_INTEGRITY, IntegritySha1>(&mut integrity)
			.parse::<SOFTWARE, &str>(&mut software);

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
			(Class::Request, Method::Allocate) => {
				key = LONG_KEY;
				common_attrs
					.parse::<LIFETIME, u32>(&mut lifetime)
					.parse::<REQUESTED_ADDRESS_FAMILY, u8>(&mut requested_family)
					.parse::<EVEN_PORT, bool>(&mut even_port)
					.parse::<REQUESTED_TRANSPORT, u8>(&mut requested_transport)
					.parse::<DONT_FRAGMENT, ()>(&mut dont_fragment)
					.collect_unknown()
			}
			(Class::Request, Method::Refresh) => {
				key = LONG_KEY;
				common_attrs
					.parse::<LIFETIME, u32>(&mut lifetime)
					.parse::<REQUESTED_ADDRESS_FAMILY, _>(&mut requested_family)
					.collect_unknown()
			}
			(Class::Request, Method::CreatePermission) => {
				key = LONG_KEY;
				common_attrs
					.parse::<LIFETIME, u32>(&mut lifetime)
					.parse::<XOR_PEER_ADDRESS, SocketAddr>(&mut xor_peer)
					.collect_unknown()
			}
			(Class::Indication, Method::Send) => {
				key = "Indications are unauthenticated! Crazy, right.".as_bytes();
				common_attrs
					.parse::<XOR_PEER_ADDRESS, _>(&mut xor_peer)
					.parse::<DATA, &[u8]>(&mut data)
					.collect_unknown()
			}
			(Class::Request, Method::ChannelBind) => {
				// This stateless relay doesn't support turn channels
				continue
			}
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
		// Send long-term challenge for TURN requests
		else if integrity.is_none() && matches!(stun.method(), Method::Allocate | Method::Refresh | Method::CreatePermission) {
			stun.set_class(Class::Error);
			stun.set_length(0);
			stun.append(&(401, "cred")).unwrap();
			stun.append::<REALM, _>(&"none").unwrap();
			stun.append::<NONCE, _>(&"none").unwrap();
		}
		// Handle specific method cases
		else {
			match stun.method() {
				// STUN / ICE
				Method::Binding if ice_controlled.is_some() => {
					stun.set_class(Class::Error);
					stun.set_length(0);
					stun.append(&(487, "flip")).unwrap();
				}
				Method::Binding => {
					stun.set_class(Class::Success);
					stun.set_length(0);
					stun.append::<XOR_MAPPED_ADDRESS, _>(&mapped).unwrap();
				}

				// TURN
				Method::Allocate if even_port.is_some() => {
					stun.set_class(Class::Error);
					stun.set_length(0);
					stun.append(&(508, "even")).unwrap();
				}
				Method::Allocate if requested_transport != Some(0x11) => {
					stun.set_class(Class::Error);
					stun.set_length(0);
					stun.append(&(508, "!udp")).unwrap();
				}
				Method::Allocate if mapped.is_ipv4() && requested_family.is_some_and(|f| f != 0x01) => {
					stun.set_class(Class::Error);
					stun.set_length(0);
					stun.append(&(440, "v4v4")).unwrap();
				}
				Method::Allocate if mapped.is_ipv6() && requested_family.is_some_and(|f| f != 0x02) => {
					stun.set_class(Class::Error);
					stun.set_length(0);
					stun.append(&(440, "v6v6")).unwrap();
				}
				Method::Allocate => {
					stun.set_class(Class::Success);
					stun.set_length(0);
					stun.append::<XOR_MAPPED_ADDRESS, _>(&mapped).unwrap();
					stun.append::<XOR_RELAYED_ADDRESS, _>(&mapped).unwrap();
					stun.append::<LIFETIME, _>(&lifetime.unwrap_or(1000)).unwrap();
				}
				Method::Refresh => {
					stun.set_class(Class::Success);
					stun.set_length(0);
					if let Some(desired) = lifetime{
						stun.append::<LIFETIME, _>(&desired).unwrap()
					}
				}
				Method::CreatePermission => {
					stun.set_class(Class::Success);
					stun.set_length(0);
				}
				Method::Send => if let (Some(mut peer), Some(data)) = (xor_peer, data) {
					if let SocketAddr::V4(v4) = peer {
						peer.set_ip(v4.ip().to_ipv6_mapped().into());
					}

					// Shift the Data attribute to the start of the Stun message's body:
					let len = 4 + data.len();
					let padding = (4 - len % 4) % 4;
					let i = data.as_ptr() as usize - 4 - stun.buffer.as_ptr() as usize;

					stun.set_method(Method::Data);
					stun.buffer.copy_within(i..i + len, 20);
					stun.buffer[i + len..][..padding].fill(0);
					stun.set_length((len + padding) as u16);

					if stun.append::<XOR_PEER_ADDRESS, _>(&mapped).is_err() { continue }

					// Forward the data
					sock.send_to(&stun.buffer[..stun.len()], peer)?;

					// Skip integrity / fingerprint
					continue;
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
		sock.send_to(&stun.buffer[..stun.len()], sender)?;
	}
}
