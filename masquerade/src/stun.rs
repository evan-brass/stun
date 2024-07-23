use std::net::{IpAddr, SocketAddr, UdpSocket};
use stun::{Stun, Class, Method, attr::*, attr::parse::AttrIter as _, attr::integrity::IntegritySha1};

pub struct Server {
	long_key: &'static [u8],
	short_key: &'static [u8]
}

impl Server {
	pub fn new() -> Self {
		Self {
			long_key: &[1, 92, 138, 151, 62, 164, 180, 169, 201, 69, 246, 144, 20, 43, 243, 173],
			short_key: "the/ice/password/constant".as_bytes()
		}
	}
	pub fn handle(&mut self, sock: &UdpSocket, sender: SocketAddr, buffer: &mut [u8], len: usize) -> Result<(), std::io::Error> {
		let mut msg = Stun::new(buffer);
		if msg.decode(len).is_err() {
			return Ok(());
		}

		let mapped = SocketAddr::new(sender.ip().to_canonical(), sender.port());

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


		let common_attrs = msg.into_iter()
			.parse::<USERNAME, &str>(&mut username)
			.parse::<REALM, &str>(&mut realm)
			.parse::<NONCE, &str>(&mut nonce)
			.parse::<FINGERPRINT, ()>(&mut fingerprint)
			.parse::<MESSAGE_INTEGRITY, IntegritySha1>(&mut integrity)
			.parse::<SOFTWARE, &str>(&mut software);

		// Decide which attributes to decode and which key to use for integrity
		let unknown: Option<[u16; 4]> = match (msg.class(), msg.method()) {
			(Class::Request, Method::Binding) => {
				key = self.short_key;

				common_attrs
					.parse::<PRIORITY, u32>(&mut priority)
					.parse::<ICE_CONTROLLED, u64>(&mut ice_controlled)
					.parse::<ICE_CONTROLLING, u64>(&mut ice_controlling)
					.parse::<USE_CANDIDATE, ()>(&mut use_candidate)
					.collect_unknown()
			}
			(Class::Request, Method::Allocate) => {
				key = self.long_key;
				common_attrs
					.parse::<LIFETIME, u32>(&mut lifetime)
					.parse::<REQUESTED_ADDRESS_FAMILY, u8>(&mut requested_family)
					.parse::<EVEN_PORT, bool>(&mut even_port)
					.parse::<REQUESTED_TRANSPORT, u8>(&mut requested_transport)
					.parse::<DONT_FRAGMENT, ()>(&mut dont_fragment)
					.collect_unknown()
			}
			(Class::Request, Method::Refresh) => {
				key = self.long_key;
				common_attrs
					.parse::<LIFETIME, u32>(&mut lifetime)
					.parse::<REQUESTED_ADDRESS_FAMILY, _>(&mut requested_family)
					.collect_unknown()
			}
			(Class::Request, Method::CreatePermission) => {
				key = self.long_key;
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
			_ => return Ok(())
		};

		// Verify integrity
		let set_integrity = integrity.and_then(|i| i.verify(key));

		// Prepare the relayed address (Used by allocate)
		let relayed = match (mapped.ip(), requested_family) {
			(_, None) => Some(mapped),
			(IpAddr::V4(_), Some(0x01)) => Some(mapped),
			(IpAddr::V4(_), Some(0x02)) => Some(sender), // Sender is a mapped address
			(IpAddr::V6(_), Some(0x02)) => Some(sender),
			_ => None
		};

		// Handle Unknown Attributes
		if let Some(unknown) = unknown {
			msg.set_class(Class::Error);
			msg.set_length(0);
			msg.append::<ERROR_CODE, _>(&(420, ""))?;
			msg.append::<UNKNOWN_ATTRIBUTES, _>(&unknown)?;
		}
		// Handle authentication failure
		else if integrity.is_some() && set_integrity.is_none() {
			msg.set_class(Class::Error);
			msg.set_length(0);
			msg.append(&(403, ""))?;
		}
		// Send long-term challenge for TURN requests
		else if integrity.is_none() && matches!(msg.method(), Method::Allocate | Method::Refresh | Method::CreatePermission) {
			msg.set_class(Class::Error);
			msg.set_length(0);
			msg.append(&(401, "cred"))?;
			msg.append::<REALM, _>(&"none")?;
			msg.append::<NONCE, _>(&"none")?;
		}
		// Handle specific method cases
		else {
			match msg.method() {
				// STUN / ICE
				Method::Binding if ice_controlled.is_some() => {
					msg.set_class(Class::Error);
					msg.set_length(0);
					msg.append(&(487, "flip"))?;
				}
				Method::Binding => {
					msg.set_class(Class::Success);
					msg.set_length(0);
					msg.append::<XOR_MAPPED_ADDRESS, _>(&mapped)?;
				}

				// TURN
				Method::Allocate if even_port.is_some() => {
					msg.set_class(Class::Error);
					msg.set_length(0);
					msg.append(&(508, "even"))?;
				}
				Method::Allocate if requested_transport != Some(0x11) => {
					msg.set_class(Class::Error);
					msg.set_length(0);
					msg.append(&(508, "!udp"))?;
				}
				Method::Allocate if relayed.is_some() => {
					msg.set_class(Class::Success);
					msg.set_length(0);
					msg.append::<XOR_MAPPED_ADDRESS, _>(&mapped)?;
					msg.append::<XOR_RELAYED_ADDRESS, _>(&relayed.unwrap())?;
					msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))?;
				}
				Method::Allocate => {
					msg.set_class(Class::Error);
					msg.set_length(0);
					msg.append(&(440, ""))?;
				}
				Method::Refresh => {
					msg.set_class(Class::Success);
					msg.set_length(0);
					let desired = lifetime.unwrap_or(0);
					if desired > 0 {
						msg.append::<LIFETIME, _>(&desired)?;
					}
				}
				Method::CreatePermission => {
					msg.set_class(Class::Success);
					msg.set_length(0);
				}
				Method::Send => if let (Some(mut peer), Some(data)) = (xor_peer, data) {
					if let SocketAddr::V4(v4) = peer {
						peer.set_ip(v4.ip().to_ipv6_mapped().into());
					}

					// Shift the Data attribute to the start of the Stun message's body:
					let len = 4 + data.len();
					let padding = (4 - len % 4) % 4;
					let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;

					msg.set_method(Method::Data);
					msg.buffer.copy_within(i..i + len, 20);
					msg.buffer[i + len..][..padding].fill(0);
					msg.set_length((len + padding) as u16);

					msg.append::<XOR_PEER_ADDRESS, _>(&mapped)?;

					// Forward the data
					sock.send_to(&msg.buffer[..msg.len()], peer)?;

					// Skip integrity / fingerprint
					return Ok(());
				}
				_ => return Ok(())
			}
		}

		// Append the integrity and fingerprint
		if let Some(int) = set_integrity {
			msg.append::<MESSAGE_INTEGRITY, _>(&int)?;
		}
		if fingerprint.is_some() {
			msg.append::<FINGERPRINT, _>(&())?;
		}

		// Send the message
		sock.send_to(&msg.buffer[..msg.len()], sender)?;

		Ok(())
	}
}
