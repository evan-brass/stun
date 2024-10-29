use std::net::SocketAddr;
use stun::{
	Stun,
	Class, Method,
	attr::{
		integrity::Integrity,
		parse::AttrIter as _,
		*
	}
};

const KNOWN_METHODS: [Method; 7] = [
	Method::Binding,
	Method::Allocate,
	Method::Refresh,
	Method::CreatePermission,
	Method::Send,
	Method::ChannelBind,
	Method::Data,
];

// Constants used by this server
const TURN_REALM: &str = "none";
const TURN_NONCE: &str = "none";
const TURN_USER: &str = "guest";
// turn_key = md5("guest:none:password")
const TURN_KEY: &[u8] = &[0x01, 0x5c, 0x8a, 0x97, 0x3e, 0xa4, 0xb4, 0xa9, 0xc9, 0x45, 0xf6, 0x90, 0x14, 0x2b, 0xf3, 0xad];
const ICE_KEY: &[u8] = "the/ice/password/constant".as_bytes();

pub struct Server {
	ice_ufrag: String,
}

impl Server {
	pub fn new() -> Result<Self, std::io::Error> {
		let ice_ufrag = String::from("w+Skud1WCH6mFV736w+9JOvE1K2SM5Ex9Dc+xVdEEdU");
		Ok(Self { ice_ufrag })
	}
	fn handle_stun(&mut self, msg: &mut Stun<&mut [u8]>, sender: SocketAddr) -> Option<SocketAddr> {
		let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());
		let mut receiver = sender;

		// Parse known attributes
		let mut software = None;
		let mut username = None;
		let mut realm = None;
		let mut integrity = None;
		let mut nonce = None;
		let mut lifetime = None;
		let mut requested_transport = None;
		let mut channel = None;
		let mut xor_peer = None;
		let mut data = None;
		let mut ice_controlled = None;
		let mut ice_controlling = None;
		let mut use_candidate = None;
		let mut fingerprint = None;
		let mut priority = None;
		let unknown_attrs = msg.into_iter()
			.parse::<SOFTWARE, &str>(&mut software)
			.parse::<USERNAME, &str>(&mut username)
			.parse::<REALM, &str>(&mut realm)
			.parse::<MESSAGE_INTEGRITY, Integrity< 20>>(&mut integrity)
			.parse::<NONCE, &str>(&mut nonce)
			.parse::<LIFETIME, u32>(&mut lifetime)
			.parse::<REQUESTED_TRANSPORT, u8>(&mut requested_transport)
			.parse::<CHANNEL_NUMBER, u16>(&mut channel)
			.parse::<XOR_PEER_ADDRESS, SocketAddr>(&mut xor_peer)
			.parse::<DATA, &[u8]>(&mut data)
			.parse::<ICE_CONTROLLED, u64>(&mut ice_controlled)
			.parse::<ICE_CONTROLLING, u64>(&mut ice_controlling)
			.parse::<USE_CANDIDATE, ()>(&mut use_candidate)
			.parse::<FINGERPRINT, ()>(&mut fingerprint)
			.parse::<PRIORITY, u32>(&mut priority)
			.collect_unknown::<4>();

		match (msg.class(), msg.method()) {
			// Unknown Methods
			(Class::Request, meth) if !KNOWN_METHODS.contains(&meth) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(404, "")).ok()?;
			}

			// Unknown Attributes
			(Class::Request, _) if unknown_attrs.is_some() => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(420, "")).ok()?;
				msg.append::<UNKNOWN_ATTRIBUTES, _>(&unknown_attrs.unwrap()).ok()?;
			}

			// Unauthenticated TURN Requests
			(Class::Request, Method::Allocate | Method::Refresh | Method::CreatePermission | Method::ChannelBind) if integrity.is_none() => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(401, "")).ok()?;
				msg.append::<REALM, _>(&TURN_REALM).ok()?;
				msg.append::<NONCE, _>(&TURN_NONCE).ok()?;
			}

			// Unauthorized TURN Requests
			(Class::Request, Method::Allocate | Method::Refresh | Method::CreatePermission | Method::ChannelBind) if username != Some(&TURN_USER) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(441, "")).ok()?;
			}
			(Class::Request, Method::Allocate | Method::Refresh | Method::CreatePermission | Method::ChannelBind) if integrity.as_ref().is_some_and(|i| !i.verify(&TURN_KEY)) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(403, "")).ok()?;
			}

			// Stale TURN Requests
			(Class::Request, Method::Allocate | Method::Refresh | Method::CreatePermission | Method::ChannelBind) if nonce != Some(&TURN_NONCE) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(438, "")).ok()?;
				msg.append::<NONCE, _>(&TURN_NONCE).ok()?;
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).ok()?;
			}

			// Normal STUN Binding
			(Class::Request, Method::Binding) if integrity.is_none() && username.is_none() => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<MAPPED_ADDRESS, _>(&canonical).ok()?;
			}

			// Allocate with Non-UDP Transport
			(Class::Request, Method::Allocate) if requested_transport != Some(17) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(442, "")).ok()?;
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).ok()?;
			}

			// Allocate
			(Class::Request, Method::Allocate) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).ok()?;
				msg.append::<XOR_RELAYED_ADDRESS, _>(&sender).ok()?;
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000)).ok()?;
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).ok()?;
			}

			// Refresh
			(Class::Request, Method::Refresh) if lifetime == Some(0) => return None, // Close notification, don't respond
			(Class::Request, Method::Refresh) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000)).ok()?;
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).ok()?;
			}

			// Create Permission
			(Class::Request, Method::CreatePermission) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).ok()?;
			}

			// Channel Bind
			(Class::Request, Method::ChannelBind) => {
				// Instead of supporting channels (which would require storing state) we send a nonsensical - but seemingly nonfatal - error response to placate Chrome.
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(438, "")).ok()?;
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).ok()?;
			}

			// Send
			(Class::Indication, Method::Send) => if let (Some(SocketAddr::V6(_)), Some(data)) = (xor_peer, data) {
				receiver = xor_peer.unwrap();
				// TODO: Special handling for loopback?
				// TODO: Special handling for ::ffff:255.255.255.255?

				// Shift the data attribute to the start of the STUN packet
				let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
				let len = data.len();
				msg.buffer.copy_within(i..i + 4 + len, 20);

				let padding = (4 - len % 4) % 4;
				msg.buffer[i + 4 + len..][..padding].fill(0);
				msg.set_length((4 + len + padding) as u16);

				msg.set_method(Method::Data);
				msg.append::<XOR_PEER_ADDRESS, _>(&sender).ok()?;
			} else { return None }

			// Data
			(Class::Indication, Method::Data) => {
				let data = data?;
				let peer = xor_peer?;

				// Shift the data attribute to the start of the STUN packet
				let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
				let len = data.len();
				msg.buffer.copy_within(i..i + 4 + len, 20);

				let (inner_len, inner_receiver) = self.handle(&mut msg.buffer[24..], len, peer)?;
				if inner_receiver != receiver {
					// Don't support multi-hop path routing. Partially because I haven't figured that part out, and partially because I feel the amplification is a bad idea.
					return None
				}
				
				let padding = (4 - inner_len % 4) % 4;
				msg.buffer[22..24].copy_from_slice(&(inner_len as u16).to_be_bytes());
				msg.buffer[24 + inner_len..][..padding].fill(0);
				msg.set_length((4 + inner_len + padding) as u16);

				msg.set_method(Method::Send);
				msg.append::<XOR_PEER_ADDRESS, _>(&peer).ok()?;
			}

			// ICE Connection Tests
			(Class::Request, Method::Binding) => {
				let (lufrag, _rufrag) = username.and_then(|s| s.split_once(':'))?;
				let integrity = integrity?;
				// fingerprint?;

				// Check if the connection test is actually for us or for someone else.
				if lufrag != self.ice_ufrag {
					println!("not us {lufrag}");
					// TODO: Rendezvous protocol - encapsulate the connection test and forward it to the intended recipient.
					return None;
				}

				// Check ICE pwd
				if !integrity.verify(&ICE_KEY) {
					msg.set_length(0);
					msg.set_class(Class::Error);
					msg.append::<ERROR_CODE, _>(&(403, "")).ok()?;
				}

				// Tell clients to control the connection
				else if ice_controlled.is_some() {
					msg.set_length(0);
					msg.set_class(Class::Error);
					msg.append::<ERROR_CODE, _>(&(487, "")).ok()?;
					msg.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).ok()?;
				}

				// Connection Tested
				else {
					msg.set_length(0);
					msg.set_class(Class::Success);
					msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).ok()?;
					msg.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).ok()?;
				}
				msg.append::<FINGERPRINT, _>(&()).ok()?;
			}

			// Drop everything else:
			_ => return None
		}

		Some(receiver)
	}
	pub fn handle(&mut self, buffer: &mut [u8], len: usize, sender: SocketAddr) -> Option<(usize, SocketAddr)> {
		match buffer.first()? {
			/* STUN */ 0..20 => {
				// Make sure that there's enough data to read it as a STUN packet
				if buffer.len() < 20 || len < 20 { return None }

				// Check expected length against actual length
				let mut msg = Stun::new(buffer);
				if msg.len() != len { return None }

				// Handle the message and return the result if a response address is returned
				let receiver = self.handle_stun(&mut msg, sender)?;
				Some((msg.len(), receiver))
			},
			/* DTLS CID */ 25 => None,
			/* DTLS */ 20..64 => None,
			/* TURN Channel Data */ 64..80 => None,
			/* DROP */ _ => None,
		}
	}
}
