use std::{net::{SocketAddr, UdpSocket}, ops::Deref};

use openssl::{hash::{Hasher, MessageDigest}, pkey::PKey, sign::Signer};
use stun::{
	attr::{
		integrity::Integrity,
		parse::AttrIter as _,
		*
	}, Class, Method, Stun
};

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = UdpSocket::bind("[::]:3478")?;

	// Expected Long-Term authentication
	let exp_realm = "none";
	let exp_nonce = "none";
	let exp_username = "guest";
	let exp_password = "password";
	let turn_key = {
		let mut hasher = Hasher::new(MessageDigest::md5()).unwrap();
		hasher.update(format!("{exp_username}:{exp_realm}:{exp_password}").as_bytes()).unwrap();
		PKey::hmac(hasher.finish().unwrap().deref())?
	};

	// Set a cap on the number of bytes the server will send
	let send_budget: usize = 50_000_000_000;
	let mut bytes_received = 0;
	let mut packets_sent = 0;
	let mut bytes_sent = 0;

	let mut buffer = [0; 2048];
	loop {
		let (len, sender) = sock.recv_from(&mut buffer)?;

		// Update the budget:
		bytes_received += len;
		if bytes_sent >= send_budget { continue }

		let mut msg = Stun::new(buffer.as_mut_slice());
		if len != msg.len() { continue }

		let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());

		let mut receiver = sender;

		// Attributes
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

		// Decide which attributes to parse based on the method:
		// NOTE: The spec says you're supposed to parse every attribute you understand, and if you don't expect an attribute to ignore it
		// ... but I think this is stupid, so this server reports known but unexpected attributes as unknown attributes.
		let common = msg.into_iter()
			.parse::<SOFTWARE, &str>(&mut software);
		let unknown: Option<[u16; 4]> = match (msg.class(), msg.method()) {
			(Class::Request, Method::Allocate) => common
				.parse::<USERNAME, &str>(&mut username)
				.parse::<REALM, &str>(&mut realm)
				.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
				.parse::<NONCE, &str>(&mut nonce)
				.parse::<LIFETIME, u32>(&mut lifetime)
				.parse::<REQUESTED_TRANSPORT, u8>(&mut requested_transport)
				.collect_unknown(),
			(Class::Request, Method::Refresh) => common
				.parse::<USERNAME, &str>(&mut username)
				.parse::<REALM, &str>(&mut realm)
				.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
				.parse::<NONCE, &str>(&mut nonce)
				.parse::<LIFETIME, u32>(&mut lifetime)
				.collect_unknown(),
			(Class::Request, Method::CreatePermission) => common
				.parse::<USERNAME, &str>(&mut username)
				.parse::<REALM, &str>(&mut realm)
				.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
				.parse::<NONCE, &str>(&mut nonce)
				.parse::<LIFETIME, u32>(&mut lifetime)
				.parse::<XOR_PEER_ADDRESS, SocketAddr>(&mut xor_peer)
				.collect_unknown(),
			(Class::Request, Method::ChannelBind) => common
				.parse::<USERNAME, &str>(&mut username)
				.parse::<REALM, &str>(&mut realm)
				.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
				.parse::<NONCE, &str>(&mut nonce)
				.parse::<XOR_PEER_ADDRESS, SocketAddr>(&mut xor_peer)
				.parse::<CHANNEL_NUMBER, u16>(&mut channel)
				.collect_unknown(),
			(Class::Indication, Method::Send) => common
				.parse::<XOR_PEER_ADDRESS, _>(&mut xor_peer)
				.parse::<DATA, &[u8]>(&mut data)
				.collect_unknown(),
			_ => common.collect_unknown(),
		};

		// Handle Unknown Attributes
		match (msg.class(), msg.method()) {
			// Error 404 for requests with unknown methods
			(Class::Request, meth) if !matches!(meth,
				Method::Binding |
				Method::Allocate |
				Method::Refresh |
				Method::CreatePermission |
				Method::ChannelBind
			) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(404, ""))?;
			}

			// Error 420 for known-methods with unexpected attributes
			(Class::Request, _) if unknown.is_some() => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(420, ""))?;
				msg.append::<UNKNOWN_ATTRIBUTES, _>(&unknown.unwrap())?;
			}

			// Binding Requests
			(Class::Request, Method::Binding) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical)?;
			}

			// Check for provided but bad integrity
			(Class::Request, _) if integrity.as_ref().map(
				|a| a.verify(Signer::new(MessageDigest::sha1(), &turn_key).unwrap())
			) == Some(false) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(403, ""))?;
			}

			// Check for missing integrity
			(Class::Request, _) if realm != Some(&exp_realm) || integrity.is_none() => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(401, ""))?;
				msg.append::<REALM, _>(&exp_realm)?;
				msg.append::<NONCE, _>(&exp_nonce)?;
			}

			(Class::Request, Method::Allocate) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical)?;
				msg.append::<XOR_RELAYED_ADDRESS, _>(&sender)?;
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))?;
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key)?;
			}

			(Class::Request, Method::Refresh) if lifetime == Some(0) => continue, // Refresh lifetime=0 means close the connection and needs no response.
			(Class::Request, Method::Refresh) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))?;
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key)?;
			}

			(Class::Request, Method::CreatePermission) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key)?;
			}

			// HACK: Chrome asks to bind channels, but we cannot implement that statelessly. So return an error and the only error that doesn't seem to kill the connection is 438 (Stale Nonce).  Except I forgot to append the nonce, but Chrome seems to be fine with that??? Whatever.  Problem solved.
			(Class::Request, Method::ChannelBind) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(438, ""))?;
				msg.append::<MESSAGE_INTEGRITY, _>(&turn_key)?;
			},

			(Class::Indication, Method::Send) => if let (Some(SocketAddr::V6(_)), Some(data)) = (xor_peer, data) {
				receiver = xor_peer.unwrap();

				// Shift the Data attribute to the start of the message:
				let len = 4 + data.len();
				let padding = (4 - len % 4) % 4;
				let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
	
				msg.buffer.copy_within(i..i + len, 20);
				msg.buffer[i + len..][..padding].fill(0);
				msg.set_length((len + padding) as u16);

				// Change method and append the peer's address
				msg.set_method(Method::Data);
				msg.append::<XOR_PEER_ADDRESS, _>(&sender)?;
			} else { continue }

			// Everything else gets dropped.
			_ => continue,
		}

		// Increment the bytes sent (this means we can overshoot the send_budget by at most 1 packet, aka <= 2048 bytes)
		let out_len = msg.len();
		bytes_sent += out_len;
		packets_sent += 1;
		if packets_sent % 1000 == 0 {
			println!("{bytes_received} bytes received, {bytes_sent} bytes sent ({packets_sent} packets) of {send_budget}");
		}

		// Send the response
		if let Err(e) = sock.send_to(&msg.buffer[..out_len], receiver) {
			println!("{e}");
		}
	}
}
