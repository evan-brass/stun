use std::net::{SocketAddr, UdpSocket};

use stun::{
	attr::{
		parse::AttrIter as _,
		*
	}, Class, Method, Stun
};

fn main() -> Result<std::convert::Infallible, std::io::Error> {
	let sock = UdpSocket::bind("[::]:3478")?;

	let mut buffer = [0; 2048];
	loop {
		let (len, sender) = sock.recv_from(&mut buffer)?;
		let mut msg = Stun::new(buffer.as_mut_slice());
		if len != msg.len() { continue }

		let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());

		let mut receiver = sender;

		// Attributes
		let mut software = None;
		let mut lifetime = None;
		let mut requested_family = None;
		let mut even_port = None;
		let mut requested_transport = None;
		let mut dont_fragment = None;
		let mut xor_peer = None;
		let mut data = None;
		let mut channel = None;

		// Decide which attributes to parse based on the method:
		let common = msg.into_iter()
			.parse::<SOFTWARE, &str>(&mut software);
		let unknown: Option<[u16; 4]> = match (msg.class(), msg.method()) {
			(Class::Request, Method::Allocate) => common
				.parse::<LIFETIME, u32>(&mut lifetime)
				.parse::<REQUESTED_ADDRESS_FAMILY, u8>(&mut requested_family)
				.parse::<EVEN_PORT, bool>(&mut even_port)
				.parse::<REQUESTED_TRANSPORT, u8>(&mut requested_transport)
				.parse::<DONT_FRAGMENT, ()>(&mut dont_fragment)
				.collect_unknown(),
			(Class::Request, Method::Refresh) => common
				.parse::<LIFETIME, u32>(&mut lifetime)
				.parse::<REQUESTED_ADDRESS_FAMILY, _>(&mut requested_family)
				.collect_unknown(),
			(Class::Request, Method::CreatePermission) => common
				.parse::<LIFETIME, u32>(&mut lifetime)
				.parse::<XOR_PEER_ADDRESS, SocketAddr>(&mut xor_peer)
				.collect_unknown(),
			(Class::Request, Method::ChannelBind) => common
				.parse::<CHANNEL_NUMBER, u16>(&mut channel)
				.collect_unknown(),
			(Class::Indication, Method::Send) => common
				.parse::<XOR_PEER_ADDRESS, _>(&mut xor_peer)
				.parse::<DATA, &[u8]>(&mut data)
				.collect_unknown(),
			_ => common.collect_unknown(),
		};

		// Reset the buffer to prepare for the response
		if let Some(data) = data {
			// Shift the Data attribute to the start of the message:
			let len = 4 + data.len();
			let padding = (4 - len % 4) % 4;
			let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;

			msg.buffer.copy_within(i..i + len, 20);
			msg.buffer[i + len..][..padding].fill(0);
			msg.set_length((len + padding) as u16);
		}
		else { 
			msg.set_length(0);
		}

		// Handle Unknown Attributes
		match msg.method() {
			// Unknown Attributes on requests with known methods
			Method::Binding | Method::Allocate | Method::Refresh | Method::CreatePermission | Method::ChannelBind if msg.class() == Class::Request && unknown.is_some() => {
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(420, "Unknown Attributes"))?;
				msg.append::<UNKNOWN_ATTRIBUTES, _>(&unknown.unwrap())?;
			}

			Method::Binding => {
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical)?;
			}

			Method::Allocate => {
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical)?;
				msg.append::<XOR_RELAYED_ADDRESS, _>(&sender)?;
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))?;
			}

			Method::Refresh if lifetime == Some(0) => continue,
			Method::Refresh => {
				msg.set_class(Class::Success);
				msg.append::<LIFETIME, _>(&lifetime.unwrap_or(1000))?;
			}

			Method::CreatePermission => {
				msg.set_class(Class::Success);
			}

			// Supporting ChannelBind would require state, so we ignore these requests and let them timeout
			Method::ChannelBind => continue,

			Method::Send => if let Some(SocketAddr::V6(_)) = xor_peer {
				receiver = xor_peer.unwrap();

				// Change method and append the peer's address
				msg.set_method(Method::Data);
				msg.append::<XOR_PEER_ADDRESS, _>(&sender)?;
			} else { continue }

			// Requests with unknown Methods
			_ if msg.class() == Class::Request => {
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(404, "Unimplemented"))?;
			}

			// Everything else gets dropped.
			_ => continue,
		}

		// Send the response
		let _ = sock.send_to(&msg.buffer[..msg.len()], receiver);
	}
}
