use openssl::{
	base64,
	error::ErrorStack,
	ex_data::Index,
	hash::MessageDigest,
	pkey::PKey,
	sign::{Signer, Verifier},
	ssl::{ErrorCode, Ssl, SslAcceptor, SslMethod, SslRef, SslStream, SslVerifyMode},
	x509::X509,
};
use parse::AttrIter;
use rand::random;
use std::{
	collections::{btree_map::Entry, BTreeMap, VecDeque},
	io::{Error, ErrorKind},
	net::{SocketAddr, SocketAddrV6},
	time::Instant,
};
use stun::{
	attr::{integrity::Integrity, *},
	Class, Method, Stun,
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
const TURN_KEY: &[u8] = &[
	0x01, 0x5c, 0x8a, 0x97, 0x3e, 0xa4, 0xb4, 0xa9, 0xc9, 0x45, 0xf6, 0x90, 0x14, 0x2b, 0xf3, 0xad,
];
const ICE_KEY: &[u8] = b"the/ice/password/constant";

#[derive(Default, Debug)]
struct Buffers {
	// Yuck.  I hate buffering.
	pub send: Vec<u8>,
	pub recv: VecDeque<u8>,
}
impl std::io::Read for Buffers {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		match self.recv.read(buf) {
			// Make read async:
			Ok(0) => Err(Error::new(ErrorKind::WouldBlock, "")),
			r => r,
		}
	}
}
impl std::io::Write for Buffers {
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		if self.send.len() < 500 {
			self.send.write(buf)
		} else {
			Err(Error::new(ErrorKind::WouldBlock, ""))
		}
	}
	fn flush(&mut self) -> std::io::Result<()> {
		self.send.flush()
	}
}

struct Mailbox {
	pub sctp_state: Option<(u32, u32)>, // (??I forgor??, txid)
	pub sctp_packet: Vec<u8>,
	pub dtls: SslStream<Buffers>,
}

pub struct Server {
	addr_index: Index<Ssl, SocketAddrV6>,
	acceptor: SslAcceptor,
	contexts: BTreeMap<SocketAddrV6, Mailbox>,
	ice_ufrag: String,
}

fn dtls_cookies() -> Result<
	(
		Index<Ssl, SocketAddrV6>,
		impl Fn(&mut SslRef, &mut [u8]) -> Result<usize, ErrorStack>,
		impl Fn(&mut SslRef, &[u8]) -> bool,
	),
	ErrorStack,
> {
	let startup = Instant::now();
	let digest = MessageDigest::sha1();
	let index = Ssl::new_ex_index()?;
	let cookie_expiration = 1000 * 60 * 2;
	let keys = PKey::hmac(&random::<[u8; 16]>())?;
	let keyv = keys.clone();
	Ok((
		index,
		move |ssl: &mut SslRef, output: &mut [u8]| {
			let addr = ssl.ex_data(index).unwrap();
			let mut signer = Signer::new(digest, &keys)?;

			let serial = (startup.elapsed().as_millis() as u32).to_be_bytes();
			signer.update(&serial)?;
			signer.update(&addr.ip().octets())?;
			signer.update(&addr.port().to_be_bytes())?;

			let (serial_dst, signature) = output.split_at_mut(4);
			serial_dst.copy_from_slice(&serial);

			Ok(4 + signer.sign(signature)?)
		},
		move |ssl: &mut SslRef, input: &[u8]| {
			let addr = ssl.ex_data(index).unwrap();
			if input.len() < 4 {
				return false;
			}
			let (serial, signature) = input.split_at(4);
			// Check the expiration of the serial
			if startup.elapsed().as_millis()
				> u32::from_be_bytes(serial.try_into().unwrap()) as u128 + cookie_expiration
			{
				return false;
			}
			let Ok(mut verifier) = Verifier::new(digest, &keyv) else {
				return false;
			};
			verifier.update(serial).is_ok()
				&& verifier.update(&addr.ip().octets()).is_ok()
				&& verifier.update(&addr.port().to_be_bytes()).is_ok()
				&& verifier.verify(signature).unwrap_or(false)
		},
	))
}

impl Server {
	pub fn new() -> Result<Self, std::io::Error> {
		let pem = std::fs::read("cert.pem")?;
		let certificate = X509::from_pem(&pem)?;
		let pkey = PKey::private_key_from_pem(&pem)?;

		// Figure out what our ufrag is
		let fingerprint = certificate.digest(MessageDigest::sha256())?;
		let mut ice_ufrag = base64::encode_block(&fingerprint);
		while ice_ufrag.ends_with('=') {
			ice_ufrag.pop();
		}
		println!("Our ufrag: {ice_ufrag}");

		// Configure a DTLS server
		let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::dtls())?;
		acceptor.set_certificate(&certificate)?;
		acceptor.set_private_key(&pkey)?;
		acceptor.check_private_key()?;
		acceptor.set_verify(SslVerifyMode::NONE);

		// Get a slot to hold the socketaddress so that we can generate and check dtls cookies:
		let (addr_index, generate, verify) = dtls_cookies()?;
		acceptor.set_cookie_generate_cb(generate);
		acceptor.set_cookie_verify_cb(verify);
		let acceptor = acceptor.build();

		Ok(Self {
			addr_index,
			acceptor,
			ice_ufrag,
			contexts: BTreeMap::new(),
		})
	}
	fn handle_ice(&mut self, msg: &mut Stun<&mut [u8]>, sender: SocketAddrV6) -> Option<()> {
		let mut username = None;
		let mut integrity = None;
		let mut ice_controlled = None;
		let mut ice_controlling = None;
		let mut priority = None;
		let mut use_candidate = None;
		let mut fingerprint = None;
		let unknowns = msg
			.into_iter()
			.parse::<USERNAME, &str>(&mut username)
			.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
			.parse::<ICE_CONTROLLED, u64>(&mut ice_controlled)
			.parse::<ICE_CONTROLLING, u64>(&mut ice_controlling)
			.parse::<PRIORITY, u32>(&mut priority)
			.parse::<USE_CANDIDATE, ()>(&mut use_candidate)
			.parse::<FINGERPRINT, ()>(&mut fingerprint)
			.collect_unknown::<1>();

		// Check + extract everything:
		let (Class::Request, Method::Binding) = (msg.class(), msg.method()) else {
			return None;
		};
		let (username, integrity, _priority, (), None) =
			(username?, integrity?, priority?, fingerprint?, unknowns)
		else {
			return None;
		};
		if ice_controlled.is_some() && ice_controlling.is_some() {
			return None;
		}
		let (dst_ufrag, _src_ufrag) = username.split_once(':')?;

		// Answer the ICE Connection test ourself
		if dst_ufrag == self.ice_ufrag {
			// Check the ICE pwd
			if !integrity.verify(ICE_KEY) {
				msg.set_class(Class::Error);
				msg.set_length(0);
				msg.append::<ERROR_CODE, _>(&(403, "")).ok()?;
				msg.append::<FINGERPRINT, _>(&()).ok()?;
			}
			// Check ICE role (clients must be controlling)
			else if ice_controlled.is_some() {
				msg.set_class(Class::Error);
				msg.set_length(0);
				msg.append::<ERROR_CODE, _>(&(487, "")).ok()?;
				msg.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).ok()?;
				msg.append::<FINGERPRINT, _>(&()).ok()?;
			}
			// Done
			else {
				msg.set_class(Class::Success);
				msg.set_length(0);
				msg.append::<XOR_MAPPED_ADDRESS, SocketAddr>(&sender.into())
					.ok()?;
				msg.append::<MESSAGE_INTEGRITY, _>(&ICE_KEY).ok()?;
				msg.append::<FINGERPRINT, _>(&()).ok()?;
			}

			Some(())
		} else {
			// TODO: Look for a mailbox that matches the dst_ufrag.
			println!("TODO: mailbox {dst_ufrag}");

			msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&sender.into())
				.ok()?;
			// TODO: Check our map of DTLS contexts for one with a base64(sha256(X509 cert)) that matches dst_ufrag
			// TODO: Append an xor_peer attribute
			None
		}
	}
	fn handl_dtls(&mut self, buffer: &mut [u8], len: usize, sender: SocketAddrV6) -> Option<usize> {
		let mailbox = match self.contexts.entry(sender) {
			Entry::Occupied(o) => {
				let mailbox = o.into_mut();
				mailbox.dtls.get_mut().recv.extend(&buffer[..len]);
				mailbox
			}
			Entry::Vacant(v) => {
				let mut buffers = Buffers::default();
				buffers.recv.extend(&buffer[..len]);

				let mut ssl = Ssl::new(self.acceptor.context()).ok()?;
				ssl.set_accept_state();
				let dtls = SslStream::new(ssl, buffers).ok()?;
				v.insert(Mailbox {
					sctp_state: None,
					sctp_packet: Vec::new(),
					dtls,
				})
			}
		};
		// Read the response DTLS back into buffer:
		match mailbox.dtls.ssl_read(buffer) {
			Ok(len) => {
				println!("dtls: {:?}", &buffer[..len]);
			}
			Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {}
			Err(e) => {
				println!("delete: {e:?}");
				self.contexts.remove(&sender);
				return None;
			}
		}
		let send = &mut mailbox.dtls.get_mut().send;
		let len = send.len();
		println!("send: {len}");
		if len <= buffer.len() {
			buffer[..len].copy_from_slice(send);
			send.clear();
			Some(len)
		} else {
			send.clear();
			None
		}
	}
	fn handle_hosted(
		&mut self,
		buffer: &mut [u8],
		len: usize,
		sender: SocketAddrV6,
	) -> Option<usize> {
		match buffer.first()? {
			/* STUN */
			0..20 => {
				let mut msg = Stun::new(buffer);
				if msg.len() != len {
					return None;
				}
				self.handle_ice(&mut msg, sender)?;
				Some(msg.len())
			}
			/* DTLS */ 20..64 => self.handl_dtls(buffer, len, sender),
			/* TURN Channel Data */ 64..80 => None,
			/* DROP */ _ => None,
		}
	}
	pub fn handle_turn(
		&mut self,
		msg: &mut Stun<&mut [u8]>,
		sender: SocketAddrV6,
	) -> Option<SocketAddrV6> {
		let canonical = SocketAddr::new(sender.ip().to_canonical(), sender.port());
		let mut receiver = sender;

		// Parse known attributes
		let mut username = None;
		let mut realm = None;
		let mut integrity = None;
		let mut nonce = None;
		let mut lifetime = None;
		let mut requested_transport = None;
		let mut channel = None;
		let mut xor_peer = None;
		let mut data = None;
		let unknown_attrs = msg
			.into_iter()
			.parse::<USERNAME, &str>(&mut username)
			.parse::<REALM, &str>(&mut realm)
			.parse::<MESSAGE_INTEGRITY, Integrity<20>>(&mut integrity)
			.parse::<NONCE, &str>(&mut nonce)
			.parse::<LIFETIME, u32>(&mut lifetime)
			.parse::<REQUESTED_TRANSPORT, u8>(&mut requested_transport)
			.parse::<CHANNEL_NUMBER, u16>(&mut channel)
			.parse::<XOR_PEER_ADDRESS, SocketAddr>(&mut xor_peer)
			.parse::<DATA, &[u8]>(&mut data)
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
				msg.append::<UNKNOWN_ATTRIBUTES, _>(&unknown_attrs.unwrap())
					.ok()?;
			}

			// Binding Request
			(Class::Request, Method::Binding) => {
				msg.set_length(0);
				msg.set_class(Class::Success);
				msg.append::<XOR_MAPPED_ADDRESS, _>(&canonical).ok()?;
			}

			// Send Indication
			(Class::Indication, Method::Send) => {
				if let (Some(SocketAddr::V6(_)), Some(data)) = (xor_peer, data) {
					let peer = xor_peer.unwrap();

					let orig_len = data.len();
					// Shift the data attribute to where we want it:
					let i = data.as_ptr() as usize - 4 - msg.buffer.as_ptr() as usize;
					msg.buffer.copy_within(i..i + 4 + orig_len, 44);

					// Change the method, and change the length
					msg.set_method(Method::Data);
					msg.set_length(0);

					// Handle hosted
					let len = if peer.ip().is_loopback() {
						msg.append::<XOR_PEER_ADDRESS, _>(&peer).unwrap();
						self.handle_hosted(&mut msg.buffer[48..], orig_len, sender)?
					}
					// Handle relay:
					else if let SocketAddr::V6(peer) = peer {
						msg.append::<XOR_PEER_ADDRESS, SocketAddr>(&sender.into())
							.unwrap();
						receiver = peer;
						orig_len
					} else {
						return None;
					} as u16;

					// Calculate the padding of the resulting data attribute:
					let padding = (4 - len % 4) % 4;
					// Update the length of the data attribute
					msg.buffer[46..48].copy_from_slice(&len.to_be_bytes());
					// Pad out the data attribute
					msg.buffer[48 + len as usize..][..padding as usize].fill(0);
					// Set the STUN data indication's length to include the data attributes new length
					msg.set_length(28 + len + padding);
				} else {
					return None;
				}
			}

			// Unauthenticated Requests
			(Class::Request, _) if integrity.is_none() => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(401, "")).ok()?;
				msg.append::<REALM, _>(&TURN_REALM).ok()?;
				msg.append::<NONCE, _>(&TURN_NONCE).ok()?;
			}

			// Unauthorized Requests
			(Class::Request, _) if username != Some(&TURN_USER) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(441, "")).ok()?;
			}
			(Class::Request, _) if integrity.as_ref().is_some_and(|i| !i.verify(&TURN_KEY)) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(403, "")).ok()?;
			}

			// Stale Requests
			(Class::Request, _) if nonce != Some(&TURN_NONCE) => {
				msg.set_length(0);
				msg.set_class(Class::Error);
				msg.append::<ERROR_CODE, _>(&(438, "")).ok()?;
				msg.append::<NONCE, _>(&TURN_NONCE).ok()?;
				msg.append::<MESSAGE_INTEGRITY, _>(&TURN_KEY).ok()?;
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
				msg.append::<XOR_RELAYED_ADDRESS, SocketAddr>(&sender.into())
					.ok()?;
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

			// Drop everything else:
			_ => return None,
		}

		Some(receiver)
	}
}
