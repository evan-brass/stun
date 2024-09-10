use std::collections::VecDeque;
use std::net::{SocketAddr, UdpSocket};
use std::fmt::Display;
use std::rc::Rc;
use std::io::{Error, ErrorKind, Read, Write};

use openssl::pkey::{PKey, Private};
use openssl::ssl::{Ssl, SslAcceptor, SslMethod, SslStream, SslVerifyMode};
use openssl::x509::X509;

#[derive(Debug)]
struct FakeError;
impl Display for FakeError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		std::fmt::Debug::fmt(self, f)
	}
}
impl std::error::Error for FakeError {}

struct Holding {
	addr: SocketAddr,
	sock: Rc<UdpSocket>,
	buffer: VecDeque<u8>
}
impl Read for Holding {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		let ret = self.buffer.read(buf);

		match ret {
			Ok(0) => Err(Error::new(ErrorKind::WouldBlock, FakeError)),
			_ => ret
		}
	}
}
impl Write for Holding {
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		self.sock.send_to(buf, self.addr)
	}
	fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

pub struct Server {
	sock: Rc<UdpSocket>,
	streams: Vec<SslStream<Holding>>,

	cert: X509,
	pkey: PKey<Private>
}
impl Server {
	pub fn new(sock: Rc<UdpSocket>) -> Result<Self, Error> {
		let pem = std::fs::read("./cert.pem")?;
		let cert = X509::from_pem(&pem)?;
		let pkey = PKey::private_key_from_pem(&pem)?;

		Ok(Self { sock, streams: Vec::new(), cert, pkey })
	}
	pub fn handle(&mut self, sender: SocketAddr, buffer: &mut [u8], len: usize) -> Result<(), Error> {
		let (pos, stream) = match self.streams.binary_search_by(|s| sender.cmp(&s.get_ref().addr)) {
			Ok(pos) => (pos, &mut self.streams[pos]),
			Err(pos) => {
				let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::dtls())?;
				builder.set_private_key(&self.pkey)?;
				builder.set_certificate(&self.cert)?;
				builder.check_private_key()?;
				builder.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
				let acceptor = builder.build();
				let mut ssl = Ssl::new(&acceptor.into_context())?;
				ssl.set_mtu(1200)?;
				ssl.set_accept_state();
				let stream = SslStream::new(ssl, Holding { sock: self.sock.clone(), addr: sender, buffer: VecDeque::new()})?;
				self.streams.insert(pos, stream);
				(pos, &mut self.streams[pos])
			}
		};
		let holding = stream.get_mut();
		holding.buffer.clear();
		holding.buffer.extend(&buffer[..len]);

		// Reuse the recv buffer for our decrypted data?  Why not!
		loop {
			match stream.ssl_read(buffer) {
				Ok(n) => {
					if n >= 12 {
						let sctp = sctp::Sctp::new(&buffer[..n]);
						println!("SCTP Packet: {sctp:?}");
						for chunk in sctp.chunks() {
							println!(" - {chunk:?}");
						}
					} else {
						println!("Data {sender} {:?}", &buffer[..n]);
					}
				}
				Err(err) => {
					if err.code() != openssl::ssl::ErrorCode::WANT_READ {
						println!("{sender} {err}");
						self.streams.remove(pos);
					}
					break;
				}
			}
		}

		Ok(())
	}
}
