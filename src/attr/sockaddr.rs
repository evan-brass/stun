use super::{Attr, MAPPED_ADDRESS};
use core::net::{IpAddr, SocketAddr};

pub enum Error {
	UnknownFamily(u8),
	UnexpectedLength,
}

impl<const T: u16> Attr<'_, T> for SocketAddr {
	type Error = Error;
	fn decode(prefix: super::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
		if value.len() < 4 {
			return Err(Error::UnexpectedLength);
		}
		let family = value[1];
		let mut port: [u8; 2] = value[2..4].try_into().unwrap();
		if T != MAPPED_ADDRESS {
			prefix.xor_bytes(&mut port)
		}
		let port = u16::from_be_bytes(port);

		let ip = match (family, value.len()) {
			(0x01, 8) => {
				let mut octets: [u8; 4] = value[4..].try_into().unwrap();
				if T != MAPPED_ADDRESS {
					prefix.xor_bytes(&mut octets)
				}
				IpAddr::from(octets)
			}
			(0x01, _) => return Err(Error::UnexpectedLength),
			(0x02, 20) => {
				let mut octets: [u8; 16] = value[4..].try_into().unwrap();
				if T != MAPPED_ADDRESS {
					prefix.xor_bytes(&mut octets)
				}
				IpAddr::from(octets)
			}
			(0x02, _) => return Err(Error::UnexpectedLength),
			_ => return Err(Error::UnknownFamily(family)),
		};

		Ok(Self::new(ip, port))
	}
	fn length(&self) -> u16 {
		match self {
			Self::V4(_) => 8,
			Self::V6(_) => 20,
		}
	}
	fn encode(&self, prefix: super::Prefix, value: &mut [u8]) {
		value[0] = 0;
		value[1] = if self.is_ipv4() { 0x01 } else { 0x02 };
		let mut port = self.port().to_be_bytes();
		if T != MAPPED_ADDRESS {
			prefix.xor_bytes(&mut port)
		}
		value[2..4].copy_from_slice(&port);
		match self.ip() {
			IpAddr::V4(v4) => {
				let mut octets = v4.octets();
				if T != MAPPED_ADDRESS {
					prefix.xor_bytes(&mut octets)
				}
				value[4..].copy_from_slice(&octets);
			}
			IpAddr::V6(v6) => {
				let mut octets = v6.octets();
				if T != MAPPED_ADDRESS {
					prefix.xor_bytes(&mut octets)
				}
				value[4..].copy_from_slice(&octets);
			}
		}
	}
}
