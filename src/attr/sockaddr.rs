use super::{MAPPED_ADDRESS, XOR_MAPPED_ADDRESS, XOR_PEER_ADDRESS, XOR_RELAYED_ADDRESS, ALTERNATE_SERVER};

pub enum Error {
	UnknownFamily(u8),
	UnexpectedLength,
}

macro_rules! def_sockaddr {
	($typ:ident, $xor:literal) => {
		impl crate::attr::Attr<'_, $typ> for core::net::SocketAddr {
			type Error = crate::attr::sockaddr::Error;
			fn decode(prefix: super::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
				if value.len() < 4 {
					return Err(Error::UnexpectedLength);
				}
				let family = value[1];
				let mut port: [u8; 2] = value[2..4].try_into().unwrap();
				if $xor { prefix.xor_bytes(&mut port); }
				let port = u16::from_be_bytes(port);
		
				let ip = match (family, value.len()) {
					(0x01, 8) => {
						let mut octets: [u8; 4] = value[4..].try_into().unwrap();
						if $xor { prefix.xor_bytes(&mut octets); }
						core::net::IpAddr::from(octets)
					}
					(0x01, _) => return Err(Error::UnexpectedLength),
					(0x02, 20) => {
						let mut octets: [u8; 16] = value[4..].try_into().unwrap();
						if $xor { prefix.xor_bytes(&mut octets); }
						core::net::IpAddr::from(octets)
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
				if $xor { prefix.xor_bytes(&mut port); }
				value[2..4].copy_from_slice(&port);
				match self.ip() {
					core::net::IpAddr::V4(v4) => {
						let mut octets = v4.octets();
						if $xor { prefix.xor_bytes(&mut octets); }
						value[4..].copy_from_slice(&octets);
					}
					core::net::IpAddr::V6(v6) => {
						let mut octets = v6.octets();
						if $xor { prefix.xor_bytes(&mut octets); }
						value[4..].copy_from_slice(&octets);
					}
				}
			}
		}
	};
}

// Old (non-xor) attributes
def_sockaddr!(MAPPED_ADDRESS, false);
def_sockaddr!(ALTERNATE_SERVER, false);

// New (xored) attributes
def_sockaddr!(XOR_MAPPED_ADDRESS, true);
def_sockaddr!(XOR_PEER_ADDRESS, true);
def_sockaddr!(XOR_RELAYED_ADDRESS, true);
