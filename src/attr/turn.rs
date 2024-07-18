use super::{Attr, CHANNEL_NUMBER, REQUESTED_ADDRESS_FAMILY, EVEN_PORT, REQUESTED_TRANSPORT, ADDITIONAL_ADDRESS_FAMILY, ADDRESS_ERROR_CODE};

pub struct UnexpectedLength;

impl Attr<'_, CHANNEL_NUMBER> for u16 {
	type Error = UnexpectedLength;
	fn decode(_: super::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
		let Some(arr) = value.first_chunk() else { return Err(UnexpectedLength) };
		Ok(u16::from_be_bytes(*arr))
	}
	fn length(&self) -> u16 {
		4
	}
	fn encode(&self, _: super::Prefix, value: &mut [u8]) {
		value[0..2].copy_from_slice(&self.to_be_bytes());
		value[2..4].fill(0);
	}
}

impl Attr<'_, EVEN_PORT> for bool {
	type Error = UnexpectedLength;
	fn decode(_: super::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
		if value.len() < 1 { return Err(UnexpectedLength) }
		Ok(value[0] & 0b10000000 != 0)
	}
	fn length(&self) -> u16 {
		1
	}
	fn encode(&self, _: super::Prefix, value: &mut [u8]) {
		value[0] = (*self as u8) << 7;
	}
}

macro_rules! weird_byte_attr {
	($typ:ident) => {
		impl Attr<'_, $typ> for u8 {
			type Error = UnexpectedLength;
			fn decode(_: super::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
				if value.len() < 1 { return Err(UnexpectedLength) }
				Ok(value[0])
			}
			fn length(&self) -> u16 {
				4
			}
			fn encode(&self, _: super::Prefix, value: &mut [u8]) {
				value[0] = *self;
				value[1..4].fill(0);
			}
		}
		
	};
}
weird_byte_attr!(REQUESTED_ADDRESS_FAMILY);
weird_byte_attr!(REQUESTED_TRANSPORT);
weird_byte_attr!(ADDITIONAL_ADDRESS_FAMILY);

// I dislike how STUN chose to represent error codes... and methods... and message integrity... and socket addresses... and ICE tiebreaker values... and most TURN attributes.
// More succinctly, I dislike everything about STUN.
impl<'i> Attr<'i, ADDRESS_ERROR_CODE> for (u8, u16, &'i str) {
	type Error = UnexpectedLength;
	fn decode(_: super::Prefix, value: &'i [u8]) -> Result<Self, Self::Error> {
		if value.len() < 4 { return Err(UnexpectedLength) }
		let family = value[0];
		let class = value[2] & 0b111;
		let number = value[3] % 100;
		let err_code = class as u16 * 100 + number as u16;
		let reason = core::str::from_utf8(&value[4..]).unwrap_or("<Reason contained invalid UTF-8>");

		Ok((family, err_code, reason))
	}
	fn length(&self) -> u16 {
		4 + self.2.len() as u16
	}
	fn encode(&self, _: super::Prefix, value: &mut [u8]) {
		assert!(self.1 <= 799); // 3-bits for the error class means 0-7
		let class = (self.1 / 100) as u8;
		let number = (self.1 % 100) as u8;
		value[0] = self.0;
		value[1] = 0;
		value[2] = class;
		value[3] = number;
		value[4..].copy_from_slice(self.2.as_bytes());
	}
}
