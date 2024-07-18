use super::{Attr, ERROR_CODE};

pub struct Error;

// I dislike how STUN chose to represent error codes... and methods... and message integrity... and socket addresses... and ICE tiebreaker values.
// More succinctly, I dislike everything about STUN.
impl<'i> Attr<'i, ERROR_CODE> for (u16, &'i str) {
	type Error = Error;
	fn decode(_: super::Prefix, value: &'i [u8]) -> Result<Self, Self::Error> {
		if value.len() < 4 { return Err(Error) }
		let class = value[2] & 0b111;
		let number = value[3] % 100;
		let err_code = class as u16 * 100 + number as u16;
		let reason = core::str::from_utf8(&value[4..]).unwrap_or("<Reason contained invalid UTF-8>");

		Ok((err_code, reason))
	}
	fn length(&self) -> u16 {
		4 + self.1.len() as u16
	}
	fn encode(&self, _: super::Prefix, value: &mut [u8]) {
		assert!(self.0 <= 799); // 3-bits for the error class means 0-7
		let class = (self.0 / 100) as u8;
		let number = (self.0 % 100) as u8;
		value[0] = 0;
		value[1] = 0;
		value[2] = class;
		value[3] = number;
		value[4..].copy_from_slice(self.1.as_bytes());
	}
}
