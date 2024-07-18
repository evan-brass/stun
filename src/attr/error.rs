use super::{Attr, ERROR_CODE};

impl<'i> Attr<'i, ERROR_CODE> for (u16, &'i str) {
	type Error = super::turn::UnexpectedLength;
	fn decode(prefix: super::Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		let (_, code, reason) = Attr::decode(prefix, value)?;
		Ok((code, reason))
	}
	fn length(&self) -> u16 {
		(0, self.0, self.1).length()
	}
	fn encode(&self, prefix: super::Prefix, value: &mut [u8]) {
		Attr::encode(&(0, self.0, self.1), prefix, value);
	}
}
