use super::Attr;

impl<'i, const T: u16> Attr<'i, T> for &'i [u8] {
	type Error = core::convert::Infallible;
	fn decode(_: super::Prefix, value: &'i [u8]) -> Result<Self, Self::Error> {
		Ok(value)
	}
	fn length(&self) -> u16 {
		self.len() as u16
	}
	fn encode(&self, _: super::Prefix, value: &mut [u8]) {
		value.copy_from_slice(self)
	}
}
