use super::Attr;

impl<'i, const T: u16> Attr<'i, T> for &'i str {
	type Error = core::str::Utf8Error;
	fn decode(_: super::Prefix, value: &'i [u8]) -> Result<Self, Self::Error> {
		core::str::from_utf8(value)
	}
	fn length(&self) -> u16 {
		self.len() as u16
	}
	fn encode(&self, _: super::Prefix, value: &mut [u8]) {
		value.copy_from_slice(self.as_bytes());
	}
}
