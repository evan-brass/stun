use super::Attr;

impl<const T: u16> Attr<'_, T> for () {
	type Error = core::convert::Infallible;
	fn decode(_: super::Prefix, _: &[u8]) -> Result<Self, Self::Error> {
		Ok(())
	}
	fn length(&self) -> u16 { 0 }
	fn encode(&self, _: super::Prefix, _: &mut [u8]) {}
}
