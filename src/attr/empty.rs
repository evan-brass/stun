use super::{Attr, USE_CANDIDATE, DONT_FRAGMENT};

macro_rules! def_empty {
	($typ:ident) => {
		impl Attr<'_, $typ> for () {
			type Error = core::convert::Infallible;
			fn decode(_: super::Prefix, _: &[u8]) -> Result<Self, Self::Error> {
				Ok(())
			}
			fn length(&self) -> u16 { 0 }
			fn encode(&self, _: super::Prefix, _: &mut [u8]) {}
		}
	};
}

def_empty!(USE_CANDIDATE);
def_empty!(DONT_FRAGMENT);
