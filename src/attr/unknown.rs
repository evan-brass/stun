use super::{Attr, UNKNOWN_ATTRIBUTES};

impl<const N: usize> Attr<'_, UNKNOWN_ATTRIBUTES> for [u16; N] {
	type Error = std::convert::Infallible;
	fn decode(_: super::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
		let mut ret = [0; N];
		for (i, c) in value.chunks_exact(2).enumerate().take(N) {
			ret[i] = u16::from_be_bytes(c.try_into().unwrap());
		}
		Ok(ret)
	}
	fn length(&self) -> u16 {
		(self.iter().filter(|a| **a != 0).count() * 2) as u16
	}
	fn encode(&self, _: super::Prefix, value: &mut [u8]) {
		for (i, a) in self.iter().enumerate() {
			if *a == 0 { break }
			value[i * 2..][..2].copy_from_slice(&a.to_be_bytes());
		}
	}
}
