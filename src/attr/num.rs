use super::Attr;

macro_rules! attr_for_num {
	($num_typ:ident) => {
		impl<const T: u16> Attr<'_, T> for $num_typ {
			type Error = core::array::TryFromSliceError;
			fn decode(_: super::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
				value.try_into().map(Self::from_be_bytes)
			}
			fn length(&self) -> u16 {
				self.to_be_bytes().len() as u16
			}
			fn encode(&self, _: super::Prefix, value: &mut [u8]) {
				value.copy_from_slice(&self.to_be_bytes())
			}
		}
	};
}

attr_for_num!(u32);
attr_for_num!(u64);
