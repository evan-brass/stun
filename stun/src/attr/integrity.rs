#[allow(unused_imports)]
use super::{Attr, Prefix, FINGERPRINT, MESSAGE_INTEGRITY, MESSAGE_INTEGRITY_SHA256};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Integrity<'i, const L: usize> {
	Check {
		prefix: Prefix<'i>,
		mac: &'i [u8; L],
	},
	Set {
		key: &'i [u8],
	},
}

impl<'i> Attr<'i, MESSAGE_INTEGRITY> for Integrity<'i, 20> {
	type Error = core::array::TryFromSliceError;
	fn must_precede(typ: u16) -> bool { typ == FINGERPRINT }
	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		Ok(Self::Check { prefix, mac: value.try_into()? })
	}
}
impl<'i> Attr<'i, MESSAGE_INTEGRITY_SHA256> for Integrity<'i, 32> {
	type Error = core::array::TryFromSliceError;
	fn must_precede(typ: u16) -> bool { typ == FINGERPRINT }
	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		Ok(Self::Check { prefix, mac: value.try_into()? })
	}
}
