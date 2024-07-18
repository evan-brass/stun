#[allow(unused_imports)]
use super::{Prefix, MESSAGE_INTEGRITY, FINGERPRINT, Attr};

#[derive(Debug, Clone, Copy)]
pub enum Integrity<'i, const L: usize> {
	Check {
		prefix: Prefix<'i>,
		mac: &'i [u8; L]
	},
	Set {
		key: &'i [u8]
	}
}

#[cfg(feature = "integrity")]
pub type IntegritySha1<'i> = Integrity<'i, 20>;

#[cfg(feature = "integrity")]
impl<'i> Attr<'i, MESSAGE_INTEGRITY> for IntegritySha1<'i> {
	type Error = core::array::TryFromSliceError;
	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		Ok(Self::Check { prefix, mac: value.try_into()? })
	}
	fn length(&self) -> u16 {
		20
	}
	fn encode(&self, prefix: Prefix, value: &mut [u8]) {
		use hmac::{Mac as _, SimpleHmac};
		let Self::Set { key } = self else { panic!("Expected Integrity::Set variant but found Integrity::Check variant.  Use .verify() first, or provide a key by creating a new Integrity.") };
		let mut mac = SimpleHmac::<sha1::Sha1>::new_from_slice(*key).expect("Failed to create hmac");
		prefix.reduce_over_prefix(|s| mac.update(s));
		value.copy_from_slice(&mac.finalize().into_bytes());
	}

	// The integrity need only precede the fingerprint attribute
	// TODO: I didn't understand the spec, does the order or integrity vs integrity-256 matter or not?
	fn must_precede(typ: u16) -> bool {
		match typ {
			FINGERPRINT => true,
			_ => false
		}
	}
}

#[cfg(feature = "integrity")]
impl<'i> IntegritySha1<'i> {
	pub fn verify(&mut self, key: &'i [u8]) -> bool {
		use hmac::{Mac as _, SimpleHmac};
		let res;
		match self {
			Self::Set { key: prev_key } => res = *prev_key == key,
			Self::Check { prefix, mac: actual } => {
				let mut mac = SimpleHmac::<sha1::Sha1>::new_from_slice(key).expect("Failed to create hmac");
				prefix.reduce_over_prefix(|s| mac.update(s));
				let expected = mac.finalize().into_bytes();
				res = expected.as_slice() == actual.as_slice();

				if res { *self = Self::Set { key }}
			}
		}

		res
	}
}
