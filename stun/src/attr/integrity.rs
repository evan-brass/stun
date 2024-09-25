#[allow(unused_imports)]
use super::{Attr, AttrEnc, Prefix, FINGERPRINT, MESSAGE_INTEGRITY, MESSAGE_INTEGRITY_SHA256};

// Decoding is always available, but encoding / verifying requires openssl
pub struct Integrity<'i, const L: usize> {
	pub prefix: Prefix<'i>,
	pub mac: &'i [u8; L]
}

impl<'i> Attr<'i, MESSAGE_INTEGRITY> for Integrity<'i, 20> {
	type Error = core::array::TryFromSliceError;
	fn must_precede(typ: u16) -> bool { typ == FINGERPRINT }
	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		Ok(Self{prefix, mac: value.try_into()?})
	}
}
impl<'i> Attr<'i, MESSAGE_INTEGRITY_SHA256> for Integrity<'i, 32> {
	type Error = core::array::TryFromSliceError;
	fn must_precede(typ: u16) -> bool { typ == FINGERPRINT }
	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		Ok(Self{prefix, mac: value.try_into()?})
	}
}


#[cfg(feature = "integrity")]
mod openssl_integrity {
	use super::*;
	use openssl::{hash::MessageDigest, pkey::{HasPrivate, PKey}, sign::Signer};

	impl<const L: usize> Integrity<'_, L> {
		// HACK: I don't know why, but Verifier::new(MessageDigest::sha1(), &pkey) is erroring, but Signer works just fine, so I guess we'll use Signer instead of Verifier...
		pub fn verify(&self, mut signer: Signer) -> bool {
			self.prefix.reduce_over_prefix(|chunk| signer.update(chunk).unwrap());
			let mut expected = [0; L];
			signer.sign(expected.as_mut_slice()).unwrap();
			expected == *self.mac
		}
	}

	impl<T: HasPrivate> AttrEnc<MESSAGE_INTEGRITY> for PKey<T> {
		fn length(&self) -> u16 { 20 }
		fn encode(&self, prefix: Prefix, value: &mut [u8]) {
			let mut signer = Signer::new(MessageDigest::sha1(), self).unwrap();
			prefix.reduce_over_prefix(|chunk| signer.update(chunk).unwrap());
			assert_eq!(signer.sign(value).unwrap(), 20);
		}
	}
}
