#[allow(unused_imports)]
use super::{Attr, Prefix, FINGERPRINT, MESSAGE_INTEGRITY};

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

#[cfg(any(feature = "integrity", feature = "integrity-openssl"))]
pub type IntegritySha1<'i> = Integrity<'i, 20>;

#[cfg(any(feature = "integrity", feature = "integrity-openssl"))]
impl<'i> Attr<'i, MESSAGE_INTEGRITY> for IntegritySha1<'i> {
	type Error = core::array::TryFromSliceError;
	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error> {
		Ok(Self::Check {
			prefix,
			mac: value.try_into()?,
		})
	}
	fn length(&self) -> u16 {
		20
	}
	fn encode(&self, prefix: Prefix, value: &mut [u8]) {
		let Self::Set { key } = self else {
			panic!("Expected Integrity::Set variant but found Integrity::Check variant.  Use .verify() to convert between the Check/Set variants.")
		};
		let expected = expected_integrity(key, prefix);
		value.copy_from_slice(expected.as_ref());
	}

	// The integrity need only precede the fingerprint attribute
	// TODO: I didn't understand the spec, does the order or integrity vs integrity-256 matter or not?
	fn must_precede(typ: u16) -> bool {
		matches!(typ, FINGERPRINT)
	}
}

#[cfg(any(feature = "integrity", feature = "integrity-openssl"))]
impl IntegritySha1<'_> {
	pub fn verify<'i>(&self, key: &'i [u8]) -> Option<IntegritySha1<'i>> {
		let test = match self {
			Self::Set { key: prev_key } => *prev_key == key,
			Self::Check {
				prefix,
				mac: actual,
			} => {
				let expected = expected_integrity(key, *prefix);
				expected.as_ref() == actual.as_slice()
			}
		};
		if test {
			Some(Integrity::Set { key })
		} else {
			None
		}
	}
}

#[cfg(feature = "integrity")]
fn expected_integrity(key: &[u8], prefix: Prefix) -> impl AsRef<[u8]> {
	use hmac::{Mac as _, SimpleHmac};
	let mut mac =
		SimpleHmac::<sha1::Sha1>::new_from_slice(key).expect("Failed to create hmac");
	prefix.reduce_over_prefix(|s| mac.update(s));
	mac.finalize().into_bytes()
}

#[cfg(all(feature = "integrity-openssl", not(feature = "integrity")))]
fn expected_integrity(key: &[u8], prefix: Prefix) -> impl AsRef<[u8]> {
	use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
	let pkey = PKey::hmac(key).unwrap();
	let mut signer = Signer::new(MessageDigest::sha1(), &pkey).unwrap();
	prefix.reduce_over_prefix(|s| signer.update(s).unwrap());
	let mut ret = [0; 20];
	assert_eq!(signer.sign(&mut ret).unwrap(), 20);
	ret
}
