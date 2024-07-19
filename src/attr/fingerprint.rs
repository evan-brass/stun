#[allow(unused_imports)]
use super::{Attr, FINGERPRINT};

const MAGIC: u32 = 0x5354554e;

pub struct BadFingerprint;

#[cfg(feature = "fingerprint")]
impl Attr<'_, FINGERPRINT> for () {
	type Error = BadFingerprint;
	fn decode(prefix: super::Prefix, value: &[u8]) -> Result<Self, Self::Error> {
		let actual = u32::from_be_bytes(value.try_into().map_err(|_| BadFingerprint)?);

		let mut hasher = crc32fast::Hasher::new();
		prefix.reduce_over_prefix(|s| hasher.update(s));
		let expected = hasher.finalize() ^ MAGIC;

		(expected == actual).then_some(()).ok_or(BadFingerprint)
	}
	fn length(&self) -> u16 {
		4
	}
	fn encode(&self, prefix: super::Prefix, value: &mut [u8]) {
		let mut hasher = crc32fast::Hasher::new();
		prefix.reduce_over_prefix(|s| hasher.update(s));
		let expected = hasher.finalize() ^ MAGIC;
		value.copy_from_slice(&expected.to_be_bytes());
	}

	fn must_precede(_: u16) -> bool { false }
}
