use super::Error;

impl core::fmt::Display for Error {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::NotStun => f.write_str(""),
			Self::TooShort(needed) => f.write_fmt(format_args!("Buffer too small or not filled with enough data. The operation can be retried with at least {needed} bytes."))
		}
	}
}
#[cfg(feature = "std")]
impl std::error::Error for Error {}
