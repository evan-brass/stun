#![cfg_attr(not(feature = "std"), no_std)]

mod attr;
mod stun;
pub use attr::AttrIter as _;

const MAGIC_COOKIE: u32 = 0x2112A442;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
	Request,
	Indication,
	Success,
	Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Method {
	#[doc(hidden)]
	Unknown = -1,

	Binding = 0x001,
	Allocate = 0x003,
	Refresh = 0x004,
	Send = 0x006,
	Data = 0x007,
	CreatePermission = 0x008,
	ChannelBind = 0x009,
}

pub struct Stun<B> {
	pub buffer: B,
}
pub enum Error {
	NotStun,
	TooShort(usize),
}
pub struct Prefix<'i> {
	first_four: [u8; 4],
	prefix: &'i [u8],
}

pub trait Attr<'i, const T: u16>: Sized {
	type Error;

	fn decode(prefix: Prefix<'i>, value: &'i [u8]) -> Result<Self, Self::Error>;
	fn length(&self) -> u16;
	fn encode(&self, prefix: Prefix, value: &mut [u8]);

	/// Some attributes must preced other attributes
	fn must_precede(typ: u16) -> bool {
		match typ {
			0x0006 /* MESSAGE-INTEGRITY */ |
			0x001C /* MESSAGE-INTEGRITY-SHA256 */ |
			0x8028 /* FINGERPRINT */ => true,
			_ => false
		}
	}
}
