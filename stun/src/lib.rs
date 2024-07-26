#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod attr;
mod stun;
mod error;
mod rfc8489;
mod rfc8656;
mod rfc8445;
mod util;

#[cfg(test)]
mod rfc5769;

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

util::declare!(Stun);
util::be_field!(Stun, typ, set_typ, u16, 0..2);
// TODO: Add these assert back to set_length?
// assert_eq!(length % 4, 0);
// assert!(self.buffer.borrow().len() >= 20 + length as usize);
util::be_field!(Stun, length, set_length, u16, 2..4);
util::be_field!(Stun, cookie, set_cookie, u32, 4..8);
util::arr_field!(Stun, txid, set_txid, 12, 8..20);

impl<B> Stun<B> {
	pub fn new(buffer: B) -> Self {
		Self { buffer }
	}
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Error {
	NotStun,
	TooShort(usize),
}
