#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod attr;
mod stun;
mod error;

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

#[derive(Debug)]
pub enum Error {
	NotStun,
	TooShort(usize),
}
