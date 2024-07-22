#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

pub use core::borrow::{Borrow, BorrowMut};
pub use stun::Stun;

pub struct ChannelData<B> {
	pub buffer: B
}

impl<B: Borrow<[u8]>> ChannelData<B> {
	pub fn channel(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[0..2].try_into().unwrap())
	}
	pub fn length(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[2..4].try_into().unwrap())
	}
	pub fn data(&self) -> &[u8] {
		&self.buffer.borrow()[4..][..self.length() as usize]
	}
}
impl<B: BorrowMut<[u8]>> ChannelData<B> {
	pub fn set_channel(&mut self, channel: u16) {
		self.buffer.borrow_mut()[0..2].copy_from_slice(&channel.to_be_bytes());
	}
	pub fn set_length(&mut self, length: u16) {
		self.buffer.borrow_mut()[2..4].copy_from_slice(&length.to_be_bytes());
	}
	pub fn set_data(&mut self) -> &mut [u8] {
		let length = self.length() as usize;
		&mut self.buffer.borrow_mut()[4..][..length]
	}
}
