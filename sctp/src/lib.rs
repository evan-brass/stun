#![cfg_attr(not(feature = "std"), no_std)]
use core::borrow::{Borrow, BorrowMut};

mod chunks;

pub enum Error {
	TooShort(usize),
	NotSctp
}

pub trait Chunk {
	const TYPE: u8;
	const MIN_LEN: u16;

	fn params(&self) -> impl Iterator<Item = (u16, &[u8])> where Self: Borrow<[u8]> {
		Params { buffer: &self.borrow()[Self::MIN_LEN as usize..] }
	}
}

struct Params<'i> {
	buffer: &'i [u8]
}
impl<'i> Iterator for Params<'i> {
	type Item = (u16, &'i [u8]);
	fn next(&mut self) -> Option<Self::Item> {
		if self.buffer.len() < 4 { return None }
		let typ = u16::from_be_bytes(self.buffer[0..2].try_into().unwrap());
		let length = u16::from_be_bytes(self.buffer[2..4].try_into().unwrap()) as usize;
		let padding = (4 - length % 4) % 4;
		if length < 4 { return None }
		if self.buffer.len() < length { return None }
		let value = &self.buffer[4..length];

		// Shift the buffer by the length and padding:
		self.buffer = if self.buffer.len() - padding < length {
			&[]
		} else {
			&self.buffer[length + padding..]
		};

		Some((typ, value))
	}
}

pub struct Chunks<'i> {
	buffer: &'i [u8],
	offset: usize
}
impl<'i> Iterator for Chunks<'i> {
	type Item = (u8, u8, &'i [u8]);
	fn next(&mut self) -> Option<Self::Item> {
		if self.offset + 4 > self.buffer.len() { return None }
		let typ = self.buffer[self.offset];
		let flags = self.buffer[self.offset + 1];
		let length = u16::from_be_bytes(self.buffer[self.offset + 2..][..2].try_into().unwrap()) as usize;
		if length < 4 { return None }
		let exp_length = (self.offset + length + 3) & !3;
		if exp_length > self.buffer.len() { return None }
		let value = &self.buffer[self.offset + 4..][..length - 4];

		self.offset = exp_length;
		Some((typ, flags, value))
	}
}
impl<'i, B: Borrow<[u8]>> IntoIterator for &'i Sctp<B> {
	type Item = (u8, u8, &'i [u8]);
	type IntoIter = Chunks<'i>;
	fn into_iter(self) -> Self::IntoIter {
		Chunks { buffer: &self.buffer.borrow()[12..], offset: 0 }
	}
}

pub struct Sctp<B> {
	pub buffer: B
}
impl<B> Sctp<B> {
	pub fn new(buffer: B) -> Self {
		Self { buffer }
	}
}


impl<B: Borrow<[u8]>> Sctp<B> {
	pub fn sport(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[0..2].try_into().unwrap())
	}
	pub fn dport(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[2..4].try_into().unwrap())
	}
	pub fn tag(&self) -> u32 {
		u32::from_be_bytes(self.buffer.borrow()[4..8].try_into().unwrap())
	}
}
impl<B: BorrowMut<[u8]>> Sctp<B> {
	pub fn set_sport(&mut self, port: u16) {
		self.buffer.borrow_mut()[0..2].copy_from_slice(&port.to_be_bytes());
	}
	pub fn set_dport(&mut self, port: u16) {
		self.buffer.borrow_mut()[2..4].copy_from_slice(&port.to_be_bytes());
	}
}

impl<B: Borrow<[u8]>> core::fmt::Debug for Sctp<B> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Sctp")
			.field("sport", &self.sport())
			.field("dport", &self.dport())
			.field("tag", &self.tag())
			.field("chunks", &self.into_iter())
			.finish()
	}
}
impl core::fmt::Debug for Chunks<'_> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_list()
			.entries(Self { buffer: self.buffer, offset: 0 })
			.finish()
	}
}
