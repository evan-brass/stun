use core::borrow::{Borrow, BorrowMut};
use super::Chunk;



pub struct Data<B> {
	pub buffer: B
}
impl<B> Chunk for Data<B> {
	const TYPE: u8 = 0;
	const MIN_LEN: u16 = 16;
}
impl<B: Borrow<[u8]>> Data<B> {
	pub fn flags(&self) -> u8 {
		self.buffer.borrow()[1]
	}
	pub fn immediate(&self) -> bool {
		self.flags() & 0b1000 != 0
	}
	pub fn unordered(&self) -> bool {
		self.flags() & 0b0100 != 0
	}
	pub fn begin(&self) -> bool {
		self.flags() & 0b0010 != 0
	}
	pub fn end(&self) -> bool {
		self.flags() & 0b0001 != 0
	}

	pub fn tsn(&self) -> u32 {
		u32::from_be_bytes(self.buffer.borrow()[4..8].try_into().unwrap())
	}
	pub fn stream(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[8..10].try_into().unwrap())
	}
	pub fn seq(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[10..12].try_into().unwrap())
	}
	pub fn ppid(&self) -> u32 {
		u32::from_be_bytes(self.buffer.borrow()[12..16].try_into().unwrap())
	}
}
impl<B: BorrowMut<[u8]>> Data<B> {
	// TODO
}

pub struct Init<B> {
	pub buffer: B
}
impl<B> Chunk for Init<B> {
	const TYPE: u8 = 1;
	const MIN_LEN: u16 = 20;
}
impl<B: Borrow<[u8]>> Borrow<[u8]> for Init<B> {
	fn borrow(&self) -> &[u8] {
		self.buffer.borrow()
	}
}
impl<B: Borrow<[u8]>> Init<B> {
	pub fn tag(&self) -> u32 {
		u32::from_be_bytes(self.buffer.borrow()[4..8].try_into().unwrap())
	}
	pub fn rwnd(&self) -> u32 {
		u32::from_be_bytes(self.buffer.borrow()[8..12].try_into().unwrap())
	}
	pub fn num_out(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[12..14].try_into().unwrap())
	}
	pub fn num_in(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[14..16].try_into().unwrap())
	}
	pub fn tsn(&self) -> u32 {
		u32::from_be_bytes(self.buffer.borrow()[16..20].try_into().unwrap())
	}
}
impl<B: BorrowMut<[u8]>> Init<B> {
	// TODO: 
}
