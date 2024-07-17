use core::borrow::{Borrow, BorrowMut};
use crate::*;

impl<B: Borrow<[u8]>> Stun<B> {
	pub fn decode(&self, len: usize) -> Result<(), Error> {
		// len is supposed to mean how much of the internal buffer is filled with data from the network
		assert!(self.buffer.borrow().len() >= len);

		// Check first 2 bits of the typ
		if len < 2 { return Err(Error::TooShort(2)) }
		if self.typ() >> 14 != 0 { return Err(Error::NotStun) }

		// Check the length
		if len < 4 { return Err(Error::TooShort(4)) }
		let length = self.length();
		if length % 4 != 0 { return Err(Error::NotStun) }

		// Check the cookie
		if len < 8 { return Err(Error::TooShort(8)) }
		if self.cookie() != MAGIC_COOKIE { return Err(Error::NotStun) }

		// Check if the buffer contains enough data for this size STUN message
		let exp_len = 20 + self.length() as usize;
		if len < exp_len { return Err(Error::TooShort(exp_len)) }

		Ok(())
	}
	fn typ(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[0..2].try_into().unwrap())
	}
	pub fn class(&self) -> Class {
		match self.typ() & 0x0110 {
			0x0000 => Class::Request,
			0x0010 => Class::Indication,
			0x0100 => Class::Success,
			0x0110 => Class::Error,
			_ => unreachable!()
		}
	}
	#[doc(hidden)]
	pub fn raw_method(&self) -> u16 /* u12 */ {
		let typ = self.typ();
		(typ & 0x3E00) >> 2 | (typ & 0x00E0) >> 1 | (typ & 0x000F)
	}
	pub fn method(&self) -> Method {
		match self.raw_method() {
			0x001 => Method::Binding,
			0x003 => Method::Allocate,
			0x004 => Method::Refresh,
			0x006 => Method::Send,
			0x007 => Method::Data,
			0x008 => Method::CreatePermission,
			0x009 => Method::ChannelBind,

			_ => Method::Unknown
		}
	}
	pub fn length(&self) -> u16 {
		u16::from_be_bytes(self.buffer.borrow()[2..4].try_into().unwrap())
	}
	#[doc(hidden)]
	pub fn cookie(&self) -> u32 {
		u32::from_be_bytes(self.buffer.borrow()[4..8].try_into().unwrap())
	}
	pub fn txid(&self) -> &[u8; 12] {
		self.buffer.borrow()[8..][..20].try_into().unwrap()
	}
}

impl<B: BorrowMut<[u8]>> Stun<B> {
	fn set_typ(&mut self, typ: u16) {
		self.buffer.borrow_mut()[0..2].copy_from_slice(&typ.to_be_bytes());
	}
	pub fn set_class(&mut self, class: Class) {
		let typ = self.typ();
		self.set_typ(typ & !0x0110 | match class {
			Class::Request => 0x0000,
			Class::Indication => 0x0010,
			Class::Success => 0x0100,
			Class::Error => 0x0110
		});
	}
	#[doc(hidden)]
	pub fn set_raw_method(&mut self, method: u16) {
		let class = self.typ() & 0x0110;
		self.set_typ(class | (method & 0x1F80) << 2 | (method & 0x0070) << 1
		| (method & 0x000F));
	}
	pub fn set_method(&mut self, method: Method) {
		self.set_raw_method(method as u16);
	}
	pub fn set_length(&mut self, length: u16) {
		assert_eq!(length % 4, 0);
		assert!(self.buffer.borrow().len() >= 20 + length as usize);
		self.buffer.borrow_mut()[2..4].copy_from_slice(&length.to_be_bytes());
	}
	#[doc(hidden)]
	pub fn set_cookie(&mut self, cookie: u32) {
		self.buffer.borrow_mut()[4..8].copy_from_slice(&cookie.to_be_bytes());
	}
	pub fn set_txid(&mut self) -> &mut [u8; 12] {
		(&mut self.buffer.borrow_mut()[8..20]).try_into().unwrap()
	}
}

pub struct Attrs<'i> {
	typ: [u8; 2],
	length: u16,
	rest: &'i [u8],
	offset: u16,
}
impl<'i> Iterator for Attrs<'i> {
	type Item = (Prefix<'i>, u16, &'i [u8]);
	fn next(&mut self) -> Option<Self::Item> {
		// Check the offset against the STUN length
		if self.offset >= self.length { return None }
		let remaining = self.length - self.offset;
		if remaining < 4 { return None }

		// Check the offset against the buffer's length
		let i = 16 + self.offset as usize;
		if self.rest.len() < i + 4 { return None }
		
		// Read the attribute's header
		let attr_typ = u16::from_be_bytes(self.rest[i..][..2].try_into().unwrap());
		let attr_len = u16::from_be_bytes(self.rest[i + 2..][2..].try_into().unwrap());
		let attr_pad = (4 - attr_len % 4) % 4;

		// Consume the attribute header:
		let remaining = remaining - 4;
		let prefix = &self.rest[..i];
		let i = i + 4;

		// Check the attribute's length against the STUN header
		if remaining < attr_len { return None }
		if remaining - attr_len < attr_pad { return None }

		// Check the attribute's length against the buffer's length
		let end = i + attr_len as usize;
		if self.rest.len() < end { return None }

		// Everything's good, construct the attribute
		let length_at = self.offset + 4 + attr_len + attr_pad;
		let mut first_four = [0; 4];
		first_four[..2].copy_from_slice(&self.typ);
		first_four[2..].copy_from_slice(&length_at.to_be_bytes());

		let value = &self.rest[i..][..end];

		self.offset = length_at;

		Some((Prefix { first_four, prefix }, attr_typ, value))
	}
}
impl<'i, B: Borrow<[u8]>> IntoIterator for &'i Stun<B> {
	type IntoIter = Attrs<'i>;
	type Item = (Prefix<'i>, u16, &'i [u8]);
	fn into_iter(self) -> Self::IntoIter {
		let buffer = self.buffer.borrow();
		let typ = if buffer.len() < 2 { [0, 0] } else { buffer[0..2].try_into().unwrap() };
		let length = if buffer.len() < 4 { 0 } else { u16::from_be_bytes(buffer[2..4].try_into().unwrap()) };
		let rest = if buffer.len() < 4 { &[] } else { &buffer[4..] };

		Self::IntoIter { typ, length, rest, offset: 0 }
	}
}
