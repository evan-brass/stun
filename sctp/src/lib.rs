pub struct Sctp<B> {
	pub buffer: B,
}
impl<B: AsRef<[u8]>> Sctp<B> {
	pub fn sport(&self) -> u16 {
		u16::from_be_bytes(self.buffer.as_ref()[0..2].try_into().unwrap())
	}
	pub fn dport(&self) -> u16 {
		u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
	}
	pub fn vtag(&self) -> u32 {
		u32::from_be_bytes(self.buffer.as_ref()[4..8].try_into().unwrap())
	}
	pub fn chksum(&self) -> u32 {
		u32::from_le_bytes(self.buffer.as_ref()[8..12].try_into().unwrap())
	}
}

pub struct Chunk<B> {
	pub buffer: B,
}
impl<B: AsRef<[u8]>> Chunk<B> {
	pub fn typ(&self) -> u8 {
		self.buffer.as_ref()[0]
	}
	pub fn flags(&self) -> u8 {
		self.buffer.as_ref()[1]
	}
	pub fn length(&self) -> u16 {
		u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
	}
}
