#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
mod util;

declare!(Sctp {
	u16 src_port,
	u16 dst_port,
	u32 tag,
	u32 chksum,
	...Chunk,
});

declare!(Chunk {
	u8 typ,
	u8 flags,
	u16 length,
	align(4),
	len(0),
});

impl<B: ::core::borrow::Borrow<[u8]>> core::fmt::Debug for Sctp<B> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Sctp")
			.field("src_port", &self.src_port())
			.field("dst_port", &self.dst_port())
			.field("tag", &self.tag())
			.finish()
	}
}
impl<B: ::core::borrow::Borrow<[u8]>> core::fmt::Debug for Chunk<B> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("Chunk")
			.field("typ", &self.typ())
			.field("flags", &self.flags())
			.field("length", &self.length())
			.finish()
	}
}
