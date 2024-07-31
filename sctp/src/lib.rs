#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
mod util;

declare!(Sctp {
	u16 src_port,
	u16 dst_port,
	u32 tag,
	u32 chksum,
});
