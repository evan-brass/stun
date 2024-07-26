#![cfg_attr(not(feature = "std"), no_std)]

mod util;

util::declare!(Sctp);
util::be_field!(Sctp, src_port, set_src_port, u16, 0..2);
util::be_field!(Sctp, dst_port, set_dst_port, u16, 2..4);
util::be_field!(Sctp, tag, set_tag, u32, 4..8);
util::be_field!(Sctp, chksum, set_chksum, u32, 4..8);
