use core::borrow::Borrow;
use super::{Attr, Prefix};

impl<'i, B: Borrow<[u8]>> crate::Stun<B> {
	pub fn parse<const T: u16, A: Attr<'i, T>>(
		&'i self,
		dest: &'i mut Option<Result<A, A::Error>>,
	) -> impl AttrIter<'i> {
		self.into_iter().parse(dest)
	}
}

pub trait AttrIter<'i>: Iterator<Item = (Prefix<'i>, u16, &'i [u8])> {
	fn parse<'d, const T: u16, A: Attr<'i, T>>(
		self,
		dest: &'d mut Option<Result<A, A::Error>>,
	) -> impl AttrIter<'i>
	where
		Self: Sized,
	{
		AttrParser {
			inner: self,
			stop: false,
			dest,
		}
	}
}
impl<'i, T: Iterator<Item = (Prefix<'i>, u16, &'i [u8])>> AttrIter<'i> for T {}

struct AttrParser<'i, 'd, I, const T: u16, A: Attr<'i, T>> {
	inner: I,
	stop: bool,
	dest: &'d mut Option<Result<A, A::Error>>,
}

impl<'i, 'd, const T: u16, I: Iterator<Item = (Prefix<'i>, u16, &'i [u8])>, A: Attr<'i, T>> Iterator
	for AttrParser<'i, 'd, I, T, A>
{
	type Item = (Prefix<'i>, u16, &'i [u8]);
	fn next(&mut self) -> Option<Self::Item> {
		let (prefix, typ, value) = self.inner.next()?;

		if !self.stop && A::must_precede(typ) {
			self.stop = true
		}

		if typ == T {
			if self.dest.is_none() && !self.stop {
				*self.dest = Some(A::decode(prefix, value))
			}
			self.next()
		} else {
			Some((prefix, typ, value))
		}
	}
}
