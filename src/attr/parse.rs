use super::{Attr, Prefix};

pub fn comprehension_required(typ: u16) -> bool {
	typ < 0x8000
}

pub trait AttrIter<'i>: Iterator<Item = (Prefix<'i>, u16, &'i [u8])> + Sized {
	fn parse<'d, const T: u16, A: Attr<'i, T>>(
		self,
		dest: &'d mut Option<Result<A, A::Error>>,
	) -> impl AttrIter<'i>
	{
		AttrParser {
			inner: self,
			stop: false,
			dest,
		}
	}

	#[cfg(feature = "std")]
	fn collect_unknown_all(self) -> std::vec::Vec<u16> {
		self.map(|(_, typ, _)| typ)
			.filter(|t| comprehension_required(*t))
			.collect()
	}
	// Collect the first N unparsed attributes
	fn collect_unknown<const N: usize>(self) -> Option<[u16; N]> {
		let mut ret = [0; N];
		for (_, typ, _) in self {
			if comprehension_required(typ) {
				for d in ret.iter_mut() {
					if *d == typ {
						break;
					}
					if *d == 0 {
						*d = typ;
						break;
					}
				}
			}
		}
		if ret.iter().all(|t| *t == 0) {
			return None;
		}
		Some(ret)
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

		if A::must_precede(typ) { self.stop = true }

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
