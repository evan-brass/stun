pub struct VarIter<'i, C, I> {
	pub buffer: &'i [u8],
	container: core::marker::PhantomData<C>,
	item: core::marker::PhantomData<I>
}
impl<'i, C, I> VarIter<'i, C, I> {
	pub fn new(buffer: &'i [u8]) -> Self {
		Self {
			buffer,
			container: core::marker::PhantomData,
			item: core::marker::PhantomData
		}
	}
}

macro_rules! declare_be_field {
	($name:ident, $offset:expr, $field:ident, $typ:ty, $len:literal) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub fn $field(&self) -> $typ {
				<$typ>::from_be_bytes(self.buffer.borrow()[$offset..][..$len].try_into().unwrap())
			}
		}
		paste::paste! {
			impl<B: ::core::borrow::BorrowMut<[u8]>> $name<B> {
				pub fn [<set_ $field>](&mut self, value: $typ) {
					self.buffer.borrow_mut()[$offset..][..$len].copy_from_slice(
						&value.to_be_bytes()
					);
				}
			}
		}
	};
}

macro_rules! declare_fields {
	($name:ident, $offset:expr, $align:literal, ) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			const ALIGN: usize = $align;
			const MIN_LEN: usize = $offset;
			pub fn new(buffer: B) -> Self {
				assert!(buffer.borrow().len() >= Self::MIN_LEN);
				Self { buffer }
			}
		}
	};
	($name:ident, $offset:expr, $align:literal, ...$typ:ident,) => {
		impl<'i, B> Iterator for crate::util::VarIter<'i, $name<B>, $typ<&'i [u8]>> {
			type Item = $typ<&'i [u8]>;
			fn next(&mut self) -> Option<Self::Item> {
				if self.buffer.len() < $typ::<&'i [u8]>::MIN_LEN { return None }
				let ret = $typ { buffer: self.buffer };
				let align = $typ::<&'i [i8]>::ALIGN;
				let len = ret.len();
				if self.buffer.len() < len { return None }
				let ret = $typ { buffer: &self.buffer[..len] };
				let padding = (align - len % align) % align;
				let total = len + padding;

				self.buffer = if self.buffer.len() >= total { &self.buffer[total..] } else { &[] };

				Some(ret)
			}
		}
		impl<'i, B: ::core::borrow::Borrow<[u8]>> IntoIterator for &'i $name<B> {
			type IntoIter = crate::util::VarIter<'i, $name<B>, $typ<&'i [u8]>>;
			type Item = $typ<&'i [u8]>;
			fn into_iter(self) -> Self::IntoIter {
				crate::util::VarIter::new(&self.buffer.borrow()[$name::<B>::MIN_LEN..])
			}
		}
		declare_fields!($name, $offset, $align, );
	};
	($name:ident, $offset:expr, $align:literal, len($adjust:literal), $($fields:tt)*) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub fn len(&self) -> usize {
				self.length() as usize + $adjust
			}
		}
		declare_fields!($name, $offset, $align, $($fields)*);
	};
	($name:ident, $offset:expr, $_:literal, align($align:literal), $($fields:tt)*) => {
		declare_fields!($name, $offset, $align, $($fields)*);
	};
	($name:ident, $offset:expr, $align:literal, u8 $field:ident, $($fields:tt)*) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub fn $field(&self) -> u8 {
				self.buffer.borrow()[$offset]
			}
		}
		paste::paste! {
			impl<B: ::core::borrow::BorrowMut<[u8]>> $name<B> {
				pub fn [<set_ $field>](&mut self, value: u8) {
					self.buffer.borrow_mut()[$offset] = value;
				}
			}
		}
		declare_fields!($name, $offset + 1, $align, $($fields)*);
	};
	($name:ident, $offset:expr, $align:literal, u16 $field:ident, $($fields:tt)*) => {
		declare_be_field!($name, $offset, $field, u16, 2);
		declare_fields!($name, $offset + 2, $align, $($fields)*);
	};
	($name:ident, $offset:expr, $align:literal, u32 $field:ident, $($fields:tt)*) => {
		declare_be_field!($name, $offset, $field, u32, 4);
		declare_fields!($name, $offset + 4, $align, $($fields)*);
	};
	($name:ident, $offset:expr, $align:literal, [u8; $n:literal] $field:ident, $($fields:tt)*) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub fn $field(&self) -> &[u8; $n] {
				self.buffer.borrow()[$offset..][..$n].try_into().unwrap()
			}
		}
		paste::paste! {
			impl<B: ::core::borrow::BorrowMut<[u8]>> $name<B> {
				pub fn [<set_ $field>](&mut self) -> &mut [u8; $n] {
					(&mut self.buffer.borrow_mut()[$offset..][..$n]).try_into().unwrap()
				}
			}
		}
		declare_fields!($name, $offset + $n, $align, $($fields)*);
	};
}

#[macro_export]
macro_rules! declare {
	($name:ident { $($fields:tt)* }) => {
		pub struct $name<B> {
			pub buffer: B
		}
		declare_fields!($name, 0, 1, $($fields)*);
	};
}

#[macro_export]
macro_rules! spec_enum {
	($name:ident:$disc:ty { $($variant:ident = $val:literal $rfc:literal,)*}) => {
		paste::paste! {
			#[derive(Debug, Clone, Copy, PartialEq, Eq)]
			#[non_exhaustive]
			pub enum $name {
				#[doc(hidden)]
				Unknown = -1,
	
				$(
					#[doc = "Defined in [" $rfc "](https://datatracker.ietf.org/doc/html/" $rfc ")"]
					$variant = $val,
				)*
			}
		}
		impl From<$disc> for $name {
			fn from(value: $disc) -> Self {
				match value {
					$($val => Self::$variant,)*

					_ => Self::Unknown
				}
			}
		}
	};
}
