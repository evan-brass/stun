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
	($name:ident, $offset:expr, ) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			const MIN_LEN: usize = $offset;
			pub fn new(buffer: B) -> Self {
				assert!(buffer.borrow().len() >= Self::MIN_LEN);
				Self { buffer }
			}
		}
	};
	($name:ident, $offset:expr, u16 $field:ident, $($fields:tt)*) => {
		declare_be_field!($name, $offset, $field, u16, 2);
		declare_fields!($name, $offset + 2, $($fields)*);
	};
	($name:ident, $offset:expr, u32 $field:ident, $($fields:tt)*) => {
		declare_be_field!($name, $offset, $field, u32, 4);
		declare_fields!($name, $offset + 4, $($fields)*);
	};
	($name:ident, $offset:expr, [u8; $n:literal] $field:ident, $($fields:tt)*) => {
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
		declare_fields!($name, $offset + 4, $($fields)*);
	};
}

#[macro_export]
macro_rules! declare {
	($name:ident { $($fields:tt)* }) => {
		pub struct $name<B> {
			pub buffer: B
		}
		declare_fields!($name, 0, $($fields)*);
	};
}
