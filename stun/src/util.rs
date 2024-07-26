

macro_rules! declare {
	($name:ident) => {
		pub struct $name<B> {
			pub buffer: B
		}
	};
}

macro_rules! be_field {
	($name:ident, $field:ident, $set_field:ident, $typ:ty, $range:expr) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub fn $field(&self) -> $typ {
				<$typ>::from_be_bytes(self.buffer.borrow()[$range].try_into().unwrap())
			}
		}
		impl<B: ::core::borrow::BorrowMut<[u8]>> $name<B> {
			pub fn $set_field(&mut self, value: $typ) {
				self.buffer.borrow_mut()[$range].copy_from_slice(&value.to_be_bytes());
			}
		}
	};
}

macro_rules! arr_field {
	($name:ident, $field:ident, $set_field:ident, $n:literal, $range:expr) => {
		impl<B: ::core::borrow::Borrow<[u8]>> $name<B> {
			pub fn $field(&self) -> &[u8; $n] {
				self.buffer.borrow()[$range].try_into().unwrap()
			}
		}
		impl<B: ::core::borrow::BorrowMut<[u8]>> $name<B> {
			pub fn $set_field(&mut self) -> &mut [u8; $n] {
				(&mut self.buffer.borrow_mut()[$range]).try_into().unwrap()
			}
		}
	};
}

pub(crate) use declare;
pub(crate) use be_field;
pub(crate) use arr_field;
