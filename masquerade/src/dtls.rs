use std::net::{SocketAddr, UdpSocket};
use std::io::Error;


pub struct Server {

}
impl Server {
	pub fn new() -> Self {
		Self {}
	}
	pub fn handle(&mut self, _sock: &UdpSocket, sender: SocketAddr, buffer: &mut [u8], len: usize) -> Result<(), Error> {
		println!("{sender} {:?}", &buffer[..len]);

		Ok(())
	}
}
