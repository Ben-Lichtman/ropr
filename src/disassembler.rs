use iced_x86::{Decoder, DecoderOptions, Instruction};

pub enum Bitness {
	Bits16,
	Bits32,
	Bits64,
}

pub struct Disassembler<'b> {
	decoder: Decoder<'b>,
}

impl<'b> Disassembler<'b> {
	pub fn new(bitness: Bitness, bytes: &'b [u8]) -> Self {
		let decoder = {
			let bitness = match bitness {
				Bitness::Bits16 => 16,
				Bitness::Bits32 => 32,
				Bitness::Bits64 => 64,
			};
			let options = DecoderOptions::AMD;
			Decoder::new(bitness, bytes, options)
		};
		Self { decoder }
	}

	pub fn decode_at_offset(&mut self, ip: u64, offset: usize, out: &mut Instruction) {
		self.decoder.set_ip(ip);
		self.decoder.try_set_position(offset).unwrap();
		self.decoder.decode_out(out);
	}
}
