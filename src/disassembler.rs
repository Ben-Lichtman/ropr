use crate::{
	binary::Section,
	gadgets::{GadgetIterator, TailsIter},
};
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

pub struct Disassembly<'b> {
	_bytes: &'b [u8],
	instructions: Vec<Instruction>,
	file_offset: usize,
}

impl<'b> Disassembly<'b> {
	pub fn new(section: &'b Section) -> Option<Self> {
		let bytes = section.bytes();

		if bytes.is_empty() {
			return None;
		}

		let mut instructions = vec![Instruction::default(); bytes.len()];
		let mut disassembler = Disassembler::new(Bitness::Bits64, bytes);

		// Fully disassemble program
		for (start, instruction) in instructions.iter_mut().enumerate().take(bytes.len()) {
			disassembler.decode_at_offset(
				(section.program_base() + section.section_vaddr() + start) as u64,
				start,
				instruction,
			)
		}

		Some(Self {
			_bytes: bytes,
			instructions,
			file_offset: section.program_base() + section.section_vaddr(),
		})
	}

	pub fn file_offset(&self) -> usize { self.file_offset }

	pub fn instruction(&self, index: usize) -> Option<&Instruction> { self.instructions.get(index) }

	pub fn tails<'d>(&'d self, rop: bool, sys: bool, jop: bool, noisy: bool) -> TailsIter<'d, 'b> {
		TailsIter::new(self, rop, sys, jop, noisy)
	}

	pub fn gadgets_from_tail(
		&self,
		tail: usize,
		max_instructions: usize,
		noisy: bool,
	) -> GadgetIterator {
		assert!(max_instructions > 0);
		let start_index = tail.saturating_sub((max_instructions - 1) * 15);
		GadgetIterator::new(self, tail, max_instructions, noisy, start_index)
	}
}
