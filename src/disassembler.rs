use crate::{
	binary::{Bitness, Section},
	gadgets::GadgetIterator,
	rules::is_gadget_tail,
};
use iced_x86::{Decoder, DecoderOptions, Instruction};

pub struct Disassembler<'b> {
	decoder: Decoder<'b>,
}

impl<'b> Disassembler<'b> {
	pub fn new(bitness: Bitness, bytes: &'b [u8]) -> Self {
		let decoder = {
			let bitness = match bitness {
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
	bytes: &'b [u8],
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
		let mut disassembler = Disassembler::new(section.bitness(), bytes);

		// Fully disassemble program - cache for later backtracking of tails
		instructions
			.iter_mut()
			.enumerate()
			.for_each(|(n, instruction)| {
				disassembler.decode_at_offset(
					(section.program_base() + section.section_vaddr() + n) as u64,
					n,
					instruction,
				)
			});

		Some(Self {
			bytes,
			instructions,
			file_offset: section.program_base() + section.section_vaddr(),
		})
	}

	pub fn bytes(&self) -> &[u8] { self.bytes }

	pub fn file_offset(&self) -> usize { self.file_offset }

	pub fn instruction(&self, index: usize) -> Option<&Instruction> { self.instructions.get(index) }

	pub fn is_tail_at(&self, index: usize, rop: bool, sys: bool, jop: bool, noisy: bool) -> bool {
		let instruction = self.instructions[index];
		is_gadget_tail(&instruction, rop, sys, jop, noisy)
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
