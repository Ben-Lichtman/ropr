use iced_x86::{Formatter, FormatterOutput, FormatterTextKind, Instruction};

use std::{
	cmp::Ordering,
	hash::{Hash, Hasher},
};

use crate::{
	disassembler::{Bitness, Disassembler},
	rules::{is_gadget_head, is_gadget_tail},
	sections::Section,
};

pub struct Gadget {
	file_offset: usize,
	len: usize,
	instructions: Vec<Instruction>,
}

impl PartialEq for Gadget {
	fn eq(&self, other: &Self) -> bool { self.instructions.eq(&other.instructions) }
}

impl Eq for Gadget {}

impl Hash for Gadget {
	fn hash<H>(&self, state: &mut H)
	where
		H: Hasher,
	{
		self.instructions.hash(state);
	}
}

impl PartialOrd for Gadget {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.file_offset.cmp(&other.file_offset))
	}
}

impl Ord for Gadget {
	fn cmp(&self, other: &Self) -> Ordering { self.file_offset.cmp(&other.file_offset) }
}

impl Gadget {
	pub fn file_offset(&self) -> usize { self.file_offset }

	pub fn len(&self) -> usize { self.len }

	pub fn instructions(&self) -> &[Instruction] { &self.instructions }

	pub fn format_instruction(&self, output: &mut impl FormatterOutput) {
		let mut formatter = iced_x86::IntelFormatter::new();
		let options = iced_x86::Formatter::options_mut(&mut formatter);
		options.set_hex_prefix("0x");
		options.set_hex_suffix("");
		options.set_space_after_operand_separator(true);
		// Write instructions
		let mut instructions = self.instructions.iter().peekable();
		while let Some(i) = instructions.next() {
			formatter.format(i, output);
			output.write(";", FormatterTextKind::Text);
			if let Some(_) = instructions.peek() {
				output.write(" ", FormatterTextKind::Text);
			}
		}
	}

	pub fn format_full(&self, output: &mut impl FormatterOutput) {
		// Write address
		output.write(
			&format!("{:#010x}: ", self.file_offset),
			FormatterTextKind::Function,
		);
		self.format_instruction(output);
	}
}

pub struct Disassembly<'b> {
	bytes: &'b [u8],
	instructions: Vec<Instruction>,
	file_offset: usize,
}

impl Disassembly<'_> {
	pub fn instruction(&self, index: usize) -> &Instruction { &self.instructions[index] }
}

pub struct TailsIter<'b, 'd> {
	disassembly: &'d Disassembly<'b>,
	rop: bool,
	sys: bool,
	jop: bool,
	index: usize,
}

impl Iterator for TailsIter<'_, '_> {
	type Item = usize;

	fn next(&mut self) -> Option<Self::Item> {
		while let Some(instr) = self.disassembly.instructions.get(self.index) {
			if is_gadget_tail(instr, self.rop, self.sys, self.jop) {
				let tail = self.index;
				self.index += 1;
				return Some(tail);
			}
			else {
				self.index += 1;
			}
		}
		None
	}
}

pub struct GadgetIterator<'b, 'd> {
	disassembly: &'d Disassembly<'b>,
	tail: usize,
	start_index: usize,
	max_instructions: usize,
}

impl<'b> Iterator for GadgetIterator<'b, '_> {
	type Item = Gadget;

	fn next(&mut self) -> Option<Self::Item> {
		'outer: while self.start_index < self.tail {
			let mut instructions = Vec::with_capacity(self.tail - self.start_index + 1);

			let mut index = self.start_index;
			while index < self.tail {
				if instructions.len() == self.max_instructions {
					self.start_index += 1;
					continue 'outer;
				}

				let current = &self.disassembly.instructions[index];
				match is_gadget_head(current) {
					true => {
						instructions.push(current.clone());
						index += current.len()
					}
					false => {
						self.start_index += 1;
						continue 'outer;
					}
				}
			}

			if index == self.tail {
				instructions.push(self.disassembly.instructions[self.tail]);
				let extra_len = self.disassembly.instructions[self.tail].len();
				let gadget = Gadget {
					file_offset: self.disassembly.file_offset + self.start_index,
					len: self.tail + extra_len - self.start_index,
					instructions,
				};
				self.start_index += 1;
				return Some(gadget);
			}
			else {
				self.start_index += 1;
			}
		}
		None
	}
}

impl<'b> Disassembly<'b> {
	pub fn new(section: &'b Section) -> Self {
		let bytes = section.bytes();

		let mut instructions = vec![Instruction::default(); bytes.len()];
		let mut disassembler = Disassembler::new(Bitness::Bits64, bytes);

		// Fully disassemble program
		for start in 0..bytes.len() - 1 {
			disassembler.decode_at_offset(
				(section.program_base() + section.section_vaddr() + start) as u64,
				start,
				&mut instructions[start],
			)
		}

		Self {
			bytes,
			instructions,
			file_offset: section.program_base() + section.section_vaddr(),
		}
	}

	pub fn tails<'d>(&'d self, rop: bool, sys: bool, jop: bool) -> TailsIter<'d, 'b> {
		TailsIter {
			disassembly: &self,
			rop,
			sys,
			jop,
			index: 0,
		}
	}

	pub fn gadgets_from_tail<'d>(&'d self, tail: usize, max_instructions: usize) -> GadgetIterator {
		let start_index = tail.checked_sub((max_instructions - 1) * 15).unwrap_or(0);
		GadgetIterator {
			disassembly: &self,
			tail,
			start_index,
			max_instructions,
		}
	}
}
