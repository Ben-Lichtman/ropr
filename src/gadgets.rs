use crate::{
	disassembler::Disassembly,
	rules::{
		is_base_pivot_head, is_gadget_tail, is_rop_gadget_head, is_stack_pivot_head,
		is_stack_pivot_tail,
	},
};
use iced_x86::{Formatter, FormatterOutput, FormatterTextKind, Instruction};
use std::{
	cmp::Ordering,
	hash::{Hash, Hasher},
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

	pub fn _len(&self) -> usize { self.len }

	pub fn instructions(&self) -> &[Instruction] { &self.instructions }

	pub fn is_stack_pivot(&self) -> bool {
		match self.instructions.as_slice() {
			[] => false,
			[t] => is_stack_pivot_tail(t),
			[h @ .., _] => h.iter().any(is_stack_pivot_head),
		}
	}

	pub fn is_base_pivot(&self) -> bool {
		match self.instructions.as_slice() {
			[] => false,
			[_] => false,
			[h @ .., _] => h.iter().any(is_base_pivot_head),
		}
	}

	pub fn format_instruction(&self, output: &mut impl FormatterOutput) {
		let mut formatter = iced_x86::IntelFormatter::new();
		let options = iced_x86::Formatter::options_mut(&mut formatter);
		options.set_hex_prefix("0x");
		options.set_hex_suffix("");
		options.set_space_after_operand_separator(true);
		options.set_branch_leading_zeroes(false);
		options.set_uppercase_hex(false);
		options.set_rip_relative_addresses(true);
		// Write instructions
		let mut instructions = self.instructions.iter().peekable();
		while let Some(i) = instructions.next() {
			formatter.format(i, output);
			output.write(";", FormatterTextKind::Text);
			if instructions.peek().is_some() {
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

pub struct TailsIter<'b, 'd> {
	disassembly: &'d Disassembly<'b>,
	rop: bool,
	sys: bool,
	jop: bool,
	noisy: bool,
	index: usize,
}

impl<'b, 'd> TailsIter<'b, 'd> {
	pub fn new(
		disassembly: &'d Disassembly<'b>,
		rop: bool,
		sys: bool,
		jop: bool,
		noisy: bool,
	) -> Self {
		Self {
			disassembly,
			rop,
			sys,
			jop,
			noisy,
			index: 0,
		}
	}
}

impl Iterator for TailsIter<'_, '_> {
	type Item = usize;

	fn next(&mut self) -> Option<Self::Item> {
		while let Some(instr) = self.disassembly.instruction(self.index) {
			if is_gadget_tail(instr, self.rop, self.sys, self.jop, self.noisy) {
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
	max_instructions: usize,
	noisy: bool,
	start_index: usize,
}

impl<'b, 'd> GadgetIterator<'b, 'd> {
	pub fn new(
		disassembly: &'d Disassembly<'b>,
		tail: usize,
		max_instructions: usize,
		noisy: bool,
		start_index: usize,
	) -> Self {
		Self {
			disassembly,
			tail,
			max_instructions,
			noisy,
			start_index,
		}
	}
}

impl<'b> Iterator for GadgetIterator<'b, '_> {
	type Item = Gadget;

	fn next(&mut self) -> Option<Self::Item> {
		'outer: while self.start_index <= self.tail {
			let mut instructions = Vec::with_capacity(self.tail - self.start_index + 1);

			let mut index = self.start_index;
			while index < self.tail {
				if instructions.len() == self.max_instructions - 1 {
					self.start_index += 1;
					continue 'outer;
				}

				let current = *self.disassembly.instruction(index).unwrap();
				match is_rop_gadget_head(&current, self.noisy) {
					true => {
						instructions.push(current);
						index += current.len()
					}
					false => {
						self.start_index += 1;
						continue 'outer;
					}
				}
			}

			if index == self.tail {
				instructions.push(*self.disassembly.instruction(self.tail).unwrap());
				let extra_len = self.disassembly.instruction(self.tail).unwrap().len();
				let gadget = Gadget {
					file_offset: self.disassembly.file_offset() + self.start_index,
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
