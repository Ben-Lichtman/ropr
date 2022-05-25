use crate::rules::{
	is_base_pivot_head, is_rop_gadget_head, is_stack_pivot_head, is_stack_pivot_tail,
};
use iced_x86::{Formatter, FormatterOutput, FormatterTextKind, Instruction};
use std::hash::Hash;

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct Gadget {
	instructions: Vec<Instruction>,
}

impl Gadget {
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
}

pub struct GadgetIterator<'d> {
	section_start: usize,
	tail_instruction: Instruction,
	predecessors: &'d [Instruction],
	max_instructions: usize,
	noisy: bool,
	start_index: usize,
	finished: bool,
}

impl<'d> GadgetIterator<'d> {
	pub fn new(
		section_start: usize,
		tail_instruction: Instruction,
		predecessors: &'d [Instruction],
		max_instructions: usize,
		noisy: bool,
		start_index: usize,
	) -> Self {
		Self {
			section_start,
			tail_instruction,
			predecessors,
			max_instructions,
			noisy,
			start_index,
			finished: false,
		}
	}
}

impl Iterator for GadgetIterator<'_> {
	type Item = (Gadget, usize);

	fn next(&mut self) -> Option<Self::Item> {
		let mut instructions = Vec::new();

		'outer: while !self.predecessors.is_empty() {
			instructions.clear();
			let len = self.predecessors.len();
			let mut index = 0;
			while index < len && instructions.len() < self.max_instructions - 1 {
				let instruction = self.predecessors[index];
				if !is_rop_gadget_head(&instruction, self.noisy) {
					// Found a bad
					self.predecessors = &self.predecessors[1..];
					self.start_index += 1;
					continue 'outer;
				}
				instructions.push(instruction);
				index += instruction.len();
			}

			let current_start_index = self.start_index;

			self.predecessors = &self.predecessors[1..];
			self.start_index += 1;

			if index == len {
				instructions.push(self.tail_instruction);
				// instructions.shrink_to_fit();
				return Some((
					Gadget { instructions },
					self.section_start + current_start_index,
				));
			}
		}

		if !self.finished {
			self.finished = true;
			instructions.clear();
			instructions.push(self.tail_instruction);
			return Some((
				Gadget { instructions },
				self.section_start + self.start_index,
			));
		}

		None
	}
}
