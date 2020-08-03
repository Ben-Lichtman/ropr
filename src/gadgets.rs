use zydis::{DecodedInstruction, Decoder};

use rayon::prelude::*;

use std::cmp::{Ord, Ordering};
use std::hash::{Hash, Hasher};
use std::iter::Peekable;

use crate::binary::Binary;
use crate::rules::is_valid_gadget;
use crate::sections::Section;
use crate::settings::Settings;

#[derive(Clone)]
pub struct Gadget {
	pub file_offset: usize,
	pub mem_offset: usize,
	instructions: Vec<DecodedInstruction>,
}

impl PartialEq for Gadget {
	fn eq(&self, other: &Self) -> bool { self.instructions == other.instructions }
}

impl Eq for Gadget {}

impl PartialOrd for Gadget {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Ord for Gadget {
	fn cmp(&self, other: &Self) -> Ordering { Ord::cmp(&self.file_offset, &other.file_offset) }
}

impl AsRef<[DecodedInstruction]> for Gadget {
	fn as_ref(&self) -> &[DecodedInstruction] { &self.instructions }
}

impl Hash for Gadget {
	fn hash<H: Hasher>(&self, state: &mut H) { self.instructions.hash(state); }
}

#[derive(Clone, Copy)]
struct GadgetEnd {
	offset: usize,
	length: u8,
}

struct GadgetEndIterator<'b, 's> {
	binary: &'b Binary,
	section: &'s Section,
	settings: Settings,
	disassembler: Decoder,
	current_pos: usize,
}

impl<'b, 's> Iterator for GadgetEndIterator<'b, 's> {
	type Item = GadgetEnd;

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			let file_pos = self.current_pos;

			if self.current_pos >= self.section.file_end {
				break None;
			}

			self.current_pos += 1;

			let inspected_slice = &self.binary.bytes()[file_pos..];
			let ip = (self.section.program_base + self.section.section_vaddr + file_pos) as u64;
			let instructions = self.disassembler.instruction_iterator(inspected_slice, ip);

			let gadget_end = match instructions.map(|x| x.0).next() {
				Some(t) => t,
				None => continue,
			};

			let array = [gadget_end];

			if !is_valid_gadget(&array, self.settings) {
				continue;
			}

			break Some(GadgetEnd {
				offset: file_pos,
				length: array[0].length,
			});
		}
	}
}

impl<'b, 's> GadgetEndIterator<'b, 's> {
	pub fn from_section(binary: &'b Binary, section: &'s Section, settings: Settings) -> Self {
		let disassembler = Decoder::new(
			settings.disassembler_machine_mode,
			settings.disassembler_address_width,
		)
		.unwrap();

		let start_pos = section.file_start;

		GadgetEndIterator {
			binary,
			section,
			settings,
			disassembler,
			current_pos: start_pos,
		}
	}
}

pub struct GadgetIterator<'b, 's> {
	binary: &'b Binary,
	section: &'s Section,
	settings: Settings,
	disassembler: Decoder,
	ends: Peekable<GadgetEndIterator<'b, 's>>,
	extra_bytes: usize,
}

impl<'b, 's> Iterator for GadgetIterator<'b, 's> {
	type Item = Gadget;

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			let extra_bytes = self.extra_bytes;

			let GadgetEnd { offset, length } = match self.ends.peek() {
				Some(e) => e,
				None => break None,
			};

			// Is slice too big
			if *length as usize + extra_bytes
				> self.settings.max_bytes_per_instruction
					* self.settings.max_instructions_per_gadget
			{
				self.extra_bytes = 0;
				self.ends.next();
				continue;
			}

			// Make sure integer doesn't overflow
			let slice_start = match offset.checked_sub(extra_bytes) {
				Some(s) => s,
				None => {
					self.extra_bytes = 0;
					self.ends.next();
					continue;
				}
			};
			let slice_end = offset + (*length as usize);

			if slice_start < self.section.file_start {
				self.extra_bytes = 0;
				self.ends.next();
				continue;
			}

			self.extra_bytes += 1;

			let current_gadget_slice = &self.binary.bytes()[slice_start..slice_end];

			let ip = (self.section.program_base + self.section.section_vaddr + slice_start) as u64;
			let current_gadget = self
				.disassembler
				.instruction_iterator(current_gadget_slice, ip);

			let current_gadget = current_gadget.map(|x| x.0).collect::<Vec<_>>();

			if current_gadget.len() == 0 {
				continue;
			}

			if current_gadget.len() > self.settings.max_instructions_per_gadget {
				continue;
			}

			if !is_valid_gadget(&current_gadget, self.settings) {
				continue;
			}

			break Some(Gadget {
				file_offset: slice_start,
				mem_offset: self.section.program_base + self.section.section_vaddr + slice_start,
				instructions: current_gadget,
			});
		}
	}
}

impl<'b, 's> GadgetIterator<'b, 's> {
	pub fn from_section(binary: &'b Binary, section: &'s Section, settings: Settings) -> Self {
		let disassembler = Decoder::new(
			settings.disassembler_machine_mode,
			settings.disassembler_address_width,
		)
		.unwrap();

		let ends = GadgetEndIterator::from_section(binary, section, settings).peekable();

		GadgetIterator {
			binary,
			section,
			disassembler,
			ends,
			settings,
			extra_bytes: 0,
		}
	}
}

pub struct ParGadgetIterator<'b, 's> {
	binary: &'b Binary,
	section: &'s Section,
	settings: Settings,
	disassembler: Decoder,
	end: GadgetEnd,
	extra_bytes: usize,
}

impl<'b, 's> Iterator for ParGadgetIterator<'b, 's> {
	type Item = Gadget;

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			let extra_bytes = self.extra_bytes;

			let GadgetEnd { offset, length } = self.end;

			// Is slice too big
			if length as usize + extra_bytes
				> self.settings.max_bytes_per_instruction
					* self.settings.max_instructions_per_gadget
			{
				break None;
			}

			// Make sure integer doesn't overflow
			let slice_start = match offset.checked_sub(extra_bytes) {
				Some(s) => s,
				None => break None,
			};
			let slice_end = offset + (length as usize);

			if slice_start < self.section.file_start {
				break None;
			}

			self.extra_bytes += 1;

			let current_gadget_slice = &self.binary.bytes()[slice_start..slice_end];

			let ip = (self.section.program_base + self.section.section_vaddr + slice_start) as u64;
			let current_gadget = self
				.disassembler
				.instruction_iterator(current_gadget_slice, ip);

			let current_gadget = current_gadget.map(|x| x.0).collect::<Vec<_>>();

			if current_gadget.len() == 0 {
				continue;
			}

			if current_gadget.len() > self.settings.max_instructions_per_gadget {
				continue;
			}

			if !is_valid_gadget(&current_gadget, self.settings) {
				continue;
			}

			break Some(Gadget {
				file_offset: slice_start,
				mem_offset: self.section.program_base + self.section.section_vaddr + slice_start,
				instructions: current_gadget,
			});
		}
	}
}

pub fn gadget_iterator_par<'b, 's>(
	binary: &'b Binary,
	section: &'s Section,
	settings: Settings,
) -> Vec<Gadget> {
	let disassembler = Decoder::new(
		settings.disassembler_machine_mode,
		settings.disassembler_address_width,
	)
	.unwrap();

	let ends = GadgetEndIterator::from_section(binary, section, settings).collect::<Vec<_>>();

	let gadgets = ends
		.par_iter()
		.copied()
		.map(|end| {
			let iterator = ParGadgetIterator {
				binary,
				section,
				disassembler: disassembler.clone(),
				end,
				settings,
				extra_bytes: 0,
			};

			iterator.collect::<Vec<_>>()
		})
		.flatten()
		.collect::<Vec<_>>();

	gadgets
}
