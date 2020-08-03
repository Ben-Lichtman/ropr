use goblin::archive::Archive;
use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::pe::PE;

use goblin::elf64::program_header::PF_X;
use goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE;

use crate::binary::Binary;
use crate::error::Error;
use crate::gadgets::{gadget_iterator_par, Gadget, GadgetIterator};
use crate::settings::Settings;

pub struct Section {
	pub file_start: usize,
	pub file_end: usize,
	pub section_vaddr: usize,
	pub program_base: usize,
}

impl<'a> Section {
	pub fn iter_gadgets(&'a self, binary: &'a Binary, settings: Settings) -> GadgetIterator {
		GadgetIterator::from_section(binary, self, settings)
	}

	pub fn par_iter_gadgets(&'a self, binary: &'a Binary, settings: Settings) -> Vec<Gadget> {
		gadget_iterator_par(binary, self, settings)
	}
}

pub fn from_elf(binary: &Binary, elf: Elf) -> Result<Vec<Section>, Error> {
	let sections = elf
		.program_headers
		.iter()
		.filter(|header| header.p_flags & PF_X != 0)
		.map(|header| {
			let start_offset = header.p_offset as usize;
			let end_offset = start_offset + header.p_filesz as usize;
			Section {
				file_start: start_offset,
				file_end: end_offset,
				section_vaddr: header.p_vaddr as usize,
				program_base: 0,
			}
		})
		.collect::<Vec<_>>();
	Ok(sections)
}

pub fn from_pe(binary: &Binary, pe: PE) -> Result<Vec<Section>, Error> {
	let sections = pe
		.sections
		.iter()
		.filter(|section| (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
		.map(|section| {
			let start_offset = section.pointer_to_raw_data as usize;
			let end_offset = start_offset + section.size_of_raw_data as usize;
			Section {
				file_start: start_offset,
				file_end: end_offset,
				section_vaddr: section.virtual_address as usize,
				program_base: pe.image_base,
			}
		})
		.collect::<Vec<_>>();
	Ok(sections)
}

pub fn from_mach(binary: &Binary, mach: Mach) -> Result<Vec<Section>, Error> { unimplemented!() }

pub fn from_archive(binary: &Binary, archive: Archive) -> Result<Vec<Section>, Error> {
	unimplemented!()
}
