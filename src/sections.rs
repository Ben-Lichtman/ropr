use crate::error::Result;
use goblin::{
	archive::Archive,
	elf::Elf,
	elf64::program_header::PF_X,
	mach::Mach,
	pe::{section_table::IMAGE_SCN_MEM_EXECUTE, PE},
};

pub struct Section<'b> {
	file_offset: usize,
	section_vaddr: usize,
	program_base: usize,
	bytes: &'b [u8],
}

impl Section<'_> {
	pub fn file_offset(&self) -> usize { self.file_offset }

	pub fn section_vaddr(&self) -> usize { self.section_vaddr }

	pub fn program_base(&self) -> usize { self.program_base }

	pub fn bytes(&self) -> &[u8] { self.bytes }
}

pub fn parse_elf<'b>(elf: &Elf, bytes: &'b [u8]) -> Result<Vec<Section<'b>>> {
	let sections = elf
		.program_headers
		.iter()
		.filter(|header| header.p_flags & PF_X != 0)
		.map(|header| {
			let start_offset = header.p_offset as usize;
			let end_offset = start_offset + header.p_filesz as usize;
			Section {
				file_offset: start_offset,
				section_vaddr: header.p_vaddr as usize,
				program_base: 0,
				bytes: &bytes[start_offset..end_offset],
			}
		})
		.collect::<Vec<_>>();
	Ok(sections)
}

pub fn parse_pe<'b>(pe: &PE, bytes: &'b [u8]) -> Result<Vec<Section<'b>>> {
	let sections = pe
		.sections
		.iter()
		.filter(|section| (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
		.map(|section| {
			let start_offset = section.pointer_to_raw_data as usize;
			let end_offset = start_offset + section.size_of_raw_data as usize;
			Section {
				file_offset: start_offset,
				section_vaddr: section.virtual_address as usize,
				program_base: pe.image_base,
				bytes: &bytes[start_offset..end_offset],
			}
		})
		.collect::<Vec<_>>();
	Ok(sections)
}

pub fn parse_mach<'b>(_mach: &Mach, _bytes: &'b [u8]) -> Result<Vec<Section<'b>>> {
	unimplemented!()
}

pub fn parse_archive<'b>(_archive: &Archive, _bytes: &'b [u8]) -> Result<Vec<Section<'b>>> {
	unimplemented!()
}

pub fn parse_blob(bytes: &[u8]) -> Result<Vec<Section<'_>>> {
	Ok(vec![Section {
		file_offset: 0,
		section_vaddr: 0,
		program_base: 0,
		bytes,
	}])
}
