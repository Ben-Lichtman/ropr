use crate::{
	error::Result,
	sections::{parse_archive, parse_blob, parse_elf, parse_mach, parse_pe, Section},
};
use goblin::Object;
use std::{fs::read, path::Path};

pub struct Binary<'p> {
	path: &'p Path,
	bytes: Vec<u8>,
}

impl<'p> Binary<'p> {
	pub fn new(path: &'p impl AsRef<Path>) -> Result<Self> {
		let path = path.as_ref();
		let bytes = read(path)?;
		Ok(Self { path, bytes })
	}

	pub fn path(&self) -> &Path { self.path }

	pub fn bytes(&self) -> &[u8] { &self.bytes }

	pub fn sections(&self) -> Result<Vec<Section>> {
		let sections = match Object::parse(&self.bytes)? {
			Object::Elf(e) => parse_elf(&e, &self.bytes)?,
			Object::PE(p) => parse_pe(&p, &self.bytes)?,
			Object::Mach(m) => parse_mach(&m, &self.bytes)?,
			Object::Archive(a) => parse_archive(&a, &self.bytes)?,
			Object::Unknown(_) => parse_blob(&self.bytes)?,
		};
		Ok(sections)
	}
}
