use std::{fs::read, path::PathBuf};

use goblin::Object;

use crate::{
	error::Error,
	sections::{self, Section},
};

pub struct Binary {
	path: PathBuf,
	bytes: Vec<u8>,
}

impl Binary {
	pub fn new(path: impl Into<PathBuf>) -> Result<Self, Error> {
		let path = path.into();
		let bytes = read(&path)?;
		Ok(Self { path, bytes })
	}

	pub fn sections(&self) -> Result<Vec<Section>, Error> {
		let sections = match Object::parse(&self.bytes)? {
			Object::Elf(e) => sections::from_elf(self, e)?,
			Object::PE(p) => sections::from_pe(self, p)?,
			Object::Mach(m) => sections::from_mach(self, m)?,
			Object::Archive(a) => sections::from_archive(self, a)?,
			Object::Unknown(_) => return Err(Error::ParseErr),
		};
		Ok(sections)
	}

	pub fn bytes(&self) -> &[u8] { &self.bytes }
}
