use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
	#[error(transparent)]
	IoErr(#[from] std::io::Error),
	#[error(transparent)]
	GoblinErr(#[from] goblin::error::Error),
	#[error("unable to parse binary")]
	ParseErr,
	#[error("unsupported format or architecture")]
	Unsupported,
}
