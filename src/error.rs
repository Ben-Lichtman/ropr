use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
	#[error(transparent)]
	IoErr(#[from] std::io::Error),

	#[error(transparent)]
	GoblinErr(#[from] goblin::error::Error),

	#[error("unable to parse binary")]
	ParseErr,

	#[error("unknown error")]
	Unknown,
}
