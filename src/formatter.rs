use iced_x86::{FormatterOutput, FormatterTextKind};

use colored::{ColoredString, Colorize};

use std::fmt::{Display, Formatter, Result};

pub struct ColourFormatter {
	output: Vec<ColoredString>,
}

impl Display for ColourFormatter {
	fn fmt(&self, f: &mut Formatter<'_>) -> Result {
		for s in &self.output {
			write!(f, "{}", s)?;
		}
		Ok(())
	}
}

impl ColourFormatter {
	pub fn new() -> Self { Self { output: Vec::new() } }

	pub fn clear(&mut self) { self.output.clear() }
}

impl FormatterOutput for ColourFormatter {
	fn write(&mut self, text: &str, kind: FormatterTextKind) {
		self.output.push(match kind {
			FormatterTextKind::Function => text.red(),
			FormatterTextKind::Mnemonic => text.yellow(),
			FormatterTextKind::Prefix => text.yellow(),
			FormatterTextKind::Register => match text {
				"esp" => text.red(),
				"rsp" => text.red(),
				_ => text.normal(),
			},
			_ => text.normal(),
		})
	}
}
