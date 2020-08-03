use zydis::{
	Formatter, FormatterBuffer, FormatterContext, FormatterStyle, OutputBuffer, Register, Status,
};

use colored::{ColoredString, Colorize};

use std::any::Any;
use std::fmt::Write;

use crate::gadgets::Gadget;
use crate::settings::Settings;

const FORMAT_BUF_SIZE: usize = 0x100;

pub fn format_gadget(gadget: &Gadget, mut settings: Settings) -> (String, String) {
	let addr = gadget.file_offset;

	let mut buf = [0u8; FORMAT_BUF_SIZE];
	let mut buf = OutputBuffer::new(&mut buf);

	let mut formatter = match settings.intel_syntax {
		true => Formatter::new(FormatterStyle::INTEL),
		false => Formatter::new(FormatterStyle::ATT),
	}
	.unwrap();

	formatter
		.set_print_register(Box::new(reg_callback))
		.unwrap();
	formatter
		.set_print_mnemonic(Box::new(mnemonic_callback))
		.unwrap();

	let mut address_output = String::new();
	write!(&mut address_output, "[{:016x}]:", addr).unwrap();
	match settings.colour {
		true => address_output = address_output.red().to_string(),
		false => (),
	}

	// Compansate for oddity in the formatting
	address_output.retain(|c| c != '\x1f');

	let mut gadget_output = String::new();
	for instruction in gadget.as_ref() {
		formatter
			.format_instruction(&instruction, &mut buf, None, Some(&mut settings))
			.unwrap();
		write!(&mut gadget_output, "{}; ", buf.as_str().unwrap()).unwrap();
	}

	// Compansate for oddity in the formatting
	gadget_output.retain(|c| c != '\x1f');

	(address_output, gadget_output)
}

fn reg_callback(
	_formatter: &Formatter,
	buffer: &mut FormatterBuffer,
	_ctx: &mut FormatterContext,
	reg: Register,
	user_data: Option<&mut dyn Any>,
) -> Result<(), Status> {
	let settings = user_data
		.ok_or(Status::User)?
		.downcast_ref::<Settings>()
		.ok_or(Status::User)?;

	let string = reg.get_string().ok_or(Status::User)?;

	let string = match settings.colour {
		false => ColoredString::from(string),
		true => match reg {
			Register::RSP | Register::ESP | Register::SP => string.red(),
			_ => ColoredString::from(string),
		},
	};

	let buffer_out = buffer.get_string().map_err(|_| Status::User)?;

	// Panics without the leading byte - not sure why
	write!(buffer_out, "\x1f{}", string).map_err(|_| Status::User)
}

fn mnemonic_callback(
	_formatter: &Formatter,
	buffer: &mut FormatterBuffer,
	ctx: &mut FormatterContext,
	user_data: Option<&mut dyn Any>,
) -> Result<(), Status> {
	let settings = user_data
		.ok_or(Status::User)?
		.downcast_ref::<Settings>()
		.ok_or(Status::User)?;

	let instr = unsafe { &*ctx.instruction }; // Unsafe necessary due to Zydis CFFI

	buffer.append(zydis::TOKEN_MNEMONIC)?;

	let buffer_out = buffer.get_string().map_err(|_| Status::User)?;

	let string = instr.mnemonic.get_string().ok_or(Status::User)?;

	let string = match settings.colour {
		false => ColoredString::from(string),
		true => string.yellow().bold(),
	};

	// Panics without the leading byte - not sure why
	write!(buffer_out, "\x1f{}", string).map_err(|_| Status::User)
}
