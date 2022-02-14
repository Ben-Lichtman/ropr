use clap::Parser;
use colored::control::set_override;
use core::panic;
use rayon::prelude::*;
use regex::Regex;
use ropr::{binary::Binary, disassembler::Disassembly, formatter::ColourFormatter};
use std::{
	collections::HashSet,
	error::Error,
	io::{stdout, BufWriter, Write},
	path::PathBuf,
	time::Instant,
};

#[derive(Parser)]
#[clap(name = "ropr")]
struct Opt {
	#[clap(short = 'n', long)]
	noisy: bool,

	#[clap(short = 'c', long)]
	colour: Option<bool>,

	#[clap(short = 'r', long)]
	norop: bool,

	#[clap(short = 's', long)]
	nosys: bool,

	#[clap(short = 'j', long)]
	nojop: bool,

	#[clap(short = 'p', long)]
	stack_pivot: bool,

	#[clap(short = 'b', long)]
	base_pivot: bool,

	#[clap(short, long, default_value = "6")]
	max_instr: u8,

	#[clap(short = 'R', long)]
	regex: Vec<String>,

	#[clap(long)]
	raw: Option<bool>,

	binary: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
	let start = Instant::now();

	let opts = Opt::parse();

	let b = opts.binary;
	let b = Binary::new(&b)?;
	let sections = b.sections(opts.raw)?;

	let noisy = opts.noisy;
	let colour = opts.colour;
	let rop = !opts.norop;
	let sys = !opts.nosys;
	let jop = !opts.nojop;
	let stack_pivot = opts.stack_pivot;
	let base_pivot = opts.base_pivot;
	let max_instructions_per_gadget = opts.max_instr as usize;

	if max_instructions_per_gadget == 0 {
		panic!("Max instructions must be >0");
	}

	let regices = opts
		.regex
		.into_iter()
		.map(|r| Regex::new(&r))
		.collect::<Result<Vec<_>, _>>()?;

	let gadgets = sections
		.iter()
		.filter_map(Disassembly::new)
		.flat_map(|dis| {
			(0..dis.bytes().len())
				.into_par_iter()
				.filter(|offset| dis.is_tail_at(*offset, rop, sys, jop, noisy))
				.flat_map_iter(|tail| {
					dis.gadgets_from_tail(tail, max_instructions_per_gadget, noisy)
				})
				.collect::<Vec<_>>()
		})
		.collect::<HashSet<_>>();

	let mut gadgets = gadgets
		.into_iter()
		.map(|g| {
			let mut formatted = String::new();
			g.format_instruction(&mut formatted);
			(g, formatted)
		})
		.filter(|(_, formatted)| regices.iter().all(|r| r.is_match(formatted)))
		.filter(|(g, _)| !stack_pivot | g.is_stack_pivot())
		.filter(|(g, _)| !base_pivot | g.is_base_pivot())
		.collect::<Vec<_>>();
	gadgets.sort_unstable_by(|(_, a), (_, b)| a.cmp(b));

	let gadget_count = gadgets.len();

	// Don't account for time it takes to print gadgets since this depends on terminal implementation
	let elapsed = Instant::now() - start;

	// Stdout uses a LineWriter internally, therefore we improve performance by wrapping stdout in a BufWriter
	let mut stdout = BufWriter::new(stdout());

	if let Some(colour) = colour {
		set_override(colour);
	}

	let mut output = ColourFormatter::new();
	for (gadget, _) in gadgets {
		output.clear();
		gadget.format_full(&mut output);
		writeln!(stdout, "{}", output).unwrap();
	}

	stdout.flush().unwrap();

	eprintln!(
		"\n==> Found {} gadgets in {:.3} seconds",
		gadget_count,
		elapsed.as_secs_f32()
	);

	Ok(())
}
