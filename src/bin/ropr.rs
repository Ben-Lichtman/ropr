use rayon::prelude::*;
use regex::Regex;
use ropr::{binary::Binary, formatter::ColourFormatter, gadgets::Disassembly};
use std::{
	collections::HashSet,
	io::{stdout, BufWriter, Write},
	path::PathBuf,
	time::Instant,
};
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "ropr")]
struct Opt {
	#[structopt(short = "n", long)]
	noisy: bool,

	#[structopt(short = "c", long)]
	nocolour: bool,

	#[structopt(short = "r", long)]
	norop: bool,

	#[structopt(short = "s", long)]
	nosys: bool,

	#[structopt(short = "j", long)]
	nojop: bool,

	#[structopt(short, long, default_value = "6")]
	max_instr: u8,

	#[structopt(short = "R", long)]
	regex: Option<String>,

	binary: PathBuf,
}

fn main() {
	let start = Instant::now();

	let opts = Opt::from_args();

	let b = opts.binary;
	let b = Binary::new(&b).unwrap();
	let sections = b.sections().unwrap();

	let noisy = opts.noisy;
	let colour = !opts.nocolour;
	let rop = !opts.norop;
	let sys = !opts.nosys;
	let jop = !opts.nojop;
	let max_instructions_per_gadget = opts.max_instr as usize;

	let regex = opts.regex.map(|r| Regex::new(&r).unwrap());

	let gadgets = sections
		.iter()
		.filter_map(|section| Disassembly::new(section))
		.flat_map(|dis| {
			let tails = dis.tails(rop, sys, jop, noisy).collect::<Vec<_>>();
			tails
				.into_par_iter()
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
		.filter(|(_, formatted)| match &regex {
			Some(r) => r.is_match(formatted),
			None => true,
		})
		.collect::<Vec<_>>();
	gadgets.sort_unstable_by(|(_, a), (_, b)| a.cmp(b));

	let gadget_count = gadgets.len();

	// Don't account for time it takes to print gadgets - since this depends on terminal speed
	let elapsed = Instant::now() - start;

	// Stdout uses a LineWriter internally, therefore we improve performance by wrapping stdout in a BufWriter
	let mut stdout = BufWriter::new(stdout());

	if colour {
		let mut output = ColourFormatter::new();
		for (gadget, _) in gadgets {
			output.clear();
			gadget.format_full(&mut output);
			writeln!(stdout, "{}", output).unwrap();
		}
	}
	else {
		let mut output = String::new();
		for (gadget, _) in gadgets {
			output.clear();
			gadget.format_full(&mut output);
			writeln!(stdout, "{}", output).unwrap();
		}
	}

	stdout.flush().unwrap();

	eprintln!(
		"\n==> Found {} gadgets in {:.3} seconds",
		gadget_count,
		elapsed.as_secs_f32()
	);
}
