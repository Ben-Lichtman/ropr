use structopt::StructOpt;

use regex::Regex;

use rayon::prelude::*;

use std::{collections::HashSet, path::PathBuf};

use ropr::{binary::Binary, formatter::ColourFormatter, gadgets::Disassembly};

#[derive(StructOpt)]
#[structopt(name = "ropr")]
struct Opt {
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
	let opts = Opt::from_args();

	let b = opts.binary;
	let b = Binary::new(&b).unwrap();
	let sections = b.sections().unwrap();

	let colour = !opts.nocolour;
	let rop = !opts.norop;
	let sys = !opts.nosys;
	let jop = !opts.nojop;
	let max_instructions_per_gadget = opts.max_instr as usize;

	let regex = opts.regex.map(|r| Regex::new(&r).unwrap());

	let gadgets = sections
		.iter()
		.filter_map(|section| Disassembly::new(&section))
		.flat_map(|dis| {
			let tails = dis.tails(rop, sys, jop).collect::<Vec<_>>();
			tails
				.into_par_iter()
				.flat_map_iter(|tail| dis.gadgets_from_tail(tail, max_instructions_per_gadget))
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

	let mut gadget_count = 0;

	if colour {
		let mut output = ColourFormatter::new();
		for (gadget, _) in gadgets {
			output.clear();
			gadget.format_full(&mut output);
			println!("{}", output);
			gadget_count += 1;
		}
	}
	else {
		let mut output = String::new();
		for (gadget, _) in gadgets {
			output.clear();
			gadget.format_full(&mut output);
			println!("{}", output);
			gadget_count += 1;
		}
	}

	println!("Found {} gadgets", gadget_count);
}
