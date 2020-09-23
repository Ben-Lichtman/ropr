use rayon::prelude::*;
use regex::Regex;
use structopt::StructOpt;

use std::path::PathBuf;

use ropr::{binary::Binary, formatting::format_gadget, settings::Settings};

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
	let b = Binary::new(b).unwrap();
	let sections = b.sections().unwrap();

	let mut settings = Settings::default();
	settings.colour = !opts.nocolour;
	settings.rop = !opts.norop;
	settings.sys = !opts.nosys;
	settings.jop = !opts.nojop;
	settings.max_instructions_per_gadget = opts.max_instr as usize;

	let regex = opts.regex.map(|r| Regex::new(&r).unwrap());

	let mut lexical = sections
		.par_iter()
		.flat_map(|s| s.par_iter_gadgets(&b, settings))
		.map(|g| {
			let (a, g_r, g_d) = format_gadget(&g, settings.clone());
			(g_r, a, g_d)
		})
		.collect::<Vec<_>>();

	lexical.sort_unstable();

	lexical.dedup_by(|a, b| a.0 == b.0);

	for (gadget_raw, addr, gadget_display) in &lexical {
		match &regex {
			Some(r) => {
				if r.is_match(gadget_raw) {
					println!("{} {}", addr, gadget_display);
				}
			}
			None => println!("{} {}", addr, gadget_display),
		}
	}

	println!("{} gadgets found", lexical.len())
}
