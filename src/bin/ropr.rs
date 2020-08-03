use rayon::prelude::*;
use structopt::StructOpt;

use std::path::PathBuf;

use ropr::binary::Binary;
use ropr::formatting::format_gadget;
use ropr::settings::Settings;

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

	// let mut set = HashSet::new();

	// for section in sections {
	// 	for gadget in section.iter_gadgets(&b, settings) {
	// 		set.insert(gadget);
	// 	}
	// }

	let mut lexical = sections
		.par_iter()
		.flat_map(|s| s.par_iter_gadgets(&b, settings))
		.map(|g| {
			let (a, g) = format_gadget(&g, settings.clone());
			(g, a)
		})
		.collect::<Vec<_>>();

	lexical.sort_unstable();

	lexical.dedup_by(|a, b| a.0 == b.0);

	for (gadget, addr) in &lexical {
		println!("{} {}", addr, gadget);
	}

	println!("{} gadgets found", lexical.len())
}
