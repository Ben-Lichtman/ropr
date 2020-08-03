use rayon::prelude::*;

use std::env::args;

use ropr::binary::Binary;
use ropr::formatting::format_gadget;
use ropr::settings::Settings;

fn main() {
	let args = args().into_iter().collect::<Vec<_>>();

	let b = Binary::new(&args[1]).unwrap();
	let sections = b.sections().unwrap();
	let settings = Settings::default();

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

	lexical.dedup();

	for (gadget, addr) in &lexical {
		println!("{} {}", addr, gadget);
	}

	println!("{} gadgets found", lexical.len())
}
