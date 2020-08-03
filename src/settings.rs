use zydis::{AddressWidth, MachineMode};

#[derive(Copy, Clone)]
pub struct Settings {
	pub disassembler_machine_mode: MachineMode,
	pub disassembler_address_width: AddressWidth,
	pub max_bytes_per_instruction: usize,
	pub max_instructions_per_gadget: usize,
	pub intel_syntax: bool,
	pub colour: bool,
}

impl Default for Settings {
	fn default() -> Self {
		Self {
			disassembler_machine_mode: MachineMode::LONG_64,
			disassembler_address_width: AddressWidth::_64,
			max_bytes_per_instruction: 15,
			max_instructions_per_gadget: 6,
			intel_syntax: true,
			colour: true,
		}
	}
}
