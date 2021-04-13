use iced_x86::{Code, FlowControl, Instruction, Mnemonic, OpKind, Register};

fn is_ret(instr: &Instruction) -> bool {
	match instr.mnemonic() {
		Mnemonic::Ret => true,
		_ => return false,
	}
}

fn is_sys(instr: &Instruction) -> bool {
	match instr.mnemonic() {
		Mnemonic::Syscall => true,
		Mnemonic::Int => match instr.try_immediate(0).unwrap() {
			0x80 => true,
			_ => false,
		},
		_ => false,
	}
}

fn is_jop(instr: &Instruction) -> bool {
	match instr.mnemonic() {
		Mnemonic::Jmp => match instr.op0_kind() {
			OpKind::Register => true,
			OpKind::Memory => match instr.memory_base() {
				Register::EIP => false,
				Register::RIP => false,
				_ => true,
			},
			_ => false,
		},
		Mnemonic::Call => match instr.op0_kind() {
			OpKind::Register => true,
			OpKind::Memory => match instr.memory_base() {
				Register::EIP => false,
				Register::RIP => false,
				_ => true,
			},
			_ => false,
		},
		_ => return false,
	}
}

fn is_invalid(instr: &Instruction) -> bool {
	match instr.code() {
		Code::INVALID => true,
		_ => false,
	}
}

pub fn is_gadget_tail(instr: &Instruction, rop: bool, sys: bool, jop: bool) -> bool {
	if is_invalid(instr) {
		return false;
	}
	match instr.flow_control() {
		FlowControl::Next => return false,
		_ => (),
	}
	if rop && is_ret(instr) {
		return true;
	}
	if sys && is_sys(instr) {
		return true;
	}
	if jop && is_jop(instr) {
		return true;
	}
	false
}

pub fn is_gadget_head(instr: &Instruction) -> bool {
	if is_invalid(instr) {
		return false;
	}
	match instr.flow_control() {
		FlowControl::Next => (),
		_ => return false,
	}
	true
}
