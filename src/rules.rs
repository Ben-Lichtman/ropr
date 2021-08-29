// Instructions currently may contains conditional branches in the head and may not contain unconditional relative branches or relative calls / jumps

use iced_x86::{Code, FlowControl, Instruction, Mnemonic, OpKind, Register};

fn is_ret(instr: &Instruction) -> bool { matches!(instr.mnemonic(), Mnemonic::Ret) }

fn is_sys(instr: &Instruction) -> bool {
	match instr.mnemonic() {
		Mnemonic::Syscall => true,
		Mnemonic::Int => matches!(instr.try_immediate(0).unwrap(), 0x80),
		_ => false,
	}
}

fn is_jop(instr: &Instruction) -> bool {
	match instr.mnemonic() {
		Mnemonic::Jmp => match instr.op0_kind() {
			OpKind::Register => true,
			OpKind::Memory => !matches!(instr.memory_base(), Register::EIP | Register::RIP),
			_ => false,
		},
		Mnemonic::Call => match instr.op0_kind() {
			OpKind::Register => true,
			OpKind::Memory => !matches!(instr.memory_base(), Register::EIP | Register::RIP),
			_ => false,
		},
		_ => false,
	}
}

fn is_invalid(instr: &Instruction) -> bool { matches!(instr.code(), Code::INVALID) }

pub fn is_gadget_tail(instr: &Instruction, rop: bool, sys: bool, jop: bool) -> bool {
	if is_invalid(instr) {
		return false;
	}
	if instr.flow_control() == FlowControl::Next {
		return false;
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
		FlowControl::ConditionalBranch => (),
		_ => return false,
	}
	true
}
