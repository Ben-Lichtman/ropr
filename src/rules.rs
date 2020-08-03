use zydis::{
	DecodedInstruction, InstructionCategory, Mnemonic, OperandAction, OperandType, Register,
};

use crate::settings::Settings;

fn is_gadget_tail(instr: &DecodedInstruction, settings: Settings) -> bool {
	if settings.rop && is_ret(instr) {
		return true;
	}
	if settings.sys && (is_int(instr) || is_syscall(instr)) {
		return true;
	}
	if settings.jop && is_jop_gadget_tail(instr) {
		return true;
	}

	false
}

fn is_gadget_head(instrs: &[DecodedInstruction]) -> bool {
	for instr in instrs {
		if is_ret(instr) || is_int(instr) || is_syscall(instr) || is_call(instr) || is_jmp(instr) {
			return false;
		}
	}
	true
}

pub fn is_valid_gadget(instrs: &[DecodedInstruction], settings: Settings) -> bool {
	let (last, rest) = instrs.split_last().unwrap();

	if !is_gadget_tail(last, settings) {
		return false;
	}

	if !is_gadget_head(rest) {
		return false;
	}

	true
}

fn is_jop_gadget_tail(instr: &DecodedInstruction) -> bool {
	is_reg_set_jmp(instr)
		|| is_reg_set_call(instr)
		|| is_mem_ptr_set_jmp(instr)
		|| is_mem_ptr_set_call(instr)
}

fn is_reg_set_call(instr: &DecodedInstruction) -> bool { is_call(&instr) && is_single_reg(&instr) }

fn is_reg_set_jmp(instr: &DecodedInstruction) -> bool { is_jmp(&instr) && is_single_reg(&instr) }

fn is_mem_ptr_set_jmp(instr: &DecodedInstruction) -> bool {
	is_jmp(&instr) && is_single_reg_deref(&instr)
}

fn is_mem_ptr_set_call(instr: &DecodedInstruction) -> bool {
	is_call(&instr) && is_single_reg_deref(&instr)
}

fn is_single_reg(instr: &DecodedInstruction) -> bool {
	let regs_read_cnt = instr
		.operands
		.iter()
		.filter(|o| (o.action == OperandAction::READ) && (o.ty == OperandType::REGISTER))
		.count();

	regs_read_cnt == 1
}

fn is_single_reg_deref(instr: &DecodedInstruction) -> bool {
	let regs_deref_cnt = instr
		.operands
		.iter()
		.filter(|o| {
			(o.action == OperandAction::READ)
				&& (o.ty == OperandType::MEMORY)
				&& (o.mem.base != Register::NONE)
		})
		.count();

	regs_deref_cnt == 1
}

fn is_ret(instr: &DecodedInstruction) -> bool { instr.meta.category == InstructionCategory::RET }

fn is_call(instr: &DecodedInstruction) -> bool { instr.meta.category == InstructionCategory::CALL }

fn is_jmp(instr: &DecodedInstruction) -> bool { instr.mnemonic == Mnemonic::JMP }

fn is_syscall(instr: &DecodedInstruction) -> bool {
	instr.meta.category == InstructionCategory::SYSCALL
}

fn is_int(instr: &DecodedInstruction) -> bool {
	instr.meta.category == InstructionCategory::INTERRUPT
}
