
#ifndef FPU_INST_H
#define FPU_INST_H

#include <stdint.h>
#include "ebpf_inst.h"
#include <iostream>

/* instruction classes */
#define FLDX (0x01)
#define FST (0x02)
#define FSTX (0x03)
#define FALU (0x04)
#define FJMP (0x05)

/* arithmetic operations */
#define FADD (0x00)
#define FSUB (0x10)
#define FMUL (0x20)
#define FDIV (0x30)
#define FNEG (0x80)
#define FMEM (0xa0) // for LDX, ST(X), equal to XOR for ALU instructions
#define FMOV (0xb0)

/* jump operations */
#define FJEQ (0x10)
#define FJOGT (0x20)
#define FJOGE (0x30)
#define FJNE (0x50)
#define FJUGT (0x60)
#define FJUGE (0x70)
#define FJOLT (0xa0)
#define FJOLE (0xb0)
#define FJULT (0xc0)
#define FJULE (0xd0)

/* src */
#define FIMM (0x00)
#define FREG (0x08)

/* size */
#define FWORD (0x00) // duotronic only supports words

/* ALU instructions */
#define DUO_OP_FADD_IMM (FADD | FIMM | FALU)
#define DUO_OP_FADD_REG (FADD | FREG | FALU)
#define DUO_OP_FSUB_IMM (FSUB | FIMM | FALU)
#define DUO_OP_FSUB_REG (FSUB | FREG | FALU)
#define DUO_OP_FMUL_IMM (FMUL | FIMM | FALU)
#define DUO_OP_FMUL_REG (FMUL | FREG | FALU)
#define DUO_OP_FDIV_IMM (FDIV | FIMM | FALU)
#define DUO_OP_FDIV_REG (FDIV | FREG | FALU)
#define DUO_OP_FNEG (FNEG | 0x00 | FALU) // FNEG uses no source
#define DUO_OP_FMOV_IMM (FMOV | FIMM | FALU)
#define DUO_OP_FMOV_REG (FMOV | FREG | FALU)

/* Load+Store instructions */
#define DUO_OP_FLDX (FMEM | FWORD | FLDX)
#define DUO_OP_FST (FMEM | FWORD | FST)
#define DUO_OP_FSTX (FMEM | FWORD | FSTX)

/* Jump instructions */
#define DUO_OP_FJEQ_IMM (FJEQ | FIMM | FJMP)
#define DUO_OP_FJEQ_REG (FJEQ | FREG | FJMP)
#define DUO_OP_FJOGT_IMM (FJOGT | FIMM | FJMP)
#define DUO_OP_FJOGT_REG (FJOGT | FREG | FJMP)
#define DUO_OP_FJOGE_IMM (FJOGE | FIMM | FJMP)
#define DUO_OP_FJOGE_REG (FJOGE | FREG | FJMP)
#define DUO_OP_FJNE_IMM (FJNE | FIMM | FJMP)
#define DUO_OP_FJNE_REG (FJNE | FREG | FJMP)
#define DUO_OP_FJUGT_IMM (FJUGT | FIMM | FJMP)
#define DUO_OP_FJUGT_REG (FJUGT | FREG | FJMP)
#define DUO_OP_FJUGE_IMM (FJUGE | FIMM | FJMP)
#define DUO_OP_FJUGE_REG (FJUGE | FREG | FJMP)
#define DUO_OP_FJOLT_IMM (FJOLT | FIMM | FJMP)
#define DUO_OP_FJOLT_REG (FJOLT | FREG | FJMP)
#define DUO_OP_FJOLE_IMM (FJOLE | FIMM | FJMP)
#define DUO_OP_FJOLE_REG (FJOLE | FREG | FJMP)
#define DUO_OP_FJULT_IMM (FJULT | FIMM | FJMP)
#define DUO_OP_FJULT_REG (FJULT | FREG | FJMP)
#define DUO_OP_FJULE_IMM (FJULE | FIMM | FJMP)
#define DUO_OP_FJULE_REG (FJULE | FREG | FJMP)

inline uint8_t duo_opcode(const ebpf_inst &inst)
{
	return inst.opcode & 0xf0;
}

inline uint8_t duo_class(const ebpf_inst &inst)
{
	return inst.opcode & 0x7;
}

inline uint8_t duo_source(const ebpf_inst &inst)
{
	return inst.opcode & 0x8;
}

inline bool duo_is_fpu(const ebpf_inst &inst)
{
	/* FJMP instructions:
	 * REG/REG: 1st bit of IMM is set
	 * REG/IMM: SRC reg = 0xf */
	if (duo_class(inst) == FJMP) {
		if (duo_source(inst) == FREG) {
			if (inst.imm & 0x02)
				return true;
		} else {
			if (inst.src == 0xf)
				return true;
		}
	}

	/* FMOV instructions:
	 * Are uniquely FPUs as FMEM isn't used elsewhere */
	if (duo_opcode(inst) == FMEM)
		return true;

	/* FALU:
	 * 1st bit of offset is set */
	if (duo_class(inst) == FALU) {
		if (inst.offset & 0x02)
			return true;
	}

	return false;
}

#endif // FPU_INST_H
