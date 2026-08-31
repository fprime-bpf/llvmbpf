/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include <iostream>
#include <algorithm>
#include "llvm/IR/Argument.h"
#include "llvm_jit_context.hpp"
#include "ebpf_inst.h"
#include "fpu_inst.h"
#include "spdlog/spdlog.h"
#include <cassert>
#include <cstdint>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/Support/Alignment.h>
#include <llvm/Support/AtomicOrdering.h>
#include <llvm/Support/Error.h>
#include <llvm/ExecutionEngine/Orc/ThreadSafeModule.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Value.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/Debug.h>
#include <map>
#include <set>
#include <unordered_map>
#include <vector>
#include <endian.h>
#include "compiler_utils.hpp"
#include "compiler_ss2.hpp"
#include <spdlog/spdlog.h>

using namespace llvm;
using namespace llvm::orc;
using namespace bpftime;

/*
    How should we compile bpf instructions into a LLVM module?
    - Split basic blocks
    - Iterate over the instructions, for each basic block, emit a LLVM
   BasicBlock for that

    Supported instructions:
	ALU:
	EBPF_OP_ADD_IMM, EBPF_OP_ADD_REG, EBPF_OP_SUB_IMM, EBPF_OP_SUB_REG,
   EBPF_OP_MUL_IMM, EBPF_OP_MUL_REG, EBPF_OP_DIV_IMM, EBPF_OP_DIV_REG,
   EBPF_OP_OR_IMM, EBPF_OP_OR_REG, EBPF_OP_AND_IMM, EBPF_OP_AND_REG,
   EBPF_OP_LSH_IMM, EBPF_OP_LSH_REG, EBPF_OP_RSH_IMM, EBPF_OP_RSH_REG,
   EBPF_OP_NEG, EBPF_OP_MOD_IMM, EBPF_OP_MOD_REG, EBPF_OP_XOR_IMM,
   EBPF_OP_XOR_REG, EBPF_OP_MOV_IMM, EBPF_OP_MOV_REG, EBPF_OP_ARSH_IMM,
   EBPF_OP_ARSH_REG, EBPF_OP_LE, EBPF_OP_BE

	EBPF_OP_ADD64_IMM, EBPF_OP_ADD64_REG, EBPF_OP_SUB64_IMM,
   EBPF_OP_SUB64_REG, EBPF_OP_MUL64_IMM, EBPF_OP_MUL64_REG, EBPF_OP_DIV64_IMM,
   EBPF_OP_DIV64_REG, EBPF_OP_OR64_IMM, EBPF_OP_OR64_REG, EBPF_OP_AND64_IMM,
   EBPF_OP_AND64_REG, EBPF_OP_LSH64_IMM, EBPF_OP_LSH64_REG, EBPF_OP_RSH64_IMM,
   EBPF_OP_RSH64_REG, EBPF_OP_NEG64, EBPF_OP_MOD64_IMM, EBPF_OP_MOD64_REG,
   EBPF_OP_XOR64_IMM, EBPF_OP_XOR64_REG, EBPF_OP_MOV64_IMM, EBPF_OP_MOV64_REG,
   EBPF_OP_ARSH64_IMM, EBPF_OP_ARSH64_REG

	Load & store:
	EBPF_OP_LDXW, EBPF_OP_LDXH, EBPF_OP_LDXB, EBPF_OP_LDXDW,
    EBPF_OP_STW, EBPF_OP_STH, EBPF_OP_STB, EBPF_OP_STDW,
    EBPF_OP_STXW, EBPF_OP_STXH, EBPF_OP_STXB, EBPF_OP_STXDW,
    EBPF_OP_LDDW,

	Jump:
	EBPF_OP_JA, EBPF_OP_JEQ_IMM, EBPF_OP_JEQ_REG, EBPF_OP_JEQ32_IMM,
   EBPF_OP_JEQ32_REG, EBPF_OP_JGT_IMM, EBPF_OP_JGT_REG, EBPF_OP_JGT32_IMM,
   EBPF_OP_JGT32_REG, EBPF_OP_JGE_IMM, EBPF_OP_JGE_REG, EBPF_OP_JGE32_IMM,
   EBPF_OP_JGE32_REG, EBPF_OP_JLT_IMM, EBPF_OP_JLT_REG, EBPF_OP_JLT32_IMM,
   EBPF_OP_JLT32_REG, EBPF_OP_JLE_IMM, EBPF_OP_JLE_REG, EBPF_OP_JLE32_IMM,
   EBPF_OP_JLE32_REG, EBPF_OP_JSET_IMM, EBPF_OP_JSET_REG, EBPF_OP_JSET32_IMM,
   EBPF_OP_JSET32_REG, EBPF_OP_JNE_IMM, EBPF_OP_JNE_REG, EBPF_OP_JNE32_IMM,
   EBPF_OP_JNE32_REG, EBPF_OP_JSGT_IMM, EBPF_OP_JSGT_REG, EBPF_OP_JSGT32_IMM,
   EBPF_OP_JSGT32_REG, EBPF_OP_JSGE_IMM, EBPF_OP_JSGE_REG, EBPF_OP_JSGE32_IMM,
   EBPF_OP_JSGE32_REG, EBPF_OP_JSLT_IMM, EBPF_OP_JSLT_REG, EBPF_OP_JSLT32_IMM,
   EBPF_OP_JSLT32_REG, EBPF_OP_JSLE_IMM, EBPF_OP_JSLE_REG, EBPF_OP_JSLE32_IMM,
   EBPF_OP_JSLE32_REG

	Other:
	EBPF_OP_EXIT, EBPF_OP_CALL
*/
Expected<ThreadSafeModule> llvm_bpf_jit_context::generateModuleWithSS2Core(
	uint8_t maxFuncNestDepth, uint16_t frameSize,
	const std::vector<std::string> &extFuncNames,
	const std::vector<std::string> &lddwHelpers,
	bool patch_map_val_at_compile_time, bool main_func_with_arguments,
	const std::string &func_name, bool is_gpu,
	const std::unordered_map<uint16_t, CompInfo> *instInfo,
	uintptr_t register_state_store_addr,
	const std::vector<TimeLoc> *snapshot_locations,
	const std::vector<uint16_t> *extra_resume_pcs)
{
	const uint32_t dataStackSize =
		static_cast<uint32_t>(frameSize) * maxFuncNestDepth;
	const uint32_t callStackSize = static_cast<uint32_t>(maxFuncNestDepth) * 5;
	SPDLOG_DEBUG(
		"Generating module: patch_map_val_at_compile_time={}, with arguments={}, func_name={}, is_gpu={}",
		patch_map_val_at_compile_time, main_func_with_arguments,
		func_name, is_gpu);
	auto context = std::make_unique<LLVMContext>();
	auto jitModule = std::make_unique<Module>("bpf-jit", *context);
	const auto &insts = vm.instructions;
	auto *registerStateStoreTy = Type::getInt64Ty(*context)->getPointerTo();
	auto *registerStateStoreBase = register_state_store_addr == 0
		? nullptr
		: llvm::ConstantExpr::getIntToPtr(
			llvm::ConstantInt::get(Type::getInt64Ty(*context),
						register_state_store_addr),
			registerStateStoreTy);
	auto *fpuRegisterStateStoreTy =
		Type::getFloatTy(*context)->getPointerTo();
	auto *fpuRegisterStateStoreBase = register_state_store_addr == 0
		? nullptr
		: llvm::ConstantExpr::getIntToPtr(
			llvm::ConstantInt::get(
				Type::getInt64Ty(*context),
				register_state_store_addr +
					offsetof(ExecState, fpuRegs)),
			fpuRegisterStateStoreTy);
	auto *i8PtrTy = Type::getInt8Ty(*context)->getPointerTo();
	auto pointerConstant = [&](const void *ptr) -> Constant * {
		return llvm::ConstantExpr::getIntToPtr(
			llvm::ConstantInt::get(Type::getInt64Ty(*context),
					       reinterpret_cast<uintptr_t>(ptr)),
			i8PtrTy);
	};
	auto execStateField = [&](size_t off, llvm::Type *ty) -> Constant * {
		if (register_state_store_addr == 0)
			return nullptr;
		return llvm::ConstantExpr::getIntToPtr(
			llvm::ConstantInt::get(Type::getInt64Ty(*context),
					       register_state_store_addr + off),
			ty->getPointerTo());
	};
	const auto *snapshotStore = reinterpret_cast<const ExecState *>(
		register_state_store_addr);
	auto *heapSnapshotDst = snapshotStore
		? pointerConstant(snapshotStore->heap)
		: nullptr;
	auto *dataStackSnapshotDst = snapshotStore
		? pointerConstant(snapshotStore->dataStack)
		: nullptr;
	auto *callStackSnapshotDst = snapshotStore
		? pointerConstant(snapshotStore->callStack)
		: nullptr;
	// Relative stack metadata, written alongside the stack copies.
	auto *dataStackOffsetSlot = execStateField(
		offsetof(ExecState, dataStackOffset), Type::getInt32Ty(*context));
	auto *callStackSizeSlot = execStateField(
		offsetof(ExecState, callStackSize), Type::getInt16Ty(*context));
	auto *pcSnapshotSlot = execStateField(offsetof(ExecState, pc),
					 Type::getInt16Ty(*context));
	if (insts.empty()) {
		return llvm::make_error<llvm::StringError>(
			"No instructions provided",
			llvm::inconvertibleErrorCode());
	}

	// Define lddw helper function type
	FunctionType *lddwHelperWithUint32 =
		FunctionType::get(Type::getInt64Ty(*context),
				  { Type::getInt32Ty(*context) }, false);
	FunctionType *lddwHelperWithUint64 =
		FunctionType::get(Type::getInt64Ty(*context),
				  { Type::getInt64Ty(*context) }, false);
	std::map<std::string, Function *> lddwHelper;
	for (const auto &helperName : lddwHelpers) {
		Function *func;
		if (helperName == LDDW_HELPER_MAP_VAL) {
			func = Function::Create(lddwHelperWithUint64,
						Function::ExternalLinkage,
						helperName, jitModule.get());

		} else {
			func = Function::Create(lddwHelperWithUint32,
						Function::ExternalLinkage,
						helperName, jitModule.get());
		}
		SPDLOG_DEBUG("Initializing lddw function with name {}",
			     helperName);
		lddwHelper[helperName] = func;
	}
	// Define ext functions
	std::map<std::string, Function *> extFunc;
	FunctionType *helperFuncTy = FunctionType::get(
		Type::getInt64Ty(*context),
		{ Type::getInt64Ty(*context), Type::getInt64Ty(*context),
		  Type::getInt64Ty(*context), Type::getInt64Ty(*context),
		  Type::getInt64Ty(*context) },
		false);

	for (const auto &name : extFuncNames) {
		Function *currFunc = Function::Create(
			helperFuncTy,
			is_gpu ? Function::LinkageTypes::ExternalLinkage :
				  Function::ExternalLinkage,
			name, jitModule.get());
		extFunc[name] = currFunc;
	}
	std::vector<bool> blockBegin(insts.size(), false);
	// Split the blocks
	blockBegin[0] = true;
	std::set<uint16_t> resumeTargets{ 0 };
	auto isConditionalBranch = [](const ebpf_inst &inst) {
		if (duo_is_fpu(inst)) {
			switch (inst.opcode) {
			case DUO_OP_FJEQ_IMM: case DUO_OP_FJEQ_REG:
			case DUO_OP_FJOGT_IMM: case DUO_OP_FJOGT_REG:
			case DUO_OP_FJOGE_IMM: case DUO_OP_FJOGE_REG:
			case DUO_OP_FJNE_IMM: case DUO_OP_FJNE_REG:
			case DUO_OP_FJUGT_IMM: case DUO_OP_FJUGT_REG:
			case DUO_OP_FJUGE_IMM: case DUO_OP_FJUGE_REG:
			case DUO_OP_FJOLT_IMM: case DUO_OP_FJOLT_REG:
			case DUO_OP_FJOLE_IMM: case DUO_OP_FJOLE_REG:
			case DUO_OP_FJULT_IMM: case DUO_OP_FJULT_REG:
			case DUO_OP_FJULE_IMM: case DUO_OP_FJULE_REG:
				return true;
			default:
				return false;
			}
		}
		const auto cls = inst.opcode & EBPF_CLS_MASK;
		const auto mode = inst.opcode & EBPF_JMP_OP_MASK;
		return (cls == EBPF_CLS_JMP || cls == EBPF_CLS_JMP32) &&
		       mode != EBPF_MODE_JA && mode != EBPF_MODE_CALL &&
		       mode != EBPF_MODE_EXIT;
	};
	if (instInfo) {
		for (const auto &[pc, unused] : *instInfo) {
			(void)unused;
			if (pc >= insts.size())
				continue;
			const auto &inst = insts[pc];
			const auto cls = inst.opcode & EBPF_CLS_MASK;
			const auto mode = inst.opcode & EBPF_JMP_OP_MASK;
			const bool isJump = cls == EBPF_CLS_JMP ||
					    cls == EBPF_CLS_JMP32;
			uint32_t target = isConditionalBranch(inst) ||
				(isJump && mode == EBPF_MODE_JA) ||
				(isJump && mode == EBPF_MODE_EXIT) ||
				((inst.opcode == EBPF_OP_CALL ||
				  inst.opcode == (EBPF_OP_CALL | 0x8)) && inst.src == 1)
					? pc
					: pc + (inst.opcode == EBPF_OP_LDDW ? 2 : 1);
			if (target < insts.size()) {
				resumeTargets.insert(static_cast<uint16_t>(target));
				blockBegin[target] = true;
			}
		}
	}
	if (extra_resume_pcs) {
		for (uint16_t pc : *extra_resume_pcs) {
			if (pc >= insts.size())
				continue;
			resumeTargets.insert(pc);
			blockBegin[pc] = true;
		}
	}
	for (uint16_t i = 0; i < insts.size(); i++) {
		auto curr = insts[i];
		SPDLOG_TRACE("check pc {} opcode={} ", i,
			     (uint16_t)curr.opcode);
		if (i > 0 && is_jmp(insts[i - 1])) {
			blockBegin[i] = true;
			SPDLOG_TRACE("mark {} block begin", i);
		}
		if (is_imm_jmp(curr)) {
			SPDLOG_TRACE("mark {} block begin", i + curr.imm + 1);
			blockBegin[i + curr.imm + 1] = true;
		} else if (is_jmp(curr) &&
			   i + curr.offset + 1 < blockBegin.size()) {
			SPDLOG_TRACE("mark {} block begin",
				     i + curr.offset + 1);
			blockBegin[i + curr.offset + 1] = true;
		}
	}
	FunctionType *func_ty;
	if (main_func_with_arguments) {
		// For SPIR-V/CUDA, use address space 1 (Global) for kernel parameters
		// For regular JIT, use default address space (0)
		unsigned addrSpace = is_gpu ? 1 : 0;
		func_ty = FunctionType::get(
			is_gpu ? Type::getVoidTy(*context) :
				  Type::getInt64Ty(*context),
			is_gpu ? std::vector<Type *>{ llvm::PointerType::get(
					 llvm::Type::getInt8Ty(*context), addrSpace),
					 Type::getInt64Ty(*context) }
			       : std::vector<Type *>{ Type::getInt32Ty(*context),
					 llvm::PointerType::get(
						 llvm::Type::getInt8Ty(*context), 0) },
			false);
	} else {
		func_ty =
			FunctionType::get(is_gpu ? Type::getVoidTy(*context) :
						    Type::getInt64Ty(*context),
					  {}, false);
	}
	// The main function
	Function *bpf_func = Function::Create(
		func_ty, Function::ExternalLinkage, func_name, jitModule.get());

	std::vector<Value *> regs;
	std::vector<Value *> fregs; /* floating point registers */

	std::vector<BasicBlock *> allBlocks;
	// Stack used to save return address and saved registers
	Value *callStack, *callItemCnt;
	Value *memSnapshotSrc = nullptr, *memSnapshotLen = nullptr;
	Value *stackEnd = nullptr;
	BasicBlock *setupBlock = nullptr;
	BasicBlock *invalidResumePcBlock = nullptr;
	Value *inputSnapshot = nullptr;
	Value *hasInputSnapshot = nullptr;
	Value *safeInputSnapshot = nullptr;
	Value *invalidResumePc = nullptr;
	{
		setupBlock = BasicBlock::Create(*context, "setupBlock", bpf_func);
		allBlocks.push_back(setupBlock);
		IRBuilder<> builder(setupBlock);
		// Create registers

		if (main_func_with_arguments && !is_gpu)
			inputSnapshot = bpf_func->getArg(1);
		hasInputSnapshot = inputSnapshot
			? builder.CreateICmpNE(inputSnapshot,
					       ConstantPointerNull::get(
						       cast<PointerType>(inputSnapshot->getType())))
			: builder.getFalse();
		safeInputSnapshot = inputSnapshot;
		if (inputSnapshot) {
			auto *emptySnapshotSize = builder.CreateSelect(
				hasInputSnapshot, builder.getInt32(0),
				builder.getInt32(sizeof(ExecState)));
			auto *emptySnapshot = builder.CreateAlloca(
				builder.getInt8Ty(), emptySnapshotSize,
				"emptySnapshot");
			safeInputSnapshot = builder.CreateSelect(
				hasInputSnapshot, inputSnapshot, emptySnapshot,
				"safeInputSnapshot");
		}
		auto inputField = [&](size_t off, Type *ty) -> Value * {
			auto *addr = builder.CreateGEP(builder.getInt8Ty(), safeInputSnapshot,
					       builder.getInt64(off));
			return builder.CreatePointerCast(addr, ty->getPointerTo());
		};
		for (int i = 0; i <= 10; i++) {
			auto *localReg = builder.CreateAlloca(
				builder.getInt64Ty(), nullptr,
				"local_r" + std::to_string(i));
			regs.push_back(localReg);
			if (i < 10 && inputSnapshot) {
				auto *snapshotValue = builder.CreateLoad(
					builder.getInt64Ty(),
					inputField(offsetof(ExecState, normRegs) +
						   i * sizeof(uint64_t),
						   builder.getInt64Ty()));
				builder.CreateStore(
					builder.CreateSelect(
						hasInputSnapshot, snapshotValue,
						builder.getInt64(0)),
					localReg);
			}
			auto *localFreg = builder.CreateAlloca(
				builder.getFloatTy(), nullptr,
				"local_f" + std::to_string(i));
			fregs.push_back(localFreg);
			if (inputSnapshot) {
				auto *snapshotValue = builder.CreateLoad(
					builder.getFloatTy(),
					inputField(offsetof(ExecState, fpuRegs) +
						   i * sizeof(float), builder.getFloatTy()));
				builder.CreateStore(
					builder.CreateSelect(
						hasInputSnapshot, snapshotValue,
						ConstantFP::get(builder.getFloatTy(), 0.0)),
					localFreg);
			}
		}

		// Create the data stack, one frame per possible nesting level.
		// For SPIR-V/CUDA, use array type to avoid VLA issues
		llvm::Value *stackBegin;
		Value *restoredDataStackUsed = nullptr;
		if (is_gpu) {
			auto stackArrayTy = llvm::ArrayType::get(
				builder.getInt8Ty(), dataStackSize);
			stackBegin = builder.CreateAlloca(stackArrayTy,
							   nullptr,
							   "stackBegin");
		} else {
			stackBegin = builder.CreateAlloca(
				builder.getInt8Ty(),
				builder.getInt32(dataStackSize), "stackBegin");
		}
		// Snapshotting copies the complete active frame. Clear bytes that the
		// program does not write so repeated snapshots are deterministic.
		builder.CreateMemSet(stackBegin, builder.getInt8(0),
				     builder.getInt64(dataStackSize), MaybeAlign(1));
		if (inputSnapshot) {
			auto *snapshotStack = builder.CreateLoad(
				builder.getPtrTy(), inputField(offsetof(ExecState, dataStack),
							 builder.getPtrTy()));
			auto *snapshotUsed = builder.CreateLoad(
				builder.getInt32Ty(), inputField(
					offsetof(ExecState, dataStackOffset),
					builder.getInt32Ty()));
			restoredDataStackUsed = builder.CreateSelect(
				hasInputSnapshot, snapshotUsed, builder.getInt32(0),
				"restoredDataStackSize");
			auto *offset = builder.CreateSub(builder.getInt32(dataStackSize),
						 restoredDataStackUsed);
			auto *srcBase = builder.CreateSelect(
				hasInputSnapshot, snapshotStack, stackBegin,
				"restoredDataStackSource");
			builder.CreateMemCpy(
				builder.CreateGEP(builder.getInt8Ty(), stackBegin, offset),
				MaybeAlign(1),
				builder.CreateGEP(builder.getInt8Ty(), srcBase, offset),
				MaybeAlign(1), restoredDataStackUsed);
		}
		stackEnd = builder.CreateGEP(
			builder.getInt8Ty(), stackBegin,
			{ builder.getInt32(dataStackSize) }, "stackEnd");
		Value *r10 = stackEnd;
		if (inputSnapshot) {
			auto *used = builder.CreateZExt(
				restoredDataStackUsed,
				builder.getInt64Ty());
			r10 = builder.CreateSelect(
				hasInputSnapshot,
				builder.CreateGEP(builder.getInt8Ty(), stackEnd,
					{ builder.CreateSub(builder.getInt64(frameSize), used) }),
				stackEnd);
		}
		builder.CreateStore(r10, regs[10]);

		Value *restoredCallStackCount = nullptr;
		if (is_gpu) {
			auto callStackArrayTy = llvm::ArrayType::get(
				builder.getPtrTy(), callStackSize);
			callStack = builder.CreateAlloca(callStackArrayTy,
							  nullptr,
							  "callStack");
		} else {
			callStack = builder.CreateAlloca(
				builder.getPtrTy(),
				builder.getInt32(callStackSize), "callStack");
		}
		// Initialize unused slots. Snapshot conversion is unrolled for the
		// maximum depth, including frames that are not active.
		builder.CreateMemSet(callStack, builder.getInt8(0),
				     builder.getInt64(callStackSize * sizeof(void *)),
				     MaybeAlign(alignof(void *)));
		if (inputSnapshot) {
			auto *snapshotCallStack = builder.CreateLoad(
				builder.getPtrTy(), inputField(offsetof(ExecState, callStack),
							 builder.getPtrTy()));
			auto *snapshotCount = builder.CreateLoad(
				builder.getInt16Ty(), inputField(
					offsetof(ExecState, callStackSize),
					builder.getInt16Ty()));
			restoredCallStackCount = builder.CreateSelect(
				hasInputSnapshot, snapshotCount, builder.getInt16(0),
				"restoredCallStackSize");
			auto *src = builder.CreateSelect(
				hasInputSnapshot, snapshotCallStack, callStack,
				"restoredCallStackSource");
			builder.CreateMemCpy(
				callStack, MaybeAlign(alignof(void *)), src,
				MaybeAlign(alignof(void *)),
				builder.CreateMul(
					builder.CreateZExt(restoredCallStackCount,
							 builder.getInt64Ty()),
					builder.getInt64(sizeof(void *))));
		}
		callItemCnt = builder.CreateAlloca(builder.getInt16Ty(),
						   nullptr, "callItemCnt");
		Value *initialCallCount = builder.getInt16(0);
		if (inputSnapshot)
			initialCallCount = restoredCallStackCount;
		builder.CreateStore(initialCallCount, callItemCnt);
		if (inputSnapshot) {
			// Values in r0-r9 that point into the snapshot data stack must
			// point into this invocation's local data stack after restore.
			auto *snapshotStack = builder.CreateLoad(
				builder.getPtrTy(), inputField(offsetof(ExecState, dataStack),
							 builder.getPtrTy()));
			auto *snapshotBegin = builder.CreatePtrToInt(
				snapshotStack, builder.getInt64Ty());
			auto *snapshotEnd = builder.CreateAdd(
				snapshotBegin, builder.getInt64(dataStackSize));
			auto *localBegin = builder.CreateSub(
				builder.CreatePtrToInt(stackEnd, builder.getInt64Ty()),
				builder.getInt64(dataStackSize));
			for (unsigned reg = 0; reg < 10; ++reg) {
				auto *value = builder.CreateLoad(builder.getInt64Ty(),
							 regs[reg]);
				auto *inStack = builder.CreateAnd(
					hasInputSnapshot,
					builder.CreateAnd(
						builder.CreateICmpUGE(value, snapshotBegin),
						builder.CreateICmpULE(value, snapshotEnd)));
				auto *rebased = builder.CreateAdd(
					localBegin, builder.CreateSub(value, snapshotBegin));
				builder.CreateStore(builder.CreateSelect(inStack, rebased,
								 value),
						    regs[reg]);
			}
		}
		if (main_func_with_arguments) {
			llvm::Value *mem = is_gpu ? bpf_func->getArg(0) : nullptr;
			llvm::Value *mem_len = is_gpu ? bpf_func->getArg(1) :
							      bpf_func->getArg(0);
			if (!is_gpu)
				mem = builder.CreateSelect(
					hasInputSnapshot,
					builder.CreateLoad(builder.getPtrTy(), inputField(
						offsetof(ExecState, heap), builder.getPtrTy())),
					ConstantPointerNull::get(builder.getPtrTy()));

			// SS2 has no heap. On resume, keep the restored r1 and r2
			// values. Other modes use r1 and r2 for the heap arguments.
			Value *initialR1 = inputSnapshot
				? builder.CreateSelect(hasInputSnapshot, mem,
						       ConstantPointerNull::get(builder.getPtrTy()))
				: mem;
			if (snapshot_locations) {
				initialR1 = builder.CreateSelect(
					hasInputSnapshot,
					builder.CreateLoad(builder.getInt64Ty(), regs[1]),
					builder.getInt64(0));
			}
			builder.CreateStore(initialR1, regs[1]);
			// Write memory length into r2.
			Value *heapLen = is_gpu ? static_cast<Value *>(mem_len) :
				builder.CreateSelect(hasInputSnapshot,
					builder.CreateZExt(mem_len, builder.getInt64Ty()),
					builder.getInt64(0));
			Value *initialR2 = inputSnapshot
				? builder.CreateSelect(hasInputSnapshot, heapLen,
						       builder.getInt64(0))
				: heapLen;
			if (snapshot_locations) {
				initialR2 = builder.CreateSelect(
					hasInputSnapshot,
					builder.CreateLoad(builder.getInt64Ty(), regs[2]),
					builder.getInt64(0));
			}
			builder.CreateStore(initialR2, regs[2]);
			// The heap buffer to snapshot is exactly the one the
			// program was called with.
			memSnapshotSrc = mem;
			memSnapshotLen = heapLen;
		}
	}

	// These blocks are the next instructions of the returning target of
	// local functions
	std::map<uint16_t, BlockAddress *> localFuncRetBlks;
	// Prepare basic blocks
	std::map<uint16_t, BasicBlock *> instBlocks;
	{
		IRBuilder<> builder(*context);

		for (uint16_t i = 0; i < insts.size(); i++) {
			if (blockBegin[i]) {
				// Create a block
				auto currBlk = BasicBlock::Create(
					*context,
					"bb_inst_" + std::to_string(i),
					bpf_func);
				instBlocks[i] = currBlk;
				allBlocks.push_back(currBlk);

				// Indicating that these block is the next
				// instruction of a local func call
				if (i > 1 &&
				    insts[i - 1].opcode == EBPF_OP_CALL &&
				    insts[i - 1].src == 0x01) {
					auto blockAddr =
						llvm::BlockAddress::get(
							bpf_func, currBlk);
					localFuncRetBlks[i] = blockAddr;
				}
			}
		}
	}
	{
		IRBuilder<> builder(setupBlock);
		if (inputSnapshot && snapshot_locations) {
			// The serialized call stack contains eBPF return PCs, not
			// process-specific LLVM block addresses. Convert the active
			// return slots before local-function return uses them. Also
			// rebase saved r6-r9 values that point into the data stack.
			auto inputField = [&](size_t off, Type *ty) -> Value * {
				auto *addr = builder.CreateGEP(builder.getInt8Ty(),
							   safeInputSnapshot,
							   builder.getInt64(off));
				return builder.CreatePointerCast(addr,
							 ty->getPointerTo());
			};
			auto *snapshotStack = builder.CreateLoad(
				builder.getPtrTy(), inputField(offsetof(ExecState, dataStack),
							 builder.getPtrTy()));
			auto *snapshotBegin = builder.CreatePtrToInt(
				snapshotStack, builder.getInt64Ty());
			auto *snapshotEnd = builder.CreateAdd(
				snapshotBegin, builder.getInt64(dataStackSize));
			auto *localBegin = builder.CreateSub(
				builder.CreatePtrToInt(stackEnd, builder.getInt64Ty()),
				builder.getInt64(dataStackSize));
			for (uint32_t frame = 0; frame < maxFuncNestDepth; ++frame) {
				const uint32_t frameBase = frame * 5;
				for (uint32_t slot = 0; slot < 4; ++slot) {
					auto *addr = builder.CreateGEP(
						builder.getInt64Ty(), callStack,
						{ builder.getInt32(frameBase + slot) });
					auto *value = builder.CreateLoad(
						builder.getInt64Ty(), addr);
					auto *inStack = builder.CreateAnd(
						builder.CreateICmpUGE(value, snapshotBegin),
						builder.CreateICmpULE(value, snapshotEnd));
					auto *rebased = builder.CreateAdd(
						localBegin,
						builder.CreateSub(value, snapshotBegin));
					builder.CreateStore(builder.CreateSelect(
								inStack, rebased, value),
							    addr);
				}

				auto *returnSlot = builder.CreateGEP(
					builder.getPtrTy(), callStack,
					{ builder.getInt32(frameBase + 4) });
				auto *returnPc = builder.CreatePtrToInt(
					builder.CreateLoad(builder.getPtrTy(), returnSlot),
					builder.getInt64Ty());
				Value *nativeAddress =
					ConstantPointerNull::get(builder.getPtrTy());
				for (const auto &[pc, blockAddress] : localFuncRetBlks) {
					nativeAddress = builder.CreateSelect(
						builder.CreateICmpEQ(returnPc,
								     builder.getInt64(pc)),
						blockAddress, nativeAddress);
				}
				builder.CreateStore(nativeAddress, returnSlot);
			}
		}
		if (inputSnapshot) {
			auto *pcAddr = builder.CreateGEP(
				builder.getInt8Ty(), safeInputSnapshot,
				builder.getInt64(offsetof(ExecState, pc)));
			auto *resumePc = builder.CreateSelect(
				hasInputSnapshot,
				builder.CreateLoad(builder.getInt16Ty(), pcAddr),
				builder.getInt16(0));
			invalidResumePc = resumePc;
			invalidResumePcBlock = BasicBlock::Create(
				*context, "invalidResumePc", bpf_func);
			auto *dispatch = builder.CreateSwitch(resumePc, invalidResumePcBlock,
							 resumeTargets.size() + 1);
			dispatch->addCase(builder.getInt16(0), instBlocks[0]);
			for (uint16_t target : resumeTargets) {
				if (target != 0)
					dispatch->addCase(builder.getInt16(target),
							  instBlocks[target]);
			}
		} else {
			builder.CreateBr(instBlocks[0]);
		}
	}
	if (invalidResumePcBlock) {
		IRBuilder<> builder(invalidResumePcBlock);
		// ExecState::pc is 16 bits, so bit 16 flags an invalid resume PC
		// without losing the PC value in the low 16 bits.
		auto *flaggedPc = builder.CreateOr(
			builder.CreateZExt(invalidResumePc, builder.getInt64Ty()),
			builder.getInt64(1ULL << 16));
		builder.CreateRet(flaggedPc);
	}

	// Basic block used to exit the eBPF program
	// will read r0 and return it
	BasicBlock *exitBlk =
		BasicBlock::Create(*context, "exitBlock", bpf_func);

	{
		IRBuilder<> builder(exitBlk);
		if (is_gpu) {
			builder.CreateRetVoid();
		} else {
			builder.CreateRet(builder.CreateLoad(
				builder.getInt64Ty(), regs[0]));
		}
	}

	// Basic blocks that handle the returning of local func

	BasicBlock *localRetBlk =
		BasicBlock::Create(*context, "localFuncReturnBlock", bpf_func);
	{
		// The most top one is the returning address, followed by r6,
		// r7, r8, r9
		IRBuilder<> builder(localRetBlk);
		Value *count =
			builder.CreateLoad(builder.getInt16Ty(), callItemCnt);
		// Load return address
		Value *targetAddr = builder.CreateLoad(
			builder.getPtrTy(),
			builder.CreateGEP(
				builder.getPtrTy(), callStack,
				{ builder.CreateSub(count,
						    builder.getInt16(1)) }));
		// Restore registers
		for (int i = 6; i <= 9; i++) {
			builder.CreateStore(
				builder.CreateLoad(
					builder.getInt64Ty(),
					builder.CreateGEP(
						builder.getInt64Ty(), callStack,
						{ builder.CreateSub(
							count,
							builder.getInt16(
								i - 4)) })),
				regs[i]);
		}
		builder.CreateStore(builder.CreateSub(count,
						      builder.getInt16(5)),
				    callItemCnt);
		// Restore data stack
		// r10 += frameSize
		builder.CreateStore(
			builder.CreateAdd(
				builder.CreateLoad(builder.getInt64Ty(),
						   regs[10]),
				builder.getInt64(frameSize)),
			regs[10]);
		auto indrBr = builder.CreateIndirectBr(targetAddr);
		for (const auto &item : localFuncRetBlks) {
			indrBr->addDestination(instBlocks[item.first]);
		}
	}
	// Iterate over instructions
	BasicBlock *currBB = instBlocks[0];
	IRBuilder<> builder(currBB);
	// Emits stores of the given normal (r0-r9) registers into the
	// snapshot buffer at the builder's current insert point.
	// CompInfo also tracks r10 (and with it the call stack), but
	// ExecState::normRegs only has room for r0-r9, so r10 is not
	// snapshotted yet.
	auto emitRegisterSnapshot = [&](const CompInfo &info) {
		if (!registerStateStoreBase)
			return;
		for (uint8_t reg = 0; reg < 10; reg++) {
			if (!info.normRegModified(reg))
				continue;
			auto *slot = builder.CreateGEP(
				builder.getInt64Ty(), registerStateStoreBase,
				{ builder.getInt64(reg) });
			Value *value = builder.CreateLoad(builder.getInt64Ty(), regs[reg]);
			if (snapshot_locations && dataStackSnapshotDst) {
				auto *localBegin = builder.CreateSub(
					builder.CreatePtrToInt(stackEnd,
							       builder.getInt64Ty()),
					builder.getInt64(dataStackSize));
				auto *localEnd = builder.CreatePtrToInt(
					stackEnd, builder.getInt64Ty());
				auto *inStack = builder.CreateAnd(
					builder.CreateICmpUGE(value, localBegin),
					builder.CreateICmpULE(value, localEnd));
				auto *snapshotBegin = builder.CreatePtrToInt(
					dataStackSnapshotDst, builder.getInt64Ty());
				auto *rebased = builder.CreateAdd(
					snapshotBegin, builder.CreateSub(value, localBegin));
				value = builder.CreateSelect(inStack, rebased, value);
			}
			builder.CreateStore(value, slot);
		}
	};
	// Emits stores of the given FPU (fpu0-fpu10) registers into the
	// snapshot buffer at the builder's current insert point.
	auto emitFPUSnapshot = [&](const CompInfo &info) {
		if (!fpuRegisterStateStoreBase)
			return;
		for (uint8_t reg = 0; reg <= 10; reg++) {
			if (!info.fpuRegModified(reg))
				continue;
			auto *slot = builder.CreateGEP(
				builder.getFloatTy(), fpuRegisterStateStoreBase,
				{ builder.getInt64(reg) });
			builder.CreateStore(
				builder.CreateLoad(builder.getFloatTy(), fregs[reg]), slot);
		}
	};
	// Emits a single memcpy of the program's heap buffer into the
	// ExecState snapshot buffer, at the builder's current insert point.
	// Unlike the stacks, the used portion of the heap can't be determined,
	// so the whole buffer is copied.
	auto emitHeapSnapshot = [&]() {
		if (!memSnapshotSrc || !heapSnapshotDst)
			return;
		builder.CreateMemCpy(heapSnapshotDst, MaybeAlign(1), memSnapshotSrc,
				     MaybeAlign(1), memSnapshotLen);
	};
	// Emits copies of the live portions of both stacks, plus the relative
	// metadata needed to restore them into a differently-located region.
	//
	// Data stack: r10 grows downward from stackEnd, and each frame is
	// addressed at negative offsets from r10 (e.g. [r10-4]), so the frame
	// currently in use lies *below* r10. The live region is therefore
	// [r10-frameSize, stackEnd) and dataStackOffset is its length. Frames
	// below that (deeper than the current call depth) are never copied.
	//
	// Call stack: callItemCnt counts the slots in use (5 per active frame),
	// so the live region is the first callItemCnt entries and
	// callStackSize = callItemCnt.
	auto emitStackSnapshot = [&]() {
		if (!dataStackOffsetSlot)
			return;
		// --- data stack ---
		auto *r10 = builder.CreateLoad(builder.getInt64Ty(), regs[10]);
		auto *endInt = builder.CreatePtrToInt(stackEnd,
						      builder.getInt64Ty());
		// Base of the frame in use: one frameSize below r10.
		auto *liveBase =
			builder.CreateSub(r10, builder.getInt64(frameSize),
					  "dataStackLiveBase");
		auto *used =
			builder.CreateSub(endInt, liveBase, "dataStackUsed");
		builder.CreateStore(builder.CreateTrunc(used, builder.getInt32Ty()),
				    dataStackOffsetSlot);
		if (dataStackSnapshotDst) {
			auto *dst = builder.CreateGEP(
				builder.getInt8Ty(), dataStackSnapshotDst,
				{ builder.CreateSub(builder.getInt64(dataStackSize), used) });
			auto *src = builder.CreateIntToPtr(liveBase,
							   builder.getPtrTy());
			builder.CreateMemCpy(dst, MaybeAlign(1), src,
					     MaybeAlign(1), used);
		}
		// --- call stack ---
		auto *count =
			builder.CreateLoad(builder.getInt16Ty(), callItemCnt);
		if (callStackSizeSlot)
			builder.CreateStore(count, callStackSizeSlot);
		if (callStackSnapshotDst) {
			auto *bytes = builder.CreateMul(
				builder.CreateZExt(count, builder.getInt64Ty()),
				builder.getInt64(sizeof(void *)),
				"callStackBytes");
			builder.CreateMemCpy(callStackSnapshotDst,
					     MaybeAlign(alignof(void *)),
					     callStack,
					     MaybeAlign(alignof(void *)), bytes);
			if (snapshot_locations) {
				auto *localBegin = builder.CreateSub(
					builder.CreatePtrToInt(stackEnd,
							       builder.getInt64Ty()),
					builder.getInt64(dataStackSize));
				auto *localEnd = builder.CreatePtrToInt(
					stackEnd, builder.getInt64Ty());
				auto *snapshotBegin = builder.CreatePtrToInt(
					dataStackSnapshotDst, builder.getInt64Ty());
				for (uint32_t frame = 0; frame < maxFuncNestDepth;
				     ++frame) {
					const uint32_t frameBase = frame * 5;
					for (uint32_t slot = 0; slot < 4; ++slot) {
						auto *source = builder.CreateGEP(
							builder.getInt64Ty(), callStack,
							{ builder.getInt32(frameBase + slot) });
						auto *value = builder.CreateLoad(
							builder.getInt64Ty(), source);
						auto *inStack = builder.CreateAnd(
							builder.CreateICmpUGE(value, localBegin),
							builder.CreateICmpULE(value, localEnd));
						auto *rebased = builder.CreateAdd(
							snapshotBegin,
							builder.CreateSub(value, localBegin));
						auto *destination = builder.CreateGEP(
							builder.getInt64Ty(), callStackSnapshotDst,
							{ builder.getInt32(frameBase + slot) });
						builder.CreateStore(builder.CreateSelect(
							inStack, rebased, value), destination);
					}
					auto *nativeReturnSlot = builder.CreateGEP(
						builder.getPtrTy(), callStack,
						{ builder.getInt32(frameBase + 4) });
					auto *nativeReturn = builder.CreateLoad(
						builder.getPtrTy(), nativeReturnSlot);
					Value *portablePc = builder.getInt64(0);
					for (const auto &[pc, blockAddress] :
					     localFuncRetBlks) {
						portablePc = builder.CreateSelect(
							builder.CreateICmpEQ(nativeReturn,
									     blockAddress),
							builder.getInt64(pc), portablePc);
					}
					auto *portableReturnSlot = builder.CreateGEP(
						builder.getInt64Ty(), callStackSnapshotDst,
						{ builder.getInt32(frameBase + 4) });
					builder.CreateStore(portablePc,
							    portableReturnSlot);
				}
			}
		}
	};
	// If `pc` is listed in `instInfo`, snapshot the registers marked
	// modified in its CompInfo. Must be called with the builder's
	// insert point already set to where the snapshot should land.
	auto maybeSnapshot = [&](uint16_t pc, uint16_t resumePc) {
		if (!instInfo)
			return;
		auto it = instInfo->find(pc);
		if (it == instInfo->end())
			return;
		BasicBlock *snapshotBlock = nullptr;
		BasicBlock *continuationBlock = nullptr;
		if (snapshot_locations) {
			auto *sourceBlock = builder.GetInsertBlock();
			auto *enabled = emitSS2SnapshotCondition(
				builder, regs[10], pc, *snapshot_locations);
			snapshotBlock = BasicBlock::Create(
				*context, "ss2_snapshot_" + std::to_string(pc), bpf_func);
			continuationBlock = BasicBlock::Create(
				*context, "ss2_continue_" + std::to_string(pc), bpf_func);
			auto sourcePosition =
				std::find(allBlocks.begin(), allBlocks.end(), sourceBlock);
			assert(sourcePosition != allBlocks.end());
			allBlocks.insert(sourcePosition + 1,
					 { snapshotBlock, continuationBlock });
			builder.CreateCondBr(enabled, snapshotBlock, continuationBlock);
			builder.SetInsertPoint(snapshotBlock);
		}
		emitRegisterSnapshot(it->second);
		emitFPUSnapshot(it->second);
		// Heap and stacks are tracked separately, so a component that
		// only touches one doesn't pay for copying the other.
		if (it->second.usedHeap())
			emitHeapSnapshot();
		if (it->second.usedStack())
			emitStackSnapshot();
		if (pcSnapshotSlot)
			builder.CreateStore(builder.getInt16(resumePc), pcSnapshotSlot);
		if (snapshotBlock) {
			builder.CreateBr(continuationBlock);
			builder.SetInsertPoint(continuationBlock);
		}
	};
	for (uint16_t pc = 0; pc < insts.size(); pc++) {
		auto inst = insts[pc];
		if (blockBegin[pc]) {
			if (auto itr = instBlocks.find(pc);
			    itr != instBlocks.end()) {
				currBB = itr->second;
			} else {
				return llvm::make_error<llvm::StringError>(
					"pc=" + std::to_string(pc) +
						" was marked block begin, but no BasicBlock* found",
					llvm::inconvertibleErrorCode());
			}
		}
		builder.SetInsertPoint(currBB);

		bool isFPU = duo_is_fpu(inst);
		if (isFPU) {
			switch (inst.opcode) {
				/* TODO: original spec mentions offsets might be
				 * used in FLDX and FST(X) ops - If so, then we
				 * need to add that */
			case DUO_OP_FSTX:
			case DUO_OP_FST: {
				Value *src_val;

				if (duo_class(inst) == FST) {
					/* bit_cast is introduced in c++20 -
					 * previous versions might have to use
					 * reinterpret_cast, although I hear
					 * it's condemned */
					float flt =
						std::bit_cast<float>(inst.imm);

					/* convert c++ float to llvm float */
					src_val = llvm::ConstantFP::get(
						builder.getFloatTy(), flt);
				} else {
					src_val = builder.CreateLoad(
						builder.getFloatTy(),
						fregs[inst.src]);
				}

				auto addr = builder.CreateGEP(
					builder.getInt8Ty(),
					builder.CreateLoad(builder.getPtrTy(),
							   regs[inst.dst]),
					{ builder.getInt64(inst.offset) });
				builder.CreateStore(src_val, addr);
				maybeSnapshot(pc, pc + 1);
				break;
			}
			case DUO_OP_FLDX: {
				Value *src_val;

				/* We're likely loading a value off the
				 * stack */
				if (inst.offset != 0 && inst.src == 0xa) {
					SPDLOG_DEBUG("loading off stack..");

					/* ptr to value off the stack
					 * We insert regs, not fregs,
					 * since that's where the
					 * stack is at */
					auto gep = emitLDXLoadingAddr(
						builder, &regs[0], inst);

					/* Convert ptr to float ptr */
					auto addr = builder.CreateBitCast(
						gep, builder.getFloatTy()
							     ->getPointerTo());

					/* dereference the ptr to
					 * grab the float */
					src_val = builder.CreateLoad(
						builder.getFloatTy(), addr);

				} else {
					src_val = builder.CreateLoad(
						builder.getFloatTy(),
						regs[inst.src]);
				}

				emitStoreFPUResult(inst, &fregs[0], builder,
						   src_val);
				maybeSnapshot(pc, pc + 1);
				break;
			}
			case DUO_OP_FADD_IMM:
			case DUO_OP_FADD_REG:
			case DUO_OP_FSUB_IMM:
			case DUO_OP_FSUB_REG:
			case DUO_OP_FMUL_IMM:
			case DUO_OP_FMUL_REG:
			case DUO_OP_FDIV_IMM:
			case DUO_OP_FDIV_REG:
			case DUO_OP_FNEG:
			case DUO_OP_FMOV_IMM:
			case DUO_OP_FMOV_REG: {
				auto func = get_falu_func(inst, builder);

				emitFPUWithDstAndSrc(inst, builder, &fregs[0],
						     func);
				maybeSnapshot(pc, pc + 1);

				break;
			}

			case DUO_OP_FJEQ_IMM:
			case DUO_OP_FJEQ_REG:
			case DUO_OP_FJOGT_IMM:
			case DUO_OP_FJOGT_REG:
			case DUO_OP_FJOGE_IMM:
			case DUO_OP_FJOGE_REG:
			case DUO_OP_FJNE_IMM:
			case DUO_OP_FJNE_REG:
			case DUO_OP_FJUGT_IMM:
			case DUO_OP_FJUGT_REG:
			case DUO_OP_FJUGE_IMM:
			case DUO_OP_FJUGE_REG:
			case DUO_OP_FJOLT_IMM:
			case DUO_OP_FJOLT_REG:
			case DUO_OP_FJOLE_IMM:
			case DUO_OP_FJOLE_REG:
			case DUO_OP_FJULT_IMM:
			case DUO_OP_FJULT_REG:
			case DUO_OP_FJULE_IMM:
			case DUO_OP_FJULE_REG: {
				auto f_cmp_func = get_fcmp_func(inst, builder);

				maybeSnapshot(pc, pc);
				auto ret = emitCondJmpWithDstAndSrcFPU(
					builder, pc, inst, instBlocks,
					&fregs[0], f_cmp_func);

				/* Can be replaced by HANDLE_ERR */
				if (!ret)
					return ret.takeError();
				break;
			}

			default: {
			badfloat:
				fprintf(stderr,
					"\x1b[31m" /* ansi RED */
					"BAD"
					"\x1b[0m" /* ansi RESET */
					": unhandled floating point op:\n"
					"opcode: 0x%02x______________\n"
					"dst:    0x__%01x_____________\n"
					"src:    0x___%01x____________\n"
					"offset: 0x____%04x________\n"
					"imm:    0x________%08x\n",
					inst.opcode, inst.dst, inst.src,
					inst.offset, inst.imm);
				exit(1);
			}
			}
		}

		if (isFPU)
			continue;

		/* FPU NOTE: Fregs will sometimes be > 10
		 * Therefore, the check below must succeed all fpu ops */

		// Precheck for registers
		if (inst.dst > 10 || inst.src > 10) {
			return llvm::make_error<llvm::StringError>(
				"Illegal src reg/dst reg at pc " +
					std::to_string(pc),
				llvm::inconvertibleErrorCode());
		}

		switch (inst.opcode) {
			// ALU
		case EBPF_OP_ADD64_IMM:
		case EBPF_OP_ADD64_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					auto ptr_val = builder.CreateIntToPtr(
						dst_val, builder.getPtrTy());
					auto result_ptr = builder.CreateGEP(
						builder.getInt8Ty(), ptr_val,
						{ src_val });
					return builder.CreatePtrToInt(
						result_ptr,
						builder.getInt64Ty());
				});

			break;
		}
		case EBPF_OP_ADD_IMM:
		case EBPF_OP_ADD_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateAdd(dst_val,
								 src_val);
				});

			break;
		}
		case EBPF_OP_SUB64_IMM:
		case EBPF_OP_SUB64_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					auto ptr_val = builder.CreateIntToPtr(
						dst_val, builder.getPtrTy());
					auto neg_src_val =
						builder.CreateNeg(src_val);
					auto result_ptr = builder.CreateGEP(
						builder.getInt8Ty(), ptr_val,
						{ neg_src_val });
					return builder.CreatePtrToInt(
						result_ptr,
						builder.getInt64Ty());
				});
			break;
		}
		case EBPF_OP_SUB_IMM:
		case EBPF_OP_SUB_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateSub(dst_val,
								 src_val);
				});
			break;
		}
		case EBPF_OP_MUL64_IMM:
		case EBPF_OP_MUL_IMM:
		case EBPF_OP_MUL64_REG:
		case EBPF_OP_MUL_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateBinOp(
						Instruction::BinaryOps::Mul,
						dst_val, src_val);
				});
			break;
		}
		case EBPF_OP_DIV64_IMM:
		case EBPF_OP_DIV_IMM:
		case EBPF_OP_DIV64_REG:
		case EBPF_OP_DIV_REG: {
			// Set dst to zero if trying to being
			// divided by zero
			{
				emitALUWithDstAndSrc(inst, builder, &regs[0], [&](Value *dst_val, Value *src_val) {
					bool is_64 = is_alu64(inst);
					bool is_sdiv = inst.offset == 1;
					auto src_is_zero = builder.CreateICmpEQ(
						src_val,
						is_64 ? builder.getInt64(0) :
							builder.getInt32(0));
					auto zero =
						is_alu64(inst) ?
							builder.getInt64(0) :
							builder.getInt32(0);
					Value *result;
					if (is_64) {
						if (is_sdiv) {
							/**
							  If
is_64 is true, src_val will be zero-extended to 64-bit.
According to eBPF docs, it should actually be sign-extended to
64-bit, so we perform this conversion.
							 */
							src_val = builder.CreateSExt(
								builder.CreateTrunc(
									src_val,
									builder.getInt32Ty()),
								builder.getInt64Ty());
							// dst =
							// I64_MIN
							// and
							// src
							// = -1?
							// Overflow!
							auto overflow_cond = builder.CreateAnd(
								{ builder.CreateCmp(
									  CmpInst::Predicate::
										  ICMP_EQ,
									  dst_val,
									  builder.getInt64(
										  INT64_MIN)),
								  builder.CreateCmp(
									  CmpInst::Predicate::
										  ICMP_EQ,
									  src_val,
									  builder.getInt64(
										  -1)) });
							result = builder.CreateSelect(
								overflow_cond,
								builder.getInt64(
									INT64_MIN),
								builder.CreateSDiv(
									dst_val,
									src_val));
						} else {
							result =
								builder.CreateUDiv(
									dst_val,
									src_val);
						}
					} else {
						if (is_sdiv) {
							// dst =
							// I64_MIN
							// and
							// src
							// = -1?
							// Overflow!
							auto overflow_cond = builder.CreateAnd(
								{ builder.CreateCmp(
									  CmpInst::Predicate::
										  ICMP_EQ,
									  dst_val,
									  builder.getInt32(
										  INT32_MIN)),
								  builder.CreateCmp(
									  CmpInst::Predicate::
										  ICMP_EQ,
									  src_val,
									  builder.getInt32(
										  -1)) });
							result = builder.CreateSelect(
								overflow_cond,
								builder.getInt32(
									INT32_MIN),
								builder.CreateSDiv(
									dst_val,
									src_val));
						} else {
							result =
								builder.CreateUDiv(
									dst_val,
									src_val);
						}
					}

					return builder.CreateSelect(
						src_is_zero, zero, result);
				});

				break;
			}
		}
		case EBPF_OP_OR64_IMM:
		case EBPF_OP_OR_IMM:
		case EBPF_OP_OR64_REG:
		case EBPF_OP_OR_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateOr(dst_val,
								src_val);
				});
			break;
		}
		case EBPF_OP_AND64_IMM:
		case EBPF_OP_AND_IMM:
		case EBPF_OP_AND64_REG:
		case EBPF_OP_AND_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateAnd(dst_val,
								 src_val);
				});
			break;
		}
		case EBPF_OP_LSH64_IMM:
		case EBPF_OP_LSH_IMM:
		case EBPF_OP_LSH64_REG:
		case EBPF_OP_LSH_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateShl(
						dst_val,
						is_alu64(inst) ?
							builder.CreateURem(
								src_val,
								builder.getInt64(
									64)) :
							builder.CreateURem(
								src_val,
								builder.getInt32(
									32)));
				});
			break;
		}
		case EBPF_OP_RSH64_IMM:
		case EBPF_OP_RSH_IMM:
		case EBPF_OP_RSH64_REG:
		case EBPF_OP_RSH_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateLShr(
						dst_val,
						is_alu64(inst) ?
							builder.CreateURem(
								src_val,
								builder.getInt64(
									64)) :
							builder.CreateURem(
								src_val,
								builder.getInt32(
									32)));
				});

			break;
		}
		case EBPF_OP_NEG:
		case EBPF_OP_NEG64: {
			Value *dst_val =
				emitLoadALUDest(inst, &regs[0], builder, false);
			Value *result = builder.CreateNeg(dst_val);
			emitStoreALUResult(inst, &regs[0], builder, result);
			break;
		}
		case EBPF_OP_MOD64_IMM:
		case EBPF_OP_MOD_IMM:
		case EBPF_OP_MOD64_REG:
		case EBPF_OP_MOD_REG: {
			bool is_smod = inst.offset == 1;
			bool is_64 = is_alu64(inst);
			emitALUWithDstAndSrc(inst, builder, &regs[0], [&](Value *dst_val, Value *src_val) {
				// Keep dst untouched is src is
				// zero
				return builder.CreateSelect(
					builder.CreateICmpEQ(
						src_val,
						is_alu64(inst) ?
							builder.getInt64(0) :
							builder.getInt32(0)),
					dst_val,
					is_smod ?
						builder.CreateSRem(
							is_64 ? builder.CreateSExt(
									dst_val,
									builder.getInt64Ty()) :
								dst_val,
							is_64 ? builder.CreateSExt(
									builder.CreateTrunc(
										src_val,
										builder.getInt32Ty()),
									builder.getInt64Ty()) :
								src_val) :
						builder.CreateURem(dst_val,
								   src_val));
			});

			break;
		}
		case EBPF_OP_XOR64_IMM:
		case EBPF_OP_XOR_IMM:
		case EBPF_OP_XOR64_REG:
		case EBPF_OP_XOR_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateXor(dst_val,
								 src_val);
				});
			break;
		}
		case EBPF_OP_MOV64_IMM:
		case EBPF_OP_MOV_IMM:
		case EBPF_OP_MOV64_REG:
		case EBPF_OP_MOV_REG: {
			bool is_mov_sx = inst.offset != 0;
			Value *src_val =
				emitLoadALUSource(inst, &regs[0], builder);
			Value *result;
			if (is_mov_sx) {
				// for alu64: dst =
				// (u64)(s64)(sOFFSET)src for
				// alu(32): dst =
				// (u32)(s32)(sOFFSET)src
				Value *extended_result;
				if (inst.offset == 8) {
					extended_result = builder.CreateSExt(
						builder.CreateTrunc(
							src_val,
							builder.getInt8Ty()),
						builder.getInt8Ty());
				} else if (inst.offset == 16) {
					extended_result = builder.CreateSExt(
						builder.CreateTrunc(
							src_val,
							builder.getInt16Ty()),
						builder.getInt16Ty());
				} else if (inst.offset == 32) {
					extended_result = builder.CreateSExt(
						builder.CreateTrunc(
							src_val,
							builder.getInt32Ty()),
						builder.getInt32Ty());
				} else {
					return llvm::make_error<
						llvm::StringError>(
						"Invalid offset " +
							std::to_string(
								inst.offset) +
							" for movsx at pc " +
							std::to_string(pc),
						llvm::inconvertibleErrorCode());
				}
				if (is_alu64(inst)) {
					// convert it to u64  is
					// not needed, llvm ir
					// uses unsigned numbers
					result = builder.CreateCast(
						Instruction::CastOps::SExt,
						extended_result,
						builder.getInt64Ty());
				} else {
					result = builder.CreateCast(
						Instruction::CastOps::SExt,
						extended_result,
						builder.getInt32Ty());
				}
			} else {
				result = src_val;
			}
			emitStoreALUResult(inst, &regs[0], builder, result);
			break;
		}

		case EBPF_OP_ARSH64_IMM:
		case EBPF_OP_ARSH_IMM:
		case EBPF_OP_ARSH64_REG:
		case EBPF_OP_ARSH_REG: {
			emitALUWithDstAndSrc(
				inst, builder, &regs[0],
				[&](Value *dst_val, Value *src_val) {
					return builder.CreateAShr(
						dst_val,
						is_alu64(inst) ?
							builder.CreateURem(
								src_val,
								builder.getInt64(
									64)) :
							builder.CreateURem(
								src_val,
								builder.getInt32(
									32)));
				});
			break;
		}
		case EBPF_OP_LE:
		case EBPF_OP_BE:
		case EBPF_OP_BYTESWAP: {
			Value *dst_val =
				emitLoadALUDest(inst, &regs[0], builder, true);
			Value *result;
			if (auto exp = emitALUEndianConversion(inst, builder,
							       dst_val);
			    exp) {
				result = exp.get();
			} else {
				return exp.takeError();
			}
			emitStoreALUResult(inst, &regs[0], builder, result);
			break;
		}

			// ST and STX
			//  Only supports mode = 0x60
		case EBPF_OP_STB:
		case EBPF_OP_STXB: {
			emitStore(inst, builder, &regs[0], builder.getInt8Ty());
			maybeSnapshot(pc, pc + 1);
			break;
		}
		case EBPF_OP_STH:
		case EBPF_OP_STXH: {
			emitStore(inst, builder, &regs[0],
				  builder.getInt16Ty());
			maybeSnapshot(pc, pc + 1);
			break;
		}
		case EBPF_OP_STW:
		case EBPF_OP_STXW: {
			emitStore(inst, builder, &regs[0],
				  builder.getInt32Ty());
			maybeSnapshot(pc, pc + 1);
			break;
		}
		case EBPF_OP_STDW:
		case EBPF_OP_STXDW: {
			emitStore(inst, builder, &regs[0],
				  builder.getInt64Ty());
			maybeSnapshot(pc, pc + 1);
			break;
		}
			// LDX
			// Only supports mode=0x60
		case EBPF_OP_LDXB: {
			emitLoadX(builder, &regs[0], inst, builder.getInt8Ty());
			break;
		}
		case EBPF_OP_LDXH: {
			emitLoadX(builder, &regs[0], inst,
				  builder.getInt16Ty());
			break;
		}
		case EBPF_OP_LDXW: {
			emitLoadX(builder, &regs[0], inst,
				  builder.getInt32Ty());
			break;
		}
		case EBPF_OP_LDXDW: {
			emitLoadX(builder, &regs[0], inst,
				  builder.getInt64Ty());
			break;
		}
		// LD
		// Keep compatiblity to ubpf
		case EBPF_OP_LDDW: {
			// ubpf only supports EBPF_OP_LDDW in
			// instruction class EBPF_CLS_LD, so do
			// us
			auto size = inst.opcode & 0x18;
			auto mode = inst.opcode & 0xe0;
			if (size != 0x18 || mode != 0x00) {
				return llvm::make_error<llvm::StringError>(
					"Unsupported size (" +
						std::to_string(size) +
						") or mode (" +
						std::to_string(mode) +
						") for non-standard load operations" +
						" at pc " + std::to_string(pc),
					llvm::inconvertibleErrorCode());
			}
			if (pc + 1 >= insts.size()) {
				return llvm::make_error<llvm::StringError>(
					"Loaded LDDW at pc=" +
						std::to_string(pc) +
						" which requires an extra pseudo instruction, but it's the last instruction",
					llvm::inconvertibleErrorCode());
			}
			const auto &nextinst = insts[pc + 1];
			if (nextinst.opcode || nextinst.dst || nextinst.src ||
			    nextinst.offset) {
				return llvm::make_error<llvm::StringError>(
					"Loaded LDDW at pc=" +
						std::to_string(pc) +
						" which requires an extra pseudo instruction, but the next instruction is not a legal one",
					llvm::inconvertibleErrorCode());
			}
			uint64_t val =
				(uint64_t)((uint32_t)inst.imm) |
				(((uint64_t)((uint32_t)nextinst.imm)) << 32);
			SPDLOG_DEBUG(
				"Load LDDW val= {} part1={:x} part2={:x} src={} pc={}",
				val, (uint64_t)inst.imm, (uint64_t)nextinst.imm,
				(int)inst.src, pc);
			pc++;
			auto raw_pc = pc - 1;

			if (inst.src == 0) {
				SPDLOG_DEBUG("Emit lddw helper 0 at pc {}",
					     raw_pc);
				builder.CreateStore(builder.getInt64(val),
						    regs[inst.dst]);
			} else if (inst.src == 1) {
				SPDLOG_DEBUG(
					"Emit lddw helper 1 (map_by_fd) at pc {}, imm={}, patched at compile time",
					raw_pc, inst.imm);
				if (vm.map_by_fd) {
					builder.CreateStore(
						builder.getInt64(
							vm.map_by_fd(inst.imm)),
						regs[inst.dst]);
				} else {
					SPDLOG_DEBUG(
						"map_by_fd is called in eBPF code, but is not provided, will use the default behavior");
					// Default: input value
					builder.CreateStore(
						builder.getInt64(
							(int64_t)inst.imm),
						regs[inst.dst]);
				}

			} else if (inst.src == 2) {
				SPDLOG_DEBUG(
					"Emit lddw helper 2 (map_by_fd + map_val) at pc {}, imm1={}, imm2={}",
					raw_pc, inst.imm, nextinst.imm);
				uint64_t mapPtr;
				if (vm.map_by_fd) {
					mapPtr = vm.map_by_fd(inst.imm);
				} else {
					SPDLOG_DEBUG(
						"map_by_fd is called in eBPF code, but is not provided, will use the default behavior");
					// Default: returns the
					// input value
					mapPtr = (uint64_t)inst.imm;
				}
				if (patch_map_val_at_compile_time) {
					SPDLOG_DEBUG(
						"map_val is required to be evaluated at compile time");
					if (!vm.map_val) {
						return llvm::make_error<
							llvm::StringError>(
							"map_val is not provided, unable to compile at pc " +
								std::to_string(
									raw_pc),
							llvm::inconvertibleErrorCode());
					}
					builder.CreateStore(
						builder.getInt64(
							vm.map_val(mapPtr) +
							nextinst.imm),
						regs[inst.dst]);
				} else {
					SPDLOG_DEBUG(
						"map_val is required to be evaluated at runtime, emitting calling instructions");
					if (auto itrMapVal = lddwHelper.find(
						    LDDW_HELPER_MAP_VAL);
					    itrMapVal != lddwHelper.end()) {
						auto retMapVal = builder.CreateCall(
							lddwHelperWithUint64,
							itrMapVal->second,
							{ builder.getInt64(
								mapPtr) });
						auto finalRet = builder.CreateAdd(
							retMapVal,
							builder.getInt64(
								nextinst.imm));
						builder.CreateStore(
							finalRet,
							regs[inst.dst]);

					} else {
						return llvm::make_error<
							llvm::StringError>(
							"Using lddw helper 2, which requires map_val to be defined at pc " +
								std::to_string(
									raw_pc),
							llvm::inconvertibleErrorCode());
					}
				}

			} else if (inst.src == 3) {
				SPDLOG_DEBUG(
					"Emit lddw helper 3 (var_addr) at pc {}, imm1={}",
					raw_pc, inst.imm);
				if (!vm.var_addr) {
					return llvm::make_error<
						llvm::StringError>(
						"var_addr is not provided, unable to compile at pc " +
							std::to_string(raw_pc),
						llvm::inconvertibleErrorCode());
				}
				builder.CreateStore(
					builder.getInt64(vm.var_addr(inst.imm)),
					regs[inst.dst]);
			} else if (inst.src == 4) {
				SPDLOG_DEBUG(
					"Emit lddw helper 4 (code_addr) at pc {}, imm1={}",
					raw_pc, inst.imm);
				if (!vm.code_addr) {
					return llvm::make_error<
						llvm::StringError>(
						"code_addr is not provided, unable to compile at pc " +
							std::to_string(raw_pc),
						llvm::inconvertibleErrorCode());
				}
				builder.CreateStore(
					builder.getInt64(
						vm.code_addr(inst.imm)),
					regs[inst.dst]);
			} else if (inst.src == 5) {
				SPDLOG_DEBUG(
					"Emit lddw helper 4 (map_by_idx) at pc {}, imm1={}",
					raw_pc, inst.imm);
				if (vm.map_by_idx) {
					builder.CreateStore(
						builder.getInt64(vm.map_by_idx(
							inst.imm)),
						regs[inst.dst]);
				} else {
					SPDLOG_INFO(
						"map_by_idx is called in eBPF code, but it's not provided, will use the default behavior");
					// Default: returns the
					// input value
					builder.CreateStore(
						builder.getInt64(
							(int64_t)inst.imm),
						regs[inst.dst]);
				}

			} else if (inst.src == 6) {
				SPDLOG_DEBUG(
					"Emit lddw helper 6 (map_by_idx + map_val) at pc {}, imm1={}, imm2={}",
					raw_pc, inst.imm, nextinst.imm);

				uint64_t mapPtr;
				if (vm.map_by_idx) {
					mapPtr = vm.map_by_idx(inst.imm);
				} else {
					SPDLOG_DEBUG(
						"map_by_idx is called in eBPF code, but it's not provided, will use the default behavior");
					// Default: returns the
					// input value
					mapPtr = (int64_t)inst.imm;
				}
				if (patch_map_val_at_compile_time) {
					SPDLOG_DEBUG(
						"Required to evaluate map_val at compile time");
					if (vm.map_val) {
						builder.CreateStore(
							builder.getInt64(
								vm.map_val(
									mapPtr) +
								nextinst.imm),
							regs[inst.dst]);
					} else {
						return llvm::make_error<
							llvm::StringError>(
							"map_val is not provided, unable to compile at pc " +
								std::to_string(
									raw_pc),
							llvm::inconvertibleErrorCode());
					}

				} else {
					SPDLOG_DEBUG(
						"Required to evaluate map_val at runtime time");
					if (auto itrMapVal = lddwHelper.find(
						    LDDW_HELPER_MAP_VAL);
					    itrMapVal != lddwHelper.end()) {
						auto retMapVal = builder.CreateCall(
							lddwHelperWithUint64,
							itrMapVal->second,
							{ builder.getInt64(
								mapPtr) });
						auto finalRet = builder.CreateAdd(
							retMapVal,
							builder.getInt64(
								nextinst.imm));
						builder.CreateStore(
							finalRet,
							regs[inst.dst]);

					} else {
						return llvm::make_error<
							llvm::StringError>(
							"Using lddw helper 6 at pc " +
								std::to_string(
									raw_pc),
							llvm::inconvertibleErrorCode());
					}
				}
			}
			maybeSnapshot(raw_pc, raw_pc + 2);
			break;
		}
			// JMP
		case EBPF_OP_JA: {
			maybeSnapshot(pc, pc);
			if (auto dst =
				    loadJmpDstBlock(pc, inst, instBlocks, true);
			    dst) {
				builder.CreateBr(dst.get());

			} else {
				return dst.takeError();
			}
			break;
		}
		// JMP imm
		case EBPF_OP_JA_IMM: {
			maybeSnapshot(pc, pc);
			if (auto dst = loadJmpDstBlock(pc, inst, instBlocks,
						       false);
			    dst) {
				builder.CreateBr(dst.get());

			} else {
				return dst.takeError();
			}
			break;
		}
			// Call helper or local function
		case EBPF_OP_CALL:
			// Work around for clang producing
			// instructions that we don't support
		case EBPF_OP_CALL | 0x8: {
			// Call local function
			if (inst.src == 0x1) {
				maybeSnapshot(pc, pc);
				// Each call will put five 8byte
				// integer onto the call stack
				// the most top one is the
				// return address, followed by
				// r6, r7, r8, r9
				Value *nextPos = builder.CreateAdd(
					builder.CreateLoad(builder.getInt16Ty(),
							   callItemCnt),
					builder.getInt16(5));
				builder.CreateStore(nextPos, callItemCnt);
				assert(localFuncRetBlks.contains(pc + 1));
				// Store returning address
				builder.CreateStore(
					localFuncRetBlks[pc + 1],
					builder.CreateGEP(
						builder.getPtrTy(), callStack,
						{ builder.CreateSub(
							nextPos,
							builder.getInt16(1)) }));
				// Store callee-saved registers
				for (int i = 6; i <= 9; i++) {
					builder.CreateStore(
						builder.CreateLoad(
							builder.getInt64Ty(),
							regs[i]),
						builder.CreateGEP(
							builder.getInt64Ty(),
							callStack,
							{ builder.CreateSub(
								nextPos,
								builder.getInt16(
									i -
									4)) }));
				}
				// Move data stack
				// r10 -= frameSize
				builder.CreateStore(
					builder.CreateSub(
						builder.CreateLoad(
							builder.getInt64Ty(),
							regs[10]),
						builder.getInt64(frameSize)),
					regs[10]);
				if (auto dstBlk = loadCallDstBlock(pc, inst,
								   instBlocks);
				    dstBlk) {
					builder.CreateBr(dstBlk.get());
				} else {
					return dstBlk.takeError();
				}

			} else {
				if (auto exp = emitExtFuncCall(
					    builder, inst, extFunc, &regs[0],
					    helperFuncTy, pc, exitBlk);
				    !exp) {
					return exp.takeError();
				}
				maybeSnapshot(pc, pc + 1);
			}

			break;
		}
		case EBPF_OP_EXIT: {
			maybeSnapshot(pc, pc);
			builder.CreateCondBr(
				builder.CreateICmpEQ(
					builder.CreateLoad(builder.getInt16Ty(),
							   callItemCnt),
					builder.getInt16(0)),
				exitBlk, localRetBlk);
			break;
		}

#define HANDLE_ERR(ret)                                                        \
	{                                                                      \
		if (!ret)                                                      \
			return ret.takeError();                                \
	}

		case EBPF_OP_JEQ32_IMM:
		case EBPF_OP_JEQ_IMM:
		case EBPF_OP_JEQ32_REG:
		case EBPF_OP_JEQ_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpEQ(dst, src);
				}));
			break;
		}

		case EBPF_OP_JGT32_IMM:
		case EBPF_OP_JGT_IMM:
		case EBPF_OP_JGT32_REG:
		case EBPF_OP_JGT_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpUGT(dst, src);
				}));
			break;
		}
		case EBPF_OP_JGE32_IMM:
		case EBPF_OP_JGE_IMM:
		case EBPF_OP_JGE32_REG:
		case EBPF_OP_JGE_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpUGE(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSET32_IMM:
		case EBPF_OP_JSET_IMM:
		case EBPF_OP_JSET32_REG:
		case EBPF_OP_JSET_REG: {
			if (auto ret =
				    localJmpDstAndNextBlk(pc, inst, instBlocks);
			    ret) {
				auto [dstBlk, nextBlk] = ret.get();
				auto [src, dst, zero] =
					emitJmpLoadSrcAndDstAndZero(
						inst, &regs[0], builder);
				maybeSnapshot(pc, pc);
				builder.CreateCondBr(
					builder.CreateICmpNE(
						builder.CreateAnd(dst, src),
						zero),
					dstBlk, nextBlk);
			} else {
				return ret.takeError();
			}

			break;
		}
		case EBPF_OP_JNE32_IMM:
		case EBPF_OP_JNE_IMM:
		case EBPF_OP_JNE32_REG:
		case EBPF_OP_JNE_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpNE(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSGT32_IMM:
		case EBPF_OP_JSGT_IMM:
		case EBPF_OP_JSGT32_REG:
		case EBPF_OP_JSGT_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpSGT(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSGE32_IMM:
		case EBPF_OP_JSGE_IMM:
		case EBPF_OP_JSGE32_REG:
		case EBPF_OP_JSGE_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpSGE(dst, src);
				}));
			break;
		}
		case EBPF_OP_JLT32_IMM:
		case EBPF_OP_JLT_IMM:
		case EBPF_OP_JLT32_REG:
		case EBPF_OP_JLT_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpULT(dst, src);
				}));
			break;
		}
		case EBPF_OP_JLE32_IMM:
		case EBPF_OP_JLE_IMM:
		case EBPF_OP_JLE32_REG:
		case EBPF_OP_JLE_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpULE(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSLT32_IMM:
		case EBPF_OP_JSLT_IMM:
		case EBPF_OP_JSLT32_REG:
		case EBPF_OP_JSLT_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpSLT(dst, src);
				}));
			break;
		}
		case EBPF_OP_JSLE32_IMM:
		case EBPF_OP_JSLE_IMM:
		case EBPF_OP_JSLE32_REG:
		case EBPF_OP_JSLE_REG: {
			maybeSnapshot(pc, pc);
			HANDLE_ERR(emitCondJmpWithDstAndSrc(
				builder, pc, inst, instBlocks, &regs[0],
				[&](auto dst, auto src) {
					return builder.CreateICmpSLE(dst, src);
				}));
			break;
		}
		case EBPF_ATOMIC_OPCODE_32:
		case EBPF_ATOMIC_OPCODE_64: {
			switch (inst.imm) {
			case EBPF_ATOMIC_ADD:
			case EBPF_ATOMIC_ADD | EBPF_ATOMIC_OP_FETCH: {
				emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::Add, inst,
					inst.opcode == EBPF_ATOMIC_OPCODE_64,
					(inst.imm & EBPF_ATOMIC_OP_FETCH) ==
						EBPF_ATOMIC_OP_FETCH);
				break;
			}

			case EBPF_ATOMIC_AND:
			case EBPF_ATOMIC_AND | EBPF_ATOMIC_OP_FETCH: {
				emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::And, inst,
					inst.opcode == EBPF_ATOMIC_OPCODE_64,
					(inst.imm & EBPF_ATOMIC_OP_FETCH) ==
						EBPF_ATOMIC_OP_FETCH);
				break;
			}

			case EBPF_ATOMIC_OR:
			case EBPF_ATOMIC_OR | EBPF_ATOMIC_OP_FETCH: {
				emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::Or, inst,
					inst.opcode == EBPF_ATOMIC_OPCODE_64,
					(inst.imm & EBPF_ATOMIC_OP_FETCH) ==
						EBPF_ATOMIC_OP_FETCH);
				break;
			}
			case EBPF_ATOMIC_XOR:
			case EBPF_ATOMIC_XOR | EBPF_ATOMIC_OP_FETCH: {
				emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::Xor, inst,
					inst.opcode == EBPF_ATOMIC_OPCODE_64,
					(inst.imm & EBPF_ATOMIC_OP_FETCH) ==
						EBPF_ATOMIC_OP_FETCH);
				break;
			}
			case EBPF_ATOMIC_OP_XCHG: {
				emitAtomicBinOp(
					builder, &regs[0],
					llvm::AtomicRMWInst::BinOp::Xchg, inst,
					inst.opcode == EBPF_ATOMIC_OPCODE_64,
					false);
				break;
			}
			case EBPF_ATOMIC_OP_CMPXCHG: {
				bool is64 =
					inst.opcode == EBPF_ATOMIC_OPCODE_64;
				auto vPtr = builder.CreateGEP(
					builder.getInt8Ty(),
					builder.CreateLoad(builder.getPtrTy(),
							   regs[inst.dst]),
					{ builder.getInt64(inst.offset) });
				auto beforeVal = builder.CreateLoad(
					is64 ? builder.getInt64Ty() :
					       builder.getInt32Ty(),
					vPtr);
				builder.CreateAtomicCmpXchg(
					vPtr,
					builder.CreateLoad(
						is64 ? builder.getInt64Ty() :
						       builder.getInt32Ty(),
						regs[0]),
					builder.CreateLoad(
						is64 ? builder.getInt64Ty() :
						       builder.getInt32Ty(),
						regs[inst.src]),
					MaybeAlign(0),
					AtomicOrdering::Monotonic,
					AtomicOrdering::Monotonic);
				builder.CreateStore(
					builder.CreateZExt(beforeVal,
							   builder.getInt64Ty()),
					regs[0]);
				break;
			}
			default: {
				return llvm::make_error<llvm::StringError>(
					"Unsupported atomic operation: " +
						std::to_string(inst.imm),
					llvm::inconvertibleErrorCode());
			}
			}
			maybeSnapshot(pc, pc + 1);
			break;
		}
		default:
			return llvm::make_error<llvm::StringError>(
				"Unsupported or illegal opcode: " +
					std::to_string(inst.opcode) +
					" at pc " + std::to_string(pc),
				llvm::inconvertibleErrorCode());
		}
		// Snapshot after every plain register-modifying instruction
		// (ALU/LD/LDX). Jumps, calls, EXIT and atomics are handled by
		// maybeSnapshot() calls placed at their emission sites above.
		switch (inst.opcode) {
		case EBPF_OP_ADD64_IMM:
		case EBPF_OP_ADD_IMM:
		case EBPF_OP_ADD64_REG:
		case EBPF_OP_ADD_REG:
		case EBPF_OP_SUB64_IMM:
		case EBPF_OP_SUB_IMM:
		case EBPF_OP_SUB64_REG:
		case EBPF_OP_SUB_REG:
		case EBPF_OP_MUL64_IMM:
		case EBPF_OP_MUL_IMM:
		case EBPF_OP_MUL64_REG:
		case EBPF_OP_MUL_REG:
		case EBPF_OP_DIV64_IMM:
		case EBPF_OP_DIV_IMM:
		case EBPF_OP_DIV64_REG:
		case EBPF_OP_DIV_REG:
		case EBPF_OP_OR64_IMM:
		case EBPF_OP_OR_IMM:
		case EBPF_OP_OR64_REG:
		case EBPF_OP_OR_REG:
		case EBPF_OP_AND64_IMM:
		case EBPF_OP_AND_IMM:
		case EBPF_OP_AND64_REG:
		case EBPF_OP_AND_REG:
		case EBPF_OP_LSH64_IMM:
		case EBPF_OP_LSH_IMM:
		case EBPF_OP_LSH64_REG:
		case EBPF_OP_LSH_REG:
		case EBPF_OP_RSH64_IMM:
		case EBPF_OP_RSH_IMM:
		case EBPF_OP_RSH64_REG:
		case EBPF_OP_RSH_REG:
		case EBPF_OP_NEG:
		case EBPF_OP_NEG64:
		case EBPF_OP_MOD64_IMM:
		case EBPF_OP_MOD_IMM:
		case EBPF_OP_MOD64_REG:
		case EBPF_OP_MOD_REG:
		case EBPF_OP_XOR64_IMM:
		case EBPF_OP_XOR_IMM:
		case EBPF_OP_XOR64_REG:
		case EBPF_OP_XOR_REG:
		case EBPF_OP_MOV64_IMM:
		case EBPF_OP_MOV_IMM:
		case EBPF_OP_MOV64_REG:
		case EBPF_OP_MOV_REG:
		case EBPF_OP_ARSH64_IMM:
		case EBPF_OP_ARSH_IMM:
		case EBPF_OP_ARSH64_REG:
		case EBPF_OP_ARSH_REG:
		case EBPF_OP_LE:
		case EBPF_OP_BE:
		case EBPF_OP_BYTESWAP:
		case EBPF_OP_LDXB:
		case EBPF_OP_LDXH:
		case EBPF_OP_LDXW:
		case EBPF_OP_LDXDW: {
			maybeSnapshot(pc, pc + 1);
			break;
		}
		default:
			break;
		}
	}

	// Add br for all blocks
	for (size_t i = 0; i < allBlocks.size() - 1; i++) {
		auto &currBlk = allBlocks[i];
		if (currBlk->getTerminator() == nullptr) {
			builder.SetInsertPoint(allBlocks[i]);
			builder.CreateBr(allBlocks[i + 1]);
		}
	}
	if (!is_gpu && verifyModule(*jitModule, &dbgs())) {
		return llvm::make_error<llvm::StringError>(
			"Invalid module generated",
			llvm::inconvertibleErrorCode());
	}

	return ThreadSafeModule(std::move(jitModule), std::move(context));
}
Value *emitSS2SnapshotCondition(
	IRBuilder<> &builder, Value *r10Storage, uint16_t pc,
	const std::vector<TimeLoc> &snapshotLocations)
{
	Value *enabled = builder.getFalse();
	for (const auto &location : snapshotLocations) {
		if (location.pc != pc)
			continue;
		Value *matches = builder.getTrue();
		for (const auto &loop : location.time) {
			auto *r10 = builder.CreateLoad(builder.getInt64Ty(),
						 r10Storage);
			auto *currAddress = builder.CreateIntToPtr(
				builder.CreateAdd(
					r10, builder.getInt64(
						static_cast<int64_t>(loop.loc) +
						3 * sizeof(int64_t))),
				builder.getInt64Ty()->getPointerTo());
			auto *curr = builder.CreateAlignedLoad(
				builder.getInt64Ty(), currAddress, Align(1));
			matches = builder.CreateAnd(
				matches,
				builder.CreateICmpEQ(curr,
						     builder.getInt64(loop.v)));
		}
		enabled = builder.CreateOr(enabled, matches);
	}
	return enabled;
}

Expected<ThreadSafeModule> llvm_bpf_jit_context::generateModuleWithSS2(
	uint8_t maxFuncNestDepth, uint16_t frameSize,
	const std::vector<std::string> &extFuncNames,
	const std::vector<std::string> &lddwHelpers,
	bool patch_map_val_at_compile_time,
	uintptr_t register_state_store_addr,
	const std::vector<TimeLoc> &snapshot_locations,
	const std::vector<uint16_t> &extra_resume_pcs)
{
	std::unordered_map<uint16_t, CompInfo> snapshot_info;
	for (const auto &location : snapshot_locations) {
		auto &info = snapshot_info[location.pc];
		info.modified.set();
		// SS2 does not copy heap memory. Bit 22 is usedHeap.
		info.modified.reset(22);
	}

	return generateModuleWithSS2Core(maxFuncNestDepth, frameSize, extFuncNames,
					 lddwHelpers,
					 patch_map_val_at_compile_time, true,
					 "bpf_main", false, &snapshot_info,
					 register_state_store_addr,
					 &snapshot_locations, &extra_resume_pcs);
}
