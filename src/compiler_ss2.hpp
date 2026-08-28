#ifndef BPFTIME_COMPILER_SS2_HPP
#define BPFTIME_COMPILER_SS2_HPP

#include <cstdint>
#include <vector>

#include <llvm/IR/IRBuilder.h>

#include <llvmbpf.hpp>

llvm::Value *emitSS2SnapshotCondition(
	llvm::IRBuilder<> &builder, llvm::Value *r10Storage, uint16_t pc,
	const std::vector<bpftime::TimeLoc> &snapshotLocations);

#endif
