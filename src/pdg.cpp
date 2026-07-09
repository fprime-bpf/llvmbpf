#include <pdg.hpp>

#include "fpu_inst.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <deque>
#include <limits>
#include <numeric>
#include <optional>
#include <set>

namespace
{

constexpr uint64_t U64Max = std::numeric_limits<uint64_t>::max();

uint64_t maskFor(bool bits64)
{
	return bits64 ? U64Max : std::numeric_limits<uint32_t>::max();
}

uint64_t normalize(uint64_t value, bool bits64)
{
	return value & maskFor(bits64);
}

bool addOverflow(uint64_t lhs, uint64_t rhs, uint64_t &out)
{
	out = lhs + rhs;
	return out < lhs;
}

bool mulOverflow(uint64_t lhs, uint64_t rhs, uint64_t &out)
{
	if (lhs != 0 && rhs > U64Max / lhs) {
		out = U64Max;
		return true;
	}
	out = lhs * rhs;
	return false;
}

std::vector<IntInterval> normalizeRanges(std::vector<IntInterval> ranges)
{
	if (ranges.empty())
		return { { 0, U64Max } };

	std::sort(ranges.begin(), ranges.end(), [](const auto &lhs, const auto &rhs) {
		return lhs.lo < rhs.lo || (lhs.lo == rhs.lo && lhs.hi < rhs.hi);
	});

	std::vector<IntInterval> merged;
	for (const auto &range : ranges) {
		if (range.lo > range.hi)
			continue;
		if (merged.empty() || merged.back().hi == U64Max ||
		    range.lo > merged.back().hi + 1) {
			merged.push_back(range);
			continue;
		}
		merged.back().hi = std::max(merged.back().hi, range.hi);
	}
	return merged.empty() ? std::vector<IntInterval>{ { 0, U64Max } } :
				merged;
}


bool isRegSource(const ebpf_inst &inst)
{
	return (inst.opcode & EBPF_SRC_REG) == EBPF_SRC_REG;
}

bool isAlu(const ebpf_inst &inst)
{
	const auto cls = inst.opcode & EBPF_CLS_MASK;
	return cls == EBPF_CLS_ALU || cls == EBPF_CLS_ALU64;
}

bool isAlu64Inst(const ebpf_inst &inst)
{
	return (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_ALU64;
}

bool isJump(const ebpf_inst &inst)
{
	const auto cls = inst.opcode & EBPF_CLS_MASK;
	return cls == EBPF_CLS_JMP || cls == EBPF_CLS_JMP32;
}

bool isCondJump(const ebpf_inst &inst)
{
	const auto op = inst.opcode & EBPF_JMP_OP_MASK;
	return isJump(inst) && op != EBPF_MODE_JA && op != EBPF_MODE_CALL &&
	       op != EBPF_MODE_EXIT;
}

bool isMemoryLoad(const ebpf_inst &inst)
{
	return (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_LDX;
}

bool isMemoryStore(const ebpf_inst &inst)
{
	const auto cls = inst.opcode & EBPF_CLS_MASK;
	return cls == EBPF_CLS_ST || cls == EBPF_CLS_STX;
}

bool isAtomic(const ebpf_inst &inst)
{
	return inst.opcode == EBPF_ATOMIC_OPCODE_32 ||
	       inst.opcode == EBPF_ATOMIC_OPCODE_64;
}

std::size_t accessSize(const ebpf_inst &inst)
{
	switch (inst.opcode & 0x18) {
	case EBPF_SIZE_B:
		return 1;
	case EBPF_SIZE_H:
		return 2;
	case EBPF_SIZE_W:
		return 4;
	case EBPF_SIZE_DW:
		return 8;
	default:
		return 8;
	}
}

Dep depBaseFor(const PDValue &value, Dep fallback)
{
	switch (kindOf(value)) {
	case PDValueKind::StackPtr:
	case PDValueKind::MapValuePtr:
		return Dep::Stack;
	case PDValueKind::MapPtr:
		return Dep::Map;
	case PDValueKind::Float:
		return Dep::FPU;
	default:
		return fallback;
	}
}

struct Slot {
	std::vector<PDEdge> writers;
	PDValue value;
};

struct State {
	std::array<Slot, 11> regs;
	std::array<Slot, 11> fregs;
	std::array<Slot, MAX_BPF_STACK> stack;
	std::vector<PDEdge> mapWriters;
	std::vector<uint16_t> callStack;

	State()
	{
		regs[10].value = StackPtrValue();
	}
};

class Builder {
    public:
	explicit Builder(const std::vector<ebpf_inst> &instructions)
		: instructions_(instructions), graph_(instructions.size())
	{
	}

	PDGraph run()
	{
		if (instructions_.empty())
			return graph_;

		std::vector<std::vector<State> > incoming(instructions_.size());
		std::deque<std::pair<uint16_t, State> > worklist;
		incoming[0].push_back(State());
		worklist.push_back({ 0, incoming[0].front() });

		while (!worklist.empty()) {
			const auto [pc, state] = worklist.front();
			worklist.pop_front();

			state_ = state;
			process(pc);

			for (auto [next, outgoing] : successorStates(pc)) {
				if (next >= instructions_.size())
					continue;
				enqueueState(incoming[next], worklist, next,
					     std::move(outgoing));
			}
		}
		return graph_;
	}

    private:
	const std::vector<ebpf_inst> &instructions_;
	PDGraph graph_;
	State state_;

	static bool sameEdgeBase(const PDEdge &lhs, const PDEdge &rhs)
	{
		return lhs.dst == rhs.dst &&
		       (static_cast<uint8_t>(lhs.type) & 0x03) ==
			       (static_cast<uint8_t>(rhs.type) & 0x03);
	}

	static bool sameIntValue(const IntValue &lhs, const IntValue &rhs)
	{
		const auto &left = lhs.ranges();
		const auto &right = rhs.ranges();
		if (left.size() != right.size())
			return false;
		for (std::size_t i = 0; i < left.size(); ++i) {
			if (left[i].lo != right[i].lo || left[i].hi != right[i].hi)
				return false;
		}
		return true;
	}

	static bool sameStackPtrValue(const StackPtrValue &lhs,
				      const StackPtrValue &rhs)
	{
		return lhs.offsets() == rhs.offsets();
	}

	static bool sameValue(const PDValue &lhs, const PDValue &rhs)
	{
		if (lhs.index() != rhs.index())
			return false;
		if (const auto *l = std::get_if<IntValue>(&lhs))
			return sameIntValue(*l, std::get<IntValue>(rhs));
		if (const auto *l = std::get_if<StackPtrValue>(&lhs))
			return sameStackPtrValue(*l, std::get<StackPtrValue>(rhs));
		if (const auto *l = std::get_if<MapPtrValue>(&lhs))
			return l->id == std::get<MapPtrValue>(rhs).id;
		return true;
	}

	static bool mergeWriters(std::vector<PDEdge> &dst,
				 const std::vector<PDEdge> &src)
	{
		bool changed = false;
		for (const auto &writer : src) {
			auto found = std::find_if(dst.begin(), dst.end(),
						 [&](const PDEdge &edge) {
							 return sameEdgeBase(edge, writer);
						 });
			if (found == dst.end()) {
				dst.push_back(writer);
				changed = true;
			} else {
				const Dep oldType = found->type;
				found->type |= writer.type;
				changed = changed || found->type != oldType;
			}
		}
		return changed;
	}

	static bool mergeSlot(Slot &dst, const Slot &src)
	{
		bool changed = mergeWriters(dst.writers, src.writers);
		if (!sameValue(dst.value, src.value)) {
			if (!std::holds_alternative<std::monostate>(dst.value)) {
				dst.value = {};
				changed = true;
			}
		}
		return changed;
	}

	static bool sameCallStack(const State &lhs, const State &rhs)
	{
		return lhs.callStack == rhs.callStack;
	}

	static bool mergeState(State &dst, const State &src)
	{
		if (!sameCallStack(dst, src))
			return false;

		bool changed = false;
		for (std::size_t i = 0; i < dst.regs.size(); ++i)
			changed = mergeSlot(dst.regs[i], src.regs[i]) || changed;
		for (std::size_t i = 0; i < dst.fregs.size(); ++i)
			changed = mergeSlot(dst.fregs[i], src.fregs[i]) || changed;
		for (std::size_t i = 0; i < dst.stack.size(); ++i)
			changed = mergeSlot(dst.stack[i], src.stack[i]) || changed;
		changed = mergeWriters(dst.mapWriters, src.mapWriters) || changed;
		return changed;
	}

	static void enqueueState(std::vector<State> &incoming,
				 std::deque<std::pair<uint16_t, State> > &worklist,
				 uint16_t pc, State state)
	{
		for (auto &existing : incoming) {
			if (sameCallStack(existing, state)) {
				if (mergeState(existing, state))
					worklist.push_back({ pc, existing });
				return;
			}
		}

		incoming.push_back(std::move(state));
		worklist.push_back({ pc, incoming.back() });
	}

	std::optional<IntValue> intersectValue(const IntValue &value,
					       uint64_t lo, uint64_t hi) const
	{
		std::vector<IntInterval> ranges;
		for (const auto &range : value.ranges()) {
			const uint64_t nextLo = std::max(range.lo, lo);
			const uint64_t nextHi = std::min(range.hi, hi);
			if (nextLo <= nextHi)
				ranges.push_back({ nextLo, nextHi });
		}
		if (ranges.empty())
			return std::nullopt;
		return IntValue(std::move(ranges));
	}

	std::optional<IntValue> excludeValue(const IntValue &value,
					     uint64_t excluded) const
	{
		std::vector<IntInterval> ranges;
		for (const auto &range : value.ranges()) {
			if (excluded < range.lo || excluded > range.hi) {
				ranges.push_back(range);
				continue;
			}
			if (range.lo < excluded)
				ranges.push_back({ range.lo, excluded - 1 });
			if (excluded < range.hi)
				ranges.push_back({ excluded + 1, range.hi });
		}
		if (ranges.empty())
			return std::nullopt;
		return IntValue(std::move(ranges));
	}

	bool refineAgainstConstant(State &state, uint8_t reg, uint8_t op,
				   uint64_t constant, bool taken) const
	{
		auto *value = std::get_if<IntValue>(&state.regs[reg].value);
		if (value == nullptr)
			return true;

		std::optional<IntValue> refined;
		switch (op) {
		case EBPF_MODE_JEQ:
			refined = taken ? intersectValue(*value, constant, constant) :
					  excludeValue(*value, constant);
			break;
		case EBPF_MODE_JNE:
			refined = taken ? excludeValue(*value, constant) :
					  intersectValue(*value, constant, constant);
			break;
		case EBPF_MODE_JGT:
			refined = taken ?
					  (constant == U64Max ?
						   std::optional<IntValue>{} :
						   intersectValue(*value, constant + 1,
								  U64Max)) :
					  intersectValue(*value, 0, constant);
			break;
		case EBPF_MODE_JGE:
			refined = taken ? intersectValue(*value, constant, U64Max) :
					  (constant == 0 ?
						   std::optional<IntValue>{} :
						   intersectValue(*value, 0,
								  constant - 1));
			break;
		case EBPF_MODE_JLT:
			refined = taken ?
					  (constant == 0 ?
						   std::optional<IntValue>{} :
						   intersectValue(*value, 0,
								  constant - 1)) :
					  intersectValue(*value, constant, U64Max);
			break;
		case EBPF_MODE_JLE:
			refined = taken ? intersectValue(*value, 0, constant) :
					  (constant == U64Max ?
						   std::optional<IntValue>{} :
						   intersectValue(*value, constant + 1,
								  U64Max));
			break;
		default:
			return true;
		}

		if (!refined)
			return false;
		state.regs[reg].value = *refined;
		return true;
	}

	bool refineConditionalState(State &state, const ebpf_inst &inst,
				    bool taken) const
	{
		const auto op = inst.opcode & EBPF_JMP_OP_MASK;
		if (op == EBPF_MODE_JSET || op == EBPF_MODE_JSGT ||
		    op == EBPF_MODE_JSGE || op == EBPF_MODE_JSLT ||
		    op == EBPF_MODE_JSLE)
			return true;

		if (!isRegSource(inst))
			return refineAgainstConstant(
				state, inst.dst, op,
				static_cast<uint64_t>(static_cast<int64_t>(inst.imm)),
				taken);

		const auto *srcValue = std::get_if<IntValue>(&state.regs[inst.src].value);
		if (srcValue != nullptr) {
			if (auto exact = srcValue->exactValue()) {
				if (!refineAgainstConstant(state, inst.dst, op,
							   *exact, taken))
					return false;
			}
		}

		const auto *dstValue = std::get_if<IntValue>(&state.regs[inst.dst].value);
		if (dstValue == nullptr)
			return true;
		const auto exactDst = dstValue->exactValue();
		if (!exactDst)
			return true;

		uint8_t reversed = op;
		switch (op) {
		case EBPF_MODE_JGT:
			reversed = EBPF_MODE_JLT;
			break;
		case EBPF_MODE_JGE:
			reversed = EBPF_MODE_JLE;
			break;
		case EBPF_MODE_JLT:
			reversed = EBPF_MODE_JGT;
			break;
		case EBPF_MODE_JLE:
			reversed = EBPF_MODE_JGE;
			break;
		default:
			break;
		}
		return refineAgainstConstant(state, inst.src, reversed, *exactDst,
					     taken);
	}

	std::vector<std::pair<uint16_t, State> > successorStates(uint16_t pc) const
	{
		const auto &inst = instructions_[pc];
		auto addNext = [&](int64_t value,
				   std::vector<std::pair<uint16_t, State> > &out,
				   State state) {
			if (value >= 0 && static_cast<std::size_t>(value) < instructions_.size())
				out.push_back({ static_cast<uint16_t>(value),
						std::move(state) });
		};

		std::vector<std::pair<uint16_t, State> > result;
		if (inst.opcode == EBPF_OP_EXIT) {
			if (state_.callStack.empty())
				return result;
			State returned = state_;
			const uint16_t target = returned.callStack.back();
			returned.callStack.pop_back();
			returned.regs[0].writers = { { pc, Dep::Int } };
			addNext(target, result, std::move(returned));
			return result;
		}
		if (inst.opcode == EBPF_OP_LDDW) {
			addNext(static_cast<int64_t>(pc) + 2, result, state_);
			return result;
		}
		if (inst.opcode == EBPF_OP_JA) {
			addNext(static_cast<int64_t>(pc) + 1 + inst.offset, result,
				state_);
			return result;
		}
		if (inst.opcode == EBPF_OP_JA_IMM) {
			addNext(static_cast<int64_t>(pc) + 1 + inst.imm, result,
				state_);
			return result;
		}
		if ((inst.opcode == EBPF_OP_CALL ||
		     inst.opcode == (EBPF_OP_CALL | 0x8)) &&
		    inst.src == 0x1) {
			State called = state_;
			called.callStack.push_back(pc + 1);
			addNext(static_cast<int64_t>(pc) + 1 + inst.imm, result,
				std::move(called));
			return result;
		}
		if (isCondJump(inst) || (duo_is_fpu(inst) && duo_class(inst) == FJMP)) {
			State fallthrough = state_;
			State taken = state_;
			const bool refine = isCondJump(inst);
			if (!refine || refineConditionalState(fallthrough, inst, false))
				addNext(static_cast<int64_t>(pc) + 1, result,
					std::move(fallthrough));
			if (!refine || refineConditionalState(taken, inst, true))
				addNext(static_cast<int64_t>(pc) + 1 + inst.offset,
					result, std::move(taken));
			return result;
		}

		addNext(static_cast<int64_t>(pc) + 1, result, state_);
		return result;
	}

	void addEdge(uint16_t src, uint16_t dst, Dep type)
	{
		if (src >= graph_.size() || src == dst)
			return;

		auto &edges = graph_[src];
		PDEdge key{ dst, type };
		auto found = std::find_if(edges.begin(), edges.end(),
					  [&](const PDEdge &edge) {
						  return sameEdgeBase(edge, key);
					  });
		if (found == edges.end()) {
			edges.push_back({ dst, type });
		} else {
			found->type |= type;
		}
	}

	void readSlot(const Slot &slot, uint16_t pc, Dep type)
	{
		for (const auto &writer : slot.writers)
			addEdge(writer.dst, pc, writer.type | type);
	}

	void writeSlot(Slot &slot, uint16_t pc, Dep type, PDValue value)
	{
		slot.writers = { { pc, type } };
		slot.value = std::move(value);
	}

	void unknownWrite(Slot &slot, uint16_t pc, Dep type)
	{
		writeSlot(slot, pc, type | Dep::Potential, {});
	}

	IntValue intFrom(const PDValue &value) const
	{
		if (const auto *intValue = std::get_if<IntValue>(&value))
			return *intValue;
		if (const auto *stackPtr = std::get_if<StackPtrValue>(&value)) {
			std::vector<IntInterval> ranges;
			for (int offset : stackPtr->offsets())
				ranges.push_back({ static_cast<uint64_t>(offset),
						   static_cast<uint64_t>(offset) });
			return IntValue(std::move(ranges));
		}
		return IntValue::unknown();
	}

	PDValue aluResult(const ebpf_inst &inst)
	{
		const bool bits64 = isAlu64Inst(inst);
		const bool srcReg = isRegSource(inst);
		const auto op = inst.opcode & EBPF_ALU_OP_MASK;
		const auto &dstValue = state_.regs[inst.dst].value;
		const PDValue srcValue =
			srcReg ? state_.regs[inst.src].value :
				 PDValue(IntValue::signedImm(inst.imm));

		if (op == EBPF_ALU_OP_MOV) {
			if (srcReg) {
				PDValue value = srcValue;
				if (!bits64) {
					if (auto *intValue = std::get_if<IntValue>(&value))
						value = intValue->trunc32();
				}
				if (inst.offset == 8 || inst.offset == 16 || inst.offset == 32) {
					if (auto *intValue = std::get_if<IntValue>(&value))
						value = intValue->signExtendFrom(inst.offset);
				}
				return value;
			}
			return bits64 ? PDValue(IntValue::signedImm(inst.imm)) :
					PDValue(IntValue::unsigned32(
						static_cast<uint32_t>(inst.imm)));
		}

		if (op == EBPF_ALU_OP_NEG)
			return PDValue(intFrom(dstValue).neg(bits64));
		if (op == EBPF_ALU_OP_END) {
			auto value = intFrom(dstValue);
			if (inst.imm == 16 || inst.imm == 32 || inst.imm == 64)
				return PDValue(value.byteSwap(inst.imm));
			return PDValue(IntValue::unknown());
		}

		if (auto *stackPtr = std::get_if<StackPtrValue>(&state_.regs[inst.dst].value)) {
			const IntValue offset = intFrom(srcValue);
			if (op == EBPF_ALU_OP_ADD)
				return PDValue(stackPtr->add(offset));
			if (op == EBPF_ALU_OP_SUB)
				return PDValue(stackPtr->sub(offset));
		}

		const IntValue lhs = intFrom(dstValue);
		const IntValue rhs = intFrom(srcValue);
		switch (op) {
		case EBPF_ALU_OP_ADD:
			return PDValue(lhs.add(rhs, bits64));
		case EBPF_ALU_OP_SUB:
			return PDValue(lhs.sub(rhs, bits64));
		case EBPF_ALU_OP_MUL:
			return PDValue(lhs.mul(rhs, bits64));
		case EBPF_ALU_OP_DIV:
			return PDValue(lhs.udiv(rhs, bits64));
		case EBPF_ALU_OP_MOD:
			return PDValue(lhs.umod(rhs, bits64));
		case EBPF_ALU_OP_OR:
			return PDValue(lhs.bitOr(rhs, bits64));
		case EBPF_ALU_OP_AND:
			return PDValue(lhs.bitAnd(rhs, bits64));
		case EBPF_ALU_OP_XOR:
			return PDValue(lhs.bitXor(rhs, bits64));
		case EBPF_ALU_OP_LSH:
			return PDValue(lhs.lsh(rhs, bits64));
		case EBPF_ALU_OP_RSH:
			return PDValue(lhs.rsh(rhs, bits64));
		case EBPF_ALU_OP_ARSH:
			return PDValue(lhs.arsh(rhs, bits64));
		default:
			return PDValue(IntValue::unknown());
		}
	}

	std::vector<std::size_t> stackIndexes(const PDValue &base, int16_t offset,
					      std::size_t size, bool &potential) const
	{
		std::vector<std::size_t> result;
		const auto *ptr = std::get_if<StackPtrValue>(&base);
		if (ptr == nullptr || ptr->offsets().empty()) {
			potential = true;
			result.resize(MAX_BPF_STACK);
			std::iota(result.begin(), result.end(), 0);
			return result;
		}

		potential = !ptr->exact();
		for (int baseOffset : ptr->offsets()) {
			const int start = baseOffset + offset;
			for (std::size_t i = 0; i < size; ++i) {
				const int byteOffset = start + static_cast<int>(i);
				if (byteOffset >= -MAX_BPF_STACK && byteOffset < 0)
					result.push_back(static_cast<std::size_t>(
						-byteOffset - 1));
				else
					potential = true;
			}
		}
		std::sort(result.begin(), result.end());
		result.erase(std::unique(result.begin(), result.end()), result.end());
		return result;
	}

	void readStackAccess(const ebpf_inst &inst, uint16_t pc, Dep baseType)
	{
		bool potential = false;
		const auto indexes = stackIndexes(state_.regs[inst.src].value, inst.offset,
						  accessSize(inst), potential);
		for (auto index : indexes) {
			readSlot(state_.stack[index], pc,
				 potential ? baseType | Dep::Potential : baseType);
		}
	}

	void readMap(uint16_t pc)
	{
		for (const auto &writer : state_.mapWriters)
			addEdge(writer.dst, pc, writer.type | Dep::Map | Dep::Potential);
	}

	void writeMap(uint16_t pc)
	{
		state_.mapWriters = { { pc, Dep::Map } };
	}

	void handleFpu(uint16_t pc, const ebpf_inst &inst)
	{
		if (inst.dst > 10 || inst.src > 10)
			return;
		if (duo_class(inst) == FJMP) {
			readSlot(state_.fregs[inst.dst], pc, Dep::FPU | Dep::Conditional);
			if (duo_source(inst) == FREG)
				readSlot(state_.fregs[inst.src], pc,
					 Dep::FPU | Dep::Conditional);
			return;
		}
		if (inst.opcode == DUO_OP_FLDX) {
			readSlot(state_.regs[inst.src], pc, Dep::Int);
			readStackAccess(inst, pc, Dep::Stack);
			writeSlot(state_.fregs[inst.dst], pc, Dep::FPU, IntValue::unknown());
			return;
		}
		if (inst.opcode == DUO_OP_FST || inst.opcode == DUO_OP_FSTX) {
			readSlot(state_.regs[inst.dst], pc, Dep::Int);
			if (inst.opcode == DUO_OP_FSTX)
				readSlot(state_.fregs[inst.src], pc, Dep::FPU);
			bool potential = false;
			const auto indexes = stackIndexes(state_.regs[inst.dst].value, inst.offset,
							  4, potential);
			for (auto index : indexes)
				writeSlot(state_.stack[index], pc,
					  potential ? Dep::Stack | Dep::Potential :
						      Dep::Stack,
					  IntValue::unknown());
			return;
		}
		if (duo_class(inst) == FALU) {
			if (duo_opcode(inst) != FNEG)
				readSlot(state_.fregs[inst.dst], pc, Dep::FPU);
			if (duo_source(inst) == FREG)
				readSlot(state_.fregs[inst.src], pc, Dep::FPU);
			writeSlot(state_.fregs[inst.dst], pc, Dep::FPU,
				  IntValue::unknown());
		}
	}

	void handleMemoryLoad(uint16_t pc, const ebpf_inst &inst)
	{
		readSlot(state_.regs[inst.src], pc, Dep::Int);
		bool potential = false;
		const auto indexes = stackIndexes(state_.regs[inst.src].value, inst.offset,
						  accessSize(inst), potential);
		for (auto index : indexes)
			readSlot(state_.stack[index], pc,
				 potential ? Dep::Stack | Dep::Potential : Dep::Stack);

		PDValue loaded = IntValue::unknown();
		writeSlot(state_.regs[inst.dst], pc, Dep::Stack, loaded);
	}

	void handleMemoryStore(uint16_t pc, const ebpf_inst &inst)
	{
		readSlot(state_.regs[inst.dst], pc, Dep::Int);
		if ((inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_STX)
			readSlot(state_.regs[inst.src], pc,
				 depBaseFor(state_.regs[inst.src].value, Dep::Int));

		bool potential = false;
		const auto indexes = stackIndexes(state_.regs[inst.dst].value, inst.offset,
						  accessSize(inst), potential);
		PDValue stored = (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_STX ?
					 state_.regs[inst.src].value :
					 PDValue(IntValue::signedImm(inst.imm));
		for (auto index : indexes)
			writeSlot(state_.stack[index], pc,
				  potential ? Dep::Stack | Dep::Potential : Dep::Stack,
				  stored);
	}

	void handleAtomic(uint16_t pc, const ebpf_inst &inst)
	{
		readSlot(state_.regs[inst.dst], pc, Dep::Int);
		readSlot(state_.regs[inst.src], pc,
			 depBaseFor(state_.regs[inst.src].value, Dep::Int));
		if (inst.imm == EBPF_ATOMIC_OP_CMPXCHG)
			readSlot(state_.regs[0], pc, Dep::Int);
		bool potential = false;
		const auto indexes = stackIndexes(state_.regs[inst.dst].value, inst.offset,
						  accessSize(inst), potential);
		for (auto index : indexes) {
			readSlot(state_.stack[index], pc,
				 potential ? Dep::Stack | Dep::Potential : Dep::Stack);
			writeSlot(state_.stack[index], pc,
				  potential ? Dep::Stack | Dep::Potential : Dep::Stack,
				  IntValue::unknown());
		}
		if ((inst.imm & EBPF_ATOMIC_OP_FETCH) || inst.imm == EBPF_ATOMIC_OP_CMPXCHG)
			writeSlot(state_.regs[inst.src == 0 ? 0 : inst.src], pc, Dep::Int,
				  IntValue::unknown());
	}

	void handleCall(uint16_t pc, const ebpf_inst &inst)
	{
		if (inst.src == 0x1)
			return;

		switch (inst.imm) {
		case 1: // bpf_map_lookup_elem
			readSlot(state_.regs[1], pc, Dep::Map);
			readSlot(state_.regs[2], pc, Dep::Int);
			readMap(pc);
			writeSlot(state_.regs[0], pc, Dep::Map, MapValuePtr{});
			break;
		case 2: // bpf_map_update_elem
			readSlot(state_.regs[1], pc, Dep::Map);
			readSlot(state_.regs[2], pc, Dep::Int);
			readSlot(state_.regs[3], pc,
				 depBaseFor(state_.regs[3].value, Dep::Int));
			readSlot(state_.regs[4], pc, Dep::Int);
			writeMap(pc);
			writeSlot(state_.regs[0], pc, Dep::Int, IntValue(0));
			break;
		case 3: // bpf_map_delete_elem
			readSlot(state_.regs[1], pc, Dep::Map);
			readSlot(state_.regs[2], pc, Dep::Int);
			readMap(pc);
			writeMap(pc);
			writeSlot(state_.regs[0], pc, Dep::Int, IntValue::unknown());
			break;
		default:
			for (int reg = 1; reg <= 5; ++reg)
				readSlot(state_.regs[reg], pc, Dep::Int | Dep::Potential);
			readMap(pc);
			unknownWrite(state_.regs[0], pc, Dep::Int);
			break;
		}
	}

	void process(uint16_t pc)
	{
		const auto &inst = instructions_[pc];
		if (duo_is_fpu(inst)) {
			handleFpu(pc, inst);
			return;
		}

		if (inst.dst > 10 || inst.src > 10)
			return;

		if (isAlu(inst)) {
			const bool srcReg = isRegSource(inst);
			const auto op = inst.opcode & EBPF_ALU_OP_MASK;
			if (op != EBPF_ALU_OP_MOV)
				readSlot(state_.regs[inst.dst], pc,
					 depBaseFor(state_.regs[inst.dst].value, Dep::Int));
			if (srcReg)
				readSlot(state_.regs[inst.src], pc,
					 depBaseFor(state_.regs[inst.src].value, Dep::Int));
			writeSlot(state_.regs[inst.dst], pc,
				  depBaseFor(aluResult(inst), Dep::Int), aluResult(inst));
			return;
		}

		if (inst.opcode == EBPF_OP_LDDW) {
			uint64_t imm = static_cast<uint32_t>(inst.imm);
			if (pc + 1 < instructions_.size())
				imm |= static_cast<uint64_t>(
					       static_cast<uint32_t>(instructions_[pc + 1].imm))
				       << 32;
			PDValue value = IntValue(imm);
			if (inst.src == 1 || inst.src == 2 || inst.src == 3)
				value = MapPtrValue{ static_cast<uint16_t>(imm & 0x3ff) };
			writeSlot(state_.regs[inst.dst], pc,
				  kindOf(value) == PDValueKind::MapPtr ? Dep::Map :
									 Dep::Int,
				  value);
			return;
		}

		if (isAtomic(inst)) {
			handleAtomic(pc, inst);
			return;
		}

		if (isMemoryLoad(inst)) {
			handleMemoryLoad(pc, inst);
			return;
		}

		if (isMemoryStore(inst)) {
			handleMemoryStore(pc, inst);
			return;
		}

		if (inst.opcode == EBPF_OP_CALL || inst.opcode == (EBPF_OP_CALL | 0x8)) {
			handleCall(pc, inst);
			return;
		}

		if (inst.opcode == EBPF_OP_EXIT) {
			readSlot(state_.regs[0], pc, Dep::Int);
			return;
		}

		if (isCondJump(inst)) {
			readSlot(state_.regs[inst.dst], pc, Dep::Int | Dep::Conditional);
			if (isRegSource(inst))
				readSlot(state_.regs[inst.src], pc,
					 Dep::Int | Dep::Conditional);
		}
	}
};

} // namespace

IntValue::IntValue(std::vector<IntInterval> ranges)
	: ranges_(normalizeRanges(std::move(ranges)))
{
}

IntValue IntValue::unknown()
{
	return IntValue({ { 0, U64Max } });
}

IntValue IntValue::signedImm(int32_t imm)
{
	return IntValue(static_cast<uint64_t>(static_cast<int64_t>(imm)));
}

IntValue IntValue::unsigned32(uint32_t value)
{
	return IntValue(value);
}

bool IntValue::exact() const noexcept
{
	return ranges_.size() == 1 && ranges_[0].lo == ranges_[0].hi;
}

std::optional<uint64_t> IntValue::exactValue() const noexcept
{
	if (!exact())
		return std::nullopt;
	return ranges_[0].lo;
}

bool IntValue::unknownRange() const noexcept
{
	return ranges_.size() == 1 && ranges_[0].lo == 0 && ranges_[0].hi == U64Max;
}

IntValue IntValue::trunc32() const
{
	if (auto exact = exactValue())
		return IntValue(static_cast<uint32_t>(*exact));
	return IntValue({ { 0, std::numeric_limits<uint32_t>::max() } });
}

IntValue IntValue::signExtendFrom(unsigned bits) const
{
	if (bits == 0 || bits >= 64)
		return *this;
	if (auto exact = exactValue()) {
		const uint64_t mask = (uint64_t{ 1 } << bits) - 1;
		uint64_t value = *exact & mask;
		const uint64_t sign = uint64_t{ 1 } << (bits - 1);
		if ((value & sign) != 0)
			value |= ~mask;
		return IntValue(value);
	}
	return IntValue::unknown();
}

IntValue IntValue::byteSwap(unsigned bits) const
{
	if (auto exact = exactValue()) {
		uint64_t value = *exact;
		switch (bits) {
		case 16:
			return IntValue(__builtin_bswap16(static_cast<uint16_t>(value)));
		case 32:
			return IntValue(__builtin_bswap32(static_cast<uint32_t>(value)));
		case 64:
			return IntValue(__builtin_bswap64(value));
		default:
			break;
		}
	}
	return IntValue::unknown();
}

IntValue IntValue::add(const IntValue &rhs, bool bits64) const
{
	if (auto l = exactValue(); l && rhs.exactValue()) {
		uint64_t out = 0;
		addOverflow(*l, *rhs.exactValue(), out);
		return IntValue(normalize(out, bits64));
	}
	const auto &lhsRange = ranges_.front();
	const auto &rhsRange = rhs.ranges_.front();
	uint64_t lo = normalize(lhsRange.lo + rhsRange.lo, bits64);
	uint64_t hi = normalize(lhsRange.hi + rhsRange.hi, bits64);
	if (lo > hi)
		return IntValue::unknown();
	return IntValue({ { lo, hi } });
}

IntValue IntValue::sub(const IntValue &rhs, bool bits64) const
{
	if (auto l = exactValue(); l && rhs.exactValue())
		return IntValue(normalize(*l - *rhs.exactValue(), bits64));
	const auto &lhsRange = ranges_.front();
	const auto &rhsRange = rhs.ranges_.front();
	if (lhsRange.lo < rhsRange.hi)
		return IntValue::unknown();
	return IntValue({ { normalize(lhsRange.lo - rhsRange.hi, bits64),
			    normalize(lhsRange.hi - rhsRange.lo, bits64) } });
}

IntValue IntValue::mul(const IntValue &rhs, bool bits64) const
{
	if (auto l = exactValue(); l && rhs.exactValue()) {
		uint64_t out = 0;
		mulOverflow(*l, *rhs.exactValue(), out);
		return IntValue(normalize(out, bits64));
	}
	const auto &lhsRange = ranges_.front();
	const auto &rhsRange = rhs.ranges_.front();
	uint64_t hi = 0;
	if (mulOverflow(lhsRange.hi, rhsRange.hi, hi) || (!bits64 && hi > maskFor(false)))
		return IntValue::unknown();
	return IntValue({ { normalize(lhsRange.lo * rhsRange.lo, bits64),
			    normalize(hi, bits64) } });
}

IntValue IntValue::udiv(const IntValue &rhs, bool bits64) const
{
	if (rhs.exactValue() == std::optional<uint64_t>{ 0 })
		return IntValue(0);
	if (auto l = exactValue(); l && rhs.exactValue())
		return IntValue(normalize(*l / *rhs.exactValue(), bits64));
	return IntValue::unknown();
}

IntValue IntValue::umod(const IntValue &rhs, bool bits64) const
{
	if (rhs.exactValue() == std::optional<uint64_t>{ 0 })
		return *this;
	if (auto l = exactValue(); l && rhs.exactValue())
		return IntValue(normalize(*l % *rhs.exactValue(), bits64));
	if (auto r = rhs.exactValue(); r && *r > 0)
		return IntValue({ { 0, normalize(*r - 1, bits64) } });
	return IntValue::unknown();
}

IntValue IntValue::bitAnd(const IntValue &rhs, bool bits64) const
{
	if (auto l = exactValue(); l && rhs.exactValue())
		return IntValue(normalize(*l & *rhs.exactValue(), bits64));
	if (auto r = rhs.exactValue())
		return IntValue({ { 0, normalize(*r, bits64) } });
	return IntValue::unknown();
}

IntValue IntValue::bitOr(const IntValue &rhs, bool bits64) const
{
	if (auto l = exactValue(); l && rhs.exactValue())
		return IntValue(normalize(*l | *rhs.exactValue(), bits64));
	return IntValue::unknown();
}

IntValue IntValue::bitXor(const IntValue &rhs, bool bits64) const
{
	if (auto l = exactValue(); l && rhs.exactValue())
		return IntValue(normalize(*l ^ *rhs.exactValue(), bits64));
	return IntValue::unknown();
}

IntValue IntValue::lsh(const IntValue &rhs, bool bits64) const
{
	if (auto l = exactValue(); l && rhs.exactValue()) {
		const unsigned shift = *rhs.exactValue() % (bits64 ? 64 : 32);
		return IntValue(normalize(*l << shift, bits64));
	}
	return IntValue::unknown();
}

IntValue IntValue::rsh(const IntValue &rhs, bool bits64) const
{
	if (auto l = exactValue(); l && rhs.exactValue()) {
		const unsigned shift = *rhs.exactValue() % (bits64 ? 64 : 32);
		return IntValue(normalize(*l, bits64) >> shift);
	}
	return IntValue::unknown();
}

IntValue IntValue::arsh(const IntValue &rhs, bool bits64) const
{
	if (auto l = exactValue(); l && rhs.exactValue()) {
		const unsigned shift = *rhs.exactValue() % (bits64 ? 64 : 32);
		if (bits64)
			return IntValue(static_cast<uint64_t>(
				static_cast<int64_t>(*l) >> shift));
		return IntValue(static_cast<uint32_t>(
			static_cast<int32_t>(static_cast<uint32_t>(*l)) >> shift));
	}
	return IntValue::unknown();
}

IntValue IntValue::neg(bool bits64) const
{
	if (auto exact = exactValue())
		return IntValue(normalize(-*exact, bits64));
	return IntValue::unknown();
}

StackPtrValue::StackPtrValue()
{
	candidates_.set(0);
}

StackPtrValue::StackPtrValue(int offset)
{
	if (offset >= -MAX_BPF_STACK && offset <= 0)
		candidates_.set(static_cast<std::size_t>(-offset));
}

bool StackPtrValue::exact() const noexcept
{
	return candidates_.count() == 1;
}

bool StackPtrValue::contains(int offset) const noexcept
{
	if (offset < -MAX_BPF_STACK || offset > 0)
		return false;
	return candidates_.test(static_cast<std::size_t>(-offset));
}

std::optional<int> StackPtrValue::exactOffset() const noexcept
{
	if (!exact())
		return std::nullopt;
	for (std::size_t i = 0; i < candidates_.size(); ++i) {
		if (candidates_.test(i))
			return -static_cast<int>(i);
	}
	return std::nullopt;
}

std::vector<int> StackPtrValue::offsets() const
{
	std::vector<int> result;
	for (std::size_t i = 0; i < candidates_.size(); ++i) {
		if (candidates_.test(i))
			result.push_back(-static_cast<int>(i));
	}
	return result;
}

StackPtrValue StackPtrValue::add(const IntValue &offset) const
{
	StackPtrValue result(-MAX_BPF_STACK - 1);
	for (int base : offsets()) {
		for (const auto &range : offset.ranges()) {
			if (range.lo != range.hi)
				continue;
			const int next = base + static_cast<int64_t>(range.lo);
			if (next >= -MAX_BPF_STACK && next <= 0)
				result.candidates_.set(static_cast<std::size_t>(-next));
		}
	}
	return result.candidates_.none() ? StackPtrValue(-MAX_BPF_STACK - 1) :
					   result;
}

StackPtrValue StackPtrValue::sub(const IntValue &offset) const
{
	std::vector<IntInterval> negated;
	for (const auto &range : offset.ranges()) {
		if (range.lo == range.hi)
			negated.push_back({ static_cast<uint64_t>(-range.lo),
					    static_cast<uint64_t>(-range.lo) });
	}
	return add(IntValue(std::move(negated)));
}

PDValueKind kindOf(const PDValue &value) noexcept
{
	if (std::holds_alternative<std::monostate>(value))
		return PDValueKind::Unknown;
	if (std::holds_alternative<IntValue>(value))
		return PDValueKind::Int;
	if (std::holds_alternative<StackPtrValue>(value))
		return PDValueKind::StackPtr;
	if (std::holds_alternative<MapPtrValue>(value))
		return PDValueKind::MapPtr;
	if (std::holds_alternative<MapValuePtr>(value))
		return PDValueKind::MapValuePtr;
	return PDValueKind::Unknown;
}

bool exactValue(const PDValue &value) noexcept
{
	if (const auto *intValue = std::get_if<IntValue>(&value))
		return intValue->exact();
	if (const auto *stackPtr = std::get_if<StackPtrValue>(&value))
		return stackPtr->exact();
	return std::holds_alternative<MapPtrValue>(value);
}

PDGraph buildPDG(const std::vector<ebpf_inst> &instructions)
{
	return Builder(instructions).run();
}

std::vector<uint16_t> partitionPDG(const PDGraph &graph, uint16_t maxPartitionSize)
{
	std::vector<uint16_t> cuts;
	if (maxPartitionSize == 0 || graph.empty())
		return cuts;

	std::vector<std::vector<uint16_t> > undirected(graph.size());
	for (uint16_t src = 0; src < graph.size(); ++src) {
		for (const auto &edge : graph[src]) {
			if (edge.dst >= graph.size())
				continue;
			undirected[src].push_back(edge.dst);
			undirected[edge.dst].push_back(src);
		}
	}

	std::vector<uint8_t> removed(graph.size(), 0);
	while (true) {
		std::vector<uint8_t> visited(graph.size(), 0);
		std::vector<uint16_t> worstComponent;

		for (uint16_t start = 0; start < graph.size(); ++start) {
			if (removed[start] || visited[start])
				continue;
			std::vector<uint16_t> component;
			std::deque<uint16_t> queue{ start };
			visited[start] = 1;
			while (!queue.empty()) {
				const auto node = queue.front();
				queue.pop_front();
				component.push_back(node);
				for (auto next : undirected[node]) {
					if (!removed[next] && !visited[next]) {
						visited[next] = 1;
						queue.push_back(next);
					}
				}
			}
			if (component.size() > worstComponent.size())
				worstComponent = std::move(component);
		}

		if (worstComponent.size() <= maxPartitionSize)
			break;

		std::set<uint16_t> componentSet(worstComponent.begin(),
						worstComponent.end());
		uint16_t best = worstComponent.front();
		std::size_t bestDegree = 0;
		for (auto node : worstComponent) {
			std::size_t degree = 0;
			for (auto next : undirected[node]) {
				if (componentSet.contains(next))
					++degree;
			}
			if (degree > bestDegree) {
				bestDegree = degree;
				best = node;
			}
		}
		removed[best] = 1;
		cuts.push_back(best);
	}

	std::sort(cuts.begin(), cuts.end());
	return cuts;
}
