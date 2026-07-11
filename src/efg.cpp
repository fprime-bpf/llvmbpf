#include <efg.hpp>

#include <fpu_inst.h>

#include <cstdint>
#include <set>
#include <vector>

namespace
{

bool isJmpClass(const ebpf_inst &inst)
{
	const auto cls = inst.opcode & EBPF_CLS_MASK;
	return cls == EBPF_CLS_JMP || cls == EBPF_CLS_JMP32;
}

bool isJa(const ebpf_inst &inst)
{
	return inst.opcode == EBPF_OP_JA || inst.opcode == EBPF_OP_JA_IMM;
}

bool isCall(const ebpf_inst &inst)
{
	return inst.opcode == EBPF_OP_CALL;
}

bool isExit(const ebpf_inst &inst)
{
	return inst.opcode == EBPF_OP_EXIT;
}

bool isLocalCall(const ebpf_inst &inst)
{
	return isCall(inst) && inst.src == 0x1;
}

// Whether `inst` is a conditional jump (integer or FPU). JA/CALL/EXIT are
// excluded even though they share the JMP/JMP32 instruction classes.
bool isCondJump(const ebpf_inst &inst)
{
	if (duo_is_fpu(inst))
		return duo_class(inst) == FJMP;
	if (!isJmpClass(inst))
		return false;
	return !isJa(inst) && !isCall(inst) && !isExit(inst);
}

// Target of a jump/local-call instruction. JMP32's JA uses `imm` as the
// offset, everything else (including FPU jumps) uses `offset`.
uint16_t jumpTarget(uint16_t pc, const ebpf_inst &inst)
{
	if (inst.opcode == EBPF_OP_JA_IMM)
		return static_cast<uint16_t>(pc + 1 + inst.imm);
	return static_cast<uint16_t>(pc + 1 + inst.offset);
}

uint16_t callTarget(uint16_t pc, const ebpf_inst &inst)
{
	return static_cast<uint16_t>(pc + 1 + inst.imm);
}

} // namespace

std::unique_ptr<G_t[]> buildEFG(const std::vector<ebpf_inst> &instructions)
{
	const uint16_t n = static_cast<uint16_t>(instructions.size());
	std::unique_ptr<G_t[]> G = std::make_unique<G_t[]>(n);
	for (uint16_t i = 0; i < n; ++i)
		G[i] = new std::vector<Edge>();

	for (uint16_t i = 0; i < n; ++i) {
		const ebpf_inst &cur = instructions[i];

		if (isExit(cur)) {
			// Resolved below via call-stack-aware traversal:
			// entry-function exits terminate (no edge), local
			// function exits return to their call site.
			continue;
		}

		if (isLocalCall(cur)) {
			G[i]->push_back(Edge{ callTarget(i, cur), Uncond });
		} else if (isCall(cur)) {
			// External function call: falls through to the next
			// instruction once the helper returns.
			G[i]->push_back(Edge{ static_cast<uint16_t>(i + 1), Exit });
		} else if (isCondJump(cur)) {
			G[i]->push_back(Edge{ jumpTarget(i, cur), Cond1 });
			G[i]->push_back(Edge{ static_cast<uint16_t>(i + 1), Cond0 });
		} else if (isJa(cur)) {
			G[i]->push_back(Edge{ jumpTarget(i, cur), Uncond });
		} else {
			// Everything else (ALU, LD/LDX/ST/STX, atomics, the
			// second slot of LDDW, FPU ALU/LD/ST, ...) simply
			// falls through.
			if (i + 1 < n)
				G[i]->push_back(Edge{ static_cast<uint16_t>(i + 1), Normal });
		}
	}

	// eBPF disallows recursion, so the local-call graph is a DAG: a
	// bounded DFS from the entry point, carrying the stack of pending
	// return addresses, reaches every EXIT once per distinct call
	// context and terminates.
	if (n > 0) {
		std::set<std::pair<uint16_t, std::vector<uint16_t> > > visited;
		std::vector<std::pair<uint16_t, std::vector<uint16_t> > > stack;
		stack.push_back({ 0, {} });

		while (!stack.empty()) {
			auto [pc, callStack] = std::move(stack.back());
			stack.pop_back();

			if (pc >= n)
				continue;
			auto key = std::make_pair(pc, callStack);
			if (!visited.insert(key).second)
				continue;

			const ebpf_inst &cur = instructions[pc];

			if (isExit(cur)) {
				if (callStack.empty())
					continue; // program termination, no outgoing edge
				uint16_t ret = callStack.back();
				auto nextCallStack = callStack;
				nextCallStack.pop_back();
				G[pc]->push_back(Edge{ ret, Uncond });
				stack.push_back({ ret, std::move(nextCallStack) });
				continue;
			}

			if (isLocalCall(cur)) {
				auto nextCallStack = callStack;
				nextCallStack.push_back(
					static_cast<uint16_t>(pc + 1));
				stack.push_back({ callTarget(pc, cur),
						   std::move(nextCallStack) });
				continue;
			}

			for (const Edge &e : *G[pc])
				stack.push_back({ e.dst, callStack });
		}
	}

	return G;
}
