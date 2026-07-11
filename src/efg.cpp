#include <efg.hpp>

#include <fpu_inst.h>

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <set>
#include <unordered_map>
#include <unordered_set>
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

// Whether `inst` accesses memory (type M). Everything else is register-only
// (type R). LD/LDX/ST/STX (including atomics and the second slot of LDDW)
// and FPU FLDX/FST/FSTX always touch memory. A CALL to an external function
// touches memory unless it's listed in `regOnlyExtFuncs`; local calls and
// EXIT are pure control flow and don't access memory themselves (the
// instructions they jump to are classified independently).
bool isMemInst(const ebpf_inst &inst,
	       const std::unordered_set<int32_t> &regOnlyExtFuncs)
{
	if (duo_is_fpu(inst)) {
		const auto cls = duo_class(inst);
		return cls == FLDX || cls == FST || cls == FSTX;
	}

	if (isCall(inst) && !isLocalCall(inst))
		return regOnlyExtFuncs.find(inst.imm) == regOnlyExtFuncs.end();

	const auto cls = inst.opcode & EBPF_CLS_MASK;
	return cls == EBPF_CLS_LD || cls == EBPF_CLS_LDX ||
	       cls == EBPF_CLS_ST || cls == EBPF_CLS_STX;
}

// An edge of G with its direction preserved (a = src, b = dst), used by
// partition() to know which side is end(e) for a given useSrc.
struct UEdge {
	uint16_t a, b;
};

// Simple union-find over instruction indices, used to compute weakly
// connected components of the (edges treated as bidirectional) graph.
class UnionFind {
    public:
	explicit UnionFind(uint16_t n) : parent(n)
	{
		std::iota(parent.begin(), parent.end(), uint16_t{ 0 });
	}

	uint16_t find(uint16_t x)
	{
		while (parent[x] != x) {
			parent[x] = parent[parent[x]];
			x = parent[x];
		}
		return x;
	}

	void unite(uint16_t a, uint16_t b)
	{
		a = find(a);
		b = find(b);
		if (a != b)
			parent[a] = b;
	}

    private:
	std::vector<uint16_t> parent;
};

} // namespace

std::unique_ptr<G_t> buildEFG(const std::vector<ebpf_inst> &instructions)
{
	const uint16_t n = static_cast<uint16_t>(instructions.size());
	std::unique_ptr<G_t> G = std::make_unique<G_t>(n);

	for (uint16_t i = 0; i < n; ++i) {
		const ebpf_inst &cur = instructions[i];

		if (isExit(cur)) {
			// Resolved below via call-stack-aware traversal:
			// entry-function exits terminate (no edge), local
			// function exits return to their call site.
			continue;
		}

		if (isLocalCall(cur)) {
			G[i].push_back(Edge{ callTarget(i, cur), Uncond });
		} else if (isCall(cur)) {
			// External function call: falls through to the next
			// instruction once the helper returns.
			G[i].push_back(Edge{ static_cast<uint16_t>(i + 1), Exit });
		} else if (isCondJump(cur)) {
			G[i].push_back(Edge{ jumpTarget(i, cur), Cond1 });
			G[i].push_back(Edge{ static_cast<uint16_t>(i + 1), Cond0 });
		} else if (isJa(cur)) {
			G[i].push_back(Edge{ jumpTarget(i, cur), Uncond });
		} else {
			// Everything else (ALU, LD/LDX/ST/STX, atomics, the
			// second slot of LDDW, FPU ALU/LD/ST, ...) simply
			// falls through.
			if (i + 1 < n)
				G[i].push_back(Edge{ static_cast<uint16_t>(i + 1), Normal });
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
				G[pc].push_back(Edge{ ret, Uncond });
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

			for (const Edge &e : G[pc])
				stack.push_back({ e.dst, callStack });
		}
	}

	return G;
}

namespace
{

// Computes the size of every weakly connected component reachable through
// edges not in `cut`, and returns the size of the largest one.
uint16_t largestComponentSize(uint16_t n, const std::vector<UEdge> &edges,
			      const std::unordered_set<std::size_t> &cutEdgeIdx)
{
	UnionFind uf(n);
	for (std::size_t i = 0; i < edges.size(); ++i) {
		if (cutEdgeIdx.count(i))
			continue;
		uf.unite(edges[i].a, edges[i].b);
	}
	std::unordered_map<uint16_t, uint16_t> size;
	uint16_t best = 0;
	for (uint16_t i = 0; i < n; ++i) {
		uint16_t s = ++size[uf.find(i)];
		best = std::max(best, s);
	}
	return best;
}

} // namespace

std::unordered_map<uint16_t, bool>
partition(const G_t G, const std::vector<ebpf_inst> &instructions,
	  uint16_t maxSize, bool useSrc,
	  const std::unordered_set<int32_t> &regOnlyExtFuncs) noexcept
{
	const uint16_t n = static_cast<uint16_t>(instructions.size());
	std::unordered_map<uint16_t, bool> B;
	if (n == 0 || maxSize == 0)
		return B;

	// Flatten to an undirected edge list, ignoring self-loops (can't
	// occur here, but be defensive).
	std::vector<UEdge> edges;
	for (uint16_t i = 0; i < n; ++i) {
		for (const Edge &e : G[i]) {
			if (e.dst == i)
				continue;
			edges.push_back(UEdge{ i, e.dst });
		}
	}

	std::vector<bool> isMem(n);
	for (uint16_t i = 0; i < n; ++i)
		isMem[i] = isMemInst(instructions[i], regOnlyExtFuncs);

	// end(e) per the useSrc parameter.
	auto endOf = [&](const UEdge &e) { return useSrc ? e.a : e.b; };

	// Group all edges by their end(e) node: since B only grows by one
	// entry no matter how many edges share the same end(e), cutting a
	// full "end-group" at once is always at least as good for |B| as
	// cutting a subset of it, so candidates are entire end-groups
	// rather than individual edges.
	std::unordered_map<uint16_t, std::vector<std::size_t> > byEnd;
	for (std::size_t i = 0; i < edges.size(); ++i)
		byEnd[endOf(edges[i])].push_back(i);

	// Greedily grow E_1 (E_2 here, since we don't try to strictly
	// minimize beyond this heuristic): repeatedly cut the single
	// end(e)-group that reduces the largest remaining weakly connected
	// component the most, until every component is within maxSize.
	// Goal 1 (minimize |B|) is primary: each round adds exactly one
	// node to B regardless of how many edges that node's group
	// contains, so this never spends more than one B-entry per
	// meaningful reduction in the oversized component. Goal 2 (regOnly
	// grouping) only breaks ties among end-groups that reduce the
	// largest component by the same amount, preferring the one that
	// separates the most memory/register-only boundary.
	std::unordered_set<std::size_t> cutEdgeIdx;
	std::unordered_set<uint16_t> cutEnds;

	while (largestComponentSize(n, edges, cutEdgeIdx) > maxSize) {
		uint16_t bestEnd = UINT16_MAX;
		uint16_t bestResultingMax = UINT16_MAX;
		int bestTypeBoundaryScore = -1;

		for (const auto &[end, idxs] : byEnd) {
			if (cutEnds.count(end))
				continue; // already cut, no further benefit

			std::unordered_set<std::size_t> trial = cutEdgeIdx;
			int typeBoundaryScore = 0;
			for (std::size_t idx : idxs) {
				trial.insert(idx);
				const UEdge &e = edges[idx];
				if (isMem[e.a] != isMem[e.b])
					++typeBoundaryScore;
			}

			uint16_t resultingMax =
				largestComponentSize(n, edges, trial);

			if (resultingMax < bestResultingMax ||
			    (resultingMax == bestResultingMax &&
			     typeBoundaryScore > bestTypeBoundaryScore)) {
				bestEnd = end;
				bestResultingMax = resultingMax;
				bestTypeBoundaryScore = typeBoundaryScore;
			}
		}

		if (bestEnd == UINT16_MAX)
			break; // no candidate helps further; avoid infinite loop

		for (std::size_t idx : byEnd[bestEnd])
			cutEdgeIdx.insert(idx);
		cutEnds.insert(bestEnd);
	}

	if (cutEdgeIdx.empty())
		return B;

	// Determine each remaining group's regOnly status from the final
	// (post-cut) weak components.
	UnionFind uf(n);
	for (std::size_t i = 0; i < edges.size(); ++i) {
		if (!cutEdgeIdx.count(i))
			uf.unite(edges[i].a, edges[i].b);
	}
	std::unordered_map<uint16_t, bool> compRegOnly;
	for (uint16_t i = 0; i < n; ++i) {
		uint16_t root = uf.find(i);
		auto it = compRegOnly.find(root);
		if (it == compRegOnly.end())
			compRegOnly[root] = !isMem[i];
		else if (isMem[i])
			it->second = false;
	}

	for (std::size_t idx : cutEdgeIdx) {
		uint16_t end = endOf(edges[idx]);
		B[end] = compRegOnly[uf.find(end)];
	}

	return B;
}
