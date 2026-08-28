#include <efg.hpp>

#include <fpu_inst.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <limits>
#include <numeric>
#include <queue>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>
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

// LDDW is the only 16-byte eBPF instruction: it occupies two consecutive
// slots, the second of which holds the upper 32 bits of the immediate and is
// not an instruction at all. Its raw bytes must never be decoded as an
// opcode, and control flow steps over it.
bool isLddw(const ebpf_inst &inst)
{
	return !duo_is_fpu(inst) && inst.opcode == EBPF_OP_LDDW;
}

// Marks the slots that are the second half of an LDDW. Indexing this by pc
// tells whether instructions[pc] is a real instruction or a payload word.
std::vector<bool> lddwPayloadSlots(const std::vector<ebpf_inst> &instructions)
{
	std::vector<bool> payload(instructions.size(), false);
	for (std::size_t i = 0; i < instructions.size(); ++i) {
		if (payload[i])
			continue;
		if (isLddw(instructions[i]) && i + 1 < instructions.size())
			payload[i + 1] = true;
	}
	return payload;
}

// Whether `inst` is an atomic (STX with the atomic mode) that also writes a
// register. Plain atomic add/or/and/xor only touch memory, but the fetching
// variants additionally deliver the old value into a register: XCHG and the
// _FETCH forms write `src`, while CMPXCHG writes r0.
bool isAtomic(const ebpf_inst &inst)
{
	if (duo_is_fpu(inst))
		return false;
	return (inst.opcode & EBPF_CLS_MASK) == EBPF_CLS_STX &&
	       (inst.opcode & EBPF_MODE_ATOMIC) == EBPF_MODE_ATOMIC;
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

// What memory an instruction writes to. These are the S and H of
// `type(v)\subseteq{R,S,H}`: a store whose base register can't be resolved
// sets both.
struct MemWrite {
	bool stack = false;
	bool heap = false;
};

// Whether `inst` writes to memory through a base register, and if so which
// register holds the base address. Only *writes* matter here: the snapshot
// records modified state, so loads (LDX/FLDX/LDDW) read memory but don't
// dirty it.
//
// ST/STX (including atomics) store to `dst + offset`; FPU FST/FSTX likewise
// store to `dst + offset`.
bool isMemStore(const ebpf_inst &inst, uint8_t &baseReg)
{
	if (duo_is_fpu(inst)) {
		const auto cls = duo_class(inst);
		if (cls == FST || cls == FSTX) {
			baseReg = inst.dst;
			return true;
		}
		return false;
	}

	const auto cls = inst.opcode & EBPF_CLS_MASK;
	if (cls == EBPF_CLS_ST || cls == EBPF_CLS_STX) {
		baseReg = inst.dst;
		return true;
	}
	return false;
}

// Syntactic classification of a store's base register into data stack / heap.
//
// r10 is the data stack pointer, so a store based on it writes the data stack
// only. Any other base is unresolved: assume it writes both. (Stores relative
// to the initial value of r1 write the heap only, but recognising them needs
// dataflow that isn't implemented yet, so they land in the conservative case.)
MemWrite classifyBase(uint8_t baseReg)
{
	if (baseReg == 10)
		return MemWrite{ true, false };
	return MemWrite{ true, true };
}

// Which memory regions `inst` writes to.
//
// A call to an external function never touches the call stack or r10 (see
// "../src/compiler.cpp": emitExtFuncCall only reads r1-r5 and stores the
// result into r0). It is assumed to write the data stack unless it's listed
// in `regOnlyExtFuncs`. Local calls and EXIT move r10 and the call stack but
// write neither data stack nor heap contents; that r10 change is recorded by
// markModified() instead.
MemWrite memWriteOf(const ebpf_inst &inst,
		    const std::unordered_set<int32_t> &regOnlyExtFuncs)
{
	if (!duo_is_fpu(inst) && isCall(inst) && !isLocalCall(inst)) {
		const bool regOnly = regOnlyExtFuncs.find(inst.imm) !=
				     regOnlyExtFuncs.end();
		return MemWrite{ !regOnly, false };
	}

	uint8_t baseReg = 0;
	if (!isMemStore(inst, baseReg))
		return MemWrite{};
	return classifyBase(baseReg);
}

// An edge of G with its direction preserved (a = src, b = dst), used by
// partition() to know which side is end(e) for a given useSrc.
struct UEdge {
	uint16_t a, b;
};

// Bit layout of CompInfo::modified: r0-r10, then fpu0-fpu10, then the two
// memory flags.
constexpr std::size_t NORM_REG_BASE = 0;
constexpr std::size_t FPU_REG_BASE = NORM_REG_BASE + 11;
constexpr std::size_t USED_HEAP_BIT = FPU_REG_BASE + 11;
constexpr std::size_t USED_STACK_BIT = USED_HEAP_BIT + 1;

// Marks the registers (if any) that `inst` writes to in `info`.
//
// Calls to external functions only set r0. Calls to and exits from local
// functions move the data stack pointer (r10 -= / += frameSize, see
// "../src/compiler.cpp") and push/pop the call stack, so both are recorded
// as modifying r10 -- per efg.hpp, a change to r10 also means the call
// stack changed. A local function's EXIT additionally restores the
// callee-saved registers r6-r9 from the call stack.
//
// Stores (ST/STX/FST/FSTX) and conditional jumps write no register.
void markModified(const ebpf_inst &inst,
		  const std::unordered_set<int32_t> &regOnlyExtFuncs,
		  CompInfo &info)
{
	if (duo_is_fpu(inst)) {
		const auto cls = duo_class(inst);
		if (cls == FALU || cls == FLDX) {
			if (inst.dst <= 10)
				info.modified[FPU_REG_BASE + inst.dst] = true;
		}
		return;
	}

	if (isExit(inst)) {
		// Returning from a local function pops the call stack, moves
		// r10 back up and restores r6-r9. An entry-function EXIT just
		// ends the program; treating it the same way is harmless
		// because nothing observes state after it.
		info.modified[NORM_REG_BASE + 10] = true;
		for (uint8_t r = 6; r <= 9; r++)
			info.modified[NORM_REG_BASE + r] = true;
		return;
	}

	if (isCall(inst)) {
		if (isLocalCall(inst))
			info.modified[NORM_REG_BASE + 10] = true;
		else
			info.modified[NORM_REG_BASE + 0] = true;
		return;
	}

	if (isJmpClass(inst)) // conditional jumps write no register
		return;

	// Atomics hand the pre-operation value back in a register, matching
	// how "../src/compiler.cpp" emits them: CMPXCHG writes r0, while the
	// _FETCH variants of add/and/or/xor write `src`. XCHG is emitted with
	// is_fetch=false there, so it writes memory only, as do the plain
	// (non-fetching) arithmetic atomics.
	if (isAtomic(inst)) {
		if (inst.imm == EBPF_ATOMIC_OP_CMPXCHG) {
			info.modified[NORM_REG_BASE + 0] = true;
			return;
		}
		if (inst.imm == EBPF_ATOMIC_OP_XCHG)
			return;
		if ((inst.imm & EBPF_ATOMIC_OP_FETCH) && inst.src <= 10)
			info.modified[NORM_REG_BASE + inst.src] = true;
		return;
	}

	const auto cls = inst.opcode & EBPF_CLS_MASK;
	if (cls == EBPF_CLS_ST || cls == EBPF_CLS_STX)
		return;

	// ALU/ALU64/LD(LDDW)/LDX all write `dst`.
	if (inst.dst <= 10)
		info.modified[NORM_REG_BASE + inst.dst] = true;
}

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
	const std::vector<bool> payload = lddwPayloadSlots(instructions);

	// Index of the instruction following the one at `pc`, stepping over
	// the payload slot of an LDDW.
	auto nextPc = [&](uint16_t pc) {
		uint16_t next = static_cast<uint16_t>(pc + 1);
		if (next < n && payload[next])
			++next;
		return next;
	};

	for (uint16_t i = 0; i < n; ++i) {
		if (payload[i])
			continue; // upper half of an LDDW: not an instruction

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
			G[i].push_back(Edge{ nextPc(i), Exit });
		} else if (isCondJump(cur)) {
			G[i].push_back(Edge{ jumpTarget(i, cur), Cond1 });
			G[i].push_back(Edge{ nextPc(i), Cond0 });
		} else if (isJa(cur)) {
			G[i].push_back(Edge{ jumpTarget(i, cur), Uncond });
		} else {
			// Everything else (ALU, LD/LDX/ST/STX, atomics, FPU
			// ALU/LD/ST, ...) simply falls through. For an LDDW,
			// nextPc() steps over its payload slot.
			if (nextPc(i) < n)
				G[i].push_back(Edge{ nextPc(i), Normal });
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
				nextCallStack.push_back(nextPc(pc));
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

// Result of evaluating a candidate cut set: the two quantities the spec's
// optimization goals are expressed in terms of.
struct CutQuality {
	uint16_t largest = 0; // |v(P_m)|, the constraint being satisfied
	uint16_t memFree = 0; // sum of memFree(w) over components, goal 2
};

// Builds the weak components of `P=(G,E-cut)` and measures them.
//
// `payload` marks LDDW upper-half slots; they are not instructions, so they
// neither count toward a component's size nor make it non-memory-free.
CutQuality evaluateCut(uint16_t n, const std::vector<UEdge> &edges,
		       const std::unordered_set<std::size_t> &cutEdgeIdx,
		       const std::vector<bool> &payload,
		       const std::vector<bool> &touchesMem)
{
	UnionFind uf(n);
	for (std::size_t i = 0; i < edges.size(); ++i) {
		if (cutEdgeIdx.count(i))
			continue;
		uf.unite(edges[i].a, edges[i].b);
	}
	std::unordered_map<uint16_t, uint16_t> size;
	std::unordered_map<uint16_t, bool> dirty;
	for (uint16_t i = 0; i < n; ++i) {
		if (payload[i])
			continue;
		uint16_t root = uf.find(i);
		++size[root];
		if (touchesMem[i])
			dirty[root] = true;
	}
	CutQuality q;
	for (const auto &[root, s] : size) {
		q.largest = std::max(q.largest, s);
		if (!dirty[root])
			++q.memFree;
	}
	return q;
}

} // namespace
/*
## Complexity

  Define:

  - (n=|V|)
  - (m=|E|)
  - (k=|{end(e):e\in E}|), the number of endpoint groups, where
    [
    k\leq\min(n,m)
    ]

  - (r\leq k), the number of groups ultimately selected.

  Assume average-case (O(1)) operations for unordered_map and unordered_set.

  ### One evaluateCut

  Union-find processes all edges and vertices:

  [
  O((m+n)\alpha(n)),
  ]

  where (\alpha(n)) is the inverse Ackermann function and is effectively constant.

  In conventional simplified notation:

  [
  O(m+n).
  ]

  ### Greedy search

  At round (i), approximately (k-i) candidates remain. Each candidate:

  - copies a cut-edge set of up to (m) entries;
  - evaluates all (m) edges and (n) vertices.

  Thus each candidate costs:

  [
  O(m+n).
  ]

  Over (r) rounds:

  # [
  O\left((m+n)\sum_{i=0}^{r-1}(k-i)\right)

  O\left((m+n)\left(rk-\frac{r(r-1)}2\right)\right).
  ]

  Therefore:

  [
  \boxed{O(rk(m+n))}
  ]

  and in the worst case (r=k):

  [
  \boxed{O(k^2(m+n))}.
  ]

  Since (k\le n), a bound using only EFG vertices and edges is:

  [
  \boxed{O(n^2(m+n))}.
  ]

  For a typical EFG with bounded out-degree, (m=O(n)), so the worst case simplifies to:

  [
  \boxed{O(n^3)}.
  ]

  Preprocessing and final metadata construction are only (O(m+n)), so the repeated candidate evaluation dominates.*/
std::unordered_map<uint16_t, CompInfo>
partition1(const G_t G, const std::vector<ebpf_inst> &instructions,
	  uint16_t maxSize, bool useSrc,
	  const std::unordered_set<int32_t> &regOnlyExtFuncs) noexcept
{
	const uint16_t n = static_cast<uint16_t>(instructions.size());
	std::unordered_map<uint16_t, CompInfo> B;
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

	// Per-instruction memory-write classification (the S/H of type(v)).
	// An LDDW's payload slot is not an instruction, so it writes nothing.
	const std::vector<bool> payload = lddwPayloadSlots(instructions);
	std::vector<MemWrite> memWrite(n);
	std::vector<bool> touchesMem(n);
	for (uint16_t i = 0; i < n; ++i) {
		if (payload[i])
			continue;
		memWrite[i] = memWriteOf(instructions[i], regOnlyExtFuncs);
		touchesMem[i] = memWrite[i].stack || memWrite[i].heap;
	}

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

	// Greedily grow the cut set until the size constraint holds. Each
	// round commits exactly one whole end(e)-group, so |B| equals the
	// number of rounds: spending as few rounds as possible *is* goal 1
	// (minimize |B|), and it is served by preferring, at every step, the
	// group that shrinks the largest component the most -- the fewest
	// such steps get under maxSize.
	//
	// Goal 2 (maximize the number of memory-free components) is strictly
	// subordinate, so it only ever breaks ties between candidates whose
	// resulting largest component is equal, i.e. between candidates that
	// are indistinguishable for goal 1. Among those we take the cut
	// yielding the most components that write neither the data stack nor
	// the heap; memFree is measured on the whole trial partition rather
	// than counting edge endpoints, so it matches the spec's definition
	// directly.
	//
	// This is a heuristic: the exact problem is NP, and the header only
	// asks for a good-enough E_2 satisfying the constraint.
	std::unordered_set<std::size_t> cutEdgeIdx;
	std::unordered_set<uint16_t> cutEnds;

	while (evaluateCut(n, edges, cutEdgeIdx, payload, touchesMem).largest >
	       maxSize) {
		uint16_t bestEnd = UINT16_MAX;
		CutQuality best{ UINT16_MAX, 0 };

		for (const auto &[end, idxs] : byEnd) {
			if (cutEnds.count(end))
				continue; // already cut, no further benefit

			std::unordered_set<std::size_t> trial = cutEdgeIdx;
			for (std::size_t idx : idxs)
				trial.insert(idx);

			const CutQuality q = evaluateCut(n, edges, trial,
							 payload, touchesMem);

			// Goal 1 first (a smaller largest component reaches
			// the constraint in fewer rounds, i.e. a smaller |B|),
			// then goal 2 as the tie-break.
			if (q.largest < best.largest ||
			    (q.largest == best.largest &&
			     q.memFree > best.memFree)) {
				bestEnd = end;
				best = q;
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

	// Determine each remaining group's modified-register set and its
	// usedHeap/usedStack flags from the final (post-cut) weak components.
	// Both flags are unions over the component: a component uses the heap
	// iff any of its instructions writes the heap, and likewise for the
	// data stack.
	UnionFind uf(n);
	for (std::size_t i = 0; i < edges.size(); ++i) {
		if (!cutEdgeIdx.count(i))
			uf.unite(edges[i].a, edges[i].b);
	}
	std::unordered_map<uint16_t, CompInfo> compInfo;
	for (uint16_t i = 0; i < n; ++i) {
		if (payload[i])
			continue; // upper half of an LDDW: not an instruction
		uint16_t root = uf.find(i);
		CompInfo &info = compInfo[root];

		markModified(instructions[i], regOnlyExtFuncs, info);
		if (memWrite[i].heap)
			info.modified[USED_HEAP_BIT] = true;
		if (memWrite[i].stack)
			info.modified[USED_STACK_BIT] = true;
	}

	for (std::size_t idx : cutEdgeIdx) {
		uint16_t end = endOf(edges[idx]);
		B[end] = compInfo[uf.find(end)];
	}

	return B;
}

std::unordered_map<uint16_t, CompInfo>
partition2(const G_t G, const std::vector<ebpf_inst> &instructions,
	   const std::unordered_set<int32_t> &regOnlyExtFuncs) noexcept
{
	const uint16_t n = static_cast<uint16_t>(instructions.size());
	std::unordered_map<uint16_t, CompInfo> B;
	if (n == 0)
		return B;

	const std::vector<bool> payload = lddwPayloadSlots(instructions);
	std::vector<bool> isBoundary(n, false);
	std::vector<bool> snapshotBefore(n, false);
	for (uint16_t pc = 0; pc < n; ++pc) {
		if (payload[pc])
			continue;

		const ebpf_inst &inst = instructions[pc];
		if (isCondJump(inst)) {
			// compiler.cpp emits a conditional-branch snapshot before
			// evaluating the branch.
			isBoundary[pc] = true;
			snapshotBefore[pc] = true;
		} else if (isJa(inst) || isExit(inst) || isLocalCall(inst)) {
			// These control transfers are likewise snapshotted before their
			// state-changing operation (if any).
			isBoundary[pc] = true;
			snapshotBefore[pc] = true;
		} else if (isCall(inst)) {
			// An external helper call is snapshotted after it returns, so
			// its outgoing edge, rather than its incoming edge, is cut.
			isBoundary[pc] = true;
		}
	}

	std::vector<UEdge> edges;
	std::vector<bool> cut;
	for (uint16_t src = 0; src < n; ++src) {
		if (payload[src])
			continue;
		for (const Edge &edge : G[src]) {
			if (edge.dst >= n || payload[edge.dst] || edge.dst == src)
				continue;
			edges.push_back(UEdge{ src, edge.dst });
			cut.push_back((snapshotBefore[edge.dst] &&
				       isBoundary[edge.dst]) ||
				      (!snapshotBefore[src] && isBoundary[src]));
		}
	}

	// Components model the state accumulated between snapshots.
	UnionFind components(n);
	for (std::size_t i = 0; i < edges.size(); ++i) {
		if (!cut[i])
			components.unite(edges[i].a, edges[i].b);
	}

	std::vector<MemWrite> memWrite(n);
	std::unordered_map<uint16_t, CompInfo> compInfo;
	for (uint16_t pc = 0; pc < n; ++pc) {
		if (payload[pc])
			continue;
		CompInfo &info = compInfo[components.find(pc)];
		memWrite[pc] = memWriteOf(instructions[pc], regOnlyExtFuncs);
		markModified(instructions[pc], regOnlyExtFuncs, info);
		if (memWrite[pc].heap)
			info.modified[USED_HEAP_BIT] = true;
		if (memWrite[pc].stack)
			info.modified[USED_STACK_BIT] = true;
	}

	for (uint16_t pc = 0; pc < n; ++pc) {
		if (!isBoundary[pc])
			continue;

		if (!snapshotBefore[pc]) {
			// External calls snapshot after the call, so the component
			// containing the call has exactly the state to save.
			B.emplace(pc, compInfo[components.find(pc)]);
			continue;
		}

		// A before-instruction snapshot must contain changes made on every
		// predecessor path.  Incoming edges were cut above, so combine the
		// metadata of each predecessor component rather than that of `pc`'s
		// following component.
		CompInfo info;
		for (std::size_t i = 0; i < edges.size(); ++i) {
			if (cut[i] && edges[i].b == pc)
				info.modified |=
					compInfo[components.find(edges[i].a)].modified;
		}
		B.emplace(pc, info);
	}

	return B;
}

std::unordered_map<uint16_t, CompInfo>
partition(const G_t G, const std::vector<ebpf_inst> &instructions,
	  uint16_t maxSize, bool useSrc,
	  const std::unordered_set<int32_t> &regOnlyExtFuncs) noexcept
{
	const uint16_t n = static_cast<uint16_t>(instructions.size());
	std::unordered_map<uint16_t, CompInfo> B;
	if (n == 0 || maxSize == 0)
		return B;

	const std::vector<bool> payload = lddwPayloadSlots(instructions);
	std::vector<UEdge> edges;
	std::vector<std::vector<uint16_t> > adjacency(n);
	for (uint16_t src = 0; src < n; ++src) {
		for (const Edge &edge : G[src]) {
			if (edge.dst == src)
				continue;
			edges.push_back(UEdge{ src, edge.dst });
			adjacency[src].push_back(edge.dst);
			adjacency[edge.dst].push_back(src);
		}
	}

	// Give nearby vertices in a weak-component traversal the same region.
	// Each region contains at most maxSize real instructions. Cutting every
	// edge that crosses a region boundary therefore guarantees the hard size
	// limit; cutting a whole endpoint group can only split regions further.
	//
	// Unlike partition1's repeated global trial cuts, this visits every vertex
	// and edge only a constant number of times.
	constexpr uint16_t noRegion = UINT16_MAX;
	std::vector<uint16_t> region(n, noRegion);
	std::vector<bool> seen(n, false);
	std::vector<uint16_t> stack;
	uint16_t nextRegion = 0;
	for (uint16_t start = 0; start < n; ++start) {
		if (payload[start] || seen[start])
			continue;

		stack.push_back(start);
		seen[start] = true;
		uint16_t regionSize = 0;
		while (!stack.empty()) {
			const uint16_t node = stack.back();
			stack.pop_back();

			if (regionSize == maxSize) {
				++nextRegion;
				regionSize = 0;
			}
			region[node] = nextRegion;
			++regionSize;

			for (uint16_t neighbour : adjacency[node]) {
				if (!payload[neighbour] && !seen[neighbour]) {
					seen[neighbour] = true;
					stack.push_back(neighbour);
				}
			}
		}
		++nextRegion;
	}

	auto endOf = [&](const UEdge &edge) {
		return useSrc ? edge.a : edge.b;
	};
	std::unordered_set<uint16_t> cutEnds;
	for (const UEdge &edge : edges) {
		if (region[edge.a] != region[edge.b])
			cutEnds.insert(endOf(edge));
	}
	if (cutEnds.empty())
		return B;

	// Rebuild the actual components after applying endpoint-group cuts. An
	// endpoint in B removes every edge in its group, including same-region
	// edges that were not part of the initial traversal split.
	UnionFind components(n);
	for (const UEdge &edge : edges) {
		if (!cutEnds.count(endOf(edge)))
			components.unite(edge.a, edge.b);
	}

	std::vector<MemWrite> memWrite(n);
	std::unordered_map<uint16_t, CompInfo> compInfo;
	for (uint16_t i = 0; i < n; ++i) {
		if (payload[i])
			continue;
		const uint16_t root = components.find(i);
		CompInfo &info = compInfo[root];
		memWrite[i] = memWriteOf(instructions[i], regOnlyExtFuncs);
		markModified(instructions[i], regOnlyExtFuncs, info);
		if (memWrite[i].heap)
			info.modified[USED_HEAP_BIT] = true;
		if (memWrite[i].stack)
			info.modified[USED_STACK_BIT] = true;
	}

	for (uint16_t end : cutEnds)
		B[end] = compInfo[components.find(end)];

	return B;
}

bool CompInfo::fpuRegModified(uint8_t i)const{
	assert(i<=10);
	return modified[FPU_REG_BASE+i];
}
bool CompInfo::normRegModified(uint8_t i)const{
	assert(i<=10);//r0-r10; r10 also implies the call stack changed
	return modified[NORM_REG_BASE+i];
}
bool CompInfo::usedHeap()const noexcept{
	return modified[USED_HEAP_BIT];
}
bool CompInfo::usedStack()const noexcept{
	return modified[USED_STACK_BIT];
}

namespace
{

// compileWithSS snapshots control transfers before executing them. Ordinary
// instructions and external helper calls are snapshotted after they execute.
// Consequently a before-snapshot removes incoming EFG edges, while an
// after-snapshot removes outgoing edges.
bool snapshotBefore(const ebpf_inst &inst)
{
	return isCondJump(inst) || isJa(inst) || isExit(inst) ||
	       isLocalCall(inst);
}

struct DirectedEdge {
	uint16_t src;
	uint16_t dst;
};

struct TrailState {
	uint16_t node;
	uint64_t used;

	bool operator==(const TrailState &) const = default;
};

struct TrailStateHash {
	std::size_t operator()(const TrailState &state) const noexcept
	{
		const std::size_t h1 = std::hash<uint64_t>{}(state.used);
		const std::size_t h2 = std::hash<uint16_t>{}(state.node);
		return h1 ^ (h2 + 0x9e3779b9U + (h1 << 6) + (h1 >> 2));
	}
};

struct CompressedEdge {
	uint16_t dst;
	uint32_t length;
	std::size_t id;
};

// Find the exact longest internal trail from `start` to every compressed
// vertex. Vertices may repeat, but compressed edges may not. For at most 64
// edges, memoising (vertex, used-edge-set) avoids evaluating the same exact
// residual problem more than once. Larger components use the same exhaustive
// search without memoisation; there is deliberately no heuristic cutoff.
std::vector<uint32_t> longestCompressedTrails(
	const std::vector<std::vector<CompressedEdge> > &adjacency,
	std::size_t edgeCount, uint16_t start,
	const std::vector<bool> &boundaryVertex)
{
	std::vector<uint32_t> best(adjacency.size(), 0);
	std::vector<bool> reached(adjacency.size(), false);
	std::vector<bool> used(edgeCount, false);
	const bool useMask = edgeCount <= 64;
	std::unordered_set<TrailState, TrailStateHash> seen;
	if (useMask)
		seen.insert(TrailState{ start, 0 });

	struct Frame {
		uint16_t node;
		std::size_t next;
		uint32_t length;
		std::size_t incoming;
		uint64_t mask;
	};
	constexpr std::size_t noEdge = std::numeric_limits<std::size_t>::max();
	std::vector<Frame> stack;
	stack.push_back(Frame{ start, 0, 0, noEdge, 0 });
	reached[start] = true;

	while (!stack.empty()) {
		Frame &frame = stack.back();
		// A boundary may start a fresh trail, but once a trail reaches any
		// boundary (including returning to its start), that boundary is its
		// endpoint and the trail must not continue through it.
		const bool reachedBoundary =
			boundaryVertex[frame.node] && frame.length != 0;
		if (reachedBoundary || frame.next == adjacency[frame.node].size()) {
			const std::size_t incoming = frame.incoming;
			stack.pop_back();
			if (incoming != noEdge)
				used[incoming] = false;
			continue;
		}

		const CompressedEdge edge = adjacency[frame.node][frame.next++];
		if (used[edge.id])
			continue;

		const uint64_t nextMask =
			useMask ? frame.mask | (uint64_t{ 1 } << edge.id) : 0;
		if (useMask &&
		    !seen.insert(TrailState{ edge.dst, nextMask }).second)
			continue;

		used[edge.id] = true;
		const uint32_t nextLength = frame.length + edge.length;
		reached[edge.dst] = true;
		best[edge.dst] = std::max(best[edge.dst], nextLength);
		stack.push_back(
			Frame{ edge.dst, 0, nextLength, edge.id, nextMask });
	}

	// UINT32_MAX denotes an unreachable target. Zero remains a valid exact
	// answer for start-to-start, including when the two boundary vertices are
	// the same.
	for (std::size_t i = 0; i < best.size(); ++i) {
		if (!reached[i])
			best[i] = UINT32_MAX;
	}
	return best;
}

// Exact longest boundary-to-boundary trail in the original EFG. Only vertices
// and edges that can lie on a structural entry-to-terminal-EXIT execution are
// admitted, and a trail stops at the first boundary it reaches. This is the
// strongest property the EFG can establish without solving data-dependent
// branch conditions.
uint32_t exactLongestTrail(
	uint16_t n, const G_t G, const std::vector<ebpf_inst> &instructions,
	const std::vector<bool> &payload,
	const std::unordered_map<uint16_t, CompInfo> &boundary)
{
	if (n == 0 || boundary.empty())
		return 0;

	// First identify the part of the original (uncut) EFG that belongs to
	// some entry-to-terminal-exit walk.
	std::vector<std::vector<uint16_t> > originalAdj(n), originalReverse(n);
	for (uint16_t src = 0; src < n; ++src) {
		if (payload[src])
			continue;
		for (const Edge &edge : G[src]) {
			if (edge.dst >= n || payload[edge.dst])
				continue;
			originalAdj[src].push_back(edge.dst);
			originalReverse[edge.dst].push_back(src);
		}
	}

	std::vector<bool> reachable(n, false), reachesExit(n, false);
	std::vector<uint16_t> work;
	if (!payload[0]) {
		reachable[0] = true;
		work.push_back(0);
	}
	while (!work.empty()) {
		const uint16_t node = work.back();
		work.pop_back();
		for (uint16_t dst : originalAdj[node]) {
			if (!reachable[dst]) {
				reachable[dst] = true;
				work.push_back(dst);
			}
		}
	}

	for (uint16_t pc = 0; pc < n; ++pc) {
		if (!payload[pc] && isExit(instructions[pc]) &&
		    originalAdj[pc].empty()) {
			reachesExit[pc] = true;
			work.push_back(pc);
		}
	}
	while (!work.empty()) {
		const uint16_t node = work.back();
		work.pop_back();
		for (uint16_t src : originalReverse[node]) {
			if (!reachesExit[src]) {
				reachesExit[src] = true;
				work.push_back(src);
			}
		}
	}

	std::vector<bool> live(n, false);
	for (uint16_t pc = 0; pc < n; ++pc)
		live[pc] = reachable[pc] && reachesExit[pc] && !payload[pc];

	std::vector<std::vector<uint16_t> > adjacency(n), reverse(n);
	std::vector<DirectedEdge> liveEdges;
	for (uint16_t src = 0; src < n; ++src) {
		if (!live[src])
			continue;
		for (uint16_t dst : originalAdj[src]) {
			if (!live[dst])
				continue;
			adjacency[src].push_back(dst);
			reverse[dst].push_back(src);
			liveEdges.push_back(DirectedEdge{ src, dst });
		}
	}

	// Kosaraju's algorithm, written iteratively so a 65K-instruction linear
	// program cannot overflow the native call stack.
	std::vector<bool> visited(n, false);
	std::vector<uint16_t> finishOrder;
	struct DfsFrame {
		uint16_t node;
		std::size_t next;
	};
	for (uint16_t start = 0; start < n; ++start) {
		if (!live[start] || visited[start])
			continue;
		std::vector<DfsFrame> dfs;
		visited[start] = true;
		dfs.push_back(DfsFrame{ start, 0 });
		while (!dfs.empty()) {
			DfsFrame &frame = dfs.back();
			if (frame.next < adjacency[frame.node].size()) {
				const uint16_t dst =
					adjacency[frame.node][frame.next++];
				if (!visited[dst]) {
					visited[dst] = true;
					dfs.push_back(DfsFrame{ dst, 0 });
				}
			} else {
				finishOrder.push_back(frame.node);
				dfs.pop_back();
			}
		}
	}

	constexpr uint16_t noComponent = UINT16_MAX;
	std::vector<uint16_t> component(n, noComponent);
	uint16_t componentCount = 0;
	for (auto it = finishOrder.rbegin(); it != finishOrder.rend(); ++it) {
		const uint16_t start = *it;
		if (component[start] != noComponent)
			continue;
		component[start] = componentCount;
		work.push_back(start);
		while (!work.empty()) {
			const uint16_t node = work.back();
			work.pop_back();
			for (uint16_t src : reverse[node]) {
				if (component[src] == noComponent) {
					component[src] = componentCount;
					work.push_back(src);
				}
			}
		}
		++componentCount;
	}

	std::vector<std::vector<uint16_t> > members(componentCount);
	std::vector<std::vector<DirectedEdge> > internalAdj(n);
	std::vector<uint32_t> internalIn(n, 0);
	std::vector<std::vector<DirectedEdge> > crossOut(n);
	std::vector<std::vector<uint16_t> > componentOut(componentCount);
	std::vector<uint32_t> indegree(componentCount, 0);
	std::vector<bool> possibleEntry(n, false), possibleExit(n, false);
	for (uint16_t pc = 0; pc < n; ++pc) {
		if (live[pc])
			members[component[pc]].push_back(pc);
		if (live[pc] && boundary.contains(pc)) {
			possibleEntry[pc] = true;
			possibleExit[pc] = true;
		}
	}
	for (const DirectedEdge &edge : liveEdges) {
		if (component[edge.src] == component[edge.dst]) {
			internalAdj[edge.src].push_back(edge);
			++internalIn[edge.dst];
		} else {
			crossOut[edge.src].push_back(edge);
			componentOut[component[edge.src]].push_back(
				component[edge.dst]);
			++indegree[component[edge.dst]];
			possibleExit[edge.src] = true;
			possibleEntry[edge.dst] = true;
		}
	}

	std::queue<uint16_t> ready;
	for (uint16_t c = 0; c < componentCount; ++c) {
		if (indegree[c] == 0)
			ready.push(c);
	}

	constexpr int64_t unreachable = -1;
	std::vector<int64_t> arrival(n, unreachable);
	std::vector<bool> critical(n, false);
	std::vector<uint16_t> criticalIndex(n, UINT16_MAX);
	uint32_t answer = 0;
	for (const auto &[pc, info] : boundary) {
		(void)info;
		if (pc < n && live[pc]) {
			arrival[pc] = 0;
			// The endpoints may be the same, so the empty trail counts.
			answer = 0;
		}
	}

	while (!ready.empty()) {
		const uint16_t c = ready.front();
		ready.pop();

		bool hasArrival = false;
		for (uint16_t node : members[c])
			hasArrival = hasArrival || arrival[node] != unreachable;

		if (hasArrival) {
			// Collapse every forced 1-in/1-out chain into one weighted edge.
			// Ports and branch/join vertices stay explicit, which preserves
			// every possible trail endpoint and every edge-use choice.
			std::vector<uint16_t> criticalNodes;
			for (uint16_t node : members[c]) {
				critical[node] = possibleEntry[node] ||
						 possibleExit[node] ||
						 internalIn[node] != 1 ||
						 internalAdj[node].size() != 1;
				if (critical[node])
					criticalNodes.push_back(node);
			}

			// A processed component has an arrival port, hence at least one
			// critical vertex even when the SCC itself is a simple cycle.
			assert(!criticalNodes.empty());
			for (uint16_t i = 0; i < criticalNodes.size(); ++i)
				criticalIndex[criticalNodes[i]] = i;

			std::vector<std::vector<CompressedEdge> > compressed(
				criticalNodes.size());
			std::vector<bool> compressedBoundary(criticalNodes.size(), false);
			std::size_t compressedEdgeCount = 0;
			for (uint16_t node : criticalNodes) {
				compressedBoundary[criticalIndex[node]] =
					boundary.contains(node);
				for (const DirectedEdge &first : internalAdj[node]) {
					uint16_t dst = first.dst;
					uint32_t length = 1;
					while (!critical[dst]) {
						assert(internalAdj[dst].size() == 1);
						dst = internalAdj[dst][0].dst;
						++length;
					}
					compressed[criticalIndex[node]].push_back(
						CompressedEdge{ criticalIndex[dst], length,
								compressedEdgeCount++ });
				}
			}

			for (uint16_t start : criticalNodes) {
				if (arrival[start] == unreachable)
					continue;
				const auto distances = longestCompressedTrails(
					compressed, compressedEdgeCount,
					criticalIndex[start], compressedBoundary);
				for (uint16_t exit : criticalNodes) {
					const uint32_t distance =
						distances[criticalIndex[exit]];
					if (distance == UINT32_MAX)
						continue;
					const uint64_t score =
						static_cast<uint64_t>(arrival[start]) +
						distance;
					assert(score <= UINT32_MAX);
					if (boundary.contains(exit))
						answer = std::max(
							answer,
							static_cast<uint32_t>(score));
					const bool endpoint = boundary.contains(exit) &&
						!(exit == start && distance == 0);
					if (endpoint)
						continue;
					for (const DirectedEdge &edge : crossOut[exit]) {
						const int64_t next =
							static_cast<int64_t>(score + 1);
						if (boundary.contains(edge.dst)) {
							answer = std::max(answer,
								static_cast<uint32_t>(next));
						} else {
							arrival[edge.dst] =
								std::max(arrival[edge.dst], next);
						}
					}
				}
			}
		}

		for (uint16_t dst : componentOut[c]) {
			assert(indegree[dst] > 0);
			if (--indegree[dst] == 0)
				ready.push(dst);
		}
	}

	return answer;
}

double interpolatedQuantile(const std::vector<uint16_t> &sorted, double p)
{
	if (sorted.empty())
		return 0.0;
	const double position = p * static_cast<double>(sorted.size() - 1);
	const std::size_t lower = static_cast<std::size_t>(position);
	const std::size_t upper = std::min(lower + 1, sorted.size() - 1);
	const double fraction = position - static_cast<double>(lower);
	return static_cast<double>(sorted[lower]) * (1.0 - fraction) +
	       static_cast<double>(sorted[upper]) * fraction;
}

} // namespace
EFGStat metrics(const G_t G, const std::vector<ebpf_inst> &instructions,
		const std::unordered_map<uint16_t, CompInfo> &boundary) noexcept
{
	EFGStat stat{};
	{
		const uint16_t n = static_cast<uint16_t>(instructions.size());
		if (n == 0)
			return stat;
		const std::vector<bool> payload = lddwPayloadSlots(instructions);
		std::vector<DirectedEdge> remainingEdges;
		UnionFind components(n);
		for (uint16_t src = 0; src < n; ++src) {
			if (payload[src])
				continue;
			for (const Edge &edge : G[src]) {
				if (edge.dst >= n || payload[edge.dst])
					continue;
				const bool cutIncoming =
					boundary.contains(edge.dst) &&
					snapshotBefore(instructions[edge.dst]);
				const bool cutOutgoing = boundary.contains(src) &&
						 !snapshotBefore(instructions[src]);
				if (cutIncoming || cutOutgoing)
					continue;
				remainingEdges.push_back(DirectedEdge{ src, edge.dst });
				components.unite(src, edge.dst);
			}
		}

		std::unordered_map<uint16_t, uint16_t> componentSizes;
		for (uint16_t pc = 0; pc < n; ++pc) {
			if (!payload[pc])
				++componentSizes[components.find(pc)];
		}
		std::vector<uint16_t> sizes;
		sizes.reserve(componentSizes.size());
		for (const auto &[root, size] : componentSizes) {
			(void)root;
			sizes.push_back(size);
		}
		std::sort(sizes.begin(), sizes.end());
		if (!sizes.empty()) {
			stat.minCompSize = sizes.front();
			stat.maxCompSize = sizes.back();
			stat.compSizeIQR[0] = interpolatedQuantile(sizes, 0.25);
			stat.compSizeIQR[1] = interpolatedQuantile(sizes, 0.50);
			stat.compSizeIQR[2] = interpolatedQuantile(sizes, 0.75);

			const double sum = std::accumulate(
				sizes.begin(), sizes.end(), 0.0);
			const double mean = sum / static_cast<double>(sizes.size());
			double squaredDeviation = 0.0;
			for (uint16_t size : sizes) {
				const double delta = static_cast<double>(size) - mean;
				squaredDeviation += delta * delta;
			}
			stat.meanCompSize = static_cast<float>(mean);
			stat.compSizeStdDev = static_cast<float>(std::sqrt(
				squaredDeviation / static_cast<double>(sizes.size())));
		}

		stat.longestTrailBetweenBoundary = exactLongestTrail(
			n, G, instructions, payload, boundary);
	}
	return stat;
}

std::string EFGStat::toString() const noexcept
{
	try {
		char buffer[512];
		const int written = std::snprintf(
			buffer, sizeof(buffer),
			"EFGStat{componentSize={min=%u, q1=%.6g, median=%.6g, "
			"q3=%.6g, max=%u, mean=%.6g, populationStdDev=%.6g}, "
			"longestTrailBetweenBoundary=%u}",
			static_cast<unsigned>(minCompSize), compSizeIQR[0],
			compSizeIQR[1], compSizeIQR[2],
			static_cast<unsigned>(maxCompSize),
			static_cast<double>(meanCompSize),
			static_cast<double>(compSizeStdDev),
			static_cast<unsigned>(longestTrailBetweenBoundary));
		if (written < 0)
			return {};
		return std::string(buffer,
				   std::min<std::size_t>(written, sizeof(buffer) - 1));
	} catch (...) {
		return {};
	}
}
std::unordered_set<uint16_t> findExits(const G_t g,const std::vector<ebpf_inst>& insts) noexcept{
	std::unordered_set<uint16_t> a;
	for (uint16_t pc = 0; pc < insts.size(); ++pc) 
		if (insts[pc].opcode == EBPF_OP_EXIT && g[pc].empty())
			a.insert(pc);
	return a;
}