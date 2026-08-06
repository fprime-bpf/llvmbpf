#include <efg.hpp>

#include <fpu_inst.h>

#include <algorithm>
#include <cassert>
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
// A call to an external function never touches the call stack, the data
// stack or r10 (see "../src/compiler.cpp": emitExtFuncCall only reads r1-r5
// and stores the result into r0). It is assumed to write the heap unless
// it's listed in `regOnlyExtFuncs`. Local calls and EXIT move r10 and the
// call stack but write neither data stack nor heap contents; that r10
// change is recorded by markModified() instead.
MemWrite memWriteOf(const ebpf_inst &inst,
		    const std::unordered_set<int32_t> &regOnlyExtFuncs)
{
	if (!duo_is_fpu(inst) && isCall(inst) && !isLocalCall(inst)) {
		const bool regOnly = regOnlyExtFuncs.find(inst.imm) !=
				     regOnlyExtFuncs.end();
		return MemWrite{ false, !regOnly };
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

std::unordered_map<uint16_t, CompInfo>
partition(const G_t G, const std::vector<ebpf_inst> &instructions,
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
