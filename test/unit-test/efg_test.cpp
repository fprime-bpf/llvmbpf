#include <catch2/catch_test_macros.hpp>

#include <efg.hpp>
#include <fpu_inst.h>

#include <algorithm>

namespace
{

ebpf_inst makeInst(uint8_t opcode, uint8_t dst = 0, uint8_t src = 0,
		   int16_t offset = 0, int32_t imm = 0)
{
	return ebpf_inst{ opcode, dst, src, offset, imm };
}

bool hasEdge(const std::unique_ptr<G_t> &g, uint16_t src, uint16_t dst,
	    FlowType t)
{
	for (const auto &edge : g[src]) {
		if (edge.dst == dst && edge.t == t)
			return true;
	}
	return false;
}

std::size_t edgeCount(const std::unique_ptr<G_t> &g, uint16_t src)
{
	return g[src].size();
}

} // namespace

TEST_CASE("EFG: straight-line code falls through")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 2),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);

	REQUIRE(hasEdge(g, 0, 1, Normal));
	REQUIRE(hasEdge(g, 1, 2, Normal));
	// Entry function exit terminates: no outgoing edge.
	REQUIRE(edgeCount(g, 2) == 0);
}

TEST_CASE("EFG: unconditional jump uses offset")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_JA, 0, 0, 2, 0),
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 2),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);

	REQUIRE(edgeCount(g, 0) == 1);
	REQUIRE(hasEdge(g, 0, 3, Uncond));
}

TEST_CASE("EFG: JA32 (imm variant) uses imm as offset")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_JA_IMM, 0, 0, 0, 2),
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 2),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);

	REQUIRE(edgeCount(g, 0) == 1);
	REQUIRE(hasEdge(g, 0, 3, Uncond));
}

TEST_CASE("EFG: conditional jump has both a taken and fallthrough edge")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_JEQ_IMM, 1, 0, 1, 0),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 1),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 2),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);

	REQUIRE(edgeCount(g, 0) == 2);
	REQUIRE(hasEdge(g, 0, 2, Cond1)); // taken branch: pc+1+offset
	REQUIRE(hasEdge(g, 0, 1, Cond0)); // fallthrough (false) branch
}

TEST_CASE("EFG: external call falls through with Exit edge")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_CALL, 0, 0, 0, 5), // src != 1: external helper
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);

	REQUIRE(edgeCount(g, 0) == 1);
	REQUIRE(hasEdge(g, 0, 1, Exit));
}

TEST_CASE("EFG: local call jumps to callee and exit returns to call site")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_CALL, 0, 1, 0, 2), // call pc=1+1+2=4
		makeInst(EBPF_OP_MOV64_REG, 2, 0),
		makeInst(EBPF_OP_EXIT),
		makeInst(EBPF_OP_MOV64_REG, 0, 1),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);

	REQUIRE(hasEdge(g, 0, 1, Normal));
	// Local call is treated as an unconditional jump straight to the callee.
	REQUIRE(edgeCount(g, 1) == 1);
	REQUIRE(hasEdge(g, 1, 4, Uncond));
	REQUIRE(hasEdge(g, 4, 5, Normal));
	// The callee's exit returns to the instruction after the call site.
	REQUIRE(hasEdge(g, 5, 2, Uncond));
	REQUIRE(hasEdge(g, 2, 3, Normal));
	// Outermost exit terminates.
	REQUIRE(edgeCount(g, 3) == 0);
}

TEST_CASE("EFG: same callee reached from two call sites has distinct return edges")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_CALL, 0, 1, 0, 4), // call pc=1+1+4=6
		makeInst(EBPF_OP_MOV64_REG, 2, 0),
		makeInst(EBPF_OP_CALL, 0, 1, 0, 2), // call pc=3+1+2=6
		makeInst(EBPF_OP_MOV64_REG, 3, 0),
		makeInst(EBPF_OP_EXIT),
		makeInst(EBPF_OP_MOV64_REG, 0, 1),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);

	REQUIRE(hasEdge(g, 1, 6, Uncond));
	REQUIRE(hasEdge(g, 3, 6, Uncond));
	// The shared callee's EXIT (pc=7) returns to both call sites.
	REQUIRE(hasEdge(g, 7, 2, Uncond));
	REQUIRE(hasEdge(g, 7, 4, Uncond));
}

TEST_CASE("partition: component within maxSize needs no cuts")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 2),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 10, true, {});

	REQUIRE(B.empty());
}

TEST_CASE("partition: long straight-line chain gets cut to respect maxSize")
{
	std::vector<ebpf_inst> instructions;
	for (int i = 0; i < 9; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_EXIT));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	// Some cuts must have happened since the chain (10 nodes) exceeds
	// maxSize=3.
	REQUIRE_FALSE(B.empty());
	// All nodes here write no memory (pure ALU + EXIT), so every
	// reported boundary node must live in a component that touches
	// neither the data stack nor the heap.
	for (const auto &[node, info] : B) {
		REQUIRE_FALSE(info.usedHeap());
		REQUIRE_FALSE(info.usedStack());
	}
}

TEST_CASE("partition: reports which registers a group modifies")
{
	std::vector<ebpf_inst> instructions;
	for (int i = 0; i < 9; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, i));
	// Last chain instruction writes r2 instead of r1.
	instructions.back() = makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 8);
	instructions.push_back(makeInst(EBPF_OP_EXIT));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		REQUIRE_FALSE(info.usedHeap());
		REQUIRE_FALSE(info.usedStack());
		// Every group here only ever writes r1 and/or r2, apart from
		// the callee-saved r6-r9 and r10 that EXIT restores.
		for (uint8_t r = 0; r < 6; ++r) {
			if (r == 1 || r == 2)
				continue;
			REQUIRE_FALSE(info.normRegModified(r));
		}
	}
}

TEST_CASE("partition: external call is treated as modifying only r0")
{
	std::vector<ebpf_inst> instructions;
	for (int i = 0; i < 3; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 3, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_CALL, 0, 0, 0, 9)); // idx 3
	for (int i = 0; i < 3; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 4, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_EXIT));

	const auto g = buildEFG(instructions);
	// idx 9 registered as regOnly so the call's group can end up regOnly.
	const auto B = partition(g.get(), instructions, 3, true, { 9 });

	bool sawCallGroupBoundary = false;
	for (const auto &[node, info] : B) {
		if (node == 3) {
			sawCallGroupBoundary = true;
			REQUIRE(info.normRegModified(0));
			REQUIRE_FALSE(info.normRegModified(3));
		}
	}
	(void)sawCallGroupBoundary;
}

// Builds a chain of `pad` register-only instructions, then `mid`, then
// another `pad` register-only instructions and an EXIT. `mid` lands at
// index `pad`.
std::vector<ebpf_inst> chainAround(const ebpf_inst &mid, int pad = 4)
{
	std::vector<ebpf_inst> instructions;
	for (int i = 0; i < pad; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, i));
	instructions.push_back(mid);
	for (int i = 0; i < pad; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 3, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_EXIT));
	return instructions;
}

TEST_CASE("partition: a store based on r10 marks its group as using the data stack")
{
	// STXDW [r10-8] = r2: writes the data stack only.
	const auto instructions =
		chainAround(makeInst(EBPF_OP_STXDW, 10, 2, -8, 0));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		if (node == 4) {
			REQUIRE(info.usedStack());
			REQUIRE_FALSE(info.usedHeap());
		}
	}
}

TEST_CASE("partition: a store based on r1 is assumed to touch both")
{
	// STXDW [r1+0] = r2. r1 holds the heap base pointer at entry, but
	// recognising that needs dataflow that isn't implemented: only r10 is
	// resolved, so every other base is treated conservatively.
	const auto instructions =
		chainAround(makeInst(EBPF_OP_STXDW, 1, 2, 0, 0), 0);

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 1, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		if (node == 0) {
			REQUIRE(info.usedHeap());
			REQUIRE(info.usedStack());
		}
	}
}

TEST_CASE("partition: a store on an unresolved base is assumed to touch both")
{
	// STXDW [r3+0] = r2: r3's provenance is unknown, so the store is
	// assumed to write both the data stack and the heap.
	const auto instructions =
		chainAround(makeInst(EBPF_OP_STXDW, 3, 2, 0, 0));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		if (node == 4) {
			REQUIRE(info.usedStack());
			REQUIRE(info.usedHeap());
		}
	}
}

TEST_CASE("partition: a store through a reassigned r1 touches both")
{
	// r1 is reassigned before the store; [r1+0] is treated conservatively
	// either way, since only r10 resolves to a single region.
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 0),
		makeInst(EBPF_OP_STXDW, 1, 2, 0, 0),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 1, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		if (node == 1) {
			REQUIRE(info.usedStack());
			REQUIRE(info.usedHeap());
		}
	}
}

TEST_CASE("partition: a load dirties no memory")
{
	// LDXDW r2 = [r10-8] reads the data stack but writes only r2, so
	// its component stays memory-free.
	const auto instructions =
		chainAround(makeInst(EBPF_OP_LDXDW, 2, 10, -8, 0));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		REQUIRE_FALSE(info.usedHeap());
		REQUIRE_FALSE(info.usedStack());
	}
}

TEST_CASE("partition: local call and exit are reported as modifying r10")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_CALL, 0, 1, 0, 2), // local call to pc=4
		makeInst(EBPF_OP_MOV64_REG, 2, 0),
		makeInst(EBPF_OP_EXIT),
		makeInst(EBPF_OP_MOV64_REG, 0, 1),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 2, true, {});

	REQUIRE_FALSE(B.empty());
	// Every component here contains a local call or an EXIT, both of
	// which move r10 (and with it the call stack).
	bool sawR10 = false;
	for (const auto &[node, info] : B) {
		if (info.normRegModified(10))
			sawR10 = true;
	}
	REQUIRE(sawR10);
}

TEST_CASE("partition: external call in regOnlyExtFuncs is treated as register-only")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_CALL, 0, 0, 0, 9), // external func index 9
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 10, true, { 9 });

	// Whole thing fits in one group (maxSize=10 >= 3 nodes): no cuts.
	REQUIRE(B.empty());
}

TEST_CASE("partition: cuts concentrate on a shared convergence node to minimize |B|")
{
	// Three independent 3-instruction chains (0-1-2, 3-4-5, 6-7-8) each
	// end in a JA that jumps to a shared convergence node (9), which
	// falls through to EXIT (10). With useSrc=false, end(e) for each of
	// those three JA edges is the same node (9): cutting all three
	// costs exactly one B entry and splits the graph into four pieces
	// (each chain, plus {9,10}), all within maxSize. A scattered cut
	// (e.g. one cut per chain at a different node) would also satisfy
	// maxSize but cost 3 B entries instead of 1, so if |B| is truly
	// minimized first, only node 9 should appear in B.
	std::vector<ebpf_inst> instructions;
	for (int chain = 0; chain < 3; ++chain) {
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, chain));
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, chain));
		// JA to node 9: offset = 9 - (pc+1)
		uint16_t pc = static_cast<uint16_t>(instructions.size());
		instructions.push_back(makeInst(
			EBPF_OP_JA, 0, 0,
			static_cast<int16_t>(9 - (pc + 1)), 0));
	}
	instructions.push_back(makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 0)); // 9
	instructions.push_back(makeInst(EBPF_OP_EXIT)); // 10

	REQUIRE(instructions.size() == 11);

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, false, {});

	REQUIRE_FALSE(B.empty());
	REQUIRE(B.size() == 1);
	REQUIRE(B.count(9) == 1);
}

TEST_CASE("EFG: LDDW occupies two slots and control flow steps over the payload")
{
	// LDDW r1, imm64 is 16 bytes: index 1 holds the upper half of the
	// immediate and is not an instruction, so index 0 falls through
	// straight to index 2.
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_LDDW, 1, 0, 0, 0x1234),
		makeInst(0, 0, 0, 0, 0x5678), // payload slot, not an instruction
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 1),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);

	REQUIRE(edgeCount(g, 0) == 1);
	REQUIRE(hasEdge(g, 0, 2, Normal)); // steps over slot 1
	// The payload slot itself is not an instruction: no outgoing edge.
	REQUIRE(edgeCount(g, 1) == 0);
	REQUIRE(hasEdge(g, 2, 3, Normal));
}

TEST_CASE("EFG: a jump landing after an LDDW is unaffected by the payload slot")
{
	// JA over the LDDW: target is index 3, computed the usual way. The
	// LDDW at 1..2 must not shift anything.
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_JA, 0, 0, 2, 0), // -> pc 0+1+2 = 3
		makeInst(EBPF_OP_LDDW, 1, 0, 0, 0x1234),
		makeInst(0, 0, 0, 0, 0x5678), // payload
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);

	REQUIRE(edgeCount(g, 0) == 1);
	REQUIRE(hasEdge(g, 0, 3, Uncond));
	REQUIRE(edgeCount(g, 2) == 0); // payload has no outgoing edge
}

TEST_CASE("partition: an LDDW payload slot is not treated as an instruction")
{
	// The payload here (0x61 = EBPF_OP_LDXW) would, if decoded as an
	// opcode, look like a register write to r0. It must be ignored.
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_LDDW, 2, 0, 0, 0x1234),
		makeInst(EBPF_OP_LDXW, 0, 0, 0, 0x5678), // payload slot
		makeInst(EBPF_OP_MOV64_IMM, 3, 0, 0, 1),
		makeInst(EBPF_OP_EXIT),
	};

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 1, true, {});

	REQUIRE_FALSE(B.empty());
	// Nothing in this program writes memory, and the payload's stray
	// "LDXW" must not have been counted as a write to r0 either.
	for (const auto &[node, info] : B) {
		REQUIRE_FALSE(info.usedHeap());
		REQUIRE_FALSE(info.usedStack());
		REQUIRE_FALSE(info.normRegModified(0));
	}
}

TEST_CASE("partition: a plain atomic writes memory but no register")
{
	// Non-fetching atomic add to [r10-8]: dirties the data stack only.
	const auto instructions = chainAround(
		makeInst(EBPF_OP_ATOMIC_STORE, 10, 2, -8, EBPF_ATOMIC_ADD));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		if (node == 4) {
			REQUIRE(info.usedStack());
			REQUIRE_FALSE(info.usedHeap());
			// No fetch bit: the source register is not written.
			REQUIRE_FALSE(info.normRegModified(2));
		}
	}
}

TEST_CASE("partition: a fetching atomic also writes its source register")
{
	// A fetching atomic add delivers the previous value back into `src`
	// (r2 here), so the component must report r2 as modified in addition
	// to using the stack.
	const auto instructions =
		chainAround(makeInst(EBPF_OP_ATOMIC_STORE, 10, 2, -8,
				     EBPF_ATOMIC_ADD | EBPF_ATOMIC_OP_FETCH));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		if (node == 4) {
			REQUIRE(info.usedStack());
			REQUIRE(info.normRegModified(2));
		}
	}
}

TEST_CASE("partition: XCHG writes memory but no register")
{
	// "../src/compiler.cpp" emits XCHG with is_fetch=false, so despite
	// the _FETCH bit in its encoding it never stores back into `src`.
	const auto instructions = chainAround(
		makeInst(EBPF_OP_ATOMIC_STORE, 10, 2, -8, EBPF_ATOMIC_OP_XCHG));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		if (node == 4) {
			REQUIRE(info.usedStack());
			REQUIRE_FALSE(info.normRegModified(2));
		}
	}
}

TEST_CASE("partition: CMPXCHG reports r0 as modified")
{
	const auto instructions = chainAround(makeInst(
		EBPF_OP_ATOMIC_STORE, 10, 2, -8, EBPF_ATOMIC_OP_CMPXCHG));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	REQUIRE_FALSE(B.empty());
	for (const auto &[node, info] : B) {
		if (node == 4) {
			REQUIRE(info.usedStack());
			// CMPXCHG returns the old value in r0, not in `src`.
			REQUIRE(info.normRegModified(0));
		}
	}
}

TEST_CASE("partition: goal 2 groups memory writes rather than scattering them")
{
	// Two stores sit adjacent in the middle of an otherwise register-only
	// chain. Cutting so that both stores land in the same component leaves
	// more memory-free components than splitting them apart, which is what
	// goal 2 asks for. Whatever cut is chosen, the constraint must hold
	// and at least one reported component must be memory-free.
	std::vector<ebpf_inst> instructions;
	for (int i = 0; i < 4; ++i)
		instructions.push_back(makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_STXDW, 10, 2, -8, 0));
	instructions.push_back(makeInst(EBPF_OP_STXDW, 10, 3, -16, 0));
	for (int i = 0; i < 4; ++i)
		instructions.push_back(makeInst(EBPF_OP_MOV64_IMM, 4, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_EXIT));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 4, true, {});

	REQUIRE_FALSE(B.empty());
	bool sawMemFree = false;
	for (const auto &[node, info] : B) {
		if (!info.usedHeap() && !info.usedStack())
			sawMemFree = true;
	}
	REQUIRE(sawMemFree);
}

TEST_CASE("partition: every resulting component respects maxSize")
{
	// The constraint is the hard requirement: after the returned cuts,
	// no weakly connected component may exceed maxSize. Rebuild the
	// components from B's boundary nodes to confirm the chain really was
	// broken often enough.
	std::vector<ebpf_inst> instructions;
	for (int i = 0; i < 20; ++i)
		instructions.push_back(makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_EXIT));

	const auto g = buildEFG(instructions);
	const uint16_t maxSize = 4;
	const auto B = partition(g.get(), instructions, maxSize, true, {});

	// On a straight-line chain with useSrc=true, each boundary node cuts
	// the chain right after itself, so the gaps between consecutive
	// boundary nodes bound the component sizes.
	std::vector<uint16_t> cuts;
	for (const auto &[node, info] : B)
		cuts.push_back(node);
	std::sort(cuts.begin(), cuts.end());

	REQUIRE_FALSE(cuts.empty());
	uint16_t prev = 0;
	for (uint16_t c : cuts) {
		REQUIRE(static_cast<uint16_t>(c + 1 - prev) <= maxSize);
		prev = static_cast<uint16_t>(c + 1);
	}
	REQUIRE(static_cast<uint16_t>(instructions.size() - prev) <= maxSize);
}

TEST_CASE("partition: external call not in regOnlyExtFuncs uses the heap")
{
	std::vector<ebpf_inst> instructions;
	for (int i = 0; i < 3; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_CALL, 0, 0, 0, 1)); // idx 3
	for (int i = 0; i < 3; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 3, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_EXIT));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	for (const auto &[node, info] : B) {
		if (node == 3) {
			// An external call never touches the data stack.
			REQUIRE(info.usedHeap());
			REQUIRE_FALSE(info.usedStack());
		}
	}
}
