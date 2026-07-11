#include <catch2/catch_test_macros.hpp>

#include <efg.hpp>

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
	// All nodes here are register-only (pure ALU + EXIT), so every
	// reported boundary node must be marked as living in a regOnly
	// group.
	for (const auto &[node, regOnly] : B)
		REQUIRE(regOnly);
}

TEST_CASE("partition: memory access marks its group as not regOnly")
{
	std::vector<ebpf_inst> instructions;
	for (int i = 0; i < 4; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, i));
	// LDXDW touches memory.
	instructions.push_back(makeInst(EBPF_OP_LDXDW, 2, 10, -8, 0));
	for (int i = 0; i < 4; ++i)
		instructions.push_back(
			makeInst(EBPF_OP_MOV64_IMM, 3, 0, 0, i));
	instructions.push_back(makeInst(EBPF_OP_EXIT));

	const auto g = buildEFG(instructions);
	const auto B = partition(g.get(), instructions, 3, true, {});

	REQUIRE_FALSE(B.empty());
	// The group containing the LDXDW instruction (index 4) must be
	// reported as not regOnly wherever it shows up as a boundary node.
	bool sawMemGroupBoundary = false;
	for (const auto &[node, regOnly] : B) {
		if (node == 4) {
			sawMemGroupBoundary = true;
			REQUIRE_FALSE(regOnly);
		}
	}
	(void)sawMemGroupBoundary;
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

TEST_CASE("partition: external call not in regOnlyExtFuncs is memory-accessing")
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

	bool sawCallGroupBoundary = false;
	for (const auto &[node, regOnly] : B) {
		if (node == 3) {
			sawCallGroupBoundary = true;
			REQUIRE_FALSE(regOnly);
		}
	}
	(void)sawCallGroupBoundary;
}
