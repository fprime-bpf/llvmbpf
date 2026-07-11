#include <catch2/catch_test_macros.hpp>

#include <efg.hpp>

namespace
{

ebpf_inst makeInst(uint8_t opcode, uint8_t dst = 0, uint8_t src = 0,
		   int16_t offset = 0, int32_t imm = 0)
{
	return ebpf_inst{ opcode, dst, src, offset, imm };
}

bool hasEdge(const std::unique_ptr<G_t[]> &g, uint16_t src, uint16_t dst,
	    FlowType t)
{
	for (const auto &edge : *g[src]) {
		if (edge.dst == dst && edge.t == t)
			return true;
	}
	return false;
}

std::size_t edgeCount(const std::unique_ptr<G_t[]> &g, uint16_t src)
{
	return g[src]->size();
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
