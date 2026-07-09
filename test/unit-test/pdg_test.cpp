#include <catch2/catch_test_macros.hpp>

#include <pdg.hpp>

namespace
{

ebpf_inst makeInst(uint8_t opcode, uint8_t dst = 0, uint8_t src = 0,
		   int16_t offset = 0, int32_t imm = 0)
{
	return ebpf_inst{ opcode, dst, src, offset, imm };
}

bool hasEdge(const PDGraph &graph, uint16_t src, uint16_t dst)
{
	if (src >= graph.size())
		return false;
	for (const auto &edge : graph[src]) {
		if (edge.dst == dst)
			return true;
	}
	return false;
}

} // namespace

TEST_CASE("PDG merges register writers at branch joins")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_JNE_IMM, 0, 0, 2, 0),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 2),
		makeInst(EBPF_OP_JA, 0, 0, 1, 0),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 3),
		makeInst(EBPF_OP_ADD64_REG, 3, 2),
	};

	const auto graph = buildPDG(instructions);

	REQUIRE(hasEdge(graph, 2, 5));
	REQUIRE(hasEdge(graph, 4, 5));
}

TEST_CASE("PDG ignores instructions unreachable after unconditional jumps")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_JA, 0, 0, 1, 0),
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 2),
		makeInst(EBPF_OP_MOV64_REG, 0, 1),
	};

	const auto graph = buildPDG(instructions);

	REQUIRE(hasEdge(graph, 0, 3));
	REQUIRE_FALSE(hasEdge(graph, 2, 3));
}


TEST_CASE("PDG refines register states after conditional jumps")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 3),
		makeInst(EBPF_OP_JGT_IMM, 1, 0, 2, 5),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 1),
		makeInst(EBPF_OP_JA, 0, 0, 1, 0),
		makeInst(EBPF_OP_MOV64_IMM, 2, 0, 0, 2),
		makeInst(EBPF_OP_MOV64_REG, 0, 2),
	};

	const auto graph = buildPDG(instructions);

	REQUIRE(hasEdge(graph, 2, 5));
	REQUIRE_FALSE(hasEdge(graph, 4, 5));
}

TEST_CASE("PDG follows local eBPF calls and returns from local exits")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_CALL, 0, 1, 0, 2),
		makeInst(EBPF_OP_MOV64_REG, 2, 0),
		makeInst(EBPF_OP_EXIT),
		makeInst(EBPF_OP_MOV64_REG, 0, 1),
		makeInst(EBPF_OP_EXIT),
	};

	const auto graph = buildPDG(instructions);

	REQUIRE(hasEdge(graph, 0, 4));
	REQUIRE(hasEdge(graph, 4, 5));
	REQUIRE(hasEdge(graph, 5, 2));
	REQUIRE_FALSE(hasEdge(graph, 1, 2));
}

TEST_CASE("PDG preserves local call return sites independently")
{
	std::vector<ebpf_inst> instructions{
		makeInst(EBPF_OP_MOV64_IMM, 1, 0, 0, 1),
		makeInst(EBPF_OP_CALL, 0, 1, 0, 4),
		makeInst(EBPF_OP_MOV64_REG, 2, 0),
		makeInst(EBPF_OP_CALL, 0, 1, 0, 2),
		makeInst(EBPF_OP_MOV64_REG, 3, 0),
		makeInst(EBPF_OP_EXIT),
		makeInst(EBPF_OP_MOV64_REG, 0, 1),
		makeInst(EBPF_OP_EXIT),
	};

	const auto graph = buildPDG(instructions);

	REQUIRE(hasEdge(graph, 7, 2));
	REQUIRE(hasEdge(graph, 7, 4));
}
