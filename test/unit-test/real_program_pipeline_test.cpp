#include <catch2/catch_test_macros.hpp>

#include "efg.hpp"
#include "fpu_inst.h"
#include "llvmbpf.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <numeric>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{

constexpr bool useSrc = true;
constexpr uint8_t maxFuncNestDepth = 4;
constexpr uint16_t frameSize = 10000;

uint64_t unusedHelper(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	return 0;
}

class UnionFind {
    public:
	explicit UnionFind(std::size_t size) : parent(size)
	{
		std::iota(parent.begin(), parent.end(), std::size_t{ 0 });
	}

	std::size_t find(std::size_t node)
	{
		while (parent[node] != node) {
			parent[node] = parent[parent[node]];
			node = parent[node];
		}
		return node;
	}

	void unite(std::size_t lhs, std::size_t rhs)
	{
		lhs = find(lhs);
		rhs = find(rhs);
		if (lhs != rhs)
			parent[lhs] = rhs;
	}

    private:
	std::vector<std::size_t> parent;
};

std::vector<bool> lddwPayloadSlots(const std::vector<ebpf_inst> &instructions)
{
	std::vector<bool> payload(instructions.size(), false);
	for (std::size_t pc = 0; pc < instructions.size(); ++pc) {
		if (payload[pc])
			continue;
		if (!duo_is_fpu(instructions[pc]) &&
		    instructions[pc].opcode == EBPF_OP_LDDW &&
		    pc + 1 < instructions.size())
			payload[pc + 1] = true;
	}
	return payload;
}

std::size_t largestComponentAfterCuts(
	const G_t graph, const std::vector<ebpf_inst> &instructions,
	const std::unordered_map<uint16_t, CompInfo> &boundaries)
{
	UnionFind components(instructions.size());
	for (std::size_t src = 0; src < instructions.size(); ++src) {
		for (const Edge &edge : graph[src]) {
			const uint16_t end = useSrc ? static_cast<uint16_t>(src) :
						 edge.dst;
			if (!boundaries.contains(end))
				components.unite(src, edge.dst);
		}
	}

	const auto payload = lddwPayloadSlots(instructions);
	std::unordered_map<std::size_t, std::size_t> sizes;
	for (std::size_t pc = 0; pc < instructions.size(); ++pc) {
		if (!payload[pc])
			++sizes[components.find(pc)];
	}

	std::size_t largest = 0;
	for (const auto &[root, size] : sizes) {
		(void)root;
		largest = std::max(largest, size);
	}
	return largest;
}

std::vector<char> readProgram(const std::string &name)
{
	const std::string path = std::string(BPF_PRIME_TEST_PROGRAM_DIR) + "/" +
				 name + "/a.o";
	std::ifstream input(path, std::ios::binary);
	REQUIRE(input.is_open());
	return { std::istreambuf_iterator<char>(input),
		 std::istreambuf_iterator<char>() };
}

void registerReferencedHelpers(bpftime::llvmbpf_vm &vm)
{
	std::unordered_set<int32_t> helperIds;
	for (const ebpf_inst &instruction : vm.instructions) {
		if (instruction.opcode == EBPF_OP_CALL && instruction.src != 1)
			helperIds.insert(instruction.imm);
	}
	for (const int32_t id : helperIds) {
		REQUIRE(id >= 0);
		REQUIRE(vm.register_external_function(
				static_cast<std::size_t>(id),
				"pipeline_test_helper_" + std::to_string(id),
				reinterpret_cast<void *>(unusedHelper)) == 0);
	}
}

void testRealProgramPipeline(const std::string &name)
{
	const auto bytecode = readProgram(name);
	REQUIRE_FALSE(bytecode.empty());

	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(bytecode.data(), bytecode.size()) == 0);
	registerReferencedHelpers(vm);

	const auto graph = buildEFG(vm.instructions);
	REQUIRE(graph != nullptr);

	const uint16_t maxComponentSize = static_cast<uint16_t>(
		(vm.instructions.size() + 3 - 1) / 3);
	INFO("partitioning " << name);
	const auto boundaries = partition(graph.get(), vm.instructions,
					  maxComponentSize, useSrc, {});
	CAPTURE(name, vm.instructions.size(), maxComponentSize,
		boundaries.size());
	REQUIRE(largestComponentAfterCuts(graph.get(), vm.instructions,
					  boundaries) <= maxComponentSize);

	std::vector<std::byte> heap(50000);
	std::vector<std::byte> dataStack(
		static_cast<std::size_t>(maxFuncNestDepth) * frameSize);
	std::vector<std::byte> callStack(
		static_cast<std::size_t>(maxFuncNestDepth) * 5 * sizeof(void *));
	bpftime::ExecState snapshot{};
	snapshot.heap = heap.data();
	snapshot.dataStack = dataStack.data();
	snapshot.callStack = callStack.data();

	INFO("compiling " << name << " with snapshot support");
	const auto compiled = vm.compileWithSS(&snapshot, boundaries,
						maxFuncNestDepth, frameSize);
	INFO(vm.get_error_message());
	REQUIRE(compiled.has_value());
}
//This isn't a test, but a "benchmark" to let us understood how partitioning algorithms behave.
void compute(const std::string &name)
{
	const auto bytecode = readProgram(name);
	REQUIRE_FALSE(bytecode.empty());

	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(bytecode.data(), bytecode.size()) == 0);
	registerReferencedHelpers(vm);

	const auto graph = buildEFG(vm.instructions);
	REQUIRE(graph != nullptr);
	constexpr uint8_t parts=32;
	const uint16_t maxComponentSize = static_cast<uint16_t>(
		(vm.instructions.size() + parts - 1) / parts);
	INFO("partitioning " << name);
	auto boundaries = partition(graph.get(), vm.instructions,
				    maxComponentSize, useSrc, {});
	boundaries.emplace(0, CompInfo{});
	for (const auto& a:findExits(graph.get(),vm.instructions))
		boundaries.emplace(a,CompInfo{});
	const auto m = metrics(graph.get(), vm.instructions, boundaries);
	std::cout << name << ": " << m.toString() << '\n';
	CAPTURE(name, vm.instructions.size(), m);
}

#define REAL_PROGRAM_PIPELINE_TEST(program, tags)                              \
	TEST_CASE("Real eBPF pipeline: " program,                              \
		  "[real-program][buildEFG][partition][compileWithSS]" tags)     \
	{                                                                        \
		testRealProgramPipeline(program);                                  \
	}

REAL_PROGRAM_PIPELINE_TEST("aberr", "[.slow]")
REAL_PROGRAM_PIPELINE_TEST("aes", "[.slow]")
REAL_PROGRAM_PIPELINE_TEST("startracker", "[.slow]")

REAL_PROGRAM_PIPELINE_TEST("ccsds", "")
REAL_PROGRAM_PIPELINE_TEST("cfdp_chunk", "")
REAL_PROGRAM_PIPELINE_TEST("kalman", "")
REAL_PROGRAM_PIPELINE_TEST("low_pass_filter", "")
REAL_PROGRAM_PIPELINE_TEST("matmul", "")
REAL_PROGRAM_PIPELINE_TEST("nccscore", "")
REAL_PROGRAM_PIPELINE_TEST("noop", "")
REAL_PROGRAM_PIPELINE_TEST("reed_solomon", "")

#undef REAL_PROGRAM_PIPELINE_TEST

TEST_CASE("Real eBPF partition statistics", "[.][real-program][metrics]")
{
	for (const char *name : { "aberr", "aes", "startracker", "ccsds",
				  "cfdp_chunk", "kalman", "low_pass_filter",
				  "matmul", "nccscore", "noop", "reed_solomon" })
		compute(name);
}

} // namespace

//cmake --build build --target llvm_jit_tests -j && ./build/test/unit-test/llvm_jit_tests "Real eBPF partition statistics"