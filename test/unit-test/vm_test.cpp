#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>
#include <iostream>
#include "llvmbpf.hpp"
#include "efg.hpp"

/*

int test()
{
	int a = 1;
	int b = 2;
	if (a + b > 2) {
		return 4;
	} else {
		return 5;
	}
}

0 mov r1, 0x1
1 stxw [r10-8], r1
2 mov r1, 0x2
3 stxw [r10-12], r1
4 ldxw r1, [r10-8]
5 ldxw r2, [r10-12]
6 add r1, r2
7 lsh r1, 0x20
8 arsh r1, 0x20
9 mov r2, 0x3
10 jsgt r2, r1, +4

11 ja +0

12 mov r1, 0x4
13 stxw [r10-4], r1
14 ja +3

15 mov r1, 0x5
16 stxw [r10-4], r1
17 ja +0

18 ldxw r0, [r10-4]
19 exit
20
*/

const unsigned char simple_cond_1[] =
	"\xb7\x01\x00\x00\x01\x00\x00\x00\x63\x1a\xf8\xff\x00\x00\x00\x00\xb7\x01\x00\x00\x02\x00\x00\x00\x63"
	"\x1a\xf4\xff\x00\x00\x00\x00\x61\xa1\xf8\xff\x00\x00\x00\x00\x61\xa2\xf4\xff\x00\x00\x00\x00\x0f\x21"
	"\x00\x00\x00\x00\x00\x00\x67\x01\x00\x00\x20\x00\x00\x00\xc7\x01\x00\x00\x20\x00\x00\x00\xb7\x02\x00"
	"\x00\x03\x00\x00\x00\x6d\x12\x04\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\xb7\x01\x00\x00"
	"\x04\x00\x00\x00\x63\x1a\xfc\xff\x00\x00\x00\x00\x05\x00\x03\x00\x00\x00\x00\x00\xb7\x01\x00\x00\x05"
	"\x00\x00\x00\x63\x1a\xfc\xff\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x61\xa0\xfc\xff\x00\x00"
	"\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00";

// Example test case for simple condition
TEST_CASE("Test simple cond")
{
	bpftime::llvmbpf_vm vm;

	SECTION("Execute without loading code")
	{
		vm.unload_code();
		uint64_t ret = 0;
		uint64_t mem = 0;

		REQUIRE(vm.exec(&mem, sizeof(mem), ret) != 0);
		REQUIRE(vm.get_error_message() == "No instructions provided");
	}

	REQUIRE(vm.load_code((const void *)simple_cond_1,
			     sizeof(simple_cond_1) - 1) == 0);

	SECTION("Load valid code and execute")
	{
		uint64_t ret = 0;
		uint64_t mem = 0;

		REQUIRE(vm.compile(1, 512));
		// compile double times
		REQUIRE(vm.compile(1, 512));

		REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
		REQUIRE(ret == 4);
	}

	SECTION("Load code with invalid length")
	{
		REQUIRE(vm.load_code((const void *)simple_cond_1,
				     sizeof(simple_cond_1) - 2) != 0);
		REQUIRE(vm.get_error_message() ==
			"Code len must be a multiple of 8");
	}

	SECTION("Execute unloading code")
	{
		vm.unload_code();
		uint64_t ret = 0;
		uint64_t mem = 0;

		REQUIRE(vm.exec(&mem, sizeof(mem), ret) != 0);
		REQUIRE(vm.get_error_message() == "No instructions provided");
	}
}

TEST_CASE("Test compileWithSS snapshots registers")
{
	bpftime::llvmbpf_vm vm;

	REQUIRE(vm.load_code((const void *)simple_cond_1,
			     sizeof(simple_cond_1) - 1) == 0);

	const auto g = buildEFG(vm.instructions);
	// maxSize=1 forces every instruction's boundary node into B, so we
	// get a snapshot point after essentially every register write.
	const auto instInfo =
		partition(g.get(), vm.instructions, 1, true, {});
	REQUIRE_FALSE(instInfo.empty());

	bpftime::ExecState state{};
	std::memset(&state, 0, sizeof(state));
	uint64_t mem = 0;
	uint64_t heapBuf = 0;
	uint8_t dataStackBuf[512] = {};
	uint8_t callStackBuf[5 * sizeof(void *)] = {};
	state.heap = reinterpret_cast<std::byte *>(&heapBuf);
	state.dataStack = reinterpret_cast<std::byte *>(dataStackBuf);
	state.callStack = reinterpret_cast<std::byte *>(callStackBuf);

	auto func = vm.compileWithSS(&state, instInfo, 1, 512);
	REQUIRE(func.has_value());

	uint64_t ret = 0;
	REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
	REQUIRE(ret == 4);

	// simple_cond_1 ends with `ldxw r0, [r10-4]; exit`, and that LDXW is
	// a plain register-modifying instruction, so with maxSize=1 it must
	// be a snapshot point: the buffer should reflect r0's final value.
	REQUIRE(state.normRegs[0] == 4);
}

TEST_CASE("Test compileWithSS1 executes directly in fixed state storage")
{
	// r0 = 7; r0 += 2; exit
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV64_IMM, BPF_REG_0, 0, 0, 7 },
		{ EBPF_OP_ADD64_IMM, BPF_REG_0, 0, 0, 2 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) ==
		0);

	constexpr uint16_t frameSize = 128;
	uint8_t heap[8] = {};
	uint8_t dataStack[frameSize] = {};
	uint8_t callStack[5 * sizeof(void *)] = {};
	bpftime::ExecState state{};
	state.heap = reinterpret_cast<std::byte *>(heap);
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);

	auto func = vm.compileWithSS1(&state, 1, frameSize, sizeof(heap));
	REQUIRE(func.has_value());
	REQUIRE((*func)(999, nullptr) == 9);
	REQUIRE(state.normRegs[0] == 9);
	REQUIRE(state.normRegs[1] == reinterpret_cast<uintptr_t>(heap));
	REQUIRE(state.normRegs[2] == sizeof(heap));
	REQUIRE(state.dataStackOffset == frameSize);
	REQUIRE(state.callStackSize == 0);
	REQUIRE(state.pc == 2);
}

TEST_CASE("Test compileWithSS1 restores and resumes every instruction")
{
	// Resuming at pc=1 must skip the assignment at pc=0.
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV64_IMM, BPF_REG_0, 0, 0, 1 },
		{ EBPF_OP_ADD64_IMM, BPF_REG_0, 0, 0, 2 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) ==
		0);

	constexpr uint16_t frameSize = 128;
	uint8_t fixedHeap[8] = {};
	uint8_t fixedDataStack[frameSize] = {};
	uint8_t fixedCallStack[5 * sizeof(void *)] = {};
	bpftime::ExecState fixed{};
	fixed.heap = reinterpret_cast<std::byte *>(fixedHeap);
	fixed.dataStack = reinterpret_cast<std::byte *>(fixedDataStack);
	fixed.callStack = reinterpret_cast<std::byte *>(fixedCallStack);

	auto func = vm.compileWithSS1(&fixed, 1, frameSize, sizeof(fixedHeap));
	REQUIRE(func.has_value());

	uint8_t sourceHeap[8] = { 0x42 };
	uint8_t sourceDataStack[frameSize] = {};
	uint8_t sourceCallStack[5 * sizeof(void *)] = {};
	bpftime::ExecState source{};
	source.normRegs[0] = 10;
	source.heap = reinterpret_cast<std::byte *>(sourceHeap);
	source.dataStack = reinterpret_cast<std::byte *>(sourceDataStack);
	source.callStack = reinterpret_cast<std::byte *>(sourceCallStack);
	source.dataStackOffset = frameSize;
	source.pc = 1;

	REQUIRE((*func)(0, &source) == 12);
	REQUIRE(fixed.normRegs[0] == 12);
	REQUIRE(fixedHeap[0] == 0x42);
	REQUIRE(fixed.pc == 2);

	source.pc = 99;
	REQUIRE((*func)(0, &source) == ((1ULL << 16) | 99));
	REQUIRE(fixed.pc == 99);
}

TEST_CASE("Test compileWithSS1 derives r10 reads and writes from the stack offset")
{
	// Move r10 down without touching memory, then read it back. r10 has no
	// persistent architectural slot in SS1: the SUB must update
	// dataStackOffset, and the MOV must reconstruct r10 from that offset.
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_SUB64_IMM, BPF_REG_10, 0, 0, 16 },
		{ EBPF_OP_MOV64_REG, BPF_REG_0, BPF_REG_10, 0, 0 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) ==
		0);

	constexpr uint16_t frameSize = 128;
	uint8_t heap[1] = {};
	uint8_t dataStack[frameSize * 2] = {};
	uint8_t callStack[10 * sizeof(void *)] = {};
	bpftime::ExecState state{};
	state.heap = reinterpret_cast<std::byte *>(heap);
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);

	auto func = vm.compileWithSS1(&state, 2, frameSize, sizeof(heap));
	REQUIRE(func.has_value());
	const auto expectedR10 = reinterpret_cast<uintptr_t>(dataStack +
							 sizeof(dataStack) - 16);
	REQUIRE((*func)(0, nullptr) == expectedR10);
	REQUIRE(state.dataStackOffset == frameSize + 16);
}

TEST_CASE("Test compileWithSS1 tracks direct stacks across local calls")
{
	// call callee; exit; callee writes its frame and returns 4
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV64_IMM, BPF_REG_0, 0, 0, 0 },
		{ EBPF_OP_CALL, 0, 1, 0, 1 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
		{ EBPF_OP_MOV64_IMM, BPF_REG_1, 0, 0, 7 },
		{ EBPF_OP_STXDW, BPF_REG_10, BPF_REG_1, -8, 0 },
		{ EBPF_OP_MOV64_IMM, BPF_REG_0, 0, 0, 4 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) ==
		0);

	constexpr uint16_t frameSize = 128;
	constexpr uint8_t maxDepth = 2;
	uint8_t heap[1] = {};
	uint8_t dataStack[frameSize * maxDepth] = {};
	uint8_t callStack[5 * maxDepth * sizeof(void *)] = {};
	bpftime::ExecState state{};
	state.heap = reinterpret_cast<std::byte *>(heap);
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);

	auto func = vm.compileWithSS1(&state, maxDepth, frameSize, sizeof(heap));
	REQUIRE(func.has_value());
	REQUIRE((*func)(0, nullptr) == 4);
	REQUIRE(state.dataStackOffset == frameSize);
	REQUIRE(state.callStackSize == 0);
	REQUIRE(state.pc == 2);
	uint64_t calleeValue = 0;
	std::memcpy(&calleeValue, dataStack + frameSize - 8,
		    sizeof(calleeValue));
	REQUIRE(calleeValue == 7);
}

TEST_CASE("Test compileWithSS snapshots memory")
{
	// r2 = 0x42; *(u8 *)(r1 + 0) = r2; r0 = 4; exit
	// Writes into the program's memory buffer (pointed to by r1), so a
	// memory snapshot point must capture that write.
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV_IMM, BPF_REG_2, 0, 0, 0x42 },
		{ EBPF_OP_STXB, BPF_REG_1, BPF_REG_2, 0, 0 },
		{ EBPF_OP_MOV_IMM, BPF_REG_0, 0, 0, 4 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};

	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) ==
		0);

	const auto g = buildEFG(vm.instructions);
	const auto instInfo = partition(g.get(), vm.instructions, 1, true, {});
	REQUIRE_FALSE(instInfo.empty());

	bpftime::ExecState state{};
	std::memset(&state, 0, sizeof(state));
	constexpr uint16_t memSize = 8;
	uint8_t snapshotBuf[memSize] = {};
	uint8_t alternateSnapshotBuf[memSize] = {};
	uint8_t dataStackBuf[512] = {};
	uint8_t callStackBuf[5 * sizeof(void *)] = {};
	state.heap = reinterpret_cast<std::byte *>(snapshotBuf);
	state.dataStack = reinterpret_cast<std::byte *>(dataStackBuf);
	state.callStack = reinterpret_cast<std::byte *>(callStackBuf);

	uint8_t progMem[memSize] = {};
	// The heap to snapshot is the buffer passed to exec() below, not a
	// compile-time constant.
	auto func = vm.compileWithSS(&state, instInfo, 1, 512);
	REQUIRE(func.has_value());
	state.heap = reinterpret_cast<std::byte *>(alternateSnapshotBuf);

	uint64_t ret = 0;
	REQUIRE(vm.exec(progMem, memSize, ret) == 0);
	REQUIRE(ret == 4);

	// The STXB writes 0x42 into progMem[0]; that write must have been
	// snapshotted into snapshotBuf by the memory snapshot at some
	// non-regOnly boundary at or after the STXB.
	REQUIRE(progMem[0] == 0x42);
	REQUIRE(snapshotBuf[0] == 0x42);
	REQUIRE(alternateSnapshotBuf[0] == 0);
}

TEST_CASE("Test compileWithSS snapshots the data stack")
{
	// simple_cond_1 stores into [r10-4]/[r10-8]/[r10-12], i.e. the data
	// stack of the single (top-level) frame.
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code((const void *)simple_cond_1,
			     sizeof(simple_cond_1) - 1) == 0);

	const auto g = buildEFG(vm.instructions);
	const auto instInfo = partition(g.get(), vm.instructions, 1, true, {});
	REQUIRE_FALSE(instInfo.empty());

	constexpr uint16_t frameSize = 512;
	bpftime::ExecState state{};
	uint64_t heapBuf = 0;
	uint8_t dataStackBuf[frameSize] = {};
	uint8_t alternateDataStackBuf[frameSize] = {};
	uint8_t callStackBuf[5 * sizeof(void *)] = {};
	state.heap = reinterpret_cast<std::byte *>(&heapBuf);
	state.dataStack = reinterpret_cast<std::byte *>(dataStackBuf);
	state.callStack = reinterpret_cast<std::byte *>(callStackBuf);

	auto func = vm.compileWithSS(&state, instInfo, 1, frameSize);
	REQUIRE(func.has_value());
	state.dataStack = reinterpret_cast<std::byte *>(alternateDataStackBuf);

	uint64_t mem = 0, ret = 0;
	REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
	REQUIRE(ret == 4);

	// The program never calls a local function, so it stays in the
	// top-level frame: exactly one frame is in use.
	REQUIRE(state.dataStackOffset == frameSize);
	// Nothing was pushed onto the call stack.
	REQUIRE(state.callStackSize == 0);
	// The final `ldxw r0, [r10-4]` reads back the 4 the program stored at
	// [r10-4]; that store must appear at the top of the copied region,
	// since dataStack holds [r10-frameSize, stackEnd) and r10 == stackEnd.
	uint32_t stored = 0;
	std::memcpy(&stored, dataStackBuf + state.dataStackOffset - 4,
		    sizeof(stored));
	REQUIRE(stored == 4);
	REQUIRE(std::all_of(std::begin(alternateDataStackBuf),
			    std::end(alternateDataStackBuf),
			    [](uint8_t byte) { return byte == 0; }));
}

TEST_CASE("Test compileWithSS snapshots stacks across a local call")
{
	// r0 = 0; call +1 (local); exit
	// callee: r1 = 7; *(u32 *)(r10-4) = r1; r0 = 4; exit
	// The local call pushes a frame, so at a snapshot point inside the
	// callee both stacks have live contents to capture. The value is set
	// inside the callee: r1 is caller-saved (only r6-r9 are preserved
	// across a local call), so setting it before the call proves nothing.
	// The leading MOV keeps the call off pc=0, which the compiler needs in
	// order to record a return block for it.
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV_IMM, BPF_REG_0, 0, 0, 0 },
		{ EBPF_OP_CALL, 0, 0x01, 0, 1 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
		{ EBPF_OP_MOV_IMM, BPF_REG_1, 0, 0, 7 },
		{ EBPF_OP_STXW, BPF_REG_10, BPF_REG_1, -4, 0 },
		{ EBPF_OP_MOV_IMM, BPF_REG_0, 0, 0, 4 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};

	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) ==
		0);

	const auto g = buildEFG(vm.instructions);
	const auto full = partition(g.get(), vm.instructions, 1, true, {});
	REQUIRE_FALSE(full.empty());
	// Snapshot only at the callee's store (pc=4). A single ExecState is
	// overwritten by every snapshot point, so restricting it to one point
	// inside the callee is what lets us observe the live frame; with every
	// point enabled the last write would come from after the unwind.
	auto it = full.find(4);
	REQUIRE(it != full.end());
	REQUIRE(it->second.usedStack());
	const std::unordered_map<uint16_t, CompInfo> instInfo{ *it };

	constexpr uint16_t frameSize = 512;
	constexpr uint8_t maxDepth = 4;
	bpftime::ExecState state{};
	uint64_t heapBuf = 0;
	uint8_t dataStackBuf[frameSize * maxDepth] = {};
	uint8_t callStackBuf[5 * maxDepth * sizeof(void *)] = {};
	uint8_t alternateCallStackBuf[5 * maxDepth * sizeof(void *)] = {};
	state.heap = reinterpret_cast<std::byte *>(&heapBuf);
	state.dataStack = reinterpret_cast<std::byte *>(dataStackBuf);
	state.callStack = reinterpret_cast<std::byte *>(callStackBuf);

	auto func = vm.compileWithSS(&state, instInfo, maxDepth, frameSize);
	REQUIRE(func.has_value());
	state.callStack = reinterpret_cast<std::byte *>(alternateCallStackBuf);

	uint64_t mem = 0, ret = 0;
	REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
	REQUIRE(ret == 4);

	// The recorded metadata must stay within the bounds the caller
	// allocated, otherwise the memcpy would have overrun the buffers.
	REQUIRE(state.dataStackOffset <= frameSize * maxDepth);
	REQUIRE(state.callStackSize <= 5 * maxDepth);
	// While the callee's frame is live, r10 sits one frameSize below
	// stackEnd, so with the entry frame plus the callee's frame two frames
	// are in use, along with the five call stack slots pushed by the call.
	REQUIRE(state.dataStackOffset == 2 * frameSize);
	REQUIRE(state.callStackSize == 5);
	REQUIRE(std::any_of(std::begin(callStackBuf), std::end(callStackBuf),
			    [](uint8_t byte) { return byte != 0; }));
	REQUIRE(std::all_of(std::begin(alternateCallStackBuf),
			    std::end(alternateCallStackBuf),
			    [](uint8_t byte) { return byte == 0; }));
	// dataStack holds [r10-frameSize, stackEnd), so the callee's store to
	// [r10-4] sits frameSize+4 bytes below the top of the copied region.
	uint32_t stored = 0;
	std::memcpy(&stored,
		    dataStackBuf + frameSize * maxDepth - frameSize - 4,
		    sizeof(stored));
	REQUIRE(stored == 7);
}

TEST_CASE("Test compileWithSS resumes normal instructions")
{
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV_IMM, BPF_REG_0, 0, 0, 10 },
		{ EBPF_OP_ADD_IMM, BPF_REG_0, 0, 0, 1 },
		{ EBPF_OP_ADD_IMM, BPF_REG_0, 0, 0, 5 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) == 0);
	const auto full = partition(buildEFG(vm.instructions).get(),
				    vm.instructions, 1, true, {});
	auto point = full.find(1);
	REQUIRE(point != full.end());

	constexpr uint16_t frameSize = 512;
	bpftime::ExecState state{};
	uint8_t heap[8] = {}, dataStack[frameSize] = {};
	void *callStack[5] = {};
	state.heap = reinterpret_cast<std::byte *>(heap);
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);
	state.dataStackOffset = frameSize;
	auto func = vm.compileWithSS(&state, { *point }, 1, frameSize);
	REQUIRE(func);

	uint64_t result = 0;
	REQUIRE(vm.exec(heap, sizeof(heap), result) == 0);
	REQUIRE(result == 16);
	REQUIRE(state.pc == 2);
	REQUIRE(state.normRegs[0] == 11);

	state.normRegs[0] = 20;
	REQUIRE((*func)(sizeof(heap), &state) == 25);
	// Resume state is copied into local register storage. With no later
	// snapshot point, executing the ADD must not modify the input state.
	REQUIRE(state.normRegs[0] == 20);
	REQUIRE((*func)(sizeof(heap), nullptr) == 16);
}

TEST_CASE("Test compileWithSS rejects an invalid resume PC")
{
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV_IMM, BPF_REG_0, 0, 0, 10 },
		{ EBPF_OP_ADD_IMM, BPF_REG_0, 0, 0, 1 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) == 0);
	const auto full = partition(buildEFG(vm.instructions).get(),
				    vm.instructions, 1, true, {});
	auto point = full.find(1);
	REQUIRE(point != full.end());

	constexpr uint16_t frameSize = 512;
	bpftime::ExecState state{};
	uint8_t heap[8] = {}, dataStack[frameSize] = {};
	void *callStack[5] = {};
	state.heap = reinterpret_cast<std::byte *>(heap);
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);
	state.dataStackOffset = frameSize;
	auto func = vm.compileWithSS(&state, { *point }, 1, frameSize);
	REQUIRE(func);

	state.pc = 42;
	REQUIRE((*func)(sizeof(heap), &state) == (uint64_t{ 42 } | (1ULL << 16)));
}

TEST_CASE("Test compileWithSS resumes in a local data stack")
{
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV_IMM, BPF_REG_3, 0, 0, 9 },
		{ EBPF_OP_JEQ_IMM, BPF_REG_3, 0, 0, 9 },
		{ EBPF_OP_STXW, BPF_REG_10, BPF_REG_3, -4, 0 },
		{ EBPF_OP_LDXW, BPF_REG_0, BPF_REG_10, -4, 0 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) == 0);
	const auto full = partition(buildEFG(vm.instructions).get(),
				    vm.instructions, 1, true, {});
	auto point = full.find(1);
	REQUIRE(point != full.end());

	constexpr uint16_t frameSize = 512;
	bpftime::ExecState state{};
	uint8_t heap[8] = {}, dataStack[frameSize] = {};
	void *callStack[5] = {};
	state.heap = reinterpret_cast<std::byte *>(heap);
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);
	state.dataStackOffset = frameSize;
	state.pc = 1;
	state.normRegs[3] = 9;
	const uint32_t original = 7;
	std::memcpy(dataStack + frameSize - sizeof(original), &original,
		    sizeof(original));

	auto func = vm.compileWithSS(&state, { *point }, 1, frameSize);
	REQUIRE(func);
	REQUIRE((*func)(sizeof(heap), &state) == 9);
	uint32_t retained = 0;
	std::memcpy(&retained, dataStack + frameSize - sizeof(retained),
		    sizeof(retained));
	REQUIRE(retained == original);
}

TEST_CASE("Test compileWithSS resumes before a conditional branch")
{
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV_IMM, BPF_REG_0, 0, 0, 0 },
		{ EBPF_OP_MOV_IMM, BPF_REG_1, 0, 0, 7 },
		{ EBPF_OP_JEQ_IMM, BPF_REG_1, 0, 1, 7 },
		{ EBPF_OP_MOV_IMM, BPF_REG_0, 0, 0, 1 },
		{ EBPF_OP_ADD_IMM, BPF_REG_0, 0, 0, 4 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) == 0);
	const auto full = partition(buildEFG(vm.instructions).get(),
				    vm.instructions, 1, true, {});
	auto point = full.find(2);
	REQUIRE(point != full.end());

	constexpr uint16_t frameSize = 512;
	bpftime::ExecState state{};
	uint8_t heap[8] = {}, dataStack[frameSize] = {};
	void *callStack[5] = {};
	state.heap = reinterpret_cast<std::byte *>(heap);
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);
	state.dataStackOffset = frameSize;
	auto func = vm.compileWithSS(&state, { *point }, 1, frameSize);
	REQUIRE(func);

	uint64_t result = 0;
	REQUIRE(vm.exec(heap, sizeof(heap), result) == 0);
	REQUIRE(result == 4);
	REQUIRE(state.pc == 2);
	state.normRegs[1] = 0;
	REQUIRE((*func)(sizeof(heap), &state) == 5);
}

TEST_CASE("Test compileWithSS resumes with live local-call stacks")
{
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV_IMM, BPF_REG_0, 0, 0, 0 },
		{ EBPF_OP_CALL, 0, 0x01, 0, 1 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
		{ EBPF_OP_MOV_IMM, BPF_REG_1, 0, 0, 7 },
		{ EBPF_OP_STXW, BPF_REG_10, BPF_REG_1, -4, 0 },
		{ EBPF_OP_LDXW, BPF_REG_0, BPF_REG_10, -4, 0 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) == 0);
	const auto full = partition(buildEFG(vm.instructions).get(),
				    vm.instructions, 1, true, {});
	auto point = full.find(4);
	REQUIRE(point != full.end());

	constexpr uint16_t frameSize = 512;
	constexpr uint8_t maxDepth = 4;
	bpftime::ExecState state{};
	uint8_t heap[8] = {}, dataStack[frameSize * maxDepth] = {};
	void *callStack[5 * maxDepth] = {};
	state.heap = reinterpret_cast<std::byte *>(heap);
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);
	state.dataStackOffset = frameSize;
	auto func = vm.compileWithSS(&state, { *point }, maxDepth, frameSize);
	REQUIRE(func);

	uint64_t result = 0;
	REQUIRE(vm.exec(heap, sizeof(heap), result) == 0);
	REQUIRE(result == 7);
	REQUIRE(state.pc == 5);
	REQUIRE(state.dataStackOffset == 2 * frameSize);
	REQUIRE(state.callStackSize == 5);
	uint32_t replacement = 9;
	std::memcpy(dataStack + frameSize * maxDepth - frameSize - 4,
		    &replacement, sizeof(replacement));
	REQUIRE((*func)(sizeof(heap), &state) == 9);
}

TEST_CASE("Test compileWithSS2 snapshots one specified loop iteration")
{
	// The iterator structure starts at r10-32. Its curr field is at
	// r10-8. The loop visits curr values 0, 1, and 2.
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV64_IMM, BPF_REG_0, 0, 0, 0 },
		{ EBPF_OP_MOV64_IMM, BPF_REG_1, 0, 0, 0 },
		{ EBPF_OP_STXDW, BPF_REG_10, BPF_REG_1, -8, 0 },
		{ EBPF_OP_ADD64_IMM, BPF_REG_0, 0, 0, 1 },
		{ EBPF_OP_ADD64_IMM, BPF_REG_1, 0, 0, 1 },
		{ EBPF_OP_STXDW, BPF_REG_10, BPF_REG_1, -8, 0 },
		{ EBPF_OP_JLT_IMM, BPF_REG_1, 0, -4, 3 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) == 0);

	constexpr uint16_t frameSize = 128;
	bpftime::ExecState state{};
	uint8_t dataStack[frameSize] = {};
	void *callStack[5] = {};
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);
	const std::vector<bpftime::TimeLoc> locations{
		{ 3, { { -32, 1 } } },
	};
	auto func = vm.compileWithSS2(&state, 1, frameSize, locations);
	REQUIRE(func);

	REQUIRE((*func)(999, nullptr) == 3);
	REQUIRE(state.pc == 4);
	REQUIRE(state.normRegs[0] == 2);
	REQUIRE(state.normRegs[1] == 1);
	REQUIRE(state.dataStackOffset == frameSize);
	REQUIRE(state.callStackSize == 0);
	uint64_t curr = 0;
	std::memcpy(&curr, dataStack + frameSize - 8, sizeof(curr));
	REQUIRE(curr == 1);

	// Resume at the instruction after the snapshot. The restored loop must
	// finish with the same result.
	const auto resumed = (*func)(0, &state);
	CAPTURE(resumed, state.normRegs[0], state.normRegs[1], state.pc);
	REQUIRE(resumed == 3);
}

TEST_CASE("Test compileWithSS2 skips a different loop iteration")
{
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV64_IMM, BPF_REG_0, 0, 0, 7 },
		{ EBPF_OP_MOV64_IMM, BPF_REG_1, 0, 0, 1 },
		{ EBPF_OP_STXDW, BPF_REG_10, BPF_REG_1, -8, 0 },
		{ EBPF_OP_ADD64_IMM, BPF_REG_0, 0, 0, 2 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) == 0);

	constexpr uint16_t frameSize = 128;
	bpftime::ExecState state{};
	uint8_t dataStack[frameSize] = {};
	void *callStack[5] = {};
	state.normRegs[0] = 55;
	state.pc = 44;
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);
	const bpftime::TimeLoc locations[] = { { 3, { { -32, 9 } } } };
	auto func = vm.compileWithSS2(&state, 1, frameSize,
				      std::begin(locations), std::end(locations));
	REQUIRE(func);
	REQUIRE((*func)(0, nullptr) == 9);
	REQUIRE(state.normRegs[0] == 55);
	REQUIRE(state.pc == 44);
}

TEST_CASE("Test compileWithSS2 uses portable local-call snapshots")
{
	// The caller keeps a data-stack pointer in r6 and values in r7-r9.
	// The callee snapshot must store an eBPF return PC, not a JIT address.
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV64_REG, BPF_REG_6, BPF_REG_10, 0, 0 },
		{ EBPF_OP_MOV64_IMM, BPF_REG_7, 0, 0, 7 },
		{ EBPF_OP_MOV64_IMM, BPF_REG_8, 0, 0, 8 },
		{ EBPF_OP_MOV64_IMM, BPF_REG_9, 0, 0, 9 },
		{ EBPF_OP_CALL, 0, 0x01, 0, 6 },
		{ EBPF_OP_MOV64_REG, BPF_REG_0, BPF_REG_6, 0, 0 },
		{ EBPF_OP_SUB64_REG, BPF_REG_0, BPF_REG_10, 0, 0 },
		{ EBPF_OP_ADD64_REG, BPF_REG_0, BPF_REG_7, 0, 0 },
		{ EBPF_OP_ADD64_REG, BPF_REG_0, BPF_REG_8, 0, 0 },
		{ EBPF_OP_ADD64_REG, BPF_REG_0, BPF_REG_9, 0, 0 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
		{ EBPF_OP_MOV64_IMM, BPF_REG_0, 0, 0, 1 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(insts.data(), insts.size() * sizeof(ebpf_inst)) == 0);

	constexpr uint16_t frameSize = 128;
	constexpr uint8_t maxDepth = 3;
	bpftime::ExecState state{};
	uint8_t dataStack[frameSize * maxDepth] = {};
	uintptr_t callStack[5 * maxDepth] = {};
	state.dataStack = reinterpret_cast<std::byte *>(dataStack);
	state.callStack = reinterpret_cast<std::byte *>(callStack);
	auto func = vm.compileWithSS2(
		&state, maxDepth, frameSize,
		std::vector<bpftime::TimeLoc>{ { 11, {} } });
	REQUIRE(func);

	REQUIRE((*func)(0, nullptr) == 24);
	REQUIRE(state.pc == 12);
	REQUIRE(state.callStackSize == 5);
	REQUIRE(callStack[0] == 9);
	REQUIRE(callStack[1] == 8);
	REQUIRE(callStack[2] == 7);
	REQUIRE(callStack[3] == reinterpret_cast<uintptr_t>(dataStack) +
				      sizeof(dataStack));
	REQUIRE(callStack[4] == 5);
	REQUIRE(state.normRegs[6] == reinterpret_cast<uintptr_t>(dataStack) +
					 sizeof(dataStack));

	// The local return must use the saved r6-r9 values. It must also
	// convert the stored data-stack pointer and return PC to this JIT run.
	for (unsigned reg = 6; reg <= 9; ++reg)
		state.normRegs[reg] = 0;
	REQUIRE((*func)(0, &state) == 24);
}

TEST_CASE("Test compileWithSS2 accepts direct resume targets")
{
	std::vector<ebpf_inst> insts = {
		{ EBPF_OP_MOV64_IMM, BPF_REG_0, 0, 0, 10 },
		{ EBPF_OP_ADD64_IMM, BPF_REG_0, 0, 0, 1 },
		{ EBPF_OP_ADD64_IMM, BPF_REG_0, 0, 0, 2 },
		{ EBPF_OP_ADD64_IMM, BPF_REG_0, 0, 0, 4 },
		{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	};
	constexpr uint16_t frameSize = 128;

	bpftime::ExecState earlier{};
	uint8_t earlierDataStack[frameSize] = {};
	uintptr_t earlierCallStack[5] = {};
	earlier.dataStack = reinterpret_cast<std::byte *>(earlierDataStack);
	earlier.callStack = reinterpret_cast<std::byte *>(earlierCallStack);
	bpftime::llvmbpf_vm earlierVm;
	REQUIRE(earlierVm.load_code(insts.data(),
				    insts.size() * sizeof(ebpf_inst)) == 0);
	auto earlierFunc = earlierVm.compileWithSS2(
		&earlier, 1, frameSize,
		std::vector<bpftime::TimeLoc>{ { 1, {} } });
	REQUIRE(earlierFunc);
	REQUIRE((*earlierFunc)(0, nullptr) == 17);
	REQUIRE(earlier.pc == 2);
	REQUIRE(earlier.normRegs[0] == 11);

	bpftime::ExecState later{};
	uint8_t laterDataStack[frameSize] = {};
	uintptr_t laterCallStack[5] = {};
	later.dataStack = reinterpret_cast<std::byte *>(laterDataStack);
	later.callStack = reinterpret_cast<std::byte *>(laterCallStack);
	bpftime::llvmbpf_vm laterVm;
	REQUIRE(laterVm.load_code(insts.data(),
				  insts.size() * sizeof(ebpf_inst)) == 0);
	auto laterFunc = laterVm.compileWithSS2(
		&later, 1, frameSize,
		std::vector<bpftime::TimeLoc>{ { 3, {} } }, { earlier.pc });
	REQUIRE(laterFunc);
	REQUIRE((*laterFunc)(0, &earlier) == 17);
	REQUIRE(later.pc == 4);
	REQUIRE(later.normRegs[0] == 17);

	bpftime::ExecState invalidState{};
	uint8_t invalidDataStack[frameSize] = {};
	uintptr_t invalidCallStack[5] = {};
	invalidState.dataStack =
		reinterpret_cast<std::byte *>(invalidDataStack);
	invalidState.callStack =
		reinterpret_cast<std::byte *>(invalidCallStack);
	bpftime::llvmbpf_vm invalidVm;
	REQUIRE(invalidVm.load_code(insts.data(),
				    insts.size() * sizeof(ebpf_inst)) == 0);
	REQUIRE_FALSE(invalidVm.compileWithSS2(
		&invalidState, 1, frameSize,
		std::vector<bpftime::TimeLoc>{ { 3, {} } },
		{ static_cast<uint16_t>(insts.size()) }));
	REQUIRE(invalidVm.get_error_message() ==
		"Resume PC is not an executable instruction");
}

TEST_CASE("Test external function registration")
{
	bpftime::llvmbpf_vm vm;

	SECTION("Register valid external function")
	{
		void *dummy_function = (void *)0xdeadbeef;
		REQUIRE(vm.register_external_function(0, "test_func",
						      dummy_function) == 0);
	}

	SECTION("Register external function with out of bounds index")
	{
		void *dummy_function = (void *)0xdeadbeef;
		REQUIRE(vm.register_external_function(MAX_EXT_FUNCS + 1,
						      "test_func",
						      dummy_function) != 0);
		REQUIRE(vm.get_error_message() == "Index too large");
	}

	SECTION("Register external function with existing index")
	{
		void *dummy_function = (void *)0xdeadbeef;
		REQUIRE(vm.register_external_function(0, "test_func",
						      dummy_function) == 0);
		REQUIRE(vm.register_external_function(0, "test_func",
						      dummy_function) != 0);
		REQUIRE(vm.get_error_message() == "Already defined");
	}
}

TEST_CASE("Test AOT compilation and loading")
{
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code((const void *)simple_cond_1,
			     sizeof(simple_cond_1) - 1) == 0);

	SECTION("load invalid AOT object")
	{
		std::vector<uint8_t> invalid_object{ 0x00, 0x01, 0x02, 0x03 };
		auto func = vm.load_aot_object(invalid_object);
		REQUIRE(!func.has_value());
		REQUIRE(vm.get_error_message() ==
			"The file was not recognized as a valid object file");
	}

	SECTION("AOT compile and load")
	{
		auto object_code_opt = vm.do_aot_compile(true);
		REQUIRE(object_code_opt.has_value()); // Ensure that the
						      // optional contains a
						      // value
		auto &object_code = object_code_opt.value(); // Extract the
							     // vector from the
							     // optional
		REQUIRE(!object_code.empty());

		auto func = vm.load_aot_object(object_code);
		REQUIRE(func.has_value());
	}

	SECTION("Load AOT object after JIT compilation")
	{
		auto object_code_opt = vm.do_aot_compile(false);
		REQUIRE(object_code_opt.has_value());
		auto &object_code = object_code_opt.value();
		REQUIRE(!object_code.empty());

		auto func = vm.load_aot_object(object_code);
		REQUIRE(func.has_value());

		// Attempt to load another object after JIT compilation
		auto another_object_code_opt = vm.do_aot_compile(true);
		REQUIRE(another_object_code_opt.has_value());
		auto &another_object_code = another_object_code_opt.value();
		REQUIRE(!another_object_code.empty());

		auto func2 = vm.load_aot_object(another_object_code);
		REQUIRE(!func2.has_value());
		REQUIRE(vm.get_error_message() == "Already compiled");
	}
}

TEST_CASE("Test loading and executing incorrect code")
{
	bpftime::llvmbpf_vm vm;

	// Example of incorrect or malformed eBPF instructions
	const unsigned char wrong_code[] =
		"\x00\x00\x00\x00\x00\x00\x00\x00"; // Invalid eBPF instruction

	SECTION("Execute without valid code")
	{
		vm.unload_code(); // Ensure no code is loaded
		uint64_t ret = 0;
		uint64_t mem = 0;

		REQUIRE(vm.exec(&mem, sizeof(mem), ret) != 0);
		REQUIRE(vm.get_error_message() ==
			"No instructions provided"); // Assuming this is the
						     // error message
	}

	SECTION("Load and execute incorrect code")
	{
		REQUIRE(vm.load_code((const void *)wrong_code,
				     sizeof(wrong_code) - 1) == 0);

		uint64_t ret = 0;
		uint64_t mem = 0;

		REQUIRE(vm.exec(&mem, sizeof(mem), ret) != 0); // Execution
							       // should fail
		REQUIRE(vm.get_error_message() ==
			"Unsupported or illegal opcode: 0 at pc 0"); // Assuming
								     // this
								     // error
								     // message
	}
}

const unsigned char xdp_counter_bytecode[] = "\x79\x16\x00\x00\x00\x00\x00\x00"
					     "\x79\x17\x08\x00\x00\x00\x00\x00"
					     "\xb7\x01\x00\x00\x00\x00\x00\x00"
					     "\x63\x1a\xfc\xff\x00\x00\x00\x00"
					     "\xbf\xa2\x00\x00\x00\x00\x00\x00"
					     "\x07\x02\x00\x00\xfc\xff\xff\xff"
					     "\x18\x11\x00\x00\x05\x00\x00\x00"
					     "\x00\x00\x00\x00\x00\x00\x00\x00"
					     "\x85\x00\x00\x00\x01\x00\x00\x00"
					     "\xbf\x01\x00\x00\x00\x00\x00\x00"
					     "\xb7\x00\x00\x00\x02\x00\x00\x00"
					     "\x15\x01\x18\x00\x00\x00\x00\x00"
					     "\x61\x11\x00\x00\x00\x00\x00\x00"
					     "\x55\x01\x16\x00\x00\x00\x00\x00"
					     "\x18\x21\x00\x00\x06\x00\x00\x00"
					     "\x00\x00\x00\x00\x00\x00\x00\x00"
					     "\x79\x12\x00\x00\x00\x00\x00\x00"
					     "\x07\x02\x00\x00\x01\x00\x00\x00"
					     "\x7b\x21\x00\x00\x00\x00\x00\x00"
					     "\xb7\x00\x00\x00\x01\x00\x00\x00"
					     "\xbf\x61\x00\x00\x00\x00\x00\x00"
					     "\x07\x01\x00\x00\x0e\x00\x00\x00"
					     "\x2d\x71\x0d\x00\x00\x00\x00\x00"
					     "\x69\x61\x00\x00\x00\x00\x00\x00"
					     "\x69\x62\x06\x00\x00\x00\x00\x00"
					     "\x6b\x26\x00\x00\x00\x00\x00\x00"
					     "\x69\x62\x08\x00\x00\x00\x00\x00"
					     "\x69\x63\x02\x00\x00\x00\x00\x00"
					     "\x6b\x36\x08\x00\x00\x00\x00\x00"
					     "\x6b\x26\x02\x00\x00\x00\x00\x00"
					     "\x69\x62\x0a\x00\x00\x00\x00\x00"
					     "\x69\x63\x04\x00\x00\x00\x00\x00"
					     "\x6b\x36\x0a\x00\x00\x00\x00\x00"
					     "\x6b\x16\x06\x00\x00\x00\x00\x00"
					     "\x6b\x26\x04\x00\x00\x00\x00\x00"
					     "\xb7\x00\x00\x00\x03\x00\x00\x00"
					     "\x95\x00\x00\x00\x00\x00\x00\x00";

TEST_CASE("Test compile with no require helper")
{
	bpftime::llvmbpf_vm vm;
	auto code = xdp_counter_bytecode;
	size_t code_len = sizeof(xdp_counter_bytecode) - 1;
	uint64_t res = 0;

	REQUIRE(vm.load_code(code, code_len) == 0);

	auto func = vm.compile(1, 512);
	REQUIRE(!func.has_value()); // Compilation should fail due to missing
				    // helpers
	REQUIRE(vm.get_error_message() ==
		"Ext func not found: _bpf_helper_ext_0001");
}

uint64_t map_val(uint64_t val)
{
	return 0;
}

TEST_CASE("Test compile with no LDDW helper")
{
	bpftime::llvmbpf_vm vm;
	auto code = xdp_counter_bytecode;
	size_t code_len = sizeof(xdp_counter_bytecode) - 1;
	uint64_t res = 0;

	REQUIRE(vm.load_code(code, code_len) == 0);

	vm.register_external_function(1, "bpf_map_lookup_elem",
				      (void *)nullptr);

	// Set some helpers to nullptr, which should simulate a missing helper
	vm.set_lddw_helpers(nullptr, nullptr, nullptr, nullptr, nullptr);

	auto func = vm.compile(1, 512);
	REQUIRE(!func.has_value()); // Compilation should fail due to missing
	REQUIRE(vm.get_error_message() ==
		"map_val is not provided, unable to compile at pc 14");
}


TEST_CASE("Test compile with default LDDW helper")
{
	bpftime::llvmbpf_vm vm;
	auto code = xdp_counter_bytecode;
	size_t code_len = sizeof(xdp_counter_bytecode) - 1;
	uint64_t res = 0;

	REQUIRE(vm.load_code(code, code_len) == 0);

	vm.register_external_function(1, "bpf_map_lookup_elem",
				      (void *)map_val);

	// Set some helpers to nullptr, which should simulate a missing helper
	vm.set_lddw_helpers(nullptr, nullptr, map_val, nullptr, nullptr);

	auto func = vm.compile(1, 512);
	REQUIRE(func.has_value()); // Compilation should success because the
				   // default helpers are provided
}
