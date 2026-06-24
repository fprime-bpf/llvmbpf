#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include "llvmbpf.hpp"

namespace {
const unsigned char simple_cond_1[] =
	"\xb7\x01\x00\x00\x01\x00\x00\x00\x63\x1a\xf8\xff\x00\x00\x00\x00\xb7\x01\x00\x00\x02\x00\x00\x00\x63"
	"\x1a\xf4\xff\x00\x00\x00\x00\x61\xa1\xf8\xff\x00\x00\x00\x00\x61\xa2\xf4\xff\x00\x00\x00\x00\x0f\x21"
	"\x00\x00\x00\x00\x00\x00\x67\x01\x00\x00\x20\x00\x00\x00\xc7\x01\x00\x00\x20\x00\x00\x00\xb7\x02\x00"
	"\x00\x03\x00\x00\x00\x6d\x12\x04\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\xb7\x01\x00\x00"
	"\x04\x00\x00\x00\x63\x1a\xfc\xff\x00\x00\x00\x00\x05\x00\x03\x00\x00\x00\x00\x00\xb7\x01\x00\x00\x05"
	"\x00\x00\x00\x63\x1a\xfc\xff\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x61\xa0\xfc\xff\x00\x00"
	"\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00";

const unsigned char helper_call_add[] =
	"\xb7\x01\x00\x00\x01\x00\x00\x00"
	"\xb7\x02\x00\x00\x03\x00\x00\x00"
	"\x85\x00\x00\x00\x03\x00\x00\x00"
	"\x95\x00\x00\x00\x00\x00\x00\x00";

const ebpf_inst local_call_snapshot_prog[] = {
	{ EBPF_OP_MOV64_IMM, 6, 0, 0, 7 },
	{ EBPF_OP_CALL, 0, 1, 0, 1 },
	{ EBPF_OP_EXIT, 0, 0, 0, 0 },
	{ EBPF_OP_MOV64_IMM, 6, 0, 0, 42 },
	{ EBPF_OP_MOV64_IMM, 0, 0, 0, 9 },
	{ EBPF_OP_EXIT, 0, 0, 0, 0 },
};

extern "C" uint64_t snapshot_add_func(uint64_t a, uint64_t b, uint64_t,
				      uint64_t, uint64_t)
{
	return a + b;
}
}
/*
mov64 r1, 1
stw [r10 - 8], r1
mov64 r1, 2
stw [r10 - 12], r1
ldxw r1, [r10 - 8]
ldxw r2, [r10 - 12]
add64 r1, r2
lsh64 r1, 32
arsh64 r1, 32
mov64 r2, 3
jsgt r1, r2, +4
ja +0
mov64 r1, 4
stw [r10 - 4], r1
ja +3
mov64 r1, 5
stw [r10 - 4], r1
ja +0
ldxw r0, [r10 - 4]
exit
*/
TEST_CASE("Instrumented compile snapshots full state before jumps and r0 before exit")
{
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code((const void *)simple_cond_1,
			     sizeof(simple_cond_1) - 1) == 0);

	bpftime::ExeState snapshot = {};
	auto func = vm.compile(&snapshot);
	REQUIRE(func.has_value());

	uint64_t mem = 0;
	uint64_t ret = 0;
	REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
	REQUIRE(ret == 4);

	CHECK(snapshot[0] == 4);
	CHECK(snapshot[1] == 4);
	CHECK(snapshot[2] == 3);
}

TEST_CASE("Instrumented compile jump snapshots overwrite the stored register set")
{
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code((const void *)simple_cond_1,
			     sizeof(simple_cond_1) - 1) == 0);

	bpftime::ExeState snapshot = { 0x100, 0x101, 0x102, 0x103, 0x104,
				       0x105, 0x106, 0x107, 0x108, 0x109 };
	auto func = vm.compile(&snapshot);
	REQUIRE(func.has_value());

	uint64_t mem = 0;
	uint64_t ret = 0;
	REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
	REQUIRE(ret == 4);

	CHECK(snapshot[0] == 4);
	CHECK(snapshot[1] == 4);
	CHECK(snapshot[2] == 3);
}

TEST_CASE("Instrumented compile snapshots r1-r9 before helper calls")
{
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.register_external_function(3, "add",
				      (void *)snapshot_add_func) == 0);
	REQUIRE(vm.load_code((const void *)helper_call_add,
			     sizeof(helper_call_add) - 1) == 0);

	bpftime::ExeState snapshot = { 0x100, 0x101, 0x102, 0x103, 0x104,
				       0x105, 0x106, 0x107, 0x108, 0x109 };
	auto func = vm.compile(&snapshot);
	REQUIRE(func.has_value());

	uint64_t mem = 0;
	uint64_t ret = 0;
	REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
	REQUIRE(ret == 4);

	CHECK(snapshot[0] == 4);
	CHECK(snapshot[1] == 1);
	CHECK(snapshot[2] == 3);
}


TEST_CASE("Instrumented compile snapshots restored caller state after local returns")
{
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code(local_call_snapshot_prog,
			     sizeof(local_call_snapshot_prog)) == 0);

	bpftime::ExeState snapshot = {};
	auto func = vm.compile(&snapshot);
	REQUIRE(func.has_value());

	uint64_t mem = 0;
	uint64_t ret = 0;
	REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
	REQUIRE(ret == 9);

	CHECK(snapshot[0] == 9);
	CHECK(snapshot[6] == 7);
}
