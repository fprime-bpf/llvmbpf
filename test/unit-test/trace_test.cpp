#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include "ebpf_inst.h"
#include "fpu_inst.h"
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

const ebpf_inst fpu_modifying[] = {
	{ DUO_OP_FST, 2, 0, 0, 0x3fc00000 },
	{ DUO_OP_FADD_IMM, 2, 0, 2, 0x40000000 },
	{ DUO_OP_FST, 10, 0, 0, static_cast<int32_t>(0xc0600000u) },
	{ EBPF_OP_MOV64_IMM, 0, 0, 0, 0 },
	{ EBPF_OP_EXIT, 0, 0, 0, 0 },
};
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
TEST_CASE("Instrumented compile stores final register snapshot")
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
	CHECK(snapshot[3] == 0);
	CHECK(snapshot[4] == 0);
	CHECK(snapshot[5] == 0);
	CHECK(snapshot[6] == 0);
	CHECK(snapshot[7] == 0);
	CHECK(snapshot[8] == 0);
	CHECK(snapshot[9] == 0);
}

TEST_CASE("Instrumented compile only updates changed registers")
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
	CHECK(snapshot[3] == 0x103);
	CHECK(snapshot[4] == 0x104);
	CHECK(snapshot[5] == 0x105);
	CHECK(snapshot[6] == 0x106);
	CHECK(snapshot[7] == 0x107);
	CHECK(snapshot[8] == 0x108);
	CHECK(snapshot[9] == 0x109);
}


TEST_CASE("Instrumented compile only updates changed FPU registers")
{
	bpftime::llvmbpf_vm vm;
	REQUIRE(vm.load_code((const void *)fpu_modifying,
				     sizeof(fpu_modifying)) == 0);

	bpftime::ExeState snapshot = {};
	for (int i = 0; i < 11; i++) {
		snapshot.fpuRegs[i] = 100.0F + static_cast<float>(i);
	}
	auto func = vm.compile(&snapshot);
	REQUIRE(func.has_value());

	uint64_t mem = 0;
	uint64_t ret = 1;
	REQUIRE(vm.exec(&mem, sizeof(mem), ret) == 0);
	REQUIRE(ret == 0);

	CHECK(snapshot.fpuRegs[0] == 100.0F);
	CHECK(snapshot.fpuRegs[1] == 101.0F);
	CHECK(snapshot.fpuRegs[2] == 3.5F);
	CHECK(snapshot.fpuRegs[3] == 103.0F);
	CHECK(snapshot.fpuRegs[9] == 109.0F);
	CHECK(snapshot.fpuRegs[10] == -3.5F);
}
