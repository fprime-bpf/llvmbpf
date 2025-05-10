#include "llvmbpf.hpp"
#include <cassert>
#include <cstdint>
#include <inttypes.h>
#include <iostream>
#include <ostream>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <llvm/ExecutionEngine/MCJIT.h>

using namespace bpftime;

uint8_t ncc_score_match_img[] = {0x00, 0x11, 0x22, 0x33, 0x44,
                                 0x55, 0x66, 0x77, 0x88};

uint64_t nccscore_get_match_image(uint64_t a, uint64_t _b, uint64_t _c,
                                  uint64_t _d, uint64_t _e) {
  // Send a pointer to example image match to match against
  return (uint64_t)&ncc_score_match_img;
}

// TODO: replace with a large image
uint8_t search_img[] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99};

// TODO: write the bpf portion to loop through and map the image
const unsigned char bpf_match_ncc_score[] = "\x7b\x1a\xf8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x8) = r1
                                            "\x63\x2a\xf4\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0xc) = w2
                                            "\xb4\x01\x00\x00\xff\xff\x00\x00" // w1 = 0xffff
                                            "\x63\x1a\xec\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0x14) = w1
                                            "\x79\xa1\xf8\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x8)
                                            "\x7b\x1a\xe0\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x20) = r1
                                            "\x18\x01\x00\x00\x00\x00\x00\x00" // r1 = 0x0 ll
                                            "\x00\x00\x00\x00\x00\x00\x00\x00"
                                            "\x79\x11\x00\x00\x00\x00\x00\x00" // r1 = *(u64 *)(r1 + 0x0)
                                            "\x85\x00\x00\x00\x01\x00\x00\x00" // callx r1
                                            "\x7b\x0a\xd8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x28) = r0
                                            "\xb4\x01\x00\x00\x00\x00\x00\x00" // w1 = 0x0
                                            "\x63\x1a\xd4\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0x2c) = w1
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x70>
                                            "\x61\xa1\xd4\xff\x00\x00\x00\x00" // w1 = *(u32 *)(r10 - 0x2c)
                                            "\x66\x01\x2e\x00\x96\x00\x00\x00" // if w1 s> 0x96 goto +0x2e <bpf_main+0x1f0>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x88>
                                            "\xb4\x01\x00\x00\x00\x00\x00\x00" // w1 = 0x0
                                            "\x63\x1a\xd0\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0x30) = w1
                                            "\x63\x1a\xcc\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0x34) = w1
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0xa8>
                                            "\x61\xa1\xcc\xff\x00\x00\x00\x00" // w1 = *(u32 *)(r10 - 0x34)
                                            "\x66\x01\x19\x00\x08\x00\x00\x00" // if w1 s> 0x8 goto +0x19 <bpf_main+0x180>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0xc0>
                                            "\x79\xa1\xe0\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x20)
                                            "\x61\xa2\xd4\xff\x00\x00\x00\x00" // w2 = *(u32 *)(r10 - 0x2c)
                                            "\x61\xa3\xcc\xff\x00\x00\x00\x00" // w3 = *(u32 *)(r10 - 0x34)
                                            "\x67\x03\x00\x00\x20\x00\x00\x00" // r3 <<= 0x20
                                            "\xc7\x03\x00\x00\x20\x00\x00\x00" // r3 s>>= 0x20
                                            "\xbc\x34\x00\x00\x00\x00\x00\x00" // w4 = w3
                                            "\x0c\x42\x00\x00\x00\x00\x00\x00" // w2 += w4
                                            "\xbc\x22\x00\x00\x00\x00\x00\x00" // w2 = w2
                                            "\x67\x02\x00\x00\x20\x00\x00\x00" // r2 <<= 0x20
                                            "\xc7\x02\x00\x00\x20\x00\x00\x00" // r2 s>>= 0x20
                                            "\x0f\x21\x00\x00\x00\x00\x00\x00" // r1 += r2
                                            "\x71\x12\x00\x00\x00\x00\x00\x00" // w2 = *(u8 *)(r1 + 0x0)
                                            "\x79\xa1\xd8\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x28)
                                            "\x0f\x31\x00\x00\x00\x00\x00\x00" // r1 += r3
                                            "\x71\x11\x00\x00\x00\x00\x00\x00" // w1 = *(u8 *)(r1 + 0x0)
                                            "\x1c\x12\x00\x00\x00\x00\x00\x00" // w2 -= w1
                                            "\x61\xa1\xd0\xff\x00\x00\x00\x00" // w1 = *(u32 *)(r10 - 0x30)
                                            "\x0c\x21\x00\x00\x00\x00\x00\x00" // w1 += w2
                                            "\x63\x1a\xd0\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0x30) = w1
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x160>
                                            "\x61\xa1\xcc\xff\x00\x00\x00\x00" // w1 = *(u32 *)(r10 - 0x34)
                                            "\x04\x01\x00\x00\x01\x00\x00\x00" // w1 += 0x1
                                            "\x63\x1a\xcc\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0x34) = w1
                                            "\x05\x00\xe5\xff\x00\x00\x00\x00" // goto -0x1b <bpf_main+0xa8>
                                            "\x61\xa1\xd0\xff\x00\x00\x00\x00" // w1 = *(u32 *)(r10 - 0x30)
                                            "\x61\xa2\xec\xff\x00\x00\x00\x00" // w2 = *(u32 *)(r10 - 0x14)
                                            "\x7e\x21\x06\x00\x00\x00\x00\x00" // if w1 s>= w2 goto +0x6 <bpf_main+0x1c8>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x1a0>
                                            "\x61\xa1\xd4\xff\x00\x00\x00\x00" // w1 = *(u32 *)(r10 - 0x2c)
                                            "\x63\x1a\xf0\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0x10) = w1
                                            "\x61\xa1\xd0\xff\x00\x00\x00\x00" // w1 = *(u32 *)(r10 - 0x30)
                                            "\x63\x1a\xec\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0x14) = w1
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x1c8>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x1d0>
                                            "\x61\xa1\xd4\xff\x00\x00\x00\x00" // w1 = *(u32 *)(r10 - 0x2c)
                                            "\x04\x01\x00\x00\x01\x00\x00\x00" // w1 += 0x1
                                            "\x63\x1a\xd4\xff\x00\x00\x00\x00" // *(u32 *)(r10 - 0x2c) = w1
                                            "\x05\x00\xd0\xff\x00\x00\x00\x00" // goto -0x30 <bpf_main+0x70>
                                            "\x61\xa0\xf0\xff\x00\x00\x00\x00" // w0 = *(u32 *)(r10 - 0x10)
                                            "\x95\x00\x00\x00\x00\x00\x00\x00"; // exit

int main(int argc, char *argv[]) {
  uint64_t res = 0;
  llvmbpf_vm vm;

  printf("running ebpf prog, code len: %zd\n", sizeof(bpf_match_ncc_score) - 1);

  res = vm.load_code(bpf_match_ncc_score, sizeof(bpf_match_ncc_score) - 1);
  if (res) {
    fprintf(stderr, "Failed to load: %s\n", vm.get_error_message().c_str());
    exit(1);
  }

  vm.register_external_function(1, "get_match_image",
                                (void *)nccscore_get_match_image);
  auto func = vm.compile();
  if (!func) {
    fprintf(stderr, "Failed to compile: %s\n", vm.get_error_message().c_str());
    exit(1);
  }

  int err = vm.exec(&search_img, sizeof(search_img), res);
  if (err != 0) {
    fprintf(stderr, "Failed to exec.");
    exit(1);
  }

  printf("res = %" PRIu64 "\n", res);
  return 0;
}
