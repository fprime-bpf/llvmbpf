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

uint8_t ncc_score_match_img[] = {0x00, 0x22, 0x22, 0x33, 0x44,
                                 0x55, 0x66, 0x77, 0x88};

uint64_t nccscore_get_match_image(uint64_t a, uint64_t _b, uint64_t _c,
                                  uint64_t _d, uint64_t _e) {
  std::cout << "get_match_image called" << std::endl;
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
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x22, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99};

// TODO: write the bpf portion to loop through and map the image
const unsigned char bpf_match_ncc_score[] = "\x7b\x1a\xf8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x8) = r1
                                            "\x7b\x2a\xf0\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x10) = r2
                                            "\x18\x01\x00\x00\xff\xff\xff\xff" // r1 = 0xffffffff ll
                                            "\x00\x00\x00\x00\x00\x00\x00\x00"
                                            "\x7b\x1a\xe0\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x20) = r1
                                            "\x18\x01\x00\x00\x00\x00\x00\x00" // r1 = 0x0 ll
                                            "\x00\x00\x00\x00\x00\x00\x00\x00"
                                            "\x79\x11\x00\x00\x00\x00\x00\x00" // r1 = *(u64 *)(r1 + 0x0)
                                            "\x85\x00\x00\x00\x01\x00\x00\x00" // callx r1
                                            "\x7b\x0a\xd8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x28) = r0
                                            "\xb7\x01\x00\x00\x00\x00\x00\x00" // r1 = 0x0
                                            "\x7b\x1a\xd0\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x30) = r1
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x68>
                                            "\x79\xa1\xd0\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x30)
                                            "\x79\xa2\xf0\xff\x00\x00\x00\x00" // r2 = *(u64 *)(r10 - 0x10)
                                            "\x07\x02\x00\x00\xf7\xff\xff\xff" // r2 += -0x9
                                            "\x7d\x21\x36\x00\x00\x00\x00\x00" // if r1 s>= r2 goto +0x36 <bpf_main+0x238>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x90>
                                            "\xb7\x01\x00\x00\x00\x00\x00\x00" // r1 = 0x0
                                            "\x7b\x1a\xc8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x38) = r1
                                            "\x7b\x1a\xb8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x48) = r1
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0xb0>
                                            "\x79\xa1\xb8\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x48)
                                            "\x65\x01\x21\x00\x08\x00\x00\x00" // if r1 s> 0x8 goto +0x21 <bpf_main+0x1c8>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0xc8>
                                            "\x79\xa1\xf8\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x8)
                                            "\x79\xa2\xd0\xff\x00\x00\x00\x00" // r2 = *(u64 *)(r10 - 0x30)
                                            "\x79\xa3\xb8\xff\x00\x00\x00\x00" // r3 = *(u64 *)(r10 - 0x48)
                                            "\x0f\x32\x00\x00\x00\x00\x00\x00" // r2 += r3
                                            "\x0f\x21\x00\x00\x00\x00\x00\x00" // r1 += r2
                                            "\x71\x11\x00\x00\x00\x00\x00\x00" // w1 = *(u8 *)(r1 + 0x0)
                                            "\x79\xa2\xd8\xff\x00\x00\x00\x00" // r2 = *(u64 *)(r10 - 0x28)
                                            "\x0f\x32\x00\x00\x00\x00\x00\x00" // r2 += r3
                                            "\x71\x22\x00\x00\x00\x00\x00\x00" // w2 = *(u8 *)(r2 + 0x0)
                                            "\x1c\x21\x00\x00\x00\x00\x00\x00" // w1 -= w2
                                            "\xbc\x11\x00\x00\x00\x00\x00\x00" // w1 = w1
                                            "\x67\x01\x00\x00\x20\x00\x00\x00" // r1 <<= 0x20
                                            "\xc7\x01\x00\x00\x20\x00\x00\x00" // r1 s>>= 0x20
                                            "\x7b\x1a\xc0\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x40) = r1
                                            "\x79\xa1\xc0\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x40)
                                            "\xc5\x01\x06\x00\x01\x00\x00\x00" // if r1 s< 0x1 goto +0x6 <bpf_main+0x178>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x150>
                                            "\x79\xa2\xc0\xff\x00\x00\x00\x00" // r2 = *(u64 *)(r10 - 0x40)
                                            "\x79\xa1\xc8\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x38)
                                            "\x0f\x21\x00\x00\x00\x00\x00\x00" // r1 += r2
                                            "\x7b\x1a\xc8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x38) = r1
                                            "\x05\x00\x05\x00\x00\x00\x00\x00" // goto +0x5 <bpf_main+0x1a0>
                                            "\x79\xa2\xc0\xff\x00\x00\x00\x00" // r2 = *(u64 *)(r10 - 0x40)
                                            "\x79\xa1\xc8\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x38)
                                            "\x1f\x21\x00\x00\x00\x00\x00\x00" // r1 -= r2
                                            "\x7b\x1a\xc8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x38) = r1
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x1a0>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x1a8>
                                            "\x79\xa1\xb8\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x48)
                                            "\x07\x01\x00\x00\x01\x00\x00\x00" // r1 += 0x1
                                            "\x7b\x1a\xb8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x48) = r1
                                            "\x05\x00\xdd\xff\x00\x00\x00\x00" // goto -0x23 <bpf_main+0xb0>
                                            "\x79\xa1\xc8\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x38)
                                            "\x79\xa2\xe0\xff\x00\x00\x00\x00" // r2 = *(u64 *)(r10 - 0x20)
                                            "\x7d\x21\x06\x00\x00\x00\x00\x00" // if r1 s>= r2 goto +0x6 <bpf_main+0x210>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x1e8>
                                            "\x79\xa1\xd0\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x30)
                                            "\x7b\x1a\xe8\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x18) = r1
                                            "\x79\xa1\xc8\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x38)
                                            "\x7b\x1a\xe0\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x20) = r1
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x210>
                                            "\x05\x00\x00\x00\x00\x00\x00\x00" // goto +0x0 <bpf_main+0x218>
                                            "\x79\xa1\xd0\xff\x00\x00\x00\x00" // r1 = *(u64 *)(r10 - 0x30)
                                            "\x07\x01\x00\x00\x01\x00\x00\x00" // r1 += 0x1
                                            "\x7b\x1a\xd0\xff\x00\x00\x00\x00" // *(u64 *)(r10 - 0x30) = r1
                                            "\x05\x00\xc6\xff\x00\x00\x00\x00" // goto -0x3a <bpf_main+0x68>
                                            "\x79\xa0\xe8\xff\x00\x00\x00\x00" // r0 = *(u64 *)(r10 - 0x18)
                                            "\x95\x00\x00\x00\x00\x00\x00\x00";// exit

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

