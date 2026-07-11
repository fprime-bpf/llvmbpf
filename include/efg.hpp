#ifndef BPFTIME_LLVM_BPF_PDG_HPP
#define BPFTIME_LLVM_BPF_PDG_HPP

#include <cstdint>
#include <vector>
#include<memory>

#include <ebpf_inst.h>
enum FlowType:uint8_t{
    Normal,//`dst` is next instruction.
    Uncond,//`dst` is target of unconditional jump. `call` and `exit` for local funcs are unconditonal jumps.
    Cond1,//`dst` is target of conditional jump
    Cond0,//`dst` is fall through (false branch) of conditional jump
    Exit//`dst` is instruction just after calling an external function.
};
struct Edge{
    uint16_t dst;
    FlowType t;
};

using G_t=std::vector<Edge>[];//adjacency list represented using array of vec of edges. indices in the array corresponds to indices of insts.

// Builds an execution flow graph. EFG describes the order that instructions are executed; it's like a fine grained CFG. If inst1 will be executed immediately after inst0, then there will be an `Edge` from inst0 to inst1.
std::unique_ptr<G_t> buildEFG(const std::vector<ebpf_inst>&);
#endif
