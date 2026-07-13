#ifndef BPFTIME_LLVM_BPF_PDG_HPP
#define BPFTIME_LLVM_BPF_PDG_HPP

#include <cstdint>
#include <vector>
#include<memory>
#include <unordered_map>
#include <unordered_set>
#include<bitset>

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
struct CompInfo{
    std::bitset<10+11+1> modified;//r0-r9, fpu0-fpu10, regOnly
    bool fpuRegModified(uint8_t)const;
    bool normRegModified(uint8_t)const;
    bool regOnly()const noexcept;
};
/*
Let `G=(V,E)`, V is set of nodes (instructions), E is set of edges. `\forall v\in V`, `type(v)\in{R,M}`. R means this instruction only accesses regsiters, M means it also accesses memory.

Let `P_m` be the largest weakly connected (treat edges as bidirectional) component/subgraph in `P=(G,E-E_1)`. Find `E_1` such that `|v(P_m)|<=maxSize|`: number of nodes (instructions) in the largest weakly connected component after removing edges in `E_1` is no larger than `maxSize`.

Let `A` be all possible `E_1`. Basically, all possible sets of edges matching the above constraint. Choose `E_2\in A` with the following optimization goals ranked in priority (smaller number=higher priority):
2. Let `W` be all the weakly connected components of `P=(G,E-E_1)`. `\forall w\in W`, define `regOnly(w)=1\equiv\forall v\in v(w), type(v)=R`, otherwise `regOnly(w)=0`. Basically, a component/subgraph has `regOnly(w)=1` iff no node(instructions) in it accesses memory.
Find `E_2` that maximizes `\sigma_{w\in W}regOnly(w)`. The goal is to group memory operations in the least amount of partitions.
A call to external function is considered register only if it's in `regOnlyExtFuncs`.

1. `\forall e\in E`, define `end(e)\in V` to be source or destination of this edge depending on `useSrc`. 
Find `E_2` that minimizes `|{end(e)|e\in E_2\in A}|`. The goal is to minimize the set of nodes that are sources or destinations of `E_2`. 

Finding `E_1` that matches the constraint shouldn't be hard, but finding the best `E_2` is NP. Therefore, you don't have to find the strict optimal: a good enough `E_2` fitting the constraint is fine.
The graph is produced by `buildEFG`, you may leverage special properties of it.

Return `B={end(e)|e\in \hat{E_2}}\subseteq V`. The keys in map will be the instructions(nodes) in B, values indicate whether it lives in a register-only component and what registers do instructions in this component modify (treat call to external functions to only modify r0).
*/
/*
The following external functions are considered register only: bpf_math_sqrt, bpf_math_sin, bpf_math_cos, bpf_math_atan2.

We only supported a limited number of external functions, they are defined in "../../iter_bpf_helpers.cpp" and "../../maps/map_bpf_helpers.cpp"
*/
// regOnlyExtFuncs identifies external functions by the `imm` field of their
// CALL instruction, i.e. the same index passed to register_external_function.
std::unordered_map<uint16_t,CompInfo> partition(const G_t,const std::vector<ebpf_inst>&,uint16_t maxSize,bool useSrc, const std::unordered_set<int32_t> &regOnlyExtFuncs)noexcept;
#endif
