#ifndef BPFTIME_LLVM_BPF_PDG_HPP
#define BPFTIME_LLVM_BPF_PDG_HPP

#include <cstdint>
#include <vector>
#include<memory>
#include <unordered_map>
#include <unordered_set>
#include<bitset>
#include <string>

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
//find `exit` instruction that actually terminates the program.
std::unordered_set<uint16_t> findExits(const G_t,const std::vector<ebpf_inst>&)noexcept;
struct CompInfo{
    std::bitset<11+11+1+1> modified;//r0-r10, fpu0-fpu10, usedHeap, usedStack. Note that changing r10 means call stack (in "../src/compiler.cpp") are also changed.
    bool fpuRegModified(uint8_t)const;
    bool normRegModified(uint8_t)const;
    bool usedHeap()const noexcept;
    bool usedStack()const noexcept;
};
/*
Let `G=(V,E)`, V is set of nodes (instructions), E is set of edges. `\forall v\in V`, `type(v)\subseteq \{R,S,H\}`. R means this instruction writes to regsiters, S means it writes to data stack memory, H means it writes heap memory.

Let `P_m` be the largest weakly connected (treat edges as bidirectional) component/subgraph in `P=(G,E-E_1)`. Find `E_1` such that `|v(P_m)|<=maxSize|`: number of nodes (instructions) in the largest weakly connected component after removing edges in `E_1` is no larger than `maxSize`.

Let `A` be all possible `E_1`. Basically, all possible sets of edges matching the above constraint. Choose `E_2\in A` with the following optimization goals ranked in priority (smaller number=higher priority):
2. Let `W` be all the weakly connected components of `P=(G,E-E_1)`. `\forall w\in W`, define `usedHeap(w)=1\equiv\exist v\in v(w), H\in type(v)`, otherwise `usedHeap(w)=0`. Define `usedStack(w)` similarily.
Define `memFree(w)=1\equiv usedHeap(w)=0 \land usedStack(w)=0`, otherwise `memFree(w)=0`: a component is memory free iff no instruction in it writes to the data stack nor to the heap.
Find `E_2` that maximizes `\sigma_{w\in W}memFree(w)`. The goal is to group memory operations in the least amount of partitions, so that as many components as possible need no memory (both heap and stack) snapshot at all.
A call to external function has `usedStack(callInst)=0` if it's in `regOnlyExtFuncs`.

1. `\forall e\in E`, define `end(e)\in V` to be source or destination of this edge depending on `useSrc`. 
Find `E_2` that minimizes `|{end(e)|e\in E_2\in A}|`. The goal is to minimize the set of nodes that are sources or destinations of `E_2`. 

Finding `E_1` that matches the constraint shouldn't be hard, but finding the best `E_2` is NP. Therefore, you don't have to find the strict optimal: a good enough `E_2` fitting the constraint is fine.
The graph is produced by `buildEFG`, you may leverage special properties of it.

Return `B={end(e)|e\in \hat{E_2}}\subseteq V`. The keys in map will be the instructions(nodes) in B, values indicate whether it lives in a register-only component and what registers do instructions in this component modify (treat call to external functions to only modify r0).
*/
/*
We only supported a limited number of external functions, they are defined in "../../iter_bpf_helpers.cpp" and "../../maps/map_bpf_helpers.cpp"

Call to and exit (return) from local functions will change r10 and call stack (see "../src/compiler.cpp"). 

Call to external function never changes call stack nor r10 (see "../src/compiler.cpp"): it only sets r0 as return value. However, it may write to data stack, unless specified by `regOnlyExtFuncs`.

Assume eBPF instructions writing to offsets relative to r10 are writing to data stack only. Every other base register is treated as unresolved: assume such a write hits both data stack and heap. (The heap base pointer is provided as the initial value of r1, so writes relative to it are in principle heap-only, but recognising them needs dataflow that isn't implemented yet.)
*/
// regOnlyExtFuncs identifies external functions by the `imm` field of their
// CALL instruction, i.e. the same index passed to register_external_function.
std::unordered_map<uint16_t,CompInfo> partition1(const G_t,const std::vector<ebpf_inst>&,uint16_t maxSize,bool useSrc, const std::unordered_set<int32_t> &regOnlyExtFuncs)noexcept;

/*
Another mode for partitioning. The returned map is simply the set of all jump instructions (including calls and exits). 
Compute `CompInfo` on the graph after deleting the below sets of edges: (1) For conditional jumps, remove incoming edges to it. (2) For non conditional
jumps (including calls and exits), remove either incoming or outgoing edges, based on where `llvmbpf_vm::compileWithSS` inserts snapshots
relative to these instructions.
*/
std::unordered_map<uint16_t,CompInfo> partition2(const G_t,const std::vector<ebpf_inst>&, const std::unordered_set<int32_t> &regOnlyExtFuncs)noexcept;

/*
Similar to `partition1`, but uses a faster single-pass heuristic instead of
repeatedly evaluating every possible endpoint group:

1. Traverse each weak component.
2. Divide the traversal into regions containing at most `maxSize` instructions.
3. Select endpoint groups for edges crossing region boundaries.
4. Recompute the resulting components and their metadata.

The implementation is O(n+m) on average, assuming O(1)
unordered-container operations. It does not optimize the two optional quality
objectives described above.
*/
std::unordered_map<uint16_t,CompInfo> partition(const G_t,const std::vector<ebpf_inst>&,uint16_t maxSize,bool useSrc, const std::unordered_set<int32_t> &regOnlyExtFuncs)noexcept;

struct EFGStat{
    //statistics for each weakly connected component.
    uint16_t maxCompSize,minCompSize;
    // Q1, median, and Q3, using linear interpolation at (N-1)*p.
    double compSizeIQR[3];
    float meanCompSize,compSizeStdDev;

    /*
    A trail is a walk that doesn't have repeated edges, but may have repeated vertices. Here, the graph is produced by
    `buildEFG`. The length is number of edges in the trail.
    */
    uint32_t longestTrailBetweenBoundary;

    std::string toString()const noexcept;
};
/*
Compute metrics of a partitioned EFG. `boundary` are the information produced by `partition*` functions and passed to ``llvmbpf_vm::compileWithSS``.

When computing component information,
for each instruction (vertex) in `boundary` remove either incoming or outgoing edges based on where `compileWithSS` inserts snapshots (like `partition2`). For
example, if a snapshot is inserted after an instruction, then remove outgoing edges.

`longestTrailBetweenBoundary` is the longest trail between any 2 vertices (instructions) in boundary that doesn't cross a boundary vertex along the way. The 2 vertices for start and end may be the same, and the trail is directed.
Only trails that can be embedded in an entry-to-terminal-EXIT walk are counted, as determined by EFG reachability. Don't remove edges for trail computation.
*/

EFGStat metrics(const G_t,const std::vector<ebpf_inst>&,const std::unordered_map<uint16_t,CompInfo>&boundary/*only keys are needed, values are unnecesary for our analysis*/)noexcept;
#endif
