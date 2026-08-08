#ifndef _BPFTIME_VM_LLVM_HPP
#define _BPFTIME_VM_LLVM_HPP

#include <memory>
#include <optional>
#include <vector>
#include <ebpf_inst.h>
#include <string>
#include<efg.hpp>

#ifndef MAX_EXT_FUNCS
#define MAX_EXT_FUNCS 8192
#endif

namespace bpftime
{

struct external_function {
	std::string name;
	void *fn;
};
struct ExecState{
	uint64_t normRegs[10];//r0-r9
	std::byte *heap, *dataStack, *callStack;//set before `compileWithSS` and remains constant until `exec` is done. user should ensure they've sufficient size.
	float fpuRegs[11];//fpu0-10.
	uint32_t dataStackOffset=0;//`stackEnd-(r10-frameSize)`: how many bytes of data stack are in use, including the frame currently being written. `frameSize` on entry, grows by frameSize per nested call. Live bytes occupy the end of the `frameSize*maxFuncNestDepth`-byte `dataStack` buffer. To restore: `r10=stackEnd-dataStackOffset+frameSize`.
	uint16_t callStackSize=0;//raw `callItemCnt`: number of call stack slots in use. `callStack` holds `callStackSize*sizeof(void*)` bytes. To restore: `callItemCnt=callStackSize`.
	uint16_t pc=0;//index of immediately next eBPF instruction after the snapshot that produced the current version of `ExecState`.
};
class llvm_bpf_jit_context;

// The JITed function signature.
// The JITed function can be called with a snapshot.
/*
When `snapshot!=nullptr`, resume execution from the state described within. This means, (1) Don't allocate float point registers, directly use `snapshot->fpuRegs`. Their size should match.
(2) Don't allocate storage for r0-r9, use `snapshot->normRegs`. r10 would still need to be allocated, but its value will be reconstructed from `snapshot->dataStackOffset`.
(3) Directly use `callStackSize` as `callItemCnt`. Even though the former is 2-byte, `callItemCnt` should never exceed uint16_t anyway. (4) Load `snapshot->heap` and `heapSize` into r1 and r2, respectively, to represent heap memory (similar to previous implementation). (5) Don't allocate call and data stack, directly use the one in `snapshot`.
(6) After setup, execute from eBPF instruction at `snapshot->pc` by jumping to it. All states are set, so execution should be able to properly resume. By using the things in `snapshot`, copying
is avoided.

When `snapshot==nullptr`, then `heapSize` is ignored (no heap). Stack memories and registers are allocated when executing the program, like previous implementation. Do the same when
the jitted function is called without any arguments.
*/
using precompiled_ebpf_function = uint64_t (*)(uint32_t heapSize,
					       ExecState *snapshot);


class llvmbpf_vm {
    public:
	llvmbpf_vm();
	~llvmbpf_vm(); // Destructor declared
	std::string get_error_message() noexcept;

	// register external function, e.g. helper functions for eBPF
	// return 0 on success
	int register_external_function(size_t index, const std::string &name,
				       void *fn) noexcept;

	// load the eBPF bytecode into the vm
	// The eBPF bytecode now can be JIT/AOT compiled
	// Or executed directly.
	// return 0 on success
	int load_code(const void *code, size_t code_len) noexcept;

	// unload the bytecode and remove the JIT/AOT compiled results
	void unload_code() noexcept;

	// execute the eBPF program
	// If the program is JIT compiled, it will be executed directly
	// If not, it will be JIT compiled, cached and executed
	// return 0 on success
	int exec(void *mem, size_t mem_len,
		 uint64_t &bpf_return_value) noexcept;

	// Do AOT compile and generate the ELF object file
	// The external functions are required to be registered before
	// calling this function. The compile result can be linked with
	// other object files to generate the final executable.
	// return the ELF object file content
	std::optional<std::vector<uint8_t> >
	do_aot_compile(bool print_ir = false) noexcept;

	// Load the AOT object file into the vm and link it with the
	// external functions
	// return the JITed function if success
	std::optional<precompiled_ebpf_function>
	load_aot_object(const std::vector<uint8_t> &object) noexcept;

	// Compile the eBPF program into a JITed function
	// return the JITed function if success
	std::optional<precompiled_ebpf_function> compile(uint8_t maxFuncNestDepth=8,uint16_t frameSize=10000) noexcept;


	/*
	Like `compile`, but with additional instructions that will store snapshots of registers and memory and location of snapshot into the provided pointer at `instInfo`.

	Consider instructions listed in `instInfo`. If the specified instruction is a conditional branch, insert snapshotting instructions right before it (otherwise we need to insert them at both true and false branch). 
	If the specified instruction is a normal register-modifing or memory-modifing instruction, snapshot right after it. If it's anything else (unconditional jumps), it doesn't matter whether the snapshot happens immediately before or after it.
	The above classifications should cover all instructions; let me know if there are exceptions.

	The heap memory to snapshot is the one passed to the jitted program at runtime (the `mem`/`mem_len` arguments of `precompiled_ebpf_function`); it is copied into `ExecState*->heap`.
	Both stack memory are allocated by the jitted program, they're copied into `ExeState*->callStack` and `dataStack`. Unlike heap, you don't have to copy entire stacks. It should be possible to determine what frames are touched using r10 and `callItemCnt`. In the worst case, the unused parts don't have to be copied. For example, suppose I have maxFuncNestDepth=8, but the jitted program only has real depth of 2, then the remaining 6 frames are never touched.

	Only snapshot what are changed in each component as described in `CompInfo`.

	After each snapshot, store the eBPF PC into `ExecState*->pc`. For example, suppose a snapshot was emitted between eBPF instruction A and B, i.e. A->snapshotting instructions->B, then `pc=indexOf(B)`. Basically, `pc` stores
	the next eBPF instruction to be executed. This way, the program can resume execution at arbitary instruction by jumping to it.

	To support execution resuming at compile time, do the following. (1) Find all potential resume targets. All eBPF instructions that a snapshot will happen before or after are described by
	`instInfo`, so resume targets are finite and can be determined compile time. Then, store the index of resume targets and where they correspond to in LLVM IR somewhere in the jitted program (can be hardcoded as well). (2) Af program start, load `ExecState*->pc` from
	provided arguments. Note that this `ExecState` is different from the argument `store`. `store` can be seen as the snapshot output, while the one in argument at runtime
	is the input. (3) Load the location of LLVM IR that eBPF instruction at `pc` corresponds to. (4) Jump to that location to resume exeuction. This describes instrumentation needed for jumping. Additional instrumentation for
	restoring register and memory states are described earlier in definition of `precompiled_ebpf_function`.
	*/
	/*Thoughts:
	Implementing execution resuming is hard. eBPF doesn't have a dynamic jump instruction, so if you want to do instrumentation at eBPF level, you
	would have to chain a bunch of conditional jumps. I'm not sure whether LLVM IR has dynamic jump instruction, but if it does, you can create a
	jump table.

	Finding where each eBPF instruction corresponds to in LLVM IR may also hard. I'm not sure if LLVM IR supports labeling to help you with the
	creation of jump tables.
	*/
	std::optional<precompiled_ebpf_function> compileWithSS(const ExecState* store,const std::unordered_map<uint16_t,CompInfo>& instInfo,uint8_t maxFuncNestDepth,uint16_t frameSize) noexcept;

	// See the spec for details.
	// If the code involve array map access, the map_val function
	// needs to be provided.
	// IF the map_by_fd, map_by_idx, var_addr, code_addr are not provided,
	// The are using imm as the address.
	void set_lddw_helpers(uint64_t (*map_by_fd)(uint32_t),
			      uint64_t (*map_by_idx)(uint32_t),
			      uint64_t (*map_val)(uint64_t),
			      uint64_t (*var_addr)(uint32_t),
			      uint64_t (*code_addr)(uint32_t)) noexcept;
	std::optional<std::string>
	generate_ptx(const char *target_cpu = "sm_60");
	std::optional<std::vector<uint8_t>>
	generate_spirv(const char *target_env = "");

	std::vector<ebpf_inst> instructions;//will be used by `buildEFG` to build the graph.

    private:
	// See spec for details
	uint64_t (*map_by_fd)(uint32_t) = nullptr;
	uint64_t (*map_by_idx)(uint32_t) = nullptr;
	uint64_t (*map_val)(uint64_t) = nullptr;
	uint64_t (*var_addr)(uint32_t) = nullptr;
	uint64_t (*code_addr)(uint32_t) = nullptr;

	/*
	There may be a need to implement a way for callers to specify `regOnlyExtFuncs` when calling `partition`. 

	At "../../bpfwrappers.cpp:77", `.compile` will be switched to `.compileWithSS`, so `buildEFG` and `partition` will be called just before that.
	*/
	std::vector<std::optional<external_function> > ext_funcs;

	std::unique_ptr<llvm_bpf_jit_context> jit_ctx;

	friend class llvm_bpf_jit_context;

	std::string error_msg;

	std::optional<precompiled_ebpf_function> jitted_function = std::nullopt;
	uint8_t compiled_max_func_nest_depth = 0;
	uint16_t compiled_frame_size = 0;
};

} // namespace bpftime

#endif // _BPFTIME_VM_LLVM_HPP
