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
	float fpuRegs[11];//fpu0-10.
	std::byte *mem;//memory. this pointer should be set before `compileWithSS` and remains constant until `exec` is done.
};
class llvm_bpf_jit_context;

// The JITed function signature.
// The JITed function can be called with the memory and memory length directly.
using precompiled_ebpf_function = uint64_t (*)(void *mem, size_t mem_len);

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
	std::optional<precompiled_ebpf_function> compile(uint8_t maxFuncNestDepth,uint16_t frameSize) noexcept;


	/*
	Like `compile`, but with additional instructions that will store snapshots of registers and memory into the provided pointer at `instInfo`.

	Consider instructions listed in `instInfo`. If the specified instruction is a conditional branch, insert snapshotting instructions right before it (otherwise we need to insert them at both true and false branch). 
	If the specified instruction is a normal register-modifing instruction, snapshot right after it. If it's anything else (unconditional jumps), it doesn't matter whether the snapshot happens immediately before or after it.
	The heap memory to snapshot is the one passed to the jitted program at runtime (the `mem`/`mem_len` arguments of `precompiled_ebpf_function`); it is copied into `ExecState*->mem`, which must therefore point to a buffer of at least `mem_len` bytes.

	Calls to external functions are considered register-modifing. Calls to local functions are unconditional jumps.

	Only snapshot registers mentioned in `CompInfo` of the corresponding instruction. Don't snapshot memory if the component of the instruction described in `CompInfo` is register-only.
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
};

} // namespace bpftime

#endif // _BPFTIME_VM_LLVM_HPP
