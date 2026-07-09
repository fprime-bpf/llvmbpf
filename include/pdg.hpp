#ifndef BPFTIME_LLVM_BPF_PDG_HPP
#define BPFTIME_LLVM_BPF_PDG_HPP

#include <bitset>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <variant>
#include <vector>

#include <ebpf_inst.h>

#ifndef MAX_BPF_STACK
#define MAX_BPF_STACK 512
#endif

enum class PDValueKind : uint8_t {
	Unknown,
	Int,
	Float,
	StackPtr,
	MapPtr,
	MapValuePtr,
};

struct IntInterval {
	uint64_t lo = 0;
	uint64_t hi = std::numeric_limits<uint64_t>::max();
};

class IntValue {
    public:
	IntValue() = default;
	explicit IntValue(uint64_t value) : ranges_({ { value, value } }) {}
	explicit IntValue(std::vector<IntInterval> ranges);

	static IntValue unknown();
	static IntValue signedImm(int32_t imm);
	static IntValue unsigned32(uint32_t value);

	bool exact() const noexcept;
	std::optional<uint64_t> exactValue() const noexcept;
	bool unknownRange() const noexcept;
	const std::vector<IntInterval> &ranges() const noexcept { return ranges_; }

	IntValue trunc32() const;
	IntValue signExtendFrom(unsigned bits) const;
	IntValue byteSwap(unsigned bits) const;

	IntValue add(const IntValue &rhs, bool bits64) const;
	IntValue sub(const IntValue &rhs, bool bits64) const;
	IntValue mul(const IntValue &rhs, bool bits64) const;
	IntValue udiv(const IntValue &rhs, bool bits64) const;
	IntValue umod(const IntValue &rhs, bool bits64) const;
	IntValue bitAnd(const IntValue &rhs, bool bits64) const;
	IntValue bitOr(const IntValue &rhs, bool bits64) const;
	IntValue bitXor(const IntValue &rhs, bool bits64) const;
	IntValue lsh(const IntValue &rhs, bool bits64) const;
	IntValue rsh(const IntValue &rhs, bool bits64) const;
	IntValue arsh(const IntValue &rhs, bool bits64) const;
	IntValue neg(bool bits64) const;

    private:
	std::vector<IntInterval> ranges_ = {
		{ 0, std::numeric_limits<uint64_t>::max() }
	};
};

class StackPtrValue {
    public:
	StackPtrValue();
	explicit StackPtrValue(int offset);

	bool exact() const noexcept;
	bool contains(int offset) const noexcept;
	std::optional<int> exactOffset() const noexcept;
	std::vector<int> offsets() const;

	StackPtrValue add(const IntValue &offset) const;
	StackPtrValue sub(const IntValue &offset) const;

    private:
	std::bitset<MAX_BPF_STACK + 1> candidates_;
};

struct MapPtrValue {
	uint16_t id = 0;
};

struct MapValuePtr {
};

using PDValue =
	std::variant<std::monostate, IntValue, StackPtrValue, MapPtrValue,
		     MapValuePtr>;

PDValueKind kindOf(const PDValue &value) noexcept;
bool exactValue(const PDValue &value) noexcept;

enum class Dep : uint8_t {
	Int = 0,
	FPU = 1,
	Map = 2,
	Stack = 3,
	Conditional = 0x04,
	Potential = 0x08,
};

constexpr Dep operator|(Dep lhs, Dep rhs) noexcept
{
	return static_cast<Dep>(static_cast<uint8_t>(lhs) |
				static_cast<uint8_t>(rhs));
}

constexpr Dep operator&(Dep lhs, Dep rhs) noexcept
{
	return static_cast<Dep>(static_cast<uint8_t>(lhs) &
				static_cast<uint8_t>(rhs));
}

constexpr Dep &operator|=(Dep &lhs, Dep rhs) noexcept
{
	lhs = lhs | rhs;
	return lhs;
}

constexpr bool hasDepFlag(Dep value, Dep flag) noexcept
{
	return (static_cast<uint8_t>(value) & static_cast<uint8_t>(flag)) != 0;
}

struct PDEdge {
	uint16_t dst = 0;
	Dep type = Dep::Int;
};

using PDGraph = std::vector<std::vector<PDEdge> >;

PDGraph buildPDG(const std::vector<ebpf_inst> &instructions);
std::vector<uint16_t> partitionPDG(const PDGraph &graph,
				   uint16_t maxPartitionSize);

#endif
