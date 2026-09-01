#include "llvmbpf.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace
{
constexpr uint8_t MAX_DEPTH = 3;
constexpr uint16_t FRAME_SIZE = 10480;
constexpr size_t DATA_STACK_SIZE = size_t(MAX_DEPTH) * FRAME_SIZE;
constexpr size_t CALL_STACK_SLOTS = size_t(MAX_DEPTH) * 5;
constexpr std::array<char, 8> MAGIC{ 'B', 'P', 'F', 'S', 'N', 'A', 'P', 0 };
constexpr uint16_t FORMAT_VERSION = 1;

struct Config {
	std::filesystem::path program_dir;
	bpftime::TimeLoc location;
};

struct Snapshot {
	alignas(8) std::array<std::byte, DATA_STACK_SIZE> data_stack{};
	alignas(8) std::array<
		std::byte, CALL_STACK_SLOTS * sizeof(uintptr_t)> call_stack{};
	bpftime::ExecState state{};

	Snapshot()
	{
		resetPointers();
	}
	Snapshot(const Snapshot &other)
		: data_stack(other.data_stack), call_stack(other.call_stack),
		  state(other.state)
	{
		rebasePointers(other);
		resetPointers();
	}
	Snapshot &operator=(const Snapshot &other)
	{
		if (this != &other) {
			data_stack = other.data_stack;
			call_stack = other.call_stack;
			state = other.state;
			rebasePointers(other);
			resetPointers();
		}
		return *this;
	}
	Snapshot(Snapshot &&other) noexcept : Snapshot(other)
	{
	}
	Snapshot &operator=(Snapshot &&other) noexcept
	{
		return *this = other;
	}

	void resetPointers()
	{
		state.heap = nullptr;
		state.dataStack = data_stack.data();
		state.callStack = call_stack.data();
	}

	void rebasePointers(const Snapshot &other)
	{
		const uint64_t old_base =
			reinterpret_cast<uintptr_t>(other.data_stack.data());
		const uint64_t old_end = old_base + other.data_stack.size();
		const uint64_t new_base =
			reinterpret_cast<uintptr_t>(data_stack.data());
		auto rebase = [&](uint64_t &value) {
			if (value >= old_base && value <= old_end)
				value = new_base + (value - old_base);
		};
		for (uint64_t &value : state.normRegs)
			rebase(value);
		for (uint16_t index = 0;
		     index <
		     std::min<uint16_t>(state.callStackSize, CALL_STACK_SLOTS);
		     ++index) {
			uintptr_t native{};
			std::memcpy(&native,
				    call_stack.data() + index * sizeof(native),
				    sizeof(native));
			uint64_t value = native;
			rebase(value);
			native = static_cast<uintptr_t>(value);
			std::memcpy(call_stack.data() + index * sizeof(native),
				    &native, sizeof(native));
		}
	}
};

std::string_view trim(std::string_view text)
{
	const size_t first = text.find_first_not_of(" \t\r\n");
	if (first == std::string_view::npos)
		return {};
	return text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}

long long integer(std::string_view text, const char *description)
{
	text = trim(text);
	long long value{};
	const auto result =
		std::from_chars(text.data(), text.data() + text.size(), value);
	if (result.ec != std::errc{} || result.ptr != text.data() + text.size())
		throw std::runtime_error(std::string("invalid ") + description);
	return value;
}

std::string scalar(std::string_view text)
{
	text = trim(text);
	if (text.size() >= 2 &&
	    ((text.front() == '\'' && text.back() == '\'') ||
	     (text.front() == '"' && text.back() == '"')))
		text = text.substr(1, text.size() - 2);
	return std::string(text);
}

Config loadConfig(const std::filesystem::path &path)
{
	std::ifstream file(path);
	if (!file)
		throw std::runtime_error("cannot open configuration: " +
					 path.string());
	std::optional<std::filesystem::path> program_dir;
	std::vector<bpftime::TimeLoc> locations;
	bool data = false;
	std::string line;
	while (std::getline(file, line)) {
		if (const size_t comment = line.find('#');
		    comment != std::string::npos)
			line.erase(comment);
		const std::string_view raw(line);
		const std::string_view text = trim(raw);
		if (text.empty())
			continue;
		if (!data && text.starts_with("dir:")) {
			program_dir = scalar(text.substr(4));
			continue;
		}
		if (text == "data:") {
			data = true;
			continue;
		}
		if (!data)
			continue;
		const size_t indentation = raw.find_first_not_of(" \t");
		if (indentation == 0 && text.starts_with("- ")) {
			const std::string_view item = trim(text.substr(2));
			const size_t colon = item.find(':');
			const long long pc =
				integer(colon == std::string_view::npos ?
						item :
						item.substr(0, colon),
					"program counter");
			if (pc < 0 || pc > std::numeric_limits<uint16_t>::max())
				throw std::runtime_error(
					"program counter is out of range");
			locations.push_back({ static_cast<uint16_t>(pc), {} });
		} else if (!locations.empty() && text.starts_with("- ")) {
			const std::string_view item = trim(text.substr(2));
			const size_t colon = item.find(':');
			if (colon == std::string_view::npos)
				throw std::runtime_error("invalid loop time");
			const long long offset =
				integer(item.substr(0, colon), "loop offset");
			const long long iteration = integer(
				item.substr(colon + 1), "loop iteration");
			if (offset < std::numeric_limits<int16_t>::min() ||
			    offset > std::numeric_limits<int16_t>::max())
				throw std::runtime_error(
					"loop offset is out of range");
			locations.back().time.push_back(
				{ static_cast<int16_t>(offset), iteration });
		}
	}
	if (!program_dir)
		throw std::runtime_error("configuration has no meta.dir");
	if (locations.size() != 1)
		throw std::runtime_error(
			"configuration must contain exactly one location");
	return { *program_dir, std::move(locations.front()) };
}

std::filesystem::path findProgram(const std::filesystem::path &config,
				  const std::filesystem::path &directory)
{
	if (directory.is_absolute() &&
	    std::filesystem::is_regular_file(directory / "a.o"))
		return directory / "a.o";
	for (auto root :
	     { std::filesystem::current_path(), config.parent_path() }) {
		for (;;) {
			const auto candidate = root / directory / "a.o";
			if (std::filesystem::is_regular_file(candidate))
				return candidate;
			if (!root.has_parent_path() ||
			    root == root.parent_path())
				break;
			root = root.parent_path();
		}
	}
	throw std::runtime_error("cannot find " + (directory / "a.o").string());
}

std::vector<std::byte> readBytes(const std::filesystem::path &path,
				 const char *description)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file)
		throw std::runtime_error(std::string("cannot open ") +
					 description + ": " + path.string());
	const auto length = file.tellg();
	if (length < 0)
		throw std::runtime_error(std::string("cannot size ") +
					 description);
	std::vector<std::byte> bytes(static_cast<size_t>(length));
	file.seekg(0);
	if (!bytes.empty() &&
	    !file.read(reinterpret_cast<char *>(bytes.data()), length))
		throw std::runtime_error(std::string("cannot read ") +
					 description);
	return bytes;
}

template <class T> void put(std::vector<std::byte> &bytes, T value)
{
	static_assert(std::is_unsigned_v<T>);
	for (unsigned shift = 0; shift < sizeof(T) * 8; shift += 8)
		bytes.push_back(std::byte((value >> shift) & 0xff));
}

template <class T> T get(const std::vector<std::byte> &bytes, size_t &position)
{
	static_assert(std::is_unsigned_v<T>);
	if (position > bytes.size() || bytes.size() - position < sizeof(T))
		throw std::runtime_error("snapshot is truncated");
	T value{};
	for (unsigned shift = 0; shift < sizeof(T) * 8; shift += 8)
		value |= T(std::to_integer<uint8_t>(bytes[position++]))
			 << shift;
	return value;
}

bool stackPointer(uint64_t value, const Snapshot &snapshot, uint64_t &offset)
{
	const auto begin =
		reinterpret_cast<uintptr_t>(snapshot.data_stack.data());
	const auto end = begin + snapshot.data_stack.size();
	if (value < begin || value > end)
		return false;
	offset = value - begin;
	return true;
}

struct ArrayMap {
	std::vector<uint32_t> values;
};
constexpr std::array<uint32_t, 22> MAP_SIZES{ 7,   7,	 7,  7,	 7,  100,
					      100, 100,	 6,  3,	 16, 256,
					      16,  2500, 25, 16, 20, 16,
					      4,   64,	 1,  11 };
std::array<ArrayMap, MAP_SIZES.size()> maps;
uint32_t random_state = 1;

bool mapPointer(uint64_t value, uint64_t &portable)
{
	for (size_t fd = 0; fd < maps.size(); ++fd) {
		if (value == reinterpret_cast<uintptr_t>(&maps[fd])) {
			portable = (uint64_t(fd) << 32) | 0xffffffffU;
			return true;
		}
		const uint64_t begin =
			reinterpret_cast<uintptr_t>(maps[fd].values.data());
		const uint64_t size = maps[fd].values.size() * sizeof(uint32_t);
		if (value >= begin && value < begin + size) {
			portable = (uint64_t(fd) << 32) | (value - begin);
			return true;
		}
	}
	return false;
}

uint64_t restoreMapPointer(uint64_t portable)
{
	const uint64_t fd = portable >> 32;
	const uint64_t offset = portable & 0xffffffffU;
	if (fd >= maps.size())
		throw std::runtime_error("invalid map relocation");
	if (offset == 0xffffffffU)
		return reinterpret_cast<uintptr_t>(&maps[fd]);
	if (offset >= maps[fd].values.size() * sizeof(uint32_t))
		throw std::runtime_error("invalid map-value relocation");
	return reinterpret_cast<uintptr_t>(maps[fd].values.data()) + offset;
}

std::vector<std::byte> encode(const Snapshot &snapshot)
{
	const auto &state = snapshot.state;
	if (state.dataStackOffset > DATA_STACK_SIZE ||
	    state.callStackSize > CALL_STACK_SLOTS)
		throw std::runtime_error("JIT produced invalid stack sizes");
	std::vector<std::byte> bytes;
	for (char value : MAGIC)
		put<uint8_t>(bytes, static_cast<uint8_t>(value));
	put<uint16_t>(bytes, FORMAT_VERSION);
	put<uint8_t>(bytes, MAX_DEPTH);
	put<uint8_t>(bytes, 0);
	put<uint16_t>(bytes, FRAME_SIZE);
	put<uint16_t>(bytes, 0);

	uint16_t register_relocations = 0;
	uint16_t register_map_relocations = 0;
	std::array<uint64_t, 10> registers{};
	for (size_t index = 0; index < registers.size(); ++index) {
		registers[index] = state.normRegs[index];
		if (stackPointer(registers[index], snapshot, registers[index]))
			register_relocations |= uint16_t(1U << index);
		else if (mapPointer(registers[index], registers[index]))
			register_map_relocations |= uint16_t(1U << index);
	}
	uint16_t call_relocations = 0;
	uint16_t call_map_relocations = 0;
	std::array<uint64_t, CALL_STACK_SLOTS> call_values{};
	for (uint16_t index = 0; index < state.callStackSize; ++index) {
		uintptr_t value{};
		std::memcpy(&value,
			    snapshot.call_stack.data() + index * sizeof(value),
			    sizeof(value));
		call_values[index] = value;
		if (stackPointer(call_values[index], snapshot,
				 call_values[index]))
			call_relocations |= uint16_t(1U << index);
		else if (mapPointer(call_values[index], call_values[index]))
			call_map_relocations |= uint16_t(1U << index);
	}
	put<uint16_t>(bytes, register_relocations);
	put<uint16_t>(bytes, call_relocations);
	put<uint16_t>(bytes, register_map_relocations);
	put<uint16_t>(bytes, call_map_relocations);
	for (uint64_t value : registers)
		put<uint64_t>(bytes, value);
	for (float value : state.fpuRegs)
		put<uint32_t>(bytes, std::bit_cast<uint32_t>(value));
	put<uint32_t>(bytes, state.dataStackOffset);
	put<uint16_t>(bytes, state.callStackSize);
	put<uint16_t>(bytes, state.pc);
	bytes.insert(bytes.end(),
		     snapshot.data_stack.end() - state.dataStackOffset,
		     snapshot.data_stack.end());
	for (uint16_t index = 0; index < state.callStackSize; ++index)
		put<uint64_t>(bytes, call_values[index]);
	return bytes;
}

Snapshot decode(const std::filesystem::path &path)
{
	const auto bytes = readBytes(path, "snapshot");
	size_t position = 0;
	for (char expected : MAGIC)
		if (get<uint8_t>(bytes, position) !=
		    static_cast<uint8_t>(expected))
			throw std::runtime_error("snapshot magic is invalid");
	if (get<uint16_t>(bytes, position) != FORMAT_VERSION)
		throw std::runtime_error("snapshot version is not supported");
	if (get<uint8_t>(bytes, position) != MAX_DEPTH)
		throw std::runtime_error(
			"snapshot function depth does not match");
	(void)get<uint8_t>(bytes, position);
	if (get<uint16_t>(bytes, position) != FRAME_SIZE)
		throw std::runtime_error("snapshot frame size does not match");
	(void)get<uint16_t>(bytes, position);
	const uint16_t register_relocations = get<uint16_t>(bytes, position);
	const uint16_t call_relocations = get<uint16_t>(bytes, position);
	const uint16_t register_map_relocations =
		get<uint16_t>(bytes, position);
	const uint16_t call_map_relocations = get<uint16_t>(bytes, position);
	if ((register_relocations & register_map_relocations) != 0 ||
	    (call_relocations & call_map_relocations) != 0)
		throw std::runtime_error("snapshot relocation tables overlap");
	Snapshot snapshot;
	for (uint64_t &value : snapshot.state.normRegs)
		value = get<uint64_t>(bytes, position);
	for (float &value : snapshot.state.fpuRegs)
		value = std::bit_cast<float>(get<uint32_t>(bytes, position));
	snapshot.state.dataStackOffset = get<uint32_t>(bytes, position);
	snapshot.state.callStackSize = get<uint16_t>(bytes, position);
	snapshot.state.pc = get<uint16_t>(bytes, position);
	if (snapshot.state.dataStackOffset > DATA_STACK_SIZE ||
	    snapshot.state.callStackSize > CALL_STACK_SLOTS)
		throw std::runtime_error("snapshot stack size is invalid");
	const size_t stack_bytes = snapshot.state.dataStackOffset;
	const size_t call_bytes = size_t(snapshot.state.callStackSize) * 8;
	if (position > bytes.size() ||
	    bytes.size() - position != stack_bytes + call_bytes)
		throw std::runtime_error("snapshot size is invalid");
	std::copy_n(bytes.begin() + position, stack_bytes,
		    snapshot.data_stack.end() - stack_bytes);
	position += stack_bytes;
	const uint64_t stack_base =
		reinterpret_cast<uintptr_t>(snapshot.data_stack.data());
	for (size_t index = 0; index < 10; ++index) {
		if (register_relocations & (1U << index)) {
			if (snapshot.state.normRegs[index] > DATA_STACK_SIZE)
				throw std::runtime_error(
					"invalid register relocation");
			snapshot.state.normRegs[index] += stack_base;
		} else if (register_map_relocations & (1U << index))
			snapshot.state.normRegs[index] = restoreMapPointer(
				snapshot.state.normRegs[index]);
	}
	for (uint16_t index = 0; index < snapshot.state.callStackSize;
	     ++index) {
		uint64_t value = get<uint64_t>(bytes, position);
		if (call_relocations & (1U << index)) {
			if (value > DATA_STACK_SIZE)
				throw std::runtime_error(
					"invalid call-stack relocation");
			value += stack_base;
		} else if (call_map_relocations & (1U << index))
			value = restoreMapPointer(value);
		if (value > std::numeric_limits<uintptr_t>::max())
			throw std::runtime_error(
				"call-stack value does not fit this ISA");
		const uintptr_t native = static_cast<uintptr_t>(value);
		std::memcpy(snapshot.call_stack.data() + index * sizeof(native),
			    &native, sizeof(native));
	}
	return snapshot;
}

void writeSnapshot(const std::vector<std::byte> &bytes)
{
	const std::filesystem::path temporary = "state.bin.tmp";
	{
		std::ofstream file(temporary,
				   std::ios::binary | std::ios::trunc);
		if (!file ||
		    !file.write(reinterpret_cast<const char *>(bytes.data()),
				bytes.size()))
			throw std::runtime_error("cannot write state.bin.tmp");
	}
	std::error_code error;
	std::filesystem::rename(temporary, "state.bin", error);
	if (error) {
		std::filesystem::remove("state.bin", error);
		error.clear();
		std::filesystem::rename(temporary, "state.bin", error);
	}
	if (error)
		throw std::runtime_error("cannot replace state.bin: " +
					 error.message());
}

uint32_t randomValue()
{
	random_state = random_state * 1664525U + 1013904223U;
	return random_state;
}
void initializeRuntime()
{
	random_state = 1;
	for (size_t fd = 0; fd < maps.size(); ++fd) {
		maps[fd].values.resize(MAP_SIZES[fd]);
		for (uint32_t &value : maps[fd].values)
			value = randomValue();
	}
}
uint64_t mapByFd(uint32_t fd)
{
	return fd < maps.size() ? reinterpret_cast<uint64_t>(&maps[fd]) : 0;
}
uint64_t mapByIndex(uint32_t index)
{
	return mapByFd(index);
}
uint64_t mapValue(uint64_t pointer)
{
	auto *map = reinterpret_cast<ArrayMap *>(pointer);
	return map && !map->values.empty() ?
		       reinterpret_cast<uint64_t>(map->values.data()) :
		       0;
}
void *mapLookup(void *pointer, const void *key_pointer)
{
	auto *map = static_cast<ArrayMap *>(pointer);
	if (!map || !key_pointer)
		return nullptr;
	const uint32_t key = *static_cast<const uint32_t *>(key_pointer);
	return key < map->values.size() ? &map->values[key] : nullptr;
}
int64_t mapUpdate(void *pointer, const void *key, const void *input, uint64_t)
{
	auto *value = static_cast<uint32_t *>(mapLookup(pointer, key));
	if (!value || !input)
		return -7;
	std::memcpy(value, input, sizeof(*value));
	return 0;
}
int64_t mapDelete(void *, const void *)
{
	return -22;
}

struct Iterator {
	uint64_t fd;
	int64_t start;
	int64_t end;
	int64_t current;
};
uint32_t iteratorNew(Iterator *it, int32_t start, int32_t end)
{
	if (!it || start > end) {
		if (it)
			it->fd = 0;
		return std::numeric_limits<uint32_t>::max();
	}
	it->fd = 1;
	it->start = start;
	it->end = end;
	it->current = int64_t(start) - 1;
	return 0;
}
int64_t *iteratorNext(Iterator *it)
{
	if (!it || it->fd != 1 || ++it->current >= it->end)
		return nullptr;
	return &it->current;
}
void iteratorDestroy(Iterator *it)
{
	if (it)
		it->fd = 2;
}
int32_t randomInteger(int32_t minimum, int32_t maximum)
{
	if (minimum > maximum)
		return minimum;
	const uint64_t range = uint64_t(int64_t(maximum) - minimum) + 1;
	// This helper has no state argument that ExecState can preserve. Use a
	// call-independent value so a resumed run matches a fresh run.
	return int32_t(minimum + 0x9e3779b9U % range);
}
template <class F> int32_t floatUnary(int32_t bits, F function)
{
	return std::bit_cast<int32_t>(function(std::bit_cast<float>(bits)));
}
int32_t squareRoot(int32_t bits)
{
	return floatUnary(bits, [](float x) { return std::sqrt(x); });
}
int32_t sine(int32_t bits)
{
	return floatUnary(bits, [](float x) { return std::sin(x); });
}
int32_t cosine(int32_t bits)
{
	return floatUnary(bits, [](float x) { return std::cos(x); });
}
int32_t arcTangent(int32_t x, int32_t y)
{
	return std::bit_cast<int32_t>(
		std::atan2(std::bit_cast<float>(x), std::bit_cast<float>(y)));
}

void registerRuntime(bpftime::llvmbpf_vm &vm)
{
	vm.set_lddw_helpers(mapByFd, mapByIndex, mapValue, nullptr, nullptr);
	const std::array<std::pair<size_t, void *>, 11> helpers{
		std::pair<size_t, void *>{
			1, reinterpret_cast<void *>(mapLookup) },
		{ 2, reinterpret_cast<void *>(mapUpdate) },
		{ 3, reinterpret_cast<void *>(mapDelete) },
		{ 5, reinterpret_cast<void *>(iteratorNew) },
		{ 6, reinterpret_cast<void *>(iteratorNext) },
		{ 7, reinterpret_cast<void *>(iteratorDestroy) },
		{ 8, reinterpret_cast<void *>(randomInteger) },
		{ 9, reinterpret_cast<void *>(squareRoot) },
		{ 10, reinterpret_cast<void *>(sine) },
		{ 11, reinterpret_cast<void *>(cosine) },
		{ 13, reinterpret_cast<void *>(arcTangent) }
	};
	for (const auto &[id, function] : helpers)
		if (vm.register_external_function(
			    id, "e2e_helper_" + std::to_string(id), function))
			throw std::runtime_error("cannot register helper " +
						 std::to_string(id));
}

int run(int argc, char **argv)
{
	if (argc != 2 && argc != 3) {
		std::cerr << "Usage: " << argv[0]
			  << " CONFIG [INPUT_SNAPSHOT]\n";
		return 2;
	}
	const std::filesystem::path config_path = argv[1];
	const Config config = loadConfig(config_path);
	const auto program_path = findProgram(config_path, config.program_dir);
	const auto program = readBytes(program_path, "program");
	if (program.empty())
		throw std::runtime_error("program is empty");

	initializeRuntime();
	bpftime::llvmbpf_vm vm;
	registerRuntime(vm);
	if (vm.load_code(program.data(), program.size()))
		throw std::runtime_error("cannot load program: " +
					 vm.get_error_message());

	Snapshot output;
	std::optional<Snapshot> input;
	std::vector<std::byte> input_bytes;
	if (argc == 3) {
		input.emplace(decode(argv[2]));
		input_bytes = encode(*input);
		output = *input;
	}
	const std::vector<bpftime::TimeLoc> locations{ config.location };
	const std::vector<uint16_t> resume_pcs =
		input ? std::vector<uint16_t>{ input->state.pc } :
			std::vector<uint16_t>{};
	if (!vm.compileWithSS2(&output.state, MAX_DEPTH, FRAME_SIZE, locations,
			       resume_pcs))
		throw std::runtime_error("cannot compile program: " +
					 vm.get_error_message());
	uint64_t return_value{};
	const int status = input ? vm.resume(0, &input->state, return_value) :
				   vm.exec(nullptr, 0, return_value);
	if (status)
		throw std::runtime_error("program execution failed: " +
					 vm.get_error_message());
	const auto output_bytes = encode(output);
	const bool changed = !input || output_bytes != input_bytes;
	if (changed)
		writeSnapshot(output_bytes);
	std::cout << "program=" << program_path.string()
		  << " return=" << return_value
		  << " snapshot_pc=" << output.state.pc
		  << " snapshot=" << (changed ? "written" : "unchanged");
	if (input)
		std::cout << " resume_cycles=" << input->state.resumeCycles;
	std::cout << '\n';
	return 0;
}
} // namespace

int main(int argc, char **argv)
{
	try {
		return run(argc, argv);
	} catch (const std::exception &error) {
		std::cerr << "llvmbpf-e2e: " << error.what() << '\n';
		return 1;
	}
}
