#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct scan {
    std::string name;
    std::string pattern;
    std::string sig;
    int up = 0;
    int down = 0;
    bool offset = false;
    ptrdiff_t byte_offset = 0;
};

extern std::vector<scan> scans;

uintptr_t process(const scan& s, uintptr_t addr);
void resolve_tasks(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_fields(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_vm_offsets(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_getcapabilities(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_tsconstrctor(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_tsdecoffsets(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolvejobevents(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_network_telemetry(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_lua_index2addr(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_luau_push_helpers(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_miscstuff(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_luauyeildoffsets(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void resolve_lua_load(const std::vector<scan>& scans, std::vector<uintptr_t>& results);
void print_scan(const scan& s, uintptr_t result, std::string& last_section);
void dump_all_fflags(const std::string& output_path);
