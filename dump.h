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
};

extern std::vector<scan> scans;

uintptr_t process(const scan& s, uintptr_t addr);
void print_scan(const scan& s, uintptr_t result, std::string& last_section);
