#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace mem {
    extern uint8_t* data;
    extern size_t size;
    extern size_t text_start;
    extern size_t text_end;
    bool open(const char* path);
    void close();
    uintptr_t find_str(const char* str);
    uintptr_t find_bytes(const char* sig);
    std::vector<uintptr_t> find_xrefs(uintptr_t target);
    uintptr_t find_func(uintptr_t from);
}
