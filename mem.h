#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace mem {
    extern uint8_t* data;
    extern size_t size;
    extern size_t text_start;
    extern size_t text_end;
    extern bool is_arm64;

    bool open(const char* path);
    void close();

    uintptr_t find_str(const char* str);
    uintptr_t find_bytes(const char* sig);
    std::vector<uintptr_t> find_xrefs(uintptr_t target);
    std::vector<uintptr_t> find_bl_xrefs(uintptr_t target, size_t limit = 32);
    std::vector<uintptr_t> find_callers(uintptr_t target, size_t limit = 32);
    uintptr_t find_func(uintptr_t from);
    uintptr_t find_str_ref(const char* str);
    uintptr_t find_func_with_str(const char* str);
    uintptr_t find_nth_func_with_str(const char* str, int n);
}

static inline bool is_bl(uint32_t insn) {
    return (insn & 0xFC000000) == 0x94000000;
}
static inline bool is_b(uint32_t insn) {
    return (insn & 0xFC000000) == 0x14000000;
}
static inline bool is_ret(uint32_t insn) {
    return (insn & 0xFFFFFC00) == 0xD65F0000;
}
static inline bool is_cbz(uint32_t insn) {
    return (insn & 0x7F000000) == 0x34000000;
}
static inline bool is_cbnz(uint32_t insn) {
    return (insn & 0x7F000000) == 0x35000000;
}
static inline bool is_tbz(uint32_t insn) {
    return (insn & 0x7F000000) == 0x36000000;
}
static inline bool is_tbnz(uint32_t insn) {
    return (insn & 0x7F000000) == 0x37000000;
}
static inline bool is_blr(uint32_t insn) {
    return (insn & 0xFFFFFC00) == 0xD63F0000;
}
static inline bool is_adrp(uint32_t insn) {
    return (insn & 0x9F000000) == 0x90000000;
}
static inline bool is_add_imm(uint32_t insn) {
    return (insn & 0xFF000000) == 0x91000000;
}
static inline bool is_ldr64(uint32_t insn) {
    return (insn & 0xFFC00000) == 0xF9400000;
}
static inline bool is_str64(uint32_t insn) {
    return (insn & 0xFFC00000) == 0xF9000000;
}
static inline bool is_ldr32(uint32_t insn) {
    return (insn & 0xFFC00000) == 0xB9400000;
}
static inline bool is_ldrb(uint32_t insn) {
    return (insn & 0xFFC00000) == 0x39400000;
}
static inline bool is_mov_imm(uint32_t insn) {
    return (insn & 0x7F800000) == 0x52800000;
}
static inline bool is_movk(uint32_t insn) {
    return (insn & 0x7F800000) == 0x72800000;
}
static inline bool is_stp(uint32_t insn) {
    return (insn & 0xFFC00000) == 0xA9000000 ||
           (insn & 0xFFC00000) == 0xA9800000;
}
static inline bool is_sub_sp(uint32_t insn) {
    return (insn & 0xFF8003FF) == 0xD10003FF;
}
static inline bool is_func_prologue_vm(uint32_t insn) {
    return (insn & 0xFFC00000) == 0xA9800000 ||
           (insn & 0xFF8003FF) == 0xD10003FF ||
            insn == 0xD503233F;
}

static inline uintptr_t decode_bl(uint32_t insn, uintptr_t pc) {
    int64_t imm = (int64_t)(insn & 0x3FFFFFF);
    if (imm & 0x2000000) imm -= 0x4000000;
    return pc + (imm << 2);
}

static inline uintptr_t decode_adrp_add(uint32_t adrp, uint32_t add, uintptr_t pc) {
    uint64_t immhi = (adrp >> 5) & 0x7FFFF;
    uint64_t immlo = (adrp >> 29) & 3;
    int64_t imm = (int64_t)((immhi << 2) | immlo) << 12;
    if (imm & (1LL << 32)) imm |= ~((1LL << 33) - 1);
    uint64_t page = (pc & ~0xFFFULL) + (uint64_t)imm;
    return (uintptr_t)(page + ((add >> 10) & 0xFFF));
}

static inline uintptr_t decode_adrp_ldr(uint32_t adrp, uint32_t ldr, uintptr_t pc) {
    uint64_t immhi = (adrp >> 5) & 0x7FFFF;
    uint64_t immlo = (adrp >> 29) & 3;
    int64_t imm = (int64_t)((immhi << 2) | immlo) << 12;
    if (imm & (1LL << 32)) imm |= ~((1LL << 33) - 1);
    uint64_t page = (pc & ~0xFFFULL) + (uint64_t)imm;
    uint32_t sz = (ldr >> 30) & 3;
    return (uintptr_t)(page + (((ldr >> 10) & 0xFFF) << sz));
}

static inline uint32_t ldr64_imm(uint32_t insn) { return ((insn >> 10) & 0xFFF) << 3; }
static inline uint32_t ldr32_imm(uint32_t insn) { return ((insn >> 10) & 0xFFF) << 2; }
static inline uint32_t ldrb_imm(uint32_t insn)  { return  (insn >> 10) & 0xFFF; }
static inline uint32_t add_imm12(uint32_t insn)  { return  (insn >> 10) & 0xFFF; }
static inline uint32_t mov_imm_val(uint32_t insn){ return  (insn >>  5) & 0xFFFF; }
static inline uint32_t insn_rd(uint32_t insn)    { return   insn        & 0x1F; }
static inline uint32_t insn_rn(uint32_t insn)    { return  (insn >>  5) & 0x1F; }

static inline uintptr_t next_func_addr_vm(uintptr_t from) {
    if (from >= mem::text_end) return mem::text_end;
    for (uintptr_t pc = from + 4; pc < mem::text_end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_func_prologue_vm(insn)) return pc;
    }
    return mem::text_end;
}

static inline size_t func_size(uintptr_t addr) {
    return next_func_addr_vm(addr) - addr;
}

static inline uintptr_t nth_bl_target(uintptr_t func, int n) {
    uintptr_t end = next_func_addr_vm(func);
    int count = 0;
    for (uintptr_t pc = func; pc < end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_bl(insn)) {
            if (count == n) return decode_bl(insn, pc);
            count++;
        }
    }
    return 0;
}

static inline uintptr_t nth_bl_site(uintptr_t func, int n) {
    uintptr_t end = next_func_addr_vm(func);
    int count = 0;
    for (uintptr_t pc = func; pc < end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_bl(insn)) {
            if (count == n) return pc;
            count++;
        }
    }
    return 0;
}

static inline int count_bl(uintptr_t func) {
    uintptr_t end = next_func_addr_vm(func);
    int count = 0;
    for (uintptr_t pc = func; pc < end; pc += 4) {
        if (is_bl(*(uint32_t*)(mem::data + pc))) count++;
    }
    return count;
}

static inline bool func_has_ldr_imm(uintptr_t func, uint32_t imm) {
    uintptr_t end = next_func_addr_vm(func);
    for (uintptr_t pc = func; pc < end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if ((is_ldr64(insn) || is_str64(insn)) && ldr64_imm(insn) == imm) return true;
    }
    return false;
}

static inline bool func_has_insn(uintptr_t func, uint32_t needle) {
    uintptr_t end = next_func_addr_vm(func);
    for (uintptr_t pc = func; pc < end; pc += 4)
        if (*(uint32_t*)(mem::data + pc) == needle) return true;
    return false;
}

static inline uintptr_t func_find_insn(uintptr_t func, uint32_t pattern, uint32_t mask) {
    uintptr_t end = next_func_addr_vm(func);
    for (uintptr_t pc = func; pc < end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if ((insn & mask) == pattern) return pc;
    }
    return 0;
}

static inline uintptr_t find_bl_to(uintptr_t func, uintptr_t target) {
    uintptr_t end = next_func_addr_vm(func);
    for (uintptr_t pc = func; pc < end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_bl(insn) && decode_bl(insn, pc) == target) return pc;
    }
    return 0;
}
