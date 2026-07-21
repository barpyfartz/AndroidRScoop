#include "mem.h"
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif
#define RST "\033[0m"
#define GRY "\033[90m"
#pragma pack(push, 1)
struct Elf64_Ehdr {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};
#pragma pack(pop)

#define ELFMAG "\177ELF"
#define SELFMAG 4
#define EM_AARCH64 183
#define EM_X86_64 62

namespace mem {
    uint8_t* data = nullptr;
    size_t size = 0;
    size_t text_start = 0;
    size_t text_end = 0;
    size_t mapped_size = 0;
    bool is_arm64 = false;

#ifdef _WIN32
    static HANDLE h_file = INVALID_HANDLE_VALUE;
    static HANDLE h_map = NULL;
#else
    static int fd = -1;
#endif

    static inline bool is_adrp(uint32_t insn) {
        return (insn & 0x9F000000) == 0x90000000;
    }

    static inline bool is_add_imm(uint32_t insn) {
        return (insn & 0xFF000000) == 0x91000000;
    }

    static inline uint64_t decode_add_imm(uint32_t insn) {
        return (insn >> 10) & 0xFFF;
    }

    static inline bool is_ldr_imm(uint32_t insn) {
        return (insn & 0xFFC00000) == 0xB9400000;
    }

    static inline uint64_t decode_ldr_imm(uint32_t insn) {
        return ((insn >> 10) & 0xFFF) << ((insn >> 30) & 1);
    }

    bool open(const char* path) {
#ifdef _WIN32
        h_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h_file == INVALID_HANDLE_VALUE) return false;
        DWORD size_high = 0;
        DWORD size_low = GetFileSize(h_file, &size_high);
        size = ((size_t)size_high << 32) | size_low;
        mapped_size = (size + 4095) & ~4095ULL;
        h_map = CreateFileMappingA(h_file, NULL, PAGE_READONLY, size_high, size_low, NULL);
        if (!h_map) { CloseHandle(h_file); return false; }
        data = (uint8_t*)MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0);
        if (!data) { CloseHandle(h_map); CloseHandle(h_file); return false; }
#else
        fd = ::open(path, O_RDONLY);
        if (fd < 0) return false;
        struct stat st;
        if (fstat(fd, &st) < 0) { ::close(fd); return false; }
        size = st.st_size;
        mapped_size = (size + 4095) & ~4095ULL;
        data = (uint8_t*)mmap(nullptr, mapped_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (data == MAP_FAILED) { ::close(fd); fd = -1; data = nullptr; return false; }
#endif

        if (size < sizeof(Elf64_Ehdr)) { mem::close(); return false; }

        Elf64_Ehdr* elf = (Elf64_Ehdr*)data;
        if (memcmp(elf->e_ident, ELFMAG, SELFMAG) != 0) { mem::close(); return false; }

        if (elf->e_machine == EM_AARCH64) {
            is_arm64 = true;
            std::cout << GRY << "[ARM64] " << RST;
        } else if (elf->e_machine == EM_X86_64) {
            is_arm64 = false;
            std::cout << GRY << "[x86_64] " << RST;
        } else {
            std::cout << GRY << "[unknown arch] " << RST;
        }

        if (elf->e_shoff + elf->e_shnum * sizeof(Elf64_Shdr) > size) { mem::close(); return false; }
        Elf64_Shdr* shdrs = (Elf64_Shdr*)(data + elf->e_shoff);
        char* shstrtab = (char*)(data + shdrs[elf->e_shstrndx].sh_offset);

        text_start = 0;
        text_end = 0;
        for (int i = 0; i < elf->e_shnum; i++) {
            if (strcmp(&shstrtab[shdrs[i].sh_name], ".text") == 0) {
                text_start = shdrs[i].sh_offset;
                text_end = text_start + shdrs[i].sh_size;
                break;
            }
        }

        if (!text_start || !text_end) { mem::close(); return false; }
        return true;
    }

    void close() {
#ifdef _WIN32
        if (data) { UnmapViewOfFile(data); data = nullptr; }
        if (h_map) { CloseHandle(h_map); h_map = NULL; }
        if (h_file != INVALID_HANDLE_VALUE) { CloseHandle(h_file); h_file = INVALID_HANDLE_VALUE; }
#else
        if (data) { munmap(data, mapped_size); data = nullptr; }
        if (fd >= 0) { ::close(fd); fd = -1; }
#endif
        size = 0;
        is_arm64 = false;
    }

    uintptr_t find_str(const char* str) {
        size_t len = strlen(str);
        if (!len || size < len) return 0;

        for (size_t i = 0; i <= size - len; i++) {
            if (memcmp(data + i, str, len) == 0)
                return i;
        }
        return 0;
    }

    uintptr_t find_bytes(const char* sig) {
        std::vector<uint8_t> bytes;
        std::vector<bool> mask;

        const char* p = sig;
        while (*p) {
            while (*p == ' ') p++;
            if (!*p) break;
            if (p[0] == '?' && p[1] == '?') {
                bytes.push_back(0);
                mask.push_back(false);
                p += 2;
            } else {
                bytes.push_back((uint8_t)strtol(p, nullptr, 16));
                mask.push_back(true);
                p += 2;
            }
        }

        size_t len = bytes.size();
        if (!len || text_end < text_start + len) return 0;

        size_t limit = text_end - len;
        for (size_t i = text_start; i <= limit; i++) {
            bool match = true;
            for (size_t k = 0; k < len && match; k++)
                if (mask[k] && data[i + k] != bytes[k]) match = false;
            if (match) return i;
        }
        return 0;
    }

    std::vector<uintptr_t> find_bl_xrefs(uintptr_t target) {
        std::vector<uintptr_t> results;
        if (!is_arm64 || !text_start || !text_end) return results;
        size_t begin = (text_start + 3) & ~3ULL;
        size_t end = text_end - 4;
        for (size_t i = begin; i < end; i += 4) {
            uint32_t insn = *(uint32_t*)(data + i);
            if ((insn & 0xFC000000) != 0x94000000) continue;
            int64_t imm = (insn & 0x3FFFFFF);
            if (imm & 0x2000000) imm -= 0x4000000;
            uintptr_t dest = i + (imm << 2);
            if (dest == target) {
                results.push_back(i);
                if (results.size() >= 32) break;
            }
        }
        return results;
    }

    std::vector<uintptr_t> find_xrefs(uintptr_t target) {
        std::vector<uintptr_t> results;
        if (!text_start || !text_end) return results;

        if (is_arm64) {
            size_t begin = (text_start + 3) & ~3ULL;
            size_t end = text_end - 8;

            for (size_t i = begin; i < end; i += 4) {
                uint32_t* code = (uint32_t*)(data + i);
                uint32_t insn1 = code[0];
                uint32_t insn2 = code[1];

                if (!is_adrp(insn1)) continue;

                uint64_t immhi = (insn1 >> 5) & 0x7FFFF;
                uint64_t immlo = (insn1 >> 29) & 3;
                int64_t imm = (int64_t)((immhi << 2) | immlo) << 12;
                if (imm & (1LL << 32)) imm |= ~((1LL << 33) - 1);
                uint64_t page_base = (i & ~0xFFFULL) + (uint64_t)imm;

                uint64_t add_val = 0;
                if (is_add_imm(insn2)) {
                    add_val = decode_add_imm(insn2);
                } else if (is_ldr_imm(insn2)) {
                    add_val = decode_ldr_imm(insn2);
                } else {
                    continue;
                }

                if (page_base + add_val == (uint64_t)target) {
                    results.push_back(i);
                    if (results.size() >= 8) break;
                }
            }
        } else {
            const uint8_t* d = data;
            size_t end = text_end - 7;

            for (size_t i = text_start; i < end; i++) {
                if ((d[i] & 0xF8) == 0x48) {
                    uint8_t b1 = d[i + 1];
                    if ((b1 & 0xF6) == 0x84) {
                        uint8_t b2 = d[i + 2];
                        if ((b2 & 0xC7) == 0x05) {
                            uint32_t disp = *(uint32_t*)(d + i + 3);
                            if (i + 7 + disp == target) results.push_back(i);
                        }
                    } else if (b1 == 0x8D) {
                        uint8_t b2 = d[i + 2];
                        if ((b2 & 0xC7) == 0x05) {
                            uint32_t disp = *(uint32_t*)(d + i + 3);
                            if (i + 7 + disp == target) results.push_back(i);
                        }
                    }
                } else if (d[i] == 0x8D) {
                    uint8_t b1 = d[i + 1];
                    if ((b1 & 0xC7) == 0x05) {
                        uint32_t disp = *(uint32_t*)(d + i + 2);
                        if (i + 6 + disp == target) results.push_back(i);
                    }
                }
            }
        }
        return results;
    }

    static inline bool is_func_prologue(uint32_t insn) {
        return (insn & 0xFFC00000) == 0xA9800000 ||
               (insn & 0xFF8003FF) == 0xD10003FF ||
               insn == 0xD503233F;
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
    
    static inline bool is_adrp_pub(uint32_t insn) {
        return (insn & 0x9F000000) == 0x90000000;
    }
    
    static inline bool is_add_imm_pub(uint32_t insn) {
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
        uint64_t off  = (add >> 10) & 0xFFF;
        return (uintptr_t)(page + off);
    }
    
    static inline uintptr_t decode_adrp_ldr(uint32_t adrp, uint32_t ldr, uintptr_t pc) {
        uint64_t immhi = (adrp >> 5) & 0x7FFFF;
        uint64_t immlo = (adrp >> 29) & 3;
        int64_t imm = (int64_t)((immhi << 2) | immlo) << 12;
        if (imm & (1LL << 32)) imm |= ~((1LL << 33) - 1);
        uint64_t page = (pc & ~0xFFFULL) + (uint64_t)imm;
        uint32_t size = (ldr >> 30) & 3;
        uint64_t off  = ((ldr >> 10) & 0xFFF) << size;
        return (uintptr_t)(page + off);
    }
    
    static inline uint32_t ldr64_imm(uint32_t insn) {
        return ((insn >> 10) & 0xFFF) << 3;
    }
    static inline uint32_t ldr32_imm(uint32_t insn) {
        return ((insn >> 10) & 0xFFF) << 2;
    }
    static inline uint32_t ldrb_imm(uint32_t insn) {
        return (insn >> 10) & 0xFFF;
    }
    
    static inline uint32_t mov_imm_val(uint32_t insn) {
        return (insn >> 5) & 0xFFFF;
    }
    
    static inline uint32_t add_imm12(uint32_t insn) {
        return (insn >> 10) & 0xFFF;
    }
    
    static inline uint32_t insn_rd(uint32_t insn) {
        return insn & 0x1F;
    }
    
    static inline uint32_t insn_rn(uint32_t insn) {
        return (insn >> 5) & 0x1F;
    }
    
    static inline uintptr_t next_func_addr_vm(uintptr_t from) {
        if (from >= mem::text_end) return mem::text_end;
        for (uintptr_t pc = from + 4; pc < mem::text_end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if ((insn & 0xFFC00000) == 0xA9800000 ||
                (insn & 0xFF8003FF) == 0xD10003FF ||
                 insn == 0xD503233F)
                return pc;
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
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if (is_bl(insn)) count++;
        }
        return count;
    }
    
    static inline uintptr_t find_bl_to(uintptr_t func, uintptr_t target) {
        uintptr_t end = next_func_addr_vm(func);
        for (uintptr_t pc = func; pc < end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if (is_bl(insn) && decode_bl(insn, pc) == target) return pc;
        }
        return 0;
    }
    
    static inline bool func_has_ldr_imm(uintptr_t func, uint32_t imm) {
        uintptr_t end = next_func_addr_vm(func);
        for (uintptr_t pc = func; pc < end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if (is_ldr64(insn) && ldr64_imm(insn) == imm) return true;
            if (is_str64(insn) && ldr64_imm(insn) == imm) return true;
        }
        return false;
    }
    
    static inline bool func_has_insn(uintptr_t func, uint32_t needle) {
        uintptr_t end = next_func_addr_vm(func);
        for (uintptr_t pc = func; pc < end; pc += 4) {
            if (*(uint32_t*)(mem::data + pc) == needle) return true;
        }
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
    
    std::vector<uintptr_t> find_bl_xrefs(uintptr_t target, size_t limit) {
        std::vector<uintptr_t> results;
        if (!is_arm64 || !text_start || !text_end) return results;
        size_t begin = (text_start + 3) & ~3ULL;
        size_t end = text_end - 4;
        for (size_t i = begin; i < end; i += 4) {
            uint32_t insn = *(uint32_t*)(data + i);
            if (!is_bl(insn)) continue;
            if (decode_bl(insn, i) == target) {
                results.push_back(i);
                if (results.size() >= limit) break;
            }
        }
        return results;
    }
    
    // useful af
    std::vector<uintptr_t> find_callers(uintptr_t target, size_t limit) {
        std::vector<uintptr_t> results;
        auto xrefs = find_bl_xrefs(target, limit * 4);
        for (uintptr_t site : xrefs) {
            uintptr_t func = find_func(site);
            if (!func) continue;
            bool dup = false;
            for (uintptr_t r : results) if (r == func) { dup = true; break; }
            if (!dup) {
                results.push_back(func);
                if (results.size() >= limit) break;
            }
        }
        return results;
    }
    
    uintptr_t find_str_ref(const char* str) {
        uintptr_t str_addr = find_str(str);
        if (!str_addr) return 0;
        auto xrefs = find_xrefs(str_addr);
        if (xrefs.empty()) return 0;
        return xrefs[0];
    }
    
    uintptr_t find_func_with_str(const char* str) {
        uintptr_t ref = find_str_ref(str);
        if (!ref) return 0;
        return find_func(ref);
    }
    
    uintptr_t find_nth_func_with_str(const char* str, int n) {
        uintptr_t str_addr = find_str(str);
        if (!str_addr) return 0;
        auto xrefs = find_xrefs(str_addr);
        std::vector<uintptr_t> funcs;
        for (uintptr_t x : xrefs) {
            uintptr_t f = find_func(x);
            if (!f) continue;
            bool dup = false;
            for (uintptr_t r : funcs) if (r == f) { dup = true; break; }
            if (!dup) funcs.push_back(f);
        }
        if (n < (int)funcs.size()) return funcs[n];
        return 0;
    }

    uintptr_t find_func(uintptr_t from) {
        if (from < text_start || from >= text_end) return 0;

        if (is_arm64) {
            const uint8_t* d = data;
            int lo = (int)from - 65536;
            if (lo < (int)text_start) lo = (int)text_start;

            size_t start_i = (from & ~3ULL);
            for (int i = (int)start_i; i >= lo; i -= 4) {
                uint32_t insn = *(uint32_t*)(d + i);

                if (is_func_prologue(insn)) {
                    if ((insn & 0xFF8003FF) == 0xD10003FF) {
                        for (int j = 1; j <= 12; ++j) {
                            int prev_idx = i - j * 4;
                            if (prev_idx < lo) break;
                            uint32_t prev_insn = *(uint32_t*)(d + prev_idx);
                            bool is_ret_prev = (prev_insn & 0xFFFFFC00) == 0xD65F0000;
                            bool is_b_prev   = (prev_insn & 0xFC000000) == 0x14000000;
                            if (is_ret_prev || is_b_prev) break;
                            if ((prev_insn & 0xFFC00000) == 0xA9800000 || prev_insn == 0xD503233F || prev_insn == 0xD50323BF) {
                                i = prev_idx;
                                break;
                            }
                        }
                    }
                    return i;
                }

                bool is_ret = (insn & 0xFFFFFC00) == 0xD65F0000;
                bool is_br  = (insn & 0xFFFFFC00) == 0xD61F0000;
                bool is_b   = (insn & 0xFC000000) == 0x14000000;

                if ((is_ret || is_br || is_b) && i + 4 <= (int)from) {

                    if (is_b) {
                        int64_t imm26 = (int64_t)(insn & 0x3FFFFFF);
                        if (imm26 & 0x2000000) imm26 |= ~(int64_t)0x3FFFFFF;
                        int64_t bt = (int64_t)i + (imm26 << 2);
                        if (bt >= (int64_t)lo && bt <= (int64_t)from)
                            continue;
                    }
                    uint32_t next = *(uint32_t*)(d + i + 4);
                    if (is_func_prologue(next))
                        return i + 4;
                }
            }
            return 0;
        } else {
            const uint8_t* d = data;
            int lo = (int)from - 16384;
            if (lo < (int)text_start) lo = (int)text_start;

            for (int i = (int)from; i >= lo; i--) {
                if (d[i] == 0x55 && d[i+1] == 0x48 && d[i+2] == 0x89 && d[i+3] == 0xE5)
                    return i;
            }
            for (int i = (int)from; i > lo; i--) {
                if (d[i] == 0x55 && (d[i+1] == 0x41 || d[i+1] == 0x53)) {
                    uint8_t prev = d[i - 1];
                    if (prev < 0x40 || prev > 0x4F)
                        return i;
                }
            }
            return 0;
        }
    }
}
