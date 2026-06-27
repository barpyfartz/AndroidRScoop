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

    uintptr_t find_func(uintptr_t from) {
        if (from < text_start || from >= text_end) return 0;

        if (is_arm64) {
            const uint8_t* d = data;
            int lo = (int)from - 65536;
            if (lo < (int)text_start) lo = (int)text_start;

            size_t start_i = (from & ~3ULL);
            for (int i = (int)start_i; i >= lo; i -= 4) {
                uint32_t insn = *(uint32_t*)(d + i);

                if (is_func_prologue(insn))
                    return i;

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
