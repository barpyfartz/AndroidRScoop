#include "mem.h"
#include <iostream>
#include <fcntl.h>
#include <sys/stat.h>
#include <algorithm>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

struct elf64_ehdr {
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

struct elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

uint8_t* mem::data = nullptr;
size_t mem::size = 0;
uintptr_t mem::text_start = 0;
uintptr_t mem::text_end = 0;

#ifdef _WIN32
static HANDLE h_file = INVALID_HANDLE_VALUE;
static HANDLE h_map = NULL;
#else
static int file_fd = -1;
#endif

bool mem::open(const char* path) {
#ifdef _WIN32
    h_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_file == INVALID_HANDLE_VALUE) return false;
    DWORD size_high = 0;
    DWORD size_low = GetFileSize(h_file, &size_high);
    mem::size = ((size_t)size_high << 32) | size_low;
    h_map = CreateFileMappingA(h_file, NULL, PAGE_READONLY, size_high, size_low, NULL);
    if (!h_map) { CloseHandle(h_file); return false; }
    mem::data = (uint8_t*)MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0);
    if (!mem::data) { CloseHandle(h_map); CloseHandle(h_file); return false; }
#else
    file_fd = ::open(path, O_RDONLY);
    if (file_fd < 0) return false;
    struct stat sb;
    if (fstat(file_fd, &sb) < 0) { ::close(file_fd); return false; }
    mem::size = sb.st_size;
    mem::data = (uint8_t*)mmap(NULL, mem::size, PROT_READ, MAP_PRIVATE, file_fd, 0);
    if (mem::data == MAP_FAILED) { ::close(file_fd); return false; }
#endif
    if (mem::size < sizeof(elf64_ehdr)) { mem::close(); return false; }
    elf64_ehdr* ehdr = (elf64_ehdr*)mem::data;
    if (ehdr->e_ident[0] != 0x7F || ehdr->e_ident[1] != 'E' || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
        mem::close();
        return false;
    }
    if (ehdr->e_phoff + ehdr->e_phnum * sizeof(elf64_phdr) > mem::size) { mem::close(); return false; }
    elf64_phdr* phdr = (elf64_phdr*)(mem::data + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == 1 && (phdr[i].p_flags & 1) && (phdr[i].p_flags & 4)) {
            mem::text_start = phdr[i].p_vaddr;
            mem::text_end = phdr[i].p_vaddr + phdr[i].p_filesz;
            break;
        }
    }

    if (!mem::text_start || !mem::text_end) { mem::close(); return false; }
    return true;
}

void mem::close() {
    if (!mem::data) return;
#ifdef _WIN32
    UnmapViewOfFile(mem::data);
    if (h_map) CloseHandle(h_map);
    if (h_file != INVALID_HANDLE_VALUE) CloseHandle(h_file);
#else
    munmap(mem::data, mem::size);
    if (file_fd >= 0) ::close(file_fd);
#endif
    mem::data = nullptr;
}

uintptr_t mem::find_str(const char* str) {
    if (!mem::data || !str) return 0;
    std::string s(str);
    auto it = std::search(mem::data, mem::data + mem::size, s.begin(), s.end());
    if (it == mem::data + mem::size) return 0;
    return std::distance(mem::data, it);
}

uintptr_t mem::find_bytes(const char* sig) {
    if (!mem::data || !sig || !mem::text_start) return 0;
    std::vector<int> pattern;
    std::string signature(sig);
    size_t pos = 0;
    while ((pos = signature.find_first_not_of(' ', pos)) != std::string::npos) {
        size_t next = signature.find_first_of(' ', pos);
        std::string token = (next == std::string::npos) ? signature.substr(pos) : signature.substr(pos, next - pos);
        if (token == "??" || token == "?") {
            pattern.push_back(-1);
        } else {
            pattern.push_back(std::stoul(token, nullptr, 16));
        }
        if (next == std::string::npos) break;
        pos = next;
    }

    if (pattern.empty()) return 0;
    size_t end_search = mem::text_end - pattern.size();
    for (size_t i = mem::text_start; i < end_search; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (pattern[j] != -1 && mem::data[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return 0;
}

std::vector<uintptr_t> mem::find_xrefs(uintptr_t target_addr) {
    std::vector<uintptr_t> xrefs;
    if (!mem::data || !mem::text_start || !target_addr) return xrefs;
    size_t search_limit = mem::text_end - 4;
    for (size_t i = mem::text_start & ~3ULL; i < search_limit; i += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + i);
        if ((insn & 0x9F000000) == 0x90000000) {
            int64_t immhi = (int64_t)((insn >> 5) & 0x7FFFF);
            int64_t immlo = (int64_t)((insn >> 29) & 3);
            int64_t imm = (immhi << 2) | immlo;
            if (imm & 0x100000) imm |= 0xFFFFFFFFFFF00000LL;
            uintptr_t page = (i & ~0xFFFULL) + (imm << 12);
            uint32_t next_insn = *(uint32_t*)(mem::data + i + 4);
            if ((next_insn & 0xFFC00000) == 0x91000000) {
                uintptr_t offset = (next_insn >> 10) & 0xFFF;
                if (page + offset == target_addr) {
                    xrefs.push_back(i);
                }
            }
            else if ((next_insn & 0xFFC00000) == 0xF9400000) {
                uintptr_t offset = ((next_insn >> 10) & 0xFFF) << 3;
                if (page + offset == target_addr) {
                    xrefs.push_back(i);
                }
            }
        }
    }
    return xrefs;
}

uintptr_t mem::find_func(uintptr_t from) {
    if (!mem::data || !mem::text_start || from < mem::text_start) return 0;
    size_t lo = (from > mem::text_start + 1024) ? from - 1024 : mem::text_start;
    lo = (lo + 3) & ~3ULL;

    for (size_t j = (from & ~3ULL); j >= lo; j -= 4) {
        uint32_t insn = *(uint32_t*)(mem::data + j);
        bool is_stp = (insn & 0xFF800000) == 0xA9800000; 
        bool is_sub = (insn & 0xFF800000) == 0xD1000000; 
        if (is_stp || is_sub) return j;
    }
    return 0;
}
