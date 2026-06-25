#include "mem.h"
#include "dump.h"
#include "extract.h"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <vector>

#define RST "\033[0m"
#define GRY "\033[90m"
#define GRN "\033[92m"
#define CYN "\033[96m"

void print_usage(const char* prog) {
    std::cout << "usage: " << prog << " <apk_path> [arch]\n"
              << "  arch: arm64-v8a | armeabi-v7a | x86_64 (default: arm64-v8a)\n"
              << "  or:   " << prog << " --so <path_to_libroblox.so>\n";
}

static void delete_file(const std::string& path) {
#ifdef _WIN32
    #ifdef DeleteFile
        DeleteFileA(path.c_str());
    #else
        DeleteFile(path.c_str());
    #endif
#else
    std::remove(path.c_str());
#endif
}

static void debug_scan(const scan& s) {
    uintptr_t addr = s.sig.empty() ? mem::find_str(s.pattern.c_str()) : mem::find_bytes(s.sig.c_str());

    std::cout << std::hex << "\n[" << s.name << "] str=0x" << addr << " up=" << std::dec << s.up << " down=" << s.down << "\n";
    if (!addr) { std::cout << "  string not found\n"; return; }

    auto xrefs = mem::find_xrefs(addr);
    std::cout << "  xrefs: " << xrefs.size() << "\n";
    if (xrefs.empty()) return;

    uintptr_t xref = xrefs[0];
    std::cout << std::hex << "  first xref @ 0x" << xref << "\n";

    if (s.up == 0 && s.down == 0) {
        std::cout << "  find_func: 0x" << mem::find_func(xref) << "\n  prologs back (400b):\n";
        size_t lo = (xref > mem::text_start + 400) ? xref - 400 : mem::text_start;
        lo = (lo + 3) & ~3ULL;
        for (size_t j = (xref & ~3ULL); j >= lo && j >= mem::text_start; j -= 4) {
            uint32_t insn = *(uint32_t*)(mem::data + j);
            bool is_stp = (insn & 0xFF800000) == 0xA9800000;
            bool is_sub = (insn & 0xFF800000) == 0xD1000000;
            bool is_ret = (insn & 0xFFFFFC00) == 0xD65F0000;
            bool is_b   = (insn & 0xFC000000) == 0x14000000;
            if (is_stp || is_sub || is_ret || is_b) {
                std::cout << "    0x" << j << ": 0x" << insn
                          << (is_stp ? " stp" : is_sub ? " sub" : is_ret ? " ret" : " b") << "\n";
            }
            if (j == lo) break;
        }
    }
    std::cout << std::dec;
}

int main(int argc, char** argv) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    std::string so_path;
    bool delete_after = false;
    bool do_debug = false;

    int arg_start = 1;
    if (std::string(argv[1]) == "--debug") { // use ts as ./dumper --debug ...(flags)
        do_debug = true;
        arg_start = 2;
    }

    if (argc <= arg_start) { print_usage(argv[0]); return 1; }

    if (std::string(argv[arg_start]) == "--so") {
        if (argc <= arg_start + 1) { print_usage(argv[0]); return 1; }
        so_path = argv[arg_start + 1];
    } else {
        std::string apk_path = argv[arg_start];
        std::string arch = (argc > arg_start + 1) ? argv[arg_start + 1] : "arm64-v8a";
        
        std::cout << GRY << "loading..." << RST << std::flush;
        
        so_path = extract_so_from_apk(apk_path, arch);
        if (so_path.empty()) return 1;
        delete_after = true;
    }

    if (!mem::open(so_path.c_str())) {
        std::cerr << "err open: " << so_path << "\n";
        return 1;
    }

    std::cout << "\r" << std::string(15, ' ') << "\r" << std::flush;

    if (do_debug) {
        for (const auto& s : scans) debug_scan(s);
        mem::close();
        if (delete_after) delete_file(so_path);
        return 0;
    }

    auto start = std::chrono::high_resolution_clock::now();

    std::vector<uintptr_t> addresses(scans.size());
    for (size_t i = 0; i < scans.size(); i++) {
        addresses[i] = scans[i].sig.empty() ? mem::find_str(scans[i].pattern.c_str()) : mem::find_bytes(scans[i].sig.c_str());
    }

    int found = 0;
    for (size_t i = 0; i < scans.size(); i++) {
        uintptr_t result = process(scans[i], addresses[i]);
        if (result) found++;

        std::cout << CYN << scans[i].name << RST " " GRY "->" RST " ";
        if (result)
            std::cout << "0x" << std::hex << std::uppercase << result << "\n";
        else
            std::cout << GRY "not found" RST "\n";
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::high_resolution_clock::now() - start).count();

    std::cout << "\n" << GRN << "+" << RST " " << GRY
              << std::fixed << std::setprecision(2)
              << elapsed / 1000.0 << "s" << RST "  "
              << "dumped by rscoop\n";

    mem::close();
    if (delete_after) delete_file(so_path);
    return 0;
}
