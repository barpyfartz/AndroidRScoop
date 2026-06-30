#include "dump.h"
#include "mem.h"
#include <algorithm>
#include <unordered_map>
#include <cstring>
#include <map>
#include <fstream>
#include <iostream>

std::vector<scan> scans = {
    // standartenfuhrer patterns. add yours broski
    {"print", "Current identity is %d", "", 1, 0, false},
    {"game_loaded", "onGameLoaded() SessionReporterState_GameLoaded placeId:%lld", "", 0, 0, false},
    {"on_game_leave", "onGameLeaveBegin() SessionReporterState_GameExitRequested placeId:%lld", "", 0, 0, false},
    {"scriptstart", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f5 03 00 aa 1f 7c 00 a9 e0 03 01 aa f3 03 02 aa f4 03 01 aa", 0, 0, false},
    {"firetouchinterest", "new overlap in different world", "", 0, 0, false},
    {"jobstart", "[FLog::TaskSchedulerRun] JobStart %s", "", 0, 0, false},
    {"jobstop", "[FLog::TaskSchedulerRun] JobStop %s", "", 0, 0, false},
    {"rbxspawn", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? df 08", 0, 0, false},
    {"taskdesynchronize", "task.desynchronize() should only be called from a script that is a descendant of an Actor", "", 0, 0, false},
    {"task_synchronize", "", "", 0, 0, false}, // thx pereoxide
    {"task_defer", "", "", 0, 0, false},
    {"task_spawn", "", "", 0, 0, false},
    {"task_delay", "", "", 0, 0, false},
    {"task_wait", "", "", 0, 0, false},
    {"task_cancel", "", "", 0, 0, false},
    {"taskschedulerconstructor", "HumanoidParallelManagerTaskQueue", "", 0, 0, false},
    {"rawscheduler", "HumanoidParallelManagerTaskQueue", "", 0, 1, false}, // caller
    {"taskschedulerfps", "", "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 ?? ?? ?? 90 ?? ?? ?? 91", 0, 0, false},
    {"lockviolationcrash", "LockViolationInstanceCrash", "", 0, 0, false},
    {"lockviolationscriptcrash", "LockViolationScriptCrash", "", 0, 0, false},
    {"luastepinternaloverride", "LuaStepIntervalMsOverrideEnabled", "", 0, 0, false},
    {"hashtablelookup", "Unable to query property {}. It is not scriptable", "", 0, 0, false},
    {"getglobalstateforinstance", "", "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 f3 03 02 aa f4 03 01 aa ?? ?? ?? ?? e1 03 14 aa e2 03 13 aa ?? ?? ?? ?? 08 24 40 29", 0, 0, false},
    {"getluastate", "", "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 f3 03 02 aa f4 03 01 aa ?? ?? ?? ?? e1 03 14 aa e2 03 13 aa ?? ?? ?? ?? 08 24 40 29", 0, 0, false},
    {"ktable", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? 15 14 40 f9 f4 03 00 aa 53 01 00 b4", 0, 0, false},
    {"scriptcontextresume", "", "ff 03 06 d1 e8 8b 00 fd fd 7b 12 a9 fc 6f 13 a9 fa 67 14 a9 f8 5f 15 a9 f6 57 16 a9 f4 4f 17 a9 fd 83 04 91 ?? ?? ?? b0 ?? ?? ?? b0 f6 03 00 aa ?? ?? ?? f9 f8 03 04 aa fa 03 03 2a", 0, 0, false},
    // {"robloxlogcrash", "", "", 0, 0, false},
    {"enableloadmodule", "EnableLoadModule", "", 0, 0, false},
    {"stdstringconstructor", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa", 0, 0, false},
    {"luauloadinternal", "", "?? ?? ?? b4 fd 7b bc a9 f8 5f 01 a9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91", 0, 0, false},
    {"luauloadcorescripts", "", "fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 03 00 91 ff 83 06 d1", 0, 0, false},
    {"validateandsetupcaps", "", "ff 83 02 d1 fd 7b 06 a9 f8 5f 07 a9 f6 57 08 a9 f4 4f 09 a9", 0, 0, false},
    {"luaG_runerror",           "attempt to index %s with '%s'",                    "", 0, 0, false},
    {"luaresume",              "cannot resume dead coroutine",                      "", 0, 0, false},
    {"luaresumefromsuspended", "cannot resume non-suspended coroutine",             "", 0, 0, false},
    {"luaHsettable",           "table index is nil",                                "", 0, 0, false},
    {"stackoverflow",           "stack overflow (%s)",                               "", 0, 0, false},
    {"invalidkeynext",          "invalid key to 'next'",                             "", 0, 0, false},
    {"newindex",                "__newindex",                                         "", 0, 0, false},
    {"namecallhandler",          "__namecall",                                        "", 0, 0, false},
    {"invokeserver",            "InvokeServer can only be called from the client",   "", 0, 0, false},
    {"fireserver",              "FireServer can only be called from the client",     "", 0, 0, false},
    {"fireallclients",          "FireAllClients can only be called from the server", "", 0, 0, false},
    {"invokeclient",            "InvokeClient can only be called from the server",   "", 0, 0, false},
    {"luauload",               "%s: bytecode version mismatch (expected [%d..%d], got %d)", "", 0, 0, false},
    {"luauyield",              "attempt to yield across metamethod/C-call boundary", "", 0, 0, false},
    {"resumewaitingscripts",    "WaitingHybridScriptsJob",                            "", 1, 0, false},
    {"getscheduler",            "", "ff c3 01 d1 fd 7b 04 a9 f5 2b 00 f9 f4 4f 06 a9 fd 03 01 91 ?? ?? ?? ?? ?? ?? ?? ?? a8 02 40 f9 a8 83 1f f8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f3 03 00 aa 08 fd df 08 ?? ?? ?? ?? e0 03 13 aa", 0, 0, false},
    {"newproxy",                "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 21 00 80 52 f3 03 00 aa ?? ?? ?? ?? 08 78 1f 12 1f 19 00 71", 0, 0, false},
    {"loadstring",           "loadstring() is not available",                               "", 0, 0, false},
    {"getfenv", "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 00 90 52 ?? ?? ?? ?? e0 03 13 aa 21 00 80 52", 0, 0, false},
    {"setfenv", "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 00 90 52 ?? ?? ?? ?? e0 03 13 aa 41 00 80 52", 0, 0, false},
    {"luaG_aritherror", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f5 03 03 2a f6 03 02 aa f3 03 00 aa ?? ?? ?? ?? f4 03 00 aa e0 03 13 aa e1 03 16 aa", 0, 0, false},
    {"luagetfield", "", "", 0, 0, false}, 
    {"luasetfield", "", "", 0, 0, false},
    {"luau_execute", "", "", 0, 0, false},
    {"luaD_throw", "", "", 0, 0, false},
    {"luaC_step", "", "", 0, 0, false},
    {"luaE_newthread", "", "", 0, 0, false},
    {"lua_newthread", "", "", 0, 0, false},
    {"getcapabilities", "", "", 0, 0, false},
    {"taskscheduler_mutex", "", "", 0, 0, true},
    {"taskscheduler_queue", "", "", 0, 0, true},
    {"taskscheduler_workers", "", "", 0, 0, true},
    {"telemetry_buffer", "", "", 0, 0, true},
    {"telemetry_size", "", "", 0, 0, true},
    {"lua_index2addr", "", "", 0, 0, false},
    {"lua_state_top", "", "", 0, 0, true},
    {"lua_state_base", "", "", 0, 0, true},
    {"lua_state_global_state", "", "", 0, 0, true},
    {"luas_newlstr", "", "", 0, 0, false},
    {"lua_pushlstring", "", "", 0, 0, false},
};

static inline bool is_bl(uint32_t insn) {
    return (insn & 0xFC000000) == 0x94000000;
}

static inline uint64_t decode_bl(uint32_t insn, uint64_t pc) {
    int64_t imm = (insn & 0x3FFFFFF);
    if (imm & 0x2000000) imm -= 0x4000000;
    return pc + (imm << 2);
}

static uintptr_t bl_up(uintptr_t from, int n) {
    const uint8_t* d = mem::data;
    int count = 0;
    int start = (int)from - 4;
    int lo = std::max((int)mem::text_start, (int)from - 600);
    start = (start & ~3);
    for (int j = start; j >= lo; j -= 4) {
        uint32_t insn = *(uint32_t*)(d + j);
        if (is_bl(insn)) {
            uintptr_t candidate = decode_bl(insn, (uint64_t)j);
            if (candidate >= mem::text_start && candidate < mem::text_end) {
                if (++count == n)
                    return candidate;
            }
        }
    }
    return 0;
}

static uintptr_t bl_down(uintptr_t from, int n) {
    const uint8_t* d = mem::data;
    int count = 0;
    size_t end = std::min(from + 600, mem::text_end - 4);
    size_t start = ((from + 4) & ~3ULL);
    for (size_t j = start; j <= end; j += 4) {
        uint32_t insn = *(uint32_t*)(d + j);
        if (is_bl(insn)) {
            uintptr_t candidate = decode_bl(insn, (uint64_t)j);
            if (candidate >= mem::text_start && candidate < mem::text_end) {
                if (++count == n)
                    return candidate;
            }
        }
    }
    return 0;
}

static uintptr_t to_func(uintptr_t candidate) {
    if (!candidate) return 0;
    uintptr_t f = mem::find_func(candidate);
    return f ? f : candidate;
}

uintptr_t process(const scan& s, uintptr_t addr) {
    if (!addr) return 0;

    if (!s.pattern.empty()) {
        auto xrefs = mem::find_xrefs(addr);
        if (xrefs.empty()) return 0;

        for (auto target : xrefs) {
            uintptr_t result = 0;
            if (s.up == 0 && s.down == 0) {
                result = mem::find_func(target);
            } else if (s.up > 0) {
                result = to_func(bl_up(target, s.up));
            } else if (s.down > 0) {
                result = to_func(bl_down(target, s.down));
            }
            if (result) return result;
        }
    } else {
        if (s.up == 0 && s.down == 0) {
            return to_func(addr);
        } else if (s.up > 0) {
            return to_func(bl_up(addr, s.up));
        } else if (s.down > 0) {
            return to_func(bl_down(addr, s.down));
        }
    }

    return 0;
}

static bool is_adrp(uint32_t insn) {
    return (insn & 0x9F000000) == 0x90000000;
}

static uint64_t decode_adrp(uint32_t insn, uint64_t pc) {
    uint64_t immhi = (insn >> 5) & 0x7FFFF;
    uint64_t immlo = (insn >> 29) & 3;
    int64_t imm = (int64_t)((immhi << 2) | immlo);
    if (imm & 0x100000) {
        imm |= ~0x1FFFFFULL;
    }
    return (pc & ~0xFFFULL) + (imm << 12);
}

static bool is_add_imm(uint32_t insn) {
    return (insn & 0xFF000000) == 0x91000000;
}

static uint64_t decode_add_imm(uint32_t insn) {
    return (insn >> 10) & 0xFFF;
}

static bool is_ldr_imm(uint32_t insn) {
    return (insn & 0xFFC00000) == 0xB9400000;
}

static uint64_t decode_ldr_imm(uint32_t insn) {
    return ((insn >> 10) & 0xFFF) << ((insn >> 30) & 1);
}

static bool is_adr(uint32_t insn) {
    return (insn & 0x9F000000) == 0x10000000;
}

static uint64_t decode_adr(uint32_t insn, uint64_t pc) {
    uint32_t immlo = (insn >> 29) & 3;
    uint32_t immhi = (insn >> 5) & 0x7FFFF;
    int64_t imm = (int64_t)((immhi << 2) | immlo);
    if (imm & 0x100000) imm -= 0x200000;
    return pc + imm;
}

static uint64_t decode_adrp_add(uint32_t ins1, uint32_t ins2, uint64_t pc) {
    uint64_t page = decode_adrp(ins1, pc);
    if (is_add_imm(ins2)) {
        return page + decode_add_imm(ins2);
    } else if (is_ldr_imm(ins2)) {
        return page + decode_ldr_imm(ins2);
    }
    return 0;
}

static std::string get_str_at(uintptr_t offset) {
    if (offset >= mem::size) return "";
    std::string res;
    const uint8_t* d = mem::data + offset;
    while (offset < mem::size && *d != 0) {
        res.push_back((char)*d);
        offset++;
        d++;
        if (res.size() > 50) break;
    }
    return res;
}

void resolve_tasks(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t desync_addr = 0;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "taskdesynchronize") {
            desync_addr = results[i];
            break;
        }
    }
    if (!desync_addr) return;

    uintptr_t reg_xref = 0;
    size_t begin = (mem::text_start + 3) & ~3ULL;
    size_t end = mem::text_end - 8;
    for (size_t i = begin; i < end; i += 4) {
        uint32_t* code = (uint32_t*)(mem::data + i);
        uint32_t insn1 = code[0];
        uint32_t insn2 = code[1];
        if (is_adrp(insn1)) {
            uint64_t target = decode_adrp_add(insn1, insn2, i);
            if (target == desync_addr) {
                reg_xref = i;
                break;
            }
        }
    }
    if (!reg_xref) return;

    size_t window_start = (reg_xref >= 300) ? reg_xref - 300 : mem::text_start;
    size_t window_end = std::min(reg_xref + 500, mem::text_end - 8);
    window_start = (window_start + 3) & ~3ULL;

    std::string pending_string = "";
    std::unordered_map<std::string, uintptr_t> resolved_tasks;

    for (size_t i = window_start; i < window_end; i += 4) {
        uint32_t* code = (uint32_t*)(mem::data + i);
        uint32_t ins1 = code[0];
        uint64_t resolved_target = 0;

        if (is_adrp(ins1) && i + 4 < window_end) {
            uint32_t ins2 = code[1];
            resolved_target = decode_adrp_add(ins1, ins2, i);
        } else if (is_adr(ins1)) {
            resolved_target = decode_adr(ins1, i);
        }

        if (resolved_target) {
            if (resolved_target >= mem::text_start && resolved_target < mem::text_end) {
                if (!pending_string.empty()) {
                    resolved_tasks[pending_string] = resolved_target;
                    pending_string = "";
                }
            } else {
                std::string s = get_str_at(resolved_target);
                if (s == "synchronize" || s == "desynchronize" || s == "defer" ||
                    s == "spawn" || s == "delay" || s == "wait" || s == "cancel") {
                    pending_string = s;
                }
            }
        }
    }

    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name.rfind("task_", 0) == 0) {
            std::string key = scans[i].name.substr(5);
            if (resolved_tasks.find(key) != resolved_tasks.end()) {
                results[i] = resolved_tasks[key];
            }
        }
    }
}

void resolve_fields(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t huge_str = mem::find_str("huge");
    if (!huge_str) return;

    auto xrefs = mem::find_xrefs(huge_str);
    if (xrefs.empty()) return;

    uintptr_t xref_huge = xrefs[0];
    uintptr_t addr_setfield = 0;

    for (uintptr_t i = xref_huge; i < xref_huge + 100; i += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + i);
        if (is_bl(insn)) {
            addr_setfield = decode_bl(insn, i);
            break;
        }
    }

    if (!addr_setfield) return;

    uintptr_t index2adr = 0;
    uintptr_t luaS_newlstr = 0;
    int bl_count = 0;

    for (uintptr_t i = addr_setfield; i < addr_setfield + 200; i += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + i);
        if (is_bl(insn)) {
            uintptr_t target = decode_bl(insn, i);
            bl_count++;
            if (bl_count == 1) {
                index2adr = target;
            } else if (bl_count == 3) {
                luaS_newlstr = target;
                break;
            }
        }
    }

    if (!index2adr || !luaS_newlstr) return;

    uintptr_t addr_getfield = 0;
    size_t begin = (mem::text_start + 3) & ~3ULL;
    size_t end = mem::text_end - 4;

    for (size_t i = begin; i < end; i += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + i);
        if (is_bl(insn)) {
            uintptr_t target = decode_bl(insn, i);
            if (target == luaS_newlstr) {
                uintptr_t f_start = mem::find_func(i);
                if (!f_start || (f_start >= addr_setfield && f_start < addr_setfield + 0x200)) continue;

                uintptr_t first_bl = 0;
                for (uintptr_t j = f_start; j < i; j += 4) {
                    uint32_t j_insn = *(uint32_t*)(mem::data + j);
                    if (is_bl(j_insn)) {
                        first_bl = decode_bl(j_insn, j);
                        break;
                    }
                }

                if (first_bl == index2adr) {
                    addr_getfield = f_start;
                    break;
                }
            }
        }
    }

    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luasetfield") {
            results[i] = addr_setfield;
        } else if (scans[i].name == "luagetfield") {
            results[i] = addr_getfield;
        }
    }
}

static inline bool is_func_prologue_vm(uint32_t insn) {
    return (insn & 0xFFC00000) == 0xA9800000 ||
           (insn & 0xFF8003FF) == 0xD10003FF ||
           insn == 0xD503233F;
}

static size_t next_func_addr_vm(size_t addr) {
    size_t curr = (addr + 4) & ~3ULL;
    while (curr < mem::text_end) {
        uint32_t insn = *(uint32_t*)(mem::data + curr);
        if (is_func_prologue_vm(insn)) return curr;
        curr += 4;
    }
    return mem::text_end;
}

bool extract_fflag_info(uintptr_t xref, std::string& out_name, uintptr_t& out_address) {
    std::string prefix = "";
    std::string name = "";
    uintptr_t bss_ptr = 0;

    const std::vector<std::string> known_prefixes = {
        "FFlag", "FInt", "FString", "FLog",
        "DFInt", "DFFlag", "DFString",
        "SFInt", "SFFlag", "SFString"
    };

    for (int i = 1; i <= 40; ++i) {
        uintptr_t pc = xref - i * 4;
        if (pc < mem::text_start) break;

        uint32_t ins1 = *(uint32_t*)(mem::data + pc);
        if (is_adrp(ins1) && pc + 4 < xref) {
            uint32_t ins2 = *(uint32_t*)(mem::data + pc + 4);
            if (is_add_imm(ins2)) {
                uint64_t target = decode_adrp_add(ins1, ins2, pc);
                if (target >= mem::text_end) {
                    if (!bss_ptr) bss_ptr = target;
                } else if (target >= 0x1000) {
                    const char* s = (const char*)(mem::data + target);
                    if (isalpha(s[0])) {
                        bool valid = true;
                        int len = 0;
                        while (s[len] && len < 200) {
                            char c = s[len];
                            if (!isalnum(c) && c != '_') {
                                valid = false;
                                break;
                            }
                            len++;
                        }
                        if (valid && len >= 2) {
                            std::string str(s, len);
                            bool is_prefix = false;
                            for (const auto& kp : known_prefixes) {
                                if (str == kp) {
                                    prefix = kp;
                                    is_prefix = true;
                                    break;
                                }
                            }
                            if (!is_prefix && name.empty()) {
                                name = str;
                            }
                        }
                    }
                }
            }
        }
    }

    if (bss_ptr && !name.empty()) {
        if (prefix.empty()) {
            prefix = "FFlag";
        }
        out_name = prefix + name;
        out_address = bss_ptr + 8;
        return true;
    }
    return false;
}

uintptr_t find_register_variable_fn() {
    uintptr_t fflag_str = mem::find_str("EnableLoadModule");
    if (!fflag_str) return 0;
    auto xrefs = mem::find_xrefs(fflag_str);
    if (xrefs.empty()) return 0;
    uintptr_t xref = xrefs[0];
    for (uintptr_t pc = xref + 4; pc < xref + 40 && pc < mem::text_end; pc += 4) {
        uint32_t ins = *(uint32_t*)(mem::data + pc);
        if (is_bl(ins)) {
            return decode_bl(ins, pc);
        }
    }
    return 0;
}

void dump_all_fflags(const std::string& output_path) {
    uintptr_t reg_fn = find_register_variable_fn();
    if (!reg_fn) return;

    std::map<std::string, uintptr_t> fflags;

    for (size_t pc = mem::text_start; pc < mem::text_end - 4; pc += 4) {
        uint32_t ins = *(uint32_t*)(mem::data + pc);
        if (is_bl(ins)) {
            if (decode_bl(ins, pc) == reg_fn) {
                std::string name;
                uintptr_t addr = 0;
                if (extract_fflag_info(pc, name, addr)) {
                    fflags[name] = addr;
                }
            }
        }
    }

    std::ofstream out(output_path);
    if (!out) return;
    out << "// dumped with rscoop!11!1\n";
    out << "#pragma once\n";
    out << "#include <cstdint>\n\n";
    out << "namespace FFlags {\n";
    for (const auto& pair : fflags) {
        out << "    constexpr uintptr_t " << pair.first << " = 0x" 
            << std::hex << std::uppercase << pair.second << ";\n";
    }
    out << "}\n";
}

void resolve_tsconstrctor(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    size_t caller_idx = -1;
    size_t ptr_idx = -1;
    
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "rawscheduler") caller_idx = i;
        if (scans[i].name == "taskschedulerconstructor") ptr_idx = i;
    }
    if (caller_idx == -1 || ptr_idx == -1 || !results[caller_idx]) return;
    uintptr_t caller_addr = results[caller_idx];
    uintptr_t cand_end = next_func_addr_vm(caller_addr);
    std::vector<uintptr_t> bl_targets;
    std::vector<uintptr_t> bl_pcs;
    for (uintptr_t pc = caller_addr; pc < cand_end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_bl(insn)) {
            uintptr_t target = decode_bl(insn, pc);
            if (target < mem::text_start || target >= mem::text_end) continue;
            
            bl_targets.push_back(target);
            bl_pcs.push_back(pc);
        }
    }
    uintptr_t rawscheduler_addr = 0;
    if (bl_targets.size() >= 3) {
        for (size_t i = 2; i < bl_targets.size(); ++i) {
            uintptr_t current_target = bl_targets[i];
            uintptr_t sub_end = next_func_addr_vm(current_target);
            size_t sub_size = sub_end - current_target;
            if (sub_size > 0 && sub_size < 0x35 && bl_pcs[i] + 150 >= cand_end) {
                uintptr_t prev_target = bl_targets[i - 1];
                uintptr_t prev_sub_end = next_func_addr_vm(prev_target);
                
                if ((prev_sub_end - prev_target) > 0x40) {
                    rawscheduler_addr = prev_target;
                    break;
                }
            }
        }
    }
    if (!rawscheduler_addr && bl_targets.size() >= 3) {
        int large_bl_count = 0;
        for (int i = (int)bl_targets.size() - 1; i >= 0; i--) {
            uintptr_t target = bl_targets[i];
            uintptr_t sub_end = next_func_addr_vm(target);
            size_t size = sub_end - target;
            
            if (size > 0x40 && size < 0x600) {
                large_bl_count++;
                if (large_bl_count == 2) {
                    rawscheduler_addr = target;
                    break;
                }
            }
        }
    }
    
    if (rawscheduler_addr) {
        results[ptr_idx] = rawscheduler_addr;
    }
}

void resolvejobevents(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return; 
    size_t start_idx = -1;
    size_t stop_idx = -1;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "jobstart") start_idx = i;
        if (scans[i].name == "jobstop") stop_idx = i;
    }
    uintptr_t start_str = mem::find_str("[FLog::TaskSchedulerRun] JobStart %s");
    if (start_str && start_idx != -1) {
        auto xrefs = mem::find_xrefs(start_str);
        for (uintptr_t xref : xrefs) {
            uintptr_t func = mem::find_func(xref);
            uintptr_t f_end = next_func_addr_vm(func);
            if ((f_end - func) > 0x60) { 
                results[start_idx] = func;
                break;
            }
        }
    }
    if (results[start_idx] && stop_idx != -1) {
        uintptr_t search_start = results[start_idx];
        uintptr_t search_end = search_start + 0x1000;
        uintptr_t current_func = search_start;
        while (current_func < search_end && current_func < mem::text_end) {
            uintptr_t func_end = next_func_addr_vm(current_func);
            bool has_mutex_offset = false;
            bool has_cond_offset = false;
            for (uintptr_t pc = current_func; pc < func_end; pc += 4) {
                uint32_t insn = *(uint32_t*)(mem::data + pc);
                if ((insn & 0xFFC003E0) == 0x91000260) { 
                    uint32_t imm12 = (insn >> 10) & 0xFFF;
                    if (imm12 == 0x98) has_mutex_offset = true;
                    if (imm12 == 0x70) has_cond_offset = true;
                }
                if ((insn & 0xFFC00000) == 0x91000000) {
                    uint32_t imm12 = (insn >> 10) & 0xFFF;
                    uint32_t rd = insn & 0x1F;
                    if (rd == 0) {
                        if (imm12 == 0x98) has_mutex_offset = true;
                        if (imm12 == 0x70) has_cond_offset = true;
                    }
                }
            }
            if (has_mutex_offset && has_cond_offset) {
                results[stop_idx] = current_func;
                break;
            }
            
            current_func = func_end;
        }
    }
    if (!results[stop_idx] || results[stop_idx] == results[start_idx] || results[stop_idx] < 0x1FDB300) {
        results[stop_idx] = results[start_idx] + 0x5E0;
    }
}

void resolve_tsdecoffsets(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    uintptr_t constructor_addr = 0;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "taskschedulerconstructor") {
            constructor_addr = results[i];
            break;
        }
    }
    if (!constructor_addr) return;
    uintptr_t cand_end = next_func_addr_vm(constructor_addr);
    uintptr_t mutex_offset = 0;
    uintptr_t queue_offset = 0;
    uintptr_t workers_offset = 0;
    bool found_first_mutex = false;
    for (uintptr_t pc = constructor_addr; pc < cand_end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (!found_first_mutex && (insn & 0xFFC00000) == 0x91000000) {
            uint32_t rd = insn & 0x1F;
            uint32_t rn = (insn >> 5) & 0x1F;
            if (rd == 0 && rn == 19) {
                mutex_offset = (insn >> 10) & 0xFFF;
                found_first_mutex = true;
            }
        }
        if (is_bl(insn)) {
            uintptr_t target = decode_bl(insn, pc);
            uint32_t prev_insn = *(uint32_t*)(mem::data + pc - 4);
            if (prev_insn == 0x52800101) { 
                uint32_t next_insn = *(uint32_t*)(mem::data + pc + 4);
                if ((next_insn & 0xFFC00000) == 0xF9000000) {
                    uint32_t rt = next_insn & 0x1F;
                    uint32_t rn = (next_insn >> 5) & 0x1F;
                    if (rt == 0 && rn == 19) {
                        queue_offset = ((next_insn >> 10) & 0xFFF) << 3;
                    }
                }
            }
            uintptr_t target_end = next_func_addr_vm(target);
            if ((target_end - target) < 0x50) {
                for (uintptr_t post_pc = pc + 4; post_pc <= pc + 40; post_pc += 4) {
                    uint32_t post_insn = *(uint32_t*)(mem::data + post_pc);
                    if ((post_insn & 0xFFC00000) == 0xF9000000) {
                        uint32_t rn = (post_insn >> 5) & 0x1F;
                        if (rn == 19) {
                            uint32_t imm12 = ((post_insn >> 10) & 0xFFF) << 3;
                            if (imm12 >= 0x140 && imm12 <= 0x180) {
                                workers_offset = imm12;
                                break;
                            }
                        }
                    }
                    if ((post_insn & 0xFFC00000) == 0x29000000) {
                        uint32_t rn = (post_insn >> 5) & 0x1F;
                        if (rn == 19) {
                            int64_t imm7 = (post_insn >> 15) & 0x7F;
                            if (imm7 & 0x40) imm7 -= 0x80;
                            uint32_t imm = imm7 << 3;
                            if (imm >= 0x140 && imm <= 0x180) {
                                workers_offset = imm;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "taskscheduler_mutex") results[i] = mutex_offset;
        else if (scans[i].name == "taskscheduler_queue") results[i] = queue_offset;
        else if (scans[i].name == "taskscheduler_workers") results[i] = workers_offset;
    }
}

void resolve_network_telemetry(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t telemetry_func = 0;
    size_t begin = (mem::text_start + 3) & ~3ULL;
    size_t end = mem::text_end - 4;
    for (size_t i = begin; i < end; i += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + i);
        if ((insn & 0xFFFFF0BF) == 0xD50330BF) {
            uintptr_t parent = mem::find_func(i);
            if (parent) {
                size_t f_end = next_func_addr_vm(parent);
                int bl_count = 0;
                for (size_t pc = parent; pc < f_end; pc += 4) {
                    if (is_bl(*(uint32_t*)(mem::data + pc))) {
                        bl_count++;
                    }
                }
                if (bl_count >= 3) {
                    telemetry_func = parent;
                    break;
                }
            }
        }
    }

    if (!telemetry_func) return;
    uintptr_t f_end = next_func_addr_vm(telemetry_func);
    uintptr_t vector_offset = 0;
    uintptr_t size_offset = 0;

    for (uintptr_t pc = telemetry_func; pc < f_end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if ((insn & 0xFFC00000) == 0xB9400000 || (insn & 0xFFC00000) == 0xF9400000 || (insn & 0xFFC00000) == 0x91000000) {
            uint32_t imm = (insn >> 10) & 0xFFF;
            uint32_t real_offset = ((insn & 0xFFC00000) == 0xF9400000) ? (imm << 3) : imm;
            if (real_offset >= 0x170 && real_offset <= 0x190) {
                vector_offset = real_offset;
            }
            if (real_offset >= 0x1B0 && real_offset <= 0x1D0) {
                size_offset = real_offset;
            }
        }
    }
    if (!vector_offset) vector_offset = 0x180;
    if (!size_offset) size_offset = 0x1C0;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "telemetry_buffer") results[i] = vector_offset;
        else if (scans[i].name == "telemetry_size") results[i] = size_offset;
    }
}

void resolve_lua_index2addr(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t index2addr_addr = 0;
    size_t begin = (mem::text_start + 3) & ~3ULL;
    size_t end = mem::text_end - 4;
    for (size_t i = begin; i < end - 4; i += 4) {
        uint32_t insn1 = *(uint32_t*)(mem::data + i);
        uint32_t insn2 = *(uint32_t*)(mem::data + i + 4);
        if ((insn1 & 0xFFC003E0) == 0xB9400C00) {
            if ((insn2 & 0xFFFFF000) == 0x71001800) {
                uintptr_t candidate = mem::find_func(i);
                if (!candidate) continue;
                size_t cand_end = next_func_addr_vm(candidate);
                int bl_count = 0;
                for (size_t pc = candidate; pc < cand_end; pc += 4) {
                    if (is_bl(*(uint32_t*)(mem::data + pc))) bl_count++;
                }
                
                if (bl_count >= 2) {
                    index2addr_addr = candidate;
                    break;
                }
            }
        }
    }
    uintptr_t top_offset = 0x38;  
    uintptr_t base_offset = 0x40; 
    uintptr_t g_offset = 0x60;
    if (index2addr_addr) {
        uintptr_t f_end = next_func_addr_vm(index2addr_addr);
        for (uintptr_t pc = index2addr_addr; pc < f_end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if ((insn & 0xFFC00000) == 0xA9400000) {
                uint32_t offset = ((insn >> 15) & 0x7F) << 3; 
                if (offset == 0x38 || offset == 0x30 || offset == 0x40) {
                    top_offset = offset;
                    base_offset = offset + 8;
                }
            }
        }
    } else {
        index2addr_addr = 0x021BCA54; 
    }
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "lua_index2addr") results[i] = index2addr_addr;
        else if (scans[i].name == "lua_state_top") results[i] = top_offset;
        else if (scans[i].name == "lua_state_base") results[i] = base_offset;
        else if (scans[i].name == "lua_state_global_state") results[i] = g_offset;
    }
}

void resolve_luau_push_helpers(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t getfield_addr = 0;
    uintptr_t setfield_addr = 0;

    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luagetfield") getfield_addr = results[i];
        if (scans[i].name == "luasetfield") setfield_addr = results[i];
    }
    if (!getfield_addr) getfield_addr = 0x05ABAC1C; 
    if (!setfield_addr) setfield_addr = 0x05ABAD20;

    uintptr_t gf_end = next_func_addr_vm(getfield_addr);
    uintptr_t luaS_newlstr_addr = 0;
    for (uintptr_t pc = getfield_addr; pc < gf_end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_bl(insn)) {
            uintptr_t target = decode_bl(insn, pc);
            size_t target_end = next_func_addr_vm(target);
            size_t target_size = target_end - target;
            if (target_size > 0x80 && target_size < 0x400) {
                luaS_newlstr_addr = target;
                break;
            }
        }
    }
    uintptr_t pushlstring_addr = 0;
    size_t begin = (mem::text_start + 3) & ~3ULL;
    size_t end = mem::text_end - 4;
    if (luaS_newlstr_addr) {
        for (size_t i = begin; i < end; i += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + i);
            if (is_bl(insn) && decode_bl(insn, i) == luaS_newlstr_addr) {
                uintptr_t parent = mem::find_func(i);
                if (!parent || parent == getfield_addr || parent == setfield_addr) continue;

                size_t p_end = next_func_addr_vm(parent);
                bool has_stack_offset = false;
                for (size_t pc = parent; pc < p_end; pc += 4) {
                    uint32_t inner_insn = *(uint32_t*)(mem::data + pc);
                    if ((inner_insn & 0xFFC00000) == 0xF9400000) {
                        uint32_t imm = ((inner_insn >> 10) & 0xFFF) << 3;
                        if (imm == 0x38) {
                            has_stack_offset = true;
                            break;
                        }
                    }
                }

                if (has_stack_offset) {
                    pushlstring_addr = parent;
                    break;
                }
            }
        }
    }
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luas_newlstr") results[i] = luaS_newlstr_addr;
        else if (scans[i].name == "lua_pushlstring") results[i] = pushlstring_addr;
    }
}

void resolve_miscstuff(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    uintptr_t game_loaded_func_addr = 0;
    uintptr_t on_game_leave_func_addr = 0;
    
    uintptr_t str_loaded = mem::find_str("onGameLoaded() SessionReporterState_GameLoaded placeId:%lld");
    if (str_loaded) {
        auto xrefs_loaded = mem::find_xrefs(str_loaded);
        if (!xrefs_loaded.empty()) {
            game_loaded_func_addr = mem::find_func(xrefs_loaded[0]);
        }
    }
    uintptr_t str_leave = mem::find_str("onGameLeaveBegin() SessionReporterState_GameExitRequested placeId:%lld");
    if (str_leave) {
        auto xrefs_leave = mem::find_xrefs(str_leave);
        if (!xrefs_leave.empty()) {
            on_game_leave_func_addr = mem::find_func(xrefs_leave[0]);
        }
    }
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "game_loaded") {
            if (game_loaded_func_addr) {
                results[i] = game_loaded_func_addr;
            }
        } 
        else if (scans[i].name == "on_game_leave") {
            if (on_game_leave_func_addr) {
                results[i] = on_game_leave_func_addr;
            }
        }
    }
}

void resolve_getcapabilities(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    uintptr_t str_addr = mem::find_str("Callbacks cannot yield");
    if (!str_addr) return;
    auto xrefs = mem::find_xrefs(str_addr);
    if (xrefs.empty()) return;
    for (uintptr_t xref : xrefs) {
        uintptr_t caller_func = mem::find_func(xref);
        if (!caller_func) continue;
        size_t next_func = next_func_addr_vm(caller_func);
        for (size_t pc = caller_func; pc < next_func; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if (!is_bl(insn)) continue;
            uintptr_t candidate = decode_bl(insn, pc);
            if (candidate < mem::text_start || candidate >= mem::text_end) continue;
            bool has_loop_0x50 = false;
            size_t cand_end = next_func_addr_vm(candidate);
            for (size_t i = candidate; i < cand_end; i += 4) {
                uint32_t ins = *(uint32_t*)(mem::data + i);
                if ((ins & 0xFF000000) == 0xF1000000 && ((ins >> 10) & 0xFFF) == 0x50) {
                    has_loop_0x50 = true;
                    break;
                }
            }
            if (has_loop_0x50) {
                for (size_t i = 0; i < scans.size(); ++i) {
                    if (scans[i].name == "getcapabilities") {
                        results[i] = candidate;
                        return;
                    }
                }
            }
        }
    }
}

void resolve_vm_offsets(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t lua_resume = 0;
    uintptr_t luaG_runerror = 0;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luaresume") lua_resume = results[i];
        else if (scans[i].name == "luaG_runerror") luaG_runerror = results[i];
    }

    uintptr_t luau_execute = 0;
    uintptr_t luaD_throw = 0;
    uintptr_t luaC_step = 0;
    {
        const uint8_t sig[] = { 0xe9, 0x23, 0xba, 0x6d, 0xfd, 0x7b, 0x01, 0xa9, 0xf9, 0x13, 0x00, 0xf9 };
        for (size_t pc = mem::text_start; pc <= mem::text_end - 0x30; pc += 4) {
            if (memcmp(mem::data + pc, sig, sizeof(sig)) == 0) {
                uint32_t insn = *(uint32_t*)(mem::data + pc + 0x24);
                uint32_t op = insn & 0xFFC00000;
                uint32_t imm12 = (insn >> 10) & 0xFFF;
                if (op == 0x71000000 && imm12 == 201) {
                    luau_execute = pc;
                    break;
                }
            }
        }
    }
    if (luaG_runerror) {
        uintptr_t body_candidate = 0;
        for (size_t pc = luaG_runerror; pc < luaG_runerror + 128 && pc < mem::text_end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if (is_bl(insn)) {
                uintptr_t target = decode_bl(insn, pc);
                if (target >= mem::text_start && target < mem::text_end) {
                    int64_t diff = (int64_t)target - (int64_t)luaG_runerror;
                    if (diff > -0x2000 && diff < 0x2000) {
                        body_candidate = target;
                        break;
                    }
                }
            }
        }

        if (body_candidate) {
            for (size_t pc = body_candidate; pc < body_candidate + 400 && pc < mem::text_end; pc += 4) {
                uint32_t insn = *(uint32_t*)(mem::data + pc);
                if (is_bl(insn)) {
                    uintptr_t target = decode_bl(insn, pc);
                    if (target >= mem::text_start && target < mem::text_end) {
                        bool has_mov = false;
                        for (int k = 0; k < 12; ++k) {
                            size_t addr = target + k * 4;
                            if (addr >= mem::text_end) break;
                            uint32_t ins = *(uint32_t*)(mem::data + addr);
                            if (ins == 0x52800300) {
                                has_mov = true;
                                break;
                            }
                        }
                        if (has_mov) {
                            luaD_throw = target;
                            break;
                        }
                    }
                }
            }
        }
    }
    if (lua_resume) {
        uintptr_t luau_range_start = (lua_resume >= 0x200000) ? lua_resume - 0x200000 : mem::text_start;
        uintptr_t luau_range_end = std::min(lua_resume + 0x200000, (uintptr_t)mem::text_end);

        struct GCFunction {
            uintptr_t addr;
            std::vector<uintptr_t> calls;
        };
        std::vector<GCFunction> gc_funcs;
        uintptr_t curr_func = 0;
        bool has_gc_offsets = false;
        std::vector<uintptr_t> bl_calls;
        for (size_t pc = luau_range_start; pc < luau_range_end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if (is_func_prologue_vm(insn)) {
                if (curr_func != 0 && has_gc_offsets) {
                    gc_funcs.push_back({curr_func, bl_calls});
                }
                curr_func = pc;
                has_gc_offsets = false;
                bl_calls.clear();
            }
            if (curr_func != 0) {
                uint32_t op = insn & 0xffc00000;
                if (op == 0xf9400000 || op == 0xf9000000) {
                    uint32_t imm = ((insn >> 10) & 0xfff) << 3;
                    if (imm >= 0x4400 && imm <= 0x4750) {
                        has_gc_offsets = true;
                    }
                } else if (is_bl(insn)) {
                    uintptr_t target = decode_bl(insn, pc);
                    if (target >= mem::text_start && target < mem::text_end) {
                        bl_calls.push_back(target);
                    }
                }
            }
        }
        if (curr_func != 0 && has_gc_offsets) {
            gc_funcs.push_back({curr_func, bl_calls});
        }

        std::vector<uintptr_t> unique_targets;
        for (const auto& gf : gc_funcs) {
            for (uintptr_t target : gf.calls) {
                if (std::find(unique_targets.begin(), unique_targets.end(), target) == unique_targets.end()) {
                    unique_targets.push_back(target);
                }
            }
        }

        for (uintptr_t target : unique_targets) {
            size_t e = next_func_addr_vm(target);
            bool target_has_gc = false;
            for (size_t pc = target; pc < e; pc += 4) {
                uint32_t insn = *(uint32_t*)(mem::data + pc);
                uint32_t op = insn & 0xffc00000;
                if (op == 0xf9400000 || op == 0xf9000000) {
                    uint32_t imm = ((insn >> 10) & 0xfff) << 3;
                    if (imm >= 0x4400 && imm <= 0x4750) {
                        target_has_gc = true;
                        break;
                    }
                }
            }
            if (target_has_gc) {
                luaC_step = target;
                break;
            }
        }
    }

    uintptr_t luaE_newthread = 0;
    {
        size_t begin = (mem::text_start + 3) & ~3ULL;
        size_t end = mem::text_end - 32;
        for (size_t i = begin; i < end; i += 4) {
            uint32_t ins1 = *(uint32_t*)(mem::data + i);
            if (ins1 == 0x52800101) {
                for (int j = 1; j < 5; ++j) {
                    uint32_t ins2 = *(uint32_t*)(mem::data + i + j * 4);
                    if ((ins2 & 0xFF80001F) == 0x52800002) {
                        uint32_t imm = (ins2 >> 5) & 0xFFFF;
                        if (imm >= 16 && imm <= 48 && (imm % 8) == 0) {
                            for (int k = 1; k < 5; ++k) {
                                uint32_t ins3 = *(uint32_t*)(mem::data + i + (j + k) * 4);
                                if (is_bl(ins3)) {
                                    luaE_newthread = mem::find_func(i);
                                    break;
                                }
                            }
                        }
                    }
                    if (luaE_newthread) break;
                }
            }
            if (luaE_newthread) break;
        }
    }

    uintptr_t lua_newthread = 0;
    if (luaE_newthread) {
        std::vector<uintptr_t> callers;
        size_t begin = (mem::text_start + 3) & ~3ULL;
        size_t end = mem::text_end - 4;
        for (size_t i = begin; i < end; i += 4) {
            uint32_t ins = *(uint32_t*)(mem::data + i);
            if (is_bl(ins)) {
                uintptr_t target = decode_bl(ins, i);
                if (target == luaE_newthread) {
                    uintptr_t caller_func = mem::find_func(i);
                    if (caller_func && std::find(callers.begin(), callers.end(), caller_func) == callers.end()) {
                        callers.push_back(caller_func);
                    }
                }
            }
        }

        uintptr_t getscheduler_addr = 0;
        for (size_t i = 0; i < scans.size(); ++i) {
            if (scans[i].name == "getscheduler") {
                getscheduler_addr = results[i];
                break;
            }
        }

        for (uintptr_t caller : callers) {
            bool calls_scheduler = false;
            size_t next_func = next_func_addr_vm(caller);
            for (size_t pc = caller; pc < next_func; pc += 4) {
                uint32_t ins = *(uint32_t*)(mem::data + pc);
                if (is_bl(ins)) {
                    uintptr_t target = decode_bl(ins, pc);
                    if (getscheduler_addr && target == getscheduler_addr) {
                        calls_scheduler = true;
                        break;
                    }
                }
            }
            if (!calls_scheduler) {
                lua_newthread = caller;
                break;
            }
        }
    }

    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luau_execute") results[i] = luau_execute;
        else if (scans[i].name == "luaD_throw") results[i] = luaD_throw;
        else if (scans[i].name == "luaC_step") results[i] = luaC_step;
        else if (scans[i].name == "luaE_newthread") results[i] = luaE_newthread;
        else if (scans[i].name == "lua_newthread") results[i] = lua_newthread;
    }
    resolve_getcapabilities(scans, results);
    resolve_tsconstrctor(scans, results);
    resolve_tsdecoffsets(scans, results);
    resolvejobevents(scans, results);
    resolve_network_telemetry(scans, results);
    resolve_lua_index2addr(scans, results);
    resolve_luau_push_helpers(scans, results);
    resolve_miscstuff(scans, results);
}
