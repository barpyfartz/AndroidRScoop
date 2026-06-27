#include "dump.h"
#include "mem.h"
#include <algorithm>
#include <unordered_map>

std::vector<scan> scans = {
	// standartenfuhrer patterns. add yours broski
    {"print", "Current identity is %d", "", 1, 0, false},
    {"game_loaded", "onGameLoaded() SessionReporterState_GameLoaded placeId:%lld", "", 1, 0, false},
    {"on_game_leave", "onGameLeaveBegin() SessionReporterState_GameExitRequested placeId:%lld", "", 0, 0, false},
    {"scriptstart", "", "fd 7b bd a9 fc 57 01 a9 f4 4f 02 a9 fd 03 00 91 ff 03 0a d1 ?? ?? ?? 90", 0, 0, false},
    {"firetouchinterest", "new overlap in different world", "", 0, 0, false},
    {"jobstart", "[FLog::TaskSchedulerRun] JobStart %s", "", 0, 0, false},
    {"jobstop", "[FLog::TaskSchedulerRun] JobStop %s", "", 0, 0, false},
    {"rbxspawn", "", "?? ?? ?? b0 ?? ?? ?? 91 09 05 80 52 ?? ?? ?? b0 ?? ?? ?? 91", 0, 0, false},
    {"taskdesynchronize", "task.desynchronize() should only be called from a script that is a descendant of an Actor", "", 0, 0, false},
    {"task_synchronize", "", "", 0, 0, false}, // thx pereoxide
    {"task_defer", "", "", 0, 0, false},
    {"task_spawn", "", "", 0, 0, false},
    {"task_delay", "", "", 0, 0, false},
    {"task_wait", "", "", 0, 0, false},
    {"task_cancel", "", "", 0, 0, false},
    {"rawscheduler", "HumanoidParallelManagerTaskQueue", "", 1, 0, false},
    {"taskschedulerfps", "", "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 ?? ?? ?? 90 ?? ?? ?? 91", 0, 0, false},
    {"lockviolationcrash", "LockViolationInstanceCrash", "", 0, 0, false},
    {"lockviolationscriptcrash", "LockViolationScriptCrash", "", 0, 0, false},
    {"luastepinternaloverride", "LuaStepIntervalMsOverrideEnabled", "", 0, 0, false},
    {"hashtablelookup", "Unable to query property {}. It is not scriptable", "", 0, 0, false},
    {"getglobalstateforinstance", "[FLog::ScriptContextAdd] LoaderFacet::addScript -- %s", "", 3, 0, false},
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
    {"namecallhandler",         "__namecall",                                        "", 0, 0, false},
    {"invokeserver",            "InvokeServer can only be called from the client",   "", 0, 0, false},
    {"fireserver",              "FireServer can only be called from the client",     "", 0, 0, false},
    {"fireallclients",          "FireAllClients can only be called from the server", "", 0, 0, false},
    {"invokeclient",            "InvokeClient can only be called from the server",   "", 0, 0, false},
    {"luauload",               "%s: bytecode version mismatch (expected [%d..%d], got %d)", "", 0, 0, false},
    {"luauyield",              "attempt to yield across metamethod/C-call boundary", "", 0, 0, false},
    {"resumewaitingscripts",    "WaitingHybridScriptsJob",                           "", 1, 0, false},
    {"getscheduler",            "", "ff c3 01 d1 fd 7b 04 a9 f5 2b 00 f9 f4 4f 06 a9 fd 03 01 91 ?? ?? ?? ?? ?? ?? ?? ?? a8 02 40 f9 a8 83 1f f8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f3 03 00 aa 08 fd df 08 ?? ?? ?? ?? e0 03 13 aa", 0, 0, false},
    {"setthreadidentity",       "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 02 aa f4 03 01 2a 3f 04 00 71 f5 03 00 aa", 0, 0, false},
    {"getthreadidentity",       "", "08 ?? 40 f9 09 ?? 40 f9 08 01 09 cb 00 fd 44 d3 c0 03 5f d6", 0, 0, false},
    {"newproxy",                "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 21 00 80 52 f3 03 00 aa ?? ?? ?? ?? 08 78 1f 12 1f 19 00 71", 0, 0, false},
    {"loadstring",              "", "ff 03 02 d1 fd 7b 04 a9 f7 2b 00 f9 f6 57 06 a9 f4 4f 07 a9 fd 03 01 91 ?? ?? ?? ?? f3 03 00 aa ?? ?? ?? ?? e8 02 40 f9 a8 83 1f f8 ?? ?? ?? ?? f5 03 00 aa 00 a0 42 a9 88 00 00 b4 a1 0e 40 f9 00 01 3f d6 a0 fe 02 a9", 0, 0, false},
    {"getfenv", "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 00 90 52 ?? ?? ?? ?? e0 03 13 aa 21 00 80 52", 0, 0, false},
    {"setfenv", "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 00 90 52 ?? ?? ?? ?? e0 03 13 aa 41 00 80 52", 0, 0, false},
    {"luaG_aritherror", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f5 03 03 2a f6 03 02 aa f3 03 00 aa ?? ?? ?? ?? f4 03 00 aa e0 03 13 aa e1 03 16 aa", 0, 0, false},
    {"luagetfield", "", "", 0, 0, false}, // d
    {"luasetfield", "", "", 0, 0, false}
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
    int64_t imm = (int64_t)((immhi << 2) | immlo) << 12;
    if (imm & (1LL << 32)) imm |= ~((1LL << 33) - 1);
    return (pc & ~0xFFFULL) + (uint64_t)imm;
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
