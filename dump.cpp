#include "dump.h"
#include "mem.h"
#include <algorithm>

std::vector<scan> scans = {
    // standartenfuhrer patterns. add yours broski
    {"print", "Current identity is %d", "", 1, 0, false},
    {"game_loaded", "onGameLoaded() SessionReporterState_GameLoaded placeId:%lld", "", 1, 0, false},
    {"on_game_leave", "onGameLeaveBegin() SessionReporterState_GameExitRequested placeId:%lld", "", 0, 0, false},
    {"scriptstart", "", "fd 7b bd a9 fc 57 01 a9 f4 4f 02 a9 fd 03 00 91 ff 03 0a d1 ?? ?? ?? 90", 0, 0, false},
    {"fireproximityprompt", "ProximityPrompt_Triggered", "", 0, 0, false},
    {"firetouchinterest", "new overlap in different world", "", 0, 0, false},
    {"jobstart", "[FLog::TaskSchedulerRun] JobStart %s", "", 0, 0, false},
    {"jobstop", "[FLog::TaskSchedulerRun] JobStop %s", "", 0, 0, false},
    {"rbxspawn", "", "?? ?? ?? b0 ?? ?? ?? 91 09 05 80 52 ?? ?? ?? b0 ?? ?? ?? 91", 0, 0, false},
    {"taskdesynchronize", "task.desynchronize() should only be called from a script that is a descendant of an Actor", "", 0, 0, false},
    {"rawscheduler", "HumanoidParallelManagerTaskQueue", "", 1, 0, false},
    {"taskschedulerfps", "", "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 ?? ?? ?? 90 ?? ?? ?? 91", 0, 0, false},
    {"lockviolationcrash", "LockViolationInstanceCrash", "", 0, 0, false},
    {"lockviolationscriptcrash", "LockViolationScriptCrash", "", 0, 0, false},
    {"luastepinternaloverride", "LuaStepIntervalMsOverrideEnabled", "", 0, 0, false},
    {"hashtablelookup", "Unable to query property {}. It is not scriptable", "", 0, 0, false},
    {"getglobalstateforinstance", "[FLog::ScriptContextAdd] LoaderFacet::addScript -- %s", "", 3, 0, false},
    {"enableloadmodule", "EnableLoadModule", "", 0, 0, false},
    {"luauregistermethod", "", "f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 94 e0 03 13 aa", 1, 0, false},
    {"stdstringconstructor", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa", 0, 0, false},
    {"luauloadinternal", "", "?? ?? ?? b4 fd 7b bc a9 f8 5f 01 a9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91", 0, 0, false},
    {"luauloadcorescripts", "", "fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 03 00 91 ff 83 06 d1", 0, 0, false},
    {"validateandsetupcaps", "", "ff 83 02 d1 fd 7b 06 a9 f8 5f 07 a9 f6 57 08 a9 f4 4f 09 a9", 0, 0, false},

};

static inline bool is_bl(uint32_t insn) {
    return (insn & 0xFC000000) == 0x94000000;
}

static inline uint64_t decode_bl(uint32_t insn, uint64_t pc) {
    int64_t imm = (insn & 0x3FFFFFF);
    if (imm & 0x2000000) imm |= 0xFC000000LL;
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
                result = bl_up(target, s.up);
            } else if (s.down > 0) {
                result = bl_down(target, s.down);
            }
            if (result) return result;
        }
    } else {
        if (s.up == 0 && s.down == 0) {
            return addr;
        } else if (s.up > 0) {
            return bl_up(addr, s.up);
        } else if (s.down > 0) {
            return bl_down(addr, s.down);
        }
    }

    return 0;
}
