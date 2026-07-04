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
    {"scriptstart", "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f3 03 04 aa f4 03 03 aa f5 03 02 aa f6 03 01 aa f7 03 08 aa ?? ?? ?? ?? e8 03 17 aa", 0, 0, false},
    {"firetouchinterest", "new overlap in different world", "", 0, 0, false},
    {"jobstart", "[FLog::TaskSchedulerRun] JobStart %s", "", 0, 0, false},
    {"jobstop", "[FLog::TaskSchedulerRun] JobStop %s", "", 0, 0, false},
    {"rbxspawn", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 48 58 02 d0", 0, 0, false},
    {"rbxspawnconstructor", "", "ff 03 02 d1 fd 7b 02 a9 fb 1b 00 f9 fa 67 04 a9 f8 5f 05 a9 f6 57 06 a9 f4 4f 07 a9 fd 83 00 91 ?? ?? ?? ?? ba 83 41 39", 0, 0, false},
    {"taskdesynchronize", "task.desynchronize() should only be called from a script that is a descendant of an Actor", "", 0, 0, false},
    {"task_synchronize", "", "", 0, 0, false}, // thx pereoxide
    {"task_defer", "", "", 0, 0, false},
    {"task_spawn", "", "", 0, 0, false},
    {"task_delay", "", "", 0, 0, false},
    {"task_wait", "", "", 0, 0, false},
    {"task_cancel", "", "", 0, 0, false},
    {"taskschedulerconstructor", "HumanoidParallelManagerTaskQueue", "", 0, 0, false},
    {"rawscheduler", "HumanoidParallelManagerTaskQueue", "", 0, 1, false}, // caller
    {"taskschedulerfps", "", "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 ?? ?? ?? 90 ?? ?? ?? 91 ?? ?? ?? f0 ?? ?? ?? 91 ?? ?? ?? 90 ?? ?? ?? 91 ?? ?? ?? a9 88 0c 80 52", 0, 0, false},
    {"lockviolationcrash", "LockViolationInstanceCrash", "", 0, 0, false},
    {"lockviolationscriptcrash", "LockViolationScriptCrash", "", 0, 0, false},
    {"luastepinternaloverride", "LuaStepIntervalMsOverrideEnabled", "", 0, 0, false},
    {"hashtablelookup", "Unable to query property {}. It is not scriptable", "", 0, 0, false},
    {"getglobalstateforinstance", "", "ff 83 00 d1 fd 7b 01 a9 fd 43 00 91 08 21 82 52 08 00 08 8b 08 fd df 88 1f 0d 00 71", 0, 0, false},
    {"getluastate", "", "ff c3 02 d1 fd 7b 05 a9 fc 6f 06 a9 fa 67 07 a9 f8 5f 08 a9 f6 57 09 a9 f4 4f 0a a9 fd 43 01 91 ?? ?? ?? b0 f3 03 01 aa f5 03 00 aa", 0, 0, false},
    {"ktable", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? 15 14 40 f9 f4 03 00 aa 53 01 00 b4", 0, 0, false},
    {"scriptcontextresume", "", "ff 03 06 d1 e8 8b 00 fd fd 7b 12 a9 fc 6f 13 a9 fa 67 14 a9 f8 5f 15 a9 f6 57 16 a9 f4 4f 17 a9 fd 83 04 91 ?? ?? ?? b0 ?? ?? ?? b0 f6 03 00 aa ?? ?? ?? f9 f8 03 04 aa fa 03 03 2a", 0, 0, false},
    // {"robloxlogcrash", "", "", 0, 0, false},
    {"enableloadmodule", "EnableLoadModule", "", 0, 0, false},
    {"stdstringconstructor", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa 00 00 40 f9 f5 03 01 aa 74 0a 40 f9 60 02 00 b4 00 00 80 f9 40 03 00 37", 0, 0, false},
    {"luauloadcorescripts", "", "fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 03 00 91 ff 83 06 d1", 0, 0, false},
    {"validateandsetupcaps", "", "ff 83 02 d1 fd 7b 06 a9 f8 5f 07 a9 f6 57 08 a9 f4 4f 09 a9", 0, 0, false},
    {"luaG_typeerror",           "attempt to index %s with '%s'",                    "", 0, 0, false},
    {"luaresume",              "", "FD 7B BF A9 FD 03 00 91 08 0C 40 39 1F 19 00 71 ?? ?? ?? 54 1F 05 00 71 ?? ?? ?? 54 ?? ?? ?? 35 08 24 40 F9 09 18 40 F9 1F 01 09 EB ?? ?? ?? 54", 0, 0, false},
    {"luaresumefromsuspended", "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 08 0C 40 39 F3 03 00 AA F4 03 01 AA ?? ?? ?? 35 68 22 40 F9 1F 01 14 EB ?? ?? ?? 54", 0, 0, false},
    {"lua_resumewrapper", "", "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 f4 03 02 2a f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? 34", 0, 0, false},
    {"luaHsettable",           "table index is nil",                                "", 0, 0, false},
    {"stackoverflow",           "stack overflow (%s)",                               "", 0, 0, false},
    {"invalidkeynext",          "invalid key to 'next'",                             "", 0, 0, false},
    {"newindex",                "__newindex",                                         "", 0, 0, false},
    {"namecallhandler",          "__namecall",                                        "", 0, 0, false},
    {"invokeserver",            "InvokeServer can only be called from the client",   "", 0, 0, false},
    {"fireserver",              "FireServer can only be called from the client",     "", 0, 0, false},
    {"fireallclients",          "FireAllClients can only be called from the server", "", 0, 0, false},
    {"invokeclient",            "InvokeClient can only be called from the server",   "", 0, 0, false},
    {"luau_load",               "%s: bytecode version mismatch (expected [%d..%d], got %d)", "", 0, 0, false}, // for stupid niggers - luau_load is roblox made wrapper, lua_load is low-level
    {"lua_load", "", "", 0, 0, false},
    {"luauyield", "", "09 40 40 79 0a 44 40 79 e8 03 00 aa 3f 01 0a 6b ?? ?? ?? 54 ?? ?? ?? ?? 2a 00 80 52 00 00 80 12", 0, 0, false},
    {"resumewaitingscripts",    "WaitingHybridScriptsJob",                            "", 1, 0, false},
    {"getscheduler",            "", "ff c3 01 d1 fd 7b 04 a9 f5 2b 00 f9 f4 4f 06 a9 fd 03 01 91 ?? ?? ?? ?? ?? ?? ?? ?? a8 02 40 f9 a8 83 1f f8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f3 03 00 aa 08 fd df 08 ?? ?? ?? ?? e0 03 13 aa", 0, 0, false},
    {"newproxy",                "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 21 00 80 52 f3 03 00 aa ?? ?? ?? ?? 08 78 1f 12 1f 19 00 71", 0, 0, false},
    {"loadstring",           "loadstring() is not available",                               "", 0, 0, false},
    {"getfenv", "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 00 90 52 ?? ?? ?? ?? e0 03 13 aa 21 00 80 52", 0, 0, false},
    {"getfenv_thread", "", "FF C3 05 D1 FD 7B ?? A9 FC 57 ?? A9 F4 4F ?? A9 FD 03 05 91 ?? ?? ?? D0 F4 03 01 2A 21 00 80 52 ?? ?? ?? F9 F3 03 00 AA ?? ?? ?? F9 ?? ?? ?? F8 ?? ?? ?? 97 1F 20 00 71 81 01 00 54", 0, 0, false},
    {"setfenv", "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 00 90 52 ?? ?? ?? ?? e0 03 13 aa 41 00 80 52", 0, 0, false},
    {"luaG_aritherror", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f5 03 03 2a f6 03 02 aa f3 03 00 aa ?? ?? ?? ?? f4 03 00 aa e0 03 13 aa e1 03 16 aa", 0, 0, false},
    {"luagetfield", "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f4 03 02 aa 3f 04 00 71 f3 03 00 aa 2b 01 00 54 69 a2 43 a9 08 51 21 8b 08 41 00 d1", 0, 0, false},
    {"luasetfield", "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f4 03 03 2a f5 03 02 aa 3f 04 00 71 f3 03 00 aa 2b 01 00 54 69 a2 43 a9 08 51 21 8b 08 41 00 d1", 0, 0, false},
    {"luau_execute", "", "", 0, 0, false},
   // {"luaD_throw", "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 A8 65 00 F0 F4 03 01 AA F3 03 00 AA 08 21 5C 39", 0, 0, false}, roblox uses rbx_raiseluaexception, luad_throw aint even exist here :sob: this signature is a miss
    {"luaC_step", "", "", 0, 0, false},
    {"luaE_newthread", "", "", 0, 0, false},
    {"lua_newthread", "", "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 08 30 40 f9 f3 03 00 aa 08 25 43 a9 3f 01 08 eb ?? ?? ?? 54 e0 03 13 aa 21 00 80 52 ?? ?? ?? ?? 68 0a 40 39", 0, 0, false},
    {"getcapabilities", "", "", 0, 0, false},
    {"taskscheduler_mutex", "", "", 0, 0, true},
    {"taskscheduler_queue", "", "", 0, 0, true},
    {"taskscheduler_workers", "", "", 0, 0, true},
    {"telemetry_buffer", "", "", 0, 0, true},
    {"telemetry_size", "", "", 0, 0, true},
    {"luaL_register", "", "?? ?? ?? ?? ?? ?? 75 39 ?? ?? ?? 34 fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 08 30 40 f9", 0, 0, false},
    {"lua_state_top", "", "", 0, 0, true},
    {"lua_state_base", "", "", 0, 0, true},
    {"lua_state_globalstate", "", "", 0, 0, true},
    {"lua_state_status",        "", "", 0, 0, true},
   // {"lua_state_nccalls",       "", "", 0, 0, true},
    {"lua_state_ci",            "", "", 0, 0, true},
    {"lua_state_base_ci",       "", "", 0, 0, true}, // all commented structs are still working ass, gna fix em in next update
   // {"lua_state_sizeof",        "", "", 0, 0, true},
   // {"tvalue_tt",               "", "", 0, 0, true},
   // {"global_state_l_gt",       "", "", 0, 0, true},
   // {"global_state_registry",   "", "", 0, 0, true},
   // {"global_state_strhash",    "", "", 0, 0, true},
   // {"callinfo_sizeof",         "", "", 0, 0, true},
   // {"tstring_hdr_sizeof",      "", "", 0, 0, true},
   // {"table_sizeof",            "", "", 0, 0, true},
   // {"lclosure_sizeof",         "", "", 0, 0, true},
   // {"upval_sizeof",            "", "", 0, 0, true},
    {"scriptcontext_facet_lvl", "", "", 0, 0, true},
    {"luas_newlstr", "", "", 0, 0, false},
    {"lua_pushlstring", "", "", 0, 0, false},
    {"luaD_call", "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 28 0c 40 b9 f4 03 02 2a f6 03 01 aa f3 03 00 aa 1f 21 00 71 ?? ?? ?? 54 e0 03 13 aa e1 03 16 aa", 0, 0, false},
    {"luaD_resume", "", "", 0, 0, false},
    {"coroutine_yield", "", "", 0, 0, false},
    {"luaH_new", "", "FD 7B ?? A9 ?? ?? ?? F9 F4 4F 02 A9 FD 03 00 91 14 14 40 F9 F3 03 01 AA 14 01 00 B4", 0, 0, false},
    {"luau_bytecodeload", "", "ff 03 02 d1 fd 7b 05 a9 f6 57 06 a9 f4 4f 07 a9 fd 43 01 91 ?? ?? ?? ?? 08 00 80 12 f4 03 00 aa", 0, 0, false},
    {"luau_validateheader", "", "ff c3 01 d1 fd 7b 03 a9 f8 5f 04 a9 f6 57 05 a9 f4 4f 06 a9 fd c3 00 91 ?? ?? ?? ?? ?? ?? ?? ?? e8 02 40 f9 a8 83 1f f8 28 08 40 f9 1f 61 04 f1 63 0a 00 54 f4 03 01 aa ?? ?? ?? ?? 01 0a 00 b4 29 00 40 39 c9 09 00 34 f3 03 02 aa e2 03 08 aa ?? ?? ?? ?? 60 02 00 b9", 0, 0, false},
    {"rbx_reportbytecode", "", "fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 03 00 91 ff 83 13 d1 ?? ?? ?? ?? f3 03 04 2a f5 03 03 2a 7b 2f 46 f9 f4 03 02 aa f7 03 01 aa 68 03 40 f9 a8 83 1f f8 ?? ?? ?? ?? 08 21 01 91 19 61 40 a9 f9 e3 03 a9", 0, 0, false},
    {"luau_toobject", "", "fd 7b bf a9 fd 03 00 91 3f 04 00 71 2b 01 00 54 09 a0 43 a9 08 51 21 8b 08 41 00 d1 1f 01 09 eb ?? ?? ?? ?? ?? ?? ?? ?? 00 31 89 9a 08 00 00 14 c8 e1 84 12 3f 00 08 6b 8b 00 00 54 08 1c 40 f9 00 d1 21 8b 02 00 00 14 ?? ?? ?? ?? 08 0c 40 b9 1f 29 00 71", 0, 0, false},
    {"lua_settop", "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 f4 03 01 2A F3 03 00 AA 41 03 F8 37 ?? ?? ?? ?? ?? ?? ?? ??", 0, 0, false},
    {"internalstringhash", "", "FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 E0 03 01 AA F3 03 01 AA ?? ?? ?? ?? A0 01 00 B4 29 37 8F 52", 0, 0, false},
    {"taskscheduler_processjob", "", "FF 43 01 D1 FD 7B 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 43 00 91 ?? ?? ?? ?? ?? ?? ?? ?? C8 02 40 F9 E8 07 00 F9 28 00 40 F9 48 06 00 B4", 0, 0, false},
    {"fireserver_bridge", "", "ff 03 04 d1 fd 7b 0c a9 f8 5f 0d a9 f6 57 0e a9 f4 4f 0f a9 fd 03 03 91 ?? ?? ?? ?? f4 03 02 aa f5 03 01 aa", 0, 0, false},
    {"lua_xmove", "", "FD 7B BD A9 F6 57 01 A9 F4 4F 02 A9 FD 03 00 91 1F 00 01 EB ?? ?? ?? 54 28 08 40 39 F4 03 01 AA F3 03 00 AA F5 03 02 2A ?? ?? ?? 36 82 22 00 91 E0 03 14 AA E1 03 14 AA ?? ?? ?? ?? ?? ?? ?? 90 08 21 5C 39", 0, 0, false},
    {"lua_checkstack", "", "FF 03 01 D1 FD 7B 01 A9 F5 13 00 F9 F4 4F 03 A9 FD 43 00 91 ?? ?? ?? ?? 08 E8 83 52 ?? ?? ?? ?? 3F 00 08 6B ?? ?? ?? ?? ?? ?? ?? ?? 4C 01 00 54 08 A4 43 A9 0A E8 83 52 F4 03 01 2A F3 03 00 AA 09 01 09 CB 29 FD 44 93 29 C1 21 8B 3F 01 0A EB", 0, 0, false},
    {"lua_istable", "", "FD 7B BF A9 FD 03 00 91 3F 04 00 71 2B 01 00 54 09 A0 43 A9 08 51 21 8B 08 41 00 D1 1F 01 09 EB ?? ?? ?? ?? ?? ?? ?? ?? 00 31 89 9A 08 00 00 14 C8 E1 84 12 3F 00 08 6B ?? ?? ?? ?? 08 1C 40 F9 00 D1 21 8B 02 00 00 14 ?? ?? ?? ?? 08 0C 40 B9 1F 21 00 71 ?? ?? ?? ?? 08 00 40 F9 08 0D 40 39 1F 01 00 71 E0 07 9F 1A", 0, 0, false},
    {"lua_isreadonly", "", "FD 7B BF A9 FD 03 00 91 3F 04 00 71 2B 01 00 54 09 A0 43 A9 08 51 21 8B 08 41 00 D1 1F 01 09 EB ?? ?? ?? ?? ?? ?? ?? ?? 00 31 89 9A 08 00 00 14 C8 E1 84 12 3F 00 08 6B ?? ?? ?? ?? 08 1C 40 F9 00 D1 21 8B 02 00 00 14 ?? ?? ?? ?? 08 0C 40 B9 1F 21 00 71 ?? ?? ?? ?? 08 00 40 F9 08 0D 40 39 1F 01 00 71 E0 17 9F 1A", 0, 0, false},
    {"lua_type", "", "FD 7B BF A9 FD 03 00 91 3F 04 00 71 ?? ?? ?? 54 09 A0 43 A9 08 51 21 8B 00 41 00 D1 1F 00 09 EB", 0, 0, false},
    {"lua_pushvalue", "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 08 08 40 39 F3 03 00 AA F4 03 01 2A A8 00 10 36 62 22 00 91", 0, 0, false},
    {"luaL_optinteger", "", "FD 7B BD A9 F5 0B 00 F9 F4 4F 02 A9 FD 03 00 91 F4 03 02 2A F3 03 01 2A F5 03 00 AA ?? ?? ?? 97 1F 04 00 71", 0, 0, false},
    {"lua_tointegerx", "", "FF 03 01 D1 FD 7B 02 A9 F4 4F 03 A9 FD 83 00 91 ?? ?? ?? F0 F3 03 02 AA 3F 04 00 71 ?? ?? ?? F9 88 02 40 F9 A8 83 1F F8", 0, 0, false},
    {"luaL_checkinteger", "", "FF 03 01 D1 FD 7B 01 A9 F5 13 00 F9 F4 4F 03 A9 FD 43 00 91 ?? ?? ?? F0 E2 13 00 91 F3 03 01 2A ?? ?? ?? F9 F4 03 00 AA", 0, 0, false},
    {"lua_getinfo", "", "FF C3 05 D1 FD 7B 14 A9 FC AB 00 F9 F4 4F 16 A9 FD 03 05 91 ?? ?? ?? F0 ?? ?? ?? D0 ?? ?? ?? 91 ?? ?? ?? F9", 0, 0, false},
    {"luaC_link", "", "28 08 40 39 09 30 40 F9 08 79 1D 12 28 08 00 39 28 11 40 F9 48 00 00 F9 21 11 00 F9 C0 03 5F D6", 0, 0, false},
    {"luaL_typerror", "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 F3 03 01 2A E1 03 02 2A F4 03 00 AA ?? ?? ?? 97 E2 03 00 AA E0 03 14 AA E1 03 13 2A ?? ?? ?? 97", 0, 0, false},
    {"luaL_error", "", "FF C3 04 D1 FD 7B 10 A9 FC 57 11 A9 F4 4F 12 A9 FD 03 04 91 E2 0F 08 A9 ?? ?? ?? F0 E9 03 00 91 E4 17 09 A9", 0, 0, false},
    {"luaL_argerror", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 02 aa f4 03 01 2a f5 03 00 aa ?? ?? ?? 97 f6 03 00 aa e0 03 15 aa e1 03 14 2a", 0, 0, false},
    {"luaT_getobjname", "", "FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 29 0C 40 B9 3F 09 00 71 ?? ?? ?? 54 3F 25 00 71", 0, 0, false},
    {"luaO_pushvfstring", "", "FF 83 01 D1 FD 7B 03 A9 F6 57 04 A9 F4 4F 05 A9 FD C3 00 91 ?? ?? ?? B0 F4 03 02 AA F3 03 00 AA", 0, 0, false},
    {"luaT_objtypename", "", "FD 7B BF A9 FD 03 00 91 ?? ?? ?? 97 00 60 00 91 FD 7B C1 A8 C0 03 5F D6", 0, 0, false}, // avitamin
    {"rbx_raiseluaexception", "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 F4 03 00 AA 00 03 80 52 F3 03 01 2A ?? ?? ?? 97", 0, 0, false},
    {"lua_typename", "", "3F 04 00 31 ?? ?? ?? 54 ?? ?? ?? B0 ?? ?? ?? 91 00 D9 61 F8 C0 03 5F D6", 0, 0, false},
    {"lua_toboolean", "", "C8 E1 84 12 3F 00 08 6B ?? ?? ?? 54 08 1C 40 F9 00 D1 21 8B ?? ?? ?? 14 ?? ?? ?? 94 08 0C 40 B9 ?? ?? ?? 34 1F 05 00 71 ?? ?? ?? 54 08 00 40 B9 1F 01 00 71 E8 07 9F 1A", 0, 0, false},
    {"lua_touserdata", "", "C8 E1 84 12 3F 00 08 6B ?? ?? ?? 54 08 1C 40 F9 00 D1 21 8B ?? ?? ?? 14 ?? ?? ?? 94 08 0C 40 B9 1F 09 00 71 ?? ?? ?? 54 1F 25 00 71 ?? ?? ?? 54 08 00 40 F9 00 41 00 91", 0, 0, false},
 //   {"lua_pushstring", "", "8A 00 80 52 14 01 00 F9 69 1E 40 F9 0A 0D 00 B9 28 41 00 91 68 1E 00 F9 F4 4F 41 A9 FD 7B C2 A8 C0 03 5F D6", 0, 0, false}, they r good but dumper has ASS memory work so ts cant work normally
 //   {"lua_pushvector3", "", "A9 00 80 52 0A 25 00 2D 08 09 00 BD 09 0D 00 B9 08 41 00 91 68 1E 00 F9 FD FB 41 A9 F3 17 40 F9 E9 A3 40 6D EA 07 43 FC C0 03 5F D6", 0, 0, false},
    {"lua_gettable", "", "C8 E1 84 12 9F 02 08 6B ?? ?? ?? 54 68 1E 40 F9 01 D1 34 8B ?? ?? ?? 14 E0 03 13 AA E1 03 14 2A ?? ?? ?? 94 68 1E 40 F9 E1 03 00 AA 02 41 00 D1 E0 03 13 AA E3 03 02 AA ?? ?? ?? 97 68 1E 40 F9 00 C1 5F B8", 0, 0, false},
    {"lua_resumefinalize",       "", "FD 7B BC A9 F8 5F 01 A9 F6 57 02 A9 F4 4F 03 A9 FD 03 00 91 F4 03 02 2A F5 03 01 2A F3 03 00 AA", 0, 0, false},
    {"luaD_calldispatcher",  "", "FD 7B BD A9 F5 0B 00 F9 F4 4F 02 A9 FD 03 00 91 F4 03 00 AA E8 03 01 AA E1 03 02 AA 00 01 3F D6", 0, 0, false},
    {"resume_error",          "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 28 08 00 51 F3 03 02 AA F4 03 00 AA 1F 09 00 71 43 01 00 54", 0, 0, false},
    {"luaD_poscall",          "", "08 24 40 F9 0C 1C 40 F9 0B 29 40 B9 0A 0D 40 F9 09 C1 00 D1 7F 01 00 71 80 11 41 FA", 0, 0, false},
    {"luaG_runerror",         "", "FD 7B BE A9 FC 4F 01 A9 FD 03 00 91 FF 03 0C D1 E2 0F 08 A9 89 45 00 F0 EA 03 02 91 E4 17 09 A9", 0, 0, false},
    {"lua_index2addr", "", "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 08 08 40 39 f3 03 00 aa f4 03 01 2a a8 00 10 36 62 22 00 91 e0 03 13 aa e1 03 13 aa ?? ?? ?? ?? 9f 06 00 71 ?? ?? ?? 54 69 a2 43 a9", 0, 0, false},
    {"luaH_getstr", "", "29 0c 40 39 4a 10 40 b9 08 21 c9 1a 29 0c 40 f9 48 01 28 0a 28 15 08 8b 09 1d 40 b9", 0, 0, false},
    {"instance_getproperty", "Unable to query property {}. It is not scriptable", "", 0, 0, false},
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
    if (start_str && start_idx != (size_t)-1) {
        auto xrefs = mem::find_xrefs(start_str);
        for (uintptr_t xref : xrefs) {
            uintptr_t func = mem::find_func(xref);
            if (!func) continue;
            uintptr_t f_end = next_func_addr_vm(func);
            if ((f_end - func) > 0x60) {
                results[start_idx] = func;
                break;
            }
        }
    }
    uintptr_t stop_str = mem::find_str("[FLog::TaskSchedulerRun] JobStop %s");
    if (stop_str && stop_idx != (size_t)-1) {
        auto xrefs = mem::find_xrefs(stop_str);
        for (uintptr_t xref : xrefs) {
            uintptr_t func = mem::find_func(xref);
            if (!func) continue;
            uintptr_t f_end = next_func_addr_vm(func);
            if ((f_end - func) > 0x60) {
                results[stop_idx] = func;
                break;
            }
        }
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

void resolve_lua_index2addr(const std::vector<scan>& scans, std::vector<uintptr_t>& results) { // lowkass
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

    // scans big booty fallback
    if (!index2addr_addr) {
        for (size_t i = 0; i < scans.size(); ++i) {
            if (scans[i].name == "lua_index2addr" && results[i]) {
                index2addr_addr = results[i];
                break;
            }
        }
    }

    if (!index2addr_addr) return;

    uintptr_t top_offset = 0x38;
    uintptr_t base_offset = 0x40;
    uintptr_t g_offset = 0x60;

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

    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "lua_index2addr") results[i] = index2addr_addr;
        else if (scans[i].name == "lua_state_top") results[i] = top_offset;
        else if (scans[i].name == "lua_state_base") results[i] = base_offset;
        else if (scans[i].name == "lua_state_global_state") results[i] = g_offset;
    }
}

void resolve_lua_load(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    uintptr_t luau_load_addr = 0;
    size_t lua_load_idx = -1;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luau_load") {
            luau_load_addr = results[i];
        }
        if (scans[i].name == "lua_load") {
            lua_load_idx = i;
        }
    }

    if (!luau_load_addr || lua_load_idx == -1) return;
    uintptr_t xref_addr = 0;
    size_t begin = (mem::text_start + 3) & ~3ULL;
    size_t end = mem::text_end - 4;
    for (size_t i = begin; i < end; i += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + i);
        if (is_adr(insn)) {
            if (decode_adr(insn, i) == luau_load_addr) {
                xref_addr = i;
                break;
            }
        }
        if (is_adrp(insn) && i + 4 < end) {
            uint32_t insn2 = *(uint32_t*)(mem::data + i + 4);
            if (decode_adrp_add(insn, insn2, i) == luau_load_addr) {
                xref_addr = i;
                break;
            }
        }
    }
    if (xref_addr) {
        uintptr_t lua_load_func = mem::find_func(xref_addr);
        if (lua_load_func) {
            results[lua_load_idx] = lua_load_func;
        }
    }
}

void resolve_luau_push_helpers(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t getfield_addr = 0;
    uintptr_t setfield_addr = 0;
    size_t newlstr_idx = -1;
    size_t pushlstring_idx = -1;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luagetfield") getfield_addr = results[i];
        if (scans[i].name == "luasetfield") setfield_addr = results[i];
        if (scans[i].name == "luas_newlstr") newlstr_idx = i;
        if (scans[i].name == "lua_pushlstring") pushlstring_idx = i;
    }

    if (!getfield_addr || !setfield_addr || newlstr_idx == -1 || pushlstring_idx == -1) return;

    uintptr_t gf_end = next_func_addr_vm(getfield_addr);
    uintptr_t luaS_newlstr_addr = 0;
    int bl_counter = 0;
    for (uintptr_t pc = getfield_addr; pc < gf_end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_bl(insn)) {
            bl_counter++;
            uintptr_t target = decode_bl(insn, pc);
            if (bl_counter > 1) {
                uintptr_t target_end = next_func_addr_vm(target);
                size_t target_size = target_end - target;
                if (target_size > 0x80 && target_size < 0x400) {
                    luaS_newlstr_addr = target;
                    results[newlstr_idx] = luaS_newlstr_addr;
                    break;
                }
            }
        }
    }

    if (!luaS_newlstr_addr) return;

    uintptr_t pushlstring_addr = 0;
    size_t begin = (mem::text_start + 3) & ~3ULL;
    size_t end = mem::text_end - 4;

    for (size_t i = begin; i < end; i += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + i);
        if (is_bl(insn) && decode_bl(insn, i) == luaS_newlstr_addr) {
            uintptr_t parent = mem::find_func(i);
            if (!parent || parent == getfield_addr || parent == setfield_addr) continue;

            size_t p_end = next_func_addr_vm(parent);
            bool has_stack_offset = false;
            int parent_bl_count = 0;

            for (size_t pc = parent; pc < p_end; pc += 4) {
                uint32_t inner_insn = *(uint32_t*)(mem::data + pc);
                if (is_bl(inner_insn)) parent_bl_count++;
                
                if ((inner_insn & 0xFFC00000) == 0xF9400000) { 
                    uint32_t imm = ((inner_insn >> 10) & 0xFFF) << 3;
                    if (imm == 0x38) {
                        has_stack_offset = true;
                    }
                }
            }
            if (has_stack_offset && parent_bl_count <= 3) {
                pushlstring_addr = parent;
                results[pushlstring_idx] = pushlstring_addr;
                break; 
            }
        }
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

void resolve_luauyeildoffsets(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    uintptr_t luau_yield_addr = 0;
    uintptr_t str_yield = mem::find_str("attempt to yield across metamethod/C-call boundary");
    if (str_yield) {
        auto xrefs_str = mem::find_xrefs(str_yield);
        if (!xrefs_str.empty()) luau_yield_addr = mem::find_func(xrefs_str[0]);
    }
    if (!luau_yield_addr) return;
    uintptr_t task_synchronize = 0, task_desynchronize = 0, task_wait = 0;
    uintptr_t coroutine_yield = 0, luaD_resume_addr = 0;
    if (str_yield) {
        auto xrefs = mem::find_xrefs(str_yield);
        for (uintptr_t xref : xrefs) {
            uintptr_t f = mem::find_func(xref);
            if (!f) continue;
            size_t f_end = next_func_addr_vm(f);
            if ((f_end - f) < 0x100) {
                coroutine_yield = f;
                break;
            }
        }
    }
    auto callers = mem::find_xrefs(luau_yield_addr);
    for (uintptr_t target : callers) {
        uintptr_t caller_func = mem::find_func(target);
        if (!caller_func) continue;
        uint32_t first_insn = *(uint32_t*)(mem::data + caller_func);
        size_t func_end = next_func_addr_vm(caller_func);
        size_t func_size = func_end - caller_func;
        if (is_func_prologue_vm(first_insn) && func_size < 0x800) {
            bool is_desync = false;
            for (size_t pc = caller_func; pc < func_end && pc < caller_func + 0x100; pc += 4) {
                if ((*(uint32_t*)(mem::data + pc) & 0xFFC00000) == 0x37000000) {
                    is_desync = true;
                    break;
                }
            }
            if (is_desync) task_desynchronize = caller_func;
            else task_synchronize = caller_func;
            continue;
        }

        if (is_func_prologue_vm(first_insn) && func_size > 0x150) {
            task_wait = caller_func;
            continue;
        }
    }
    uintptr_t luaresumefromsuspended_addr = 0;
    uintptr_t str_nonsuspended = mem::find_str("cannot resume non-suspended coroutine");
    if (str_nonsuspended) {
        auto xrefs = mem::find_xrefs(str_nonsuspended);
        for (uintptr_t xref : xrefs) {
            uintptr_t f = mem::find_func(xref);
            if (f) {
                luaresumefromsuspended_addr = f;
                break;
            }
        }
    }
    
    uintptr_t lua_resume_addr = 0;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luaresume") {
            lua_resume_addr = results[i];
            break;
        }
    }
    if (luaresumefromsuspended_addr) {
        auto callers = mem::find_bl_xrefs(luaresumefromsuspended_addr);
        for (uintptr_t site : callers) {
            uintptr_t caller = mem::find_func(site);
            if (!caller || caller >= 0x04000000) continue;
            size_t c_end = next_func_addr_vm(caller);
            size_t c_size = c_end - caller;
            if (c_size > 0x50 && c_size < 0x200) {
                luaD_resume_addr = caller;
                break;
            }
        }
    }
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luauyield") results[i] = luau_yield_addr;
        else if (scans[i].name == "task_synchronize" && task_synchronize) results[i] = task_synchronize;
        else if (scans[i].name == "taskdesynchronize" && task_desynchronize) results[i] = task_desynchronize;
        else if (scans[i].name == "task_wait" && task_wait) results[i] = task_wait;
        else if (scans[i].name == "coroutine_yield" && coroutine_yield) results[i] = coroutine_yield;
        else if (scans[i].name == "luaD_resume" && luaD_resume_addr) results[i] = luaD_resume_addr;
    }
}

void resolve_struct_offsets(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    auto set_result = [&](const std::string& name, uintptr_t val) {
        for (size_t i = 0; i < scans.size(); ++i)
            if (scans[i].name == name) { results[i] = val; return; }
    };

    uintptr_t index2addr_addr = 0;
    uintptr_t getstr_addr = 0;
    uintptr_t newthread_addr = 0;
    uintptr_t newthread_internal = 0;
    
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "lua_index2addr") index2addr_addr = results[i];
        if (scans[i].name == "luaH_getstr") getstr_addr = results[i];
        if (scans[i].name == "lua_newthread") newthread_addr = results[i];
        if (scans[i].name == "luaE_newthread") newthread_internal = results[i];
    }

    if (!newthread_internal && newthread_addr) {
        for (size_t i = 0; i < 0x100; i += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + newthread_addr + i);
            uint32_t next_insn = *(uint32_t*)(mem::data + newthread_addr + i + 4);
            if (is_bl(insn) && next_insn == 0xf9401e69) {
                newthread_internal = decode_bl(insn, newthread_addr + i);
                break;
            }
        }
    }

    if (newthread_internal) {
        uint32_t insn_size = *(uint32_t*)(mem::data + newthread_internal + 0x10);
        if ((insn_size & 0xFFFF0000) == 0x52800000) {
            set_result("lua_state_sizeof", (insn_size >> 5) & 0xFFFF);
        }

        uintptr_t f_end = next_func_addr_vm(newthread_internal);
        for (uintptr_t pc = newthread_internal; pc < f_end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if ((insn & 0xFFC00000) == 0xA9000000) {
                uint32_t offset = ((insn >> 15) & 0x7F) << 3;
                if (offset >= 0x20 && offset <= 0x60) {
                    set_result("lua_state_globalstate", offset + 8);
                    set_result("lua_state_global_state", offset + 8);
                }
            }
            if ((insn & 0xFFC00000) == 0xF9000000) {
                uint32_t offset = ((insn >> 10) & 0xFFF) << 3;
                if (offset == 0x30) set_result("lua_state_base_ci", 0x30);
                if (offset == 0x48) set_result("lua_state_ci", 0x48);
            }
            if ((insn & 0xFFC00000) == 0x39400000) {
                uint32_t offset = (insn >> 10) & 0xFFF;
                if (offset < 0x10) set_result("lua_state_status", 0x03);
            }
            if ((insn & 0xFFC00000) == 0x79000000) {
                uint32_t offset = ((insn >> 10) & 0xFFF) << 1;
                if (offset >= 0x18 && offset <= 0x30) set_result("lua_state_nccalls", offset);
            }
        }
    }

    if (index2addr_addr) {
        uintptr_t f_end = next_func_addr_vm(index2addr_addr);
        for (uintptr_t pc = index2addr_addr; pc < f_end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if ((insn & 0xFFC00000) == 0xA9400000) {
                uint32_t offset = ((insn >> 15) & 0x7F) << 3;
                if (offset == 0x38 || offset == 0x30 || offset == 0x40) {
                    set_result("lua_state_top", offset);
                    set_result("lua_state_base", offset + 8);
                    break;
                }
            }
        }
    }

    if (getstr_addr) {
        uint32_t insn = *(uint32_t*)(mem::data + getstr_addr + 0x18);
        if ((insn & 0xFFC00000) == 0xF9400000) {
            uint32_t strhash_offset = ((insn >> 10) & 0xFFF) << 3;
            set_result("global_state_strhash", strhash_offset);
        }
    }

    uintptr_t reg_str = mem::find_str("Unable to query property {}. It is not scriptable");
    if (reg_str) {
        auto xrefs = mem::find_xrefs(reg_str);
        if (!xrefs.empty()) {
            uintptr_t func = mem::find_func(xrefs[0]);
            if (func) {
                uintptr_t f_end = next_func_addr_vm(func);
                std::vector<uint32_t> candidates;
                for (uintptr_t pc = func; pc < f_end; pc += 4) {
                    uint32_t insn = *(uint32_t*)(mem::data + pc);
                    if ((insn & 0xFF000000) == 0x91000000) {
                        uint32_t imm = (insn >> 10) & 0xFFF;
                        if (imm >= 0x400 && imm <= 0x600) candidates.push_back(imm);
                    }
                }
                std::sort(candidates.begin(), candidates.end());
                candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
                if (candidates.size() >= 2) {
                    set_result("global_state_l_gt", candidates[0]);
                    set_result("global_state_registry", candidates[1]);
                }
            }
        }
    }

    uintptr_t str_addr = mem::find_str("Invalid Facet Access");
    if (str_addr) {
        auto xrefs = mem::find_xrefs(str_addr);
        for (uintptr_t xref : xrefs) {
            uintptr_t func = mem::find_func(xref);
            if (!func) continue;
            uintptr_t f_end = next_func_addr_vm(func);
            for (uintptr_t pc = func; pc < std::min(f_end, func + 0x80); pc += 4) {
                uint32_t ins  = *(uint32_t*)(mem::data + pc);
                uint32_t ins2 = *(uint32_t*)(mem::data + pc + 4);
                if ((ins & 0xFF0003FF) == 0x91000008) {
                    uint32_t imm = (ins >> 10) & 0xFFF;
                    if (imm > 0x100 && (ins2 & 0xFFFFFC00) == 0x88DFFC00) {
                        set_result("scriptcontext_facet_lvl", imm);
                        break;
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
    uintptr_t lua_newthread = 0;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luaresume") lua_resume = results[i];
        else if (scans[i].name == "luaG_runerror") luaG_runerror = results[i];
        else if (scans[i].name == "lua_newthread") lua_newthread = results[i]; 
    }

    uintptr_t luau_execute = 0;
    uintptr_t luaD_throw = 0;
    uintptr_t luaC_step = 0;
    size_t max_func_size = 0;
    uintptr_t best_candidate = 0;
    for (size_t pc = mem::text_start; pc < mem::text_end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_func_prologue_vm(insn)) {
            uintptr_t next_f = next_func_addr_vm(pc);
            size_t curr_size = next_f - pc;
            if (curr_size > max_func_size) {
                max_func_size = curr_size;
                best_candidate = pc;
            }
        }
    }

    if (max_func_size > 0x3000) {
        luau_execute = best_candidate;
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
    if (lua_newthread) {
        for (size_t i = 0; i < 0x100; i += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + lua_newthread + i);
            uint32_t next_insn = *(uint32_t*)(mem::data + lua_newthread + i + 4);
            
            if (is_bl(insn) && next_insn == 0xf9401e69) {
                luaE_newthread = decode_bl(insn, lua_newthread + i);
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
    resolve_luauyeildoffsets(scans, results);
    resolve_lua_load(scans, results);
    resolve_struct_offsets(scans, results);
}
