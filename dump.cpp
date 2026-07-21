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
    {"print",                       "Current identity is %d",                                                   "", 1, 0, false, 0},
    {"game_loaded",                 "onGameLoaded() SessionReporterState_GameLoaded placeId:%lld",              "", 0, 0, false, 0},
    {"on_game_leave",               "onGameLeaveBegin() SessionReporterState_GameExitRequested placeId:%lld",  "", 0, 0, false, 0},
    {"taskschedulerconstructor",    "HumanoidParallelManagerTaskQueue",                                         "", 0, 0, false, 0},
    {"taskschedulerinlinerawjob",                "HumanoidParallelManagerTaskQueue",                                         "", 0, 1, false, 0},
    {"rawschedulerptr",                "", "", 0, 0, false, 0}, // ptr
    {"taskschedulertargetfps",      "", "fd 7b bd a9 ?? 0b 00 f9 ?? 4f ?? a9 fd 03 00 91 ?? ?? ?? 90 ?? ?? ?? 91 ?? ?? ?? ?? ?? ?? ?? 91 ?? ?? ?? ?? ?? ?? ?? 91 ?? ?? ?? a9", 0, 0, false, 0},
    {"taskscheduler_processjob",    "", "FF 43 01 D1 FD 7B 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 43 00 91 ?? ?? ?? ?? ?? ?? ?? ?? C8 02 40 F9 E8 07 00 F9 28 00 40 F9 48 06 00 B4", 0, 0, false, 0},
    {"taskscheduler_mutex",         "", "", 0, 0, true, 0},
    {"taskscheduler_init_inline",   "", "00 40 80 52 ?? ?? ?? ?? F4 03 00 AA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? F9", 0, 0, false, 0},
    {"taskscheduler_queue",         "", "", 0, 0, true, 0},
    {"taskscheduler_workers",       "", "", 0, 0, true, 0},
    {"allocator_free",                "", "ff c3 01 d1 fd 7b 04 a9 f5 2b 00 f9 f4 4f 06 a9 fd 03 01 91 ?? ?? ?? ?? ?? ?? ?? ?? a8 02 40 f9 a8 83 1f f8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? f3 03 00 aa 08 fd df 08 ?? ?? ?? ?? e0 03 13 aa", 0, 0, false, 0},
    {"resumewaitingscripts",        "WaitingHybridScriptsJob",                                                  "", 1, 0, false, 0},
    {"taskdesynchronize",           "task.desynchronize() should only be called from a script that is a descendant of an Actor", "", 0, 0, false, 0},
    {"task_synchronize",            "", "", 0, 0, false, 0}, // thx pereoxide
    {"task_defer",                  "", "", 0, 0, false, 0},
    {"task_spawn",                  "", "", 0, 0, false, 0},
    {"task_delay",                  "", "", 0, 0, false, 0},
    {"task_wait",                   "", "", 0, 0, false, 0},
    {"task_cancel",                 "", "", 0, 0, false, 0},
    {"pseudo2addr", "", "28 E2 84 12 3F 00 08 6B 60 02 00 54 08 E2 84 12 3F 00 08 6B E0 00 00 54 E8 E1 84 12 3F 00 08 6B", 0, 0, true, 0},
    {"scriptcontextresume",         "", "ff 03 06 d1 e8 8b 00 fd fd 7b 12 a9 fc 6f 13 a9 fa 67 14 a9 f8 5f 15 a9 f6 57 16 a9 f4 4f 17 a9 fd 83 04 91 ?? ?? ?? b0 ?? ?? ?? b0 f6 03 00 aa ?? ?? ?? f9 f8 03 04 aa fa 03 03 2a", 0, 0, false, 0},
    {"scriptcontext_createscript",  "", "c2 05 80 52 a3 bb 81 52 85 00 80 52 ?? ?? ?? 94 e8 23 41 39", 0, 0, false, 0},
    {"getscriptcontext",        "", "", 0, 0, false, 0},
    {"getscriptcapabilities",  "", "", 0, 0, false, 0},
    {"rbx_scriptcontextconstructor","", "75 46 00 F9 ?? ?? ?? ?? ?? ?? ?? ?? 75 A2 00 A9 69 0E 00 F9 60 62 03 91 ?? ?? ?? ??", 0, 0, false, 0}, // body of func
    {"getglobalstateforinstance",   "", "62 00 80 52 a4 09 80 52 e5 03 1f aa e7 03 1f 2a ?? ?? ?? 97", 0, 0, false, 0},
    {"getluastate",                 "", "FD 7B BC A9 FC 0B 00 F9 F6 57 02 A9 F4 4F 03 A9 FD 03 00 91 FF 83 0B D1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 08 40 4A 39", 0, 0, false, 0},
    {"luaE_newthread",              "", "", 0, 0, false, 0},
    {"lua_newthread",               "", "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 08 30 40 f9 f3 03 00 aa 08 25 41 a9 3f 01 08 eb ?? ?? ?? 54 e0 03 13 aa 21 00 80 52 ?? ?? ?? ?? 68 02 40 39", 0, 0, false, 0},
    {"getcurrentthreadcontext",              "", "08 45 40 F9 00 01 3F D6 E8 03 00 91 ?? ?? ?? ?? ?? ?? ?? ?? 08 00 40 F9 08 91 40 F9 E1 03 00 91 00 01 3F D6", 0, 0, false, 0},
    {"rbx_luastateinit",            "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? ?? 00 00 09 91 02 00 81 52", 0, 0, false, 0},
    {"lua_status",                  "", "c0 03 5f d6 00 60 40 39 c0 03 5f d6", 4, 0, false, 0},
    {"lua_clock",                   "", "48 E0 3B D5 C9 7E 5F C8 CB 06 40 F9 CA 0E 40 F9", 0, 0, false, 0}, // the most useful function in the world :sob:
    {"lua_checkstack",              "", "FF 03 01 D1 FD 7B 01 A9 F5 13 00 F9 F4 4F 03 A9 FD 43 00 91 ?? ?? ?? ?? 08 E8 83 52 ?? ?? ?? ?? 3F 00 08 6B", 0, 0, false, 0},
    {"lua_checkcstack",             "", "FD 7B BF A9 FD 03 00 91 08 40 40 79 1F 21 03 71 A0 00 00 54 1F 85 03 71 C2 00 00 54", 0, 0, false, 0}, // checkC stack, not js check stack
    {"lua_xmove",                   "", "FD 7B BD A9 F6 57 01 A9 F4 4F 02 A9 FD 03 00 91 1F 00 01 EB ?? ?? ?? 54 28 ?? 40 39 F4 03 01 AA F3 03 00 AA F5 03 02 2A A8 00 10 36 ?? ?? 00 91 E0 03 14 AA E1 03 14 AA", 0, 0, false, 0},
    {"lua_replace", "", "fd 7b be a9 ?? ?? ?? a9 fd 03 00 91 ?? ?? 40 39 ?? ?? ?? aa ?? ?? ?? 2a ?? ?? ?? 36 ?? ?? ?? 91 ?? ?? ?? aa ?? ?? ?? aa ?? ?? ?? 94 ?? 06 00 71 ?? ?? ?? 54 69 a2 ?? a9", 0, 0, false, 0},
    {"getcapabilities",             "", "", 0, 0, false, 0},
    {"luau_execute",                "", "", 0, 0, false, 0},
    {"luau_precall",                "", "FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 08 00 01 91 08 FD DF 08 68 00 00 37 E0 03 1F 2A 06 00 00 14", 0, 0, false, 0},
    {"luaD_call",                   "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 28 0c 40 b9 f4 03 02 2a f6 03 01 aa f3 03 00 aa 1f 21 00 71 ?? ?? ?? 54 e0 03 13 aa e1 03 16 aa", 0, 0, false, 0},
    {"luaD_calldispatcher",         "", "FD 7B BD A9 F5 0B 00 F9 F4 4F 02 A9 FD 03 00 91 F4 03 00 AA E8 03 01 AA E1 03 02 AA 00 01 3F D6", 0, 0, false, 0},
    // {"luaD_throw",                  "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 F4 03 00 AA 00 03 80 52 F3 03 01 2A", 0, 0, false, 0},
    {"luaD_reallocstack", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 28 00 80 52 f3 03 00 aa 08 80 a0 72 3f 00 08 6b ?? ?? ?? 54 f5 03 01 2a 3f 14 00 31 ?? ?? ?? 54", 0, 0, false, 0},
    {"luaresume",                   "", "fd 7b bf a9 fd 03 00 91 08 0c 40 39 1f 19 00 71 ?? ?? ?? 54 1f 05 00 71 ?? ?? ?? 54 ?? ?? ?? 35 08 28 40 f9 09 20 40 f9 1f 01 09 eb ?? ?? ?? 54", 0, 0, false, 0},
 //   {"luaresumefromsuspended",      "", "", 0, 0, false, 0}, inlined
    {"lua_resumewrapper",           "", "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 f4 03 02 2a f3 03 00 aa ?? ?? ?? ?? ?? ?? ?? 34", 0, 0, false, 0},
    // {"lua_resumefinalize",          "", "?? ?? 40 79 ?? ?? 40 79 ?? ?? 09 6b ?? ?? ?? 54 ?? ?? 40 f9 ?? ?? 42 f9 ?? ?? ?? b4 ?? ?? aa 00 01 3f d6", 0, 0, false, 0}, useless, why do u need it :sob:
    {"resume_error",                "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 28 08 00 51 F3 03 02 AA F4 03 00 AA 1F 09 00 71 43 01 00 54", 0, 0, false, 0},
    {"luauyield", "", "09 40 40 79 0a 44 40 79 e8 03 00 aa 3f 01 0a 6b 08 01 00 54 ?? ?? 40 f9 2a 00 80 52 00 00 80 12", 0, 0, false, 0},
 //   {"coroutine_yield",             "", "", 0, 0, false, 0}, same luauyeild but resolve method, unpack ts if sig will break
    {"luaC_step",                   "", "", 0, 0, false, 0},
    {"luaM_realloc",                "", "fd 7b bb a9 fa 67 01 a9 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 03 00 91 68 04 00 d1 f6 03 04 2a", 0, 0, false, 0},
    {"luaM_new",                "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 28 04 00 d1 ?? ?? ?? ?? f3 03 01 aa f4 03 00 aa 1f fd 0f f1 f5 03 02 2a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 08 01 13 8b 01 81 c2 39", 0, 0, false, 0},
    {"luaM_toobig",                "memory allocation error: block too big", "", 0, 0, false, 0},
    {"luaC_link",                   "", "28 00 40 39 ?? ?? ?? f9 08 79 1d 12 28 00 00 39 28 15 40 f9 ?? ?? ?? f9 21 15 00 f9 c0 03 5f d6", 0, 0, false, 0},
    {"luaF_close",                  "", "FD 7B BD A9 F6 57 01 A9 F4 4F 02 A9 FD 03 00 91 F4 03 00 AA ?? ?? ?? ?? F3 03 00 AA ?? ?? ?? ?? 95 16 40 B9", 0, 0, false, 0},
    {"lua_settop",                  "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 f4 03 01 2A F3 03 00 AA 41 03 F8 37 ?? ?? ?? ?? ?? ?? ?? ??", 0, 0, false, 0},
    {"lua_insert",                  "", "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 82 00 80 52 f3 03 01 aa f4 03 00 aa ?? ?? ?? 97 08 0c 40 b9 1f 21 00 71", 0, 0, false, 0},
    {"lua_getscript",          "", "", 0, 0, false, 0},
    {"lua_pushvalue",               "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 08 ?? 40 39 F3 03 00 AA F4 03 01 2A A8 00 10 36 62 ?? 00 91 E0 03 13 AA E1 03 13 AA ?? ?? ?? 94 ?? ?? ?? ?? ?? ?? ?? 39 68 01 00 34 ?? ?? 40 F9 69 ?? 40 F9", 0, 0, false, 0},
 // {"lua_pushstring",              "", "8A 00 80 52 14 01 00 F9 69 1E 40 F9 0A 0D 00 B9 28 41 00 91 68 1E 00 F9 F4 4F 41 A9 FD 7B C2 A8 C0 03 5F D6", 0, 0, false, 0},
 // {"lua_pushvector3",             "", "A9 00 80 52 0A 25 00 2D 08 09 00 BD 09 0D 00 B9 08 41 00 91 68 1E 00 F9 FD FB 41 A9 F3 17 40 F9 E9 A3 40 6D EA 07 43 FC C0 03 5F D6", 0, 0, false, 0},
    {"lua_pushlstring",             "", "", 0, 0, false, 0},
    {"lua_pushstring",             "", "FD 7B ?? A9 F4 4F 01 A9 FD 03 00 91 F4 03 00 AA ?? ?? 00 B4 E0 03 01 AA F3 03 01 AA ?? ?? ?? 94 E2 03 00 AA E0 03 14 AA E1 03 13 AA", 0, 0, false, 0},
    {"lua_getmetatable", "", "1F 35 00 71 60 01 00 54 1F 25 00 71 C0 00 00 54 1F 1D 00 71", 0, 0, false, -0xB0},
    {"lua_setmetatable", "", "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa 7f 00 00 71 00 00 80 12 ?? ?? ?? 54 bf 08 00 71 ?? ?? ?? 54 48 0c 40 b9 1f 1d 00 71", 0, 0, false, 0},
    {"lua_type",                    "", "FD 7B BF A9 FD 03 00 91 3F 04 00 71 ?? ?? ?? 54 09 A0 ?? A9 08 51 21 8B 00 41 00 D1 1F 00 09 EB", 0, 0, false, 0},
    {"lua_typename",                "", "3f 04 00 31 ?? ?? ?? 54 ?? ?? ?? ?? ?? ?? ?? ?? 00 d9 61 f8 c0 03 5f d6 ?? ?? ?? ?? ?? ?? ?? ?? c0 03 5f d6", 0, 0, false, 0},
    {"lua_toboolean",               "", "?? 0c 40 b9 ?? ?? ?? 34 1f 05 00 71 ?? ?? ?? 54 ?? ?? 40 b9 1f 01 00 71 ?? 07 9f 1a", 0, 0, false, 0},
    {"lua_touserdata",              "", "?? 0c 40 b9 1f 09 00 71 ?? ?? ?? 54 1f 25 00 71 ?? ?? ?? 54 ?? 00 40 f9 ?? 41 00 91", 0, 0, false, 0},
    {"lua_isuserdata",              "", "08 0c 40 b9 1f 25 00 71 04 19 42 7a e0 17 9f 1a", 0, 0, false, 0},
    {"lua_tointegerx",              "", "FF 03 01 D1 FD 7B 02 A9 F4 4F 03 A9 FD 83 00 91 ?? ?? ?? F0 F3 03 02 AA 3F 04 00 71 ?? ?? ?? F9 88 02 40 F9 A8 83 1F F8", 0, 0, false, 0},
  //  {"lua_istable",                 "", "FD 7B BF A9 FD 03 00 91 3F 04 00 71 2B 01 00 54 09 A0 ?? A9 08 51 21 8B 08 41 00 D1 1F 01 09 EB ?? ?? ?? ?? ?? ?? ?? ?? 00 31 89 9A 08 00 00 14 C8 E1 84 12 3F 00 08 6B ?? ?? ?? ?? 08 ?? 40 F9 00 D1 21 8B 02 00 00 14 ?? ?? ?? 94 08 0C 40 B9 1F 21 00 71 C1 00 00 54 08 00 40 F9 08 ?? 40 39 1F 01 00 71 E0 07 9F 1A", 0, 0, false, 0},
    {"lua_iscfunction",              "", "08 0c 40 b9 1f 21 00 71 ?? ?? ?? 54 08 00 40 f9 08 ?? 40 39 1f 01 00 71 e0 07 9f 1a", 0, 0, false, 0},
    {"lua_islfunction",              "", "08 0c 40 b9 1f 21 00 71 ?? ?? ?? 54 08 00 40 f9 08 ?? 40 39 1f 01 00 71 e0 17 9f 1a", 0, 0, false, 0},
   // {"lua_isreadonly",              "", "FD 7B BF A9 FD 03 00 91 3F 04 00 71 2B 01 00 54 09 A0 ?? A9 08 51 21 8B 08 41 00 D1 1F 01 09 EB ?? ?? ?? ?? ?? ?? ?? ?? 00 31 89 9A 08 00 00 14 C8 E1 84 12 3F 00 08 6B ?? ?? ?? ?? 08 ?? 40 F9 00 D1 21 8B 02 00 00 14 ?? ?? ?? 94 08 0C 40 B9 1F 21 00 71 C1 00 00 54 08 00 40 F9 08 ?? 40 39 1F 01 00 71 E0 17 9F 1A", 0, 0, false, 0},
    {"hashtableresize",                    "", "FD 7B ?? A9 ?? ?? ?? F9 F4 4F 02 A9 FD 03 00 91 14 14 40 F9 F3 03 01 AA 14 01 00 B4", 0, 0, false, 0},
    {"luaH_new", "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 02 2a ?? ?? ?? 39 f6 03 01 2a 01 06 80 52 f4 03 00 aa", 0, 0, false, 0},
    {"luaH_settable",               "table index is nil",                                                       "", 0, 0, false, 0},
    {"lua_settable", "", "ff 03 02 d1 fd 7b 02 a9 fb 1b 00 f9 fa 67 04 a9 f8 5f 05 a9 f6 57 06 a9 f4 4f 07 a9 fd 83 00 91 ?? ?? ?? d0 f4 03 03 aa f5 03 02 aa ?? ?? ?? f9 f6 03 01 aa f3 03 00 aa 9a 0c 80 52", 0, 0, false, 0},
    {"lua_gettable", "", "00 00 40 F9 01 41 00 D1 ?? ?? ?? 97 ?? ?? 40 F9 00 00 C0 3D 00 01 9F 3C ?? ?? 40 F9 00 C1 5F B8", 0, 0, false, -0x7C},
    {"luaV_gettable", "", "fd 7b ba a9 fb 0b 00 f9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 03 00 91 28 0c 40 b9 f3 03 03 aa f4 03 02 aa f6 03 01 aa f5 03 00 aa 99 0c 80 52 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1f 1d 00 71 ?? ?? ?? ?? d8 02 40 f9 e1 03 14 aa e0 03 18 aa ?? ?? ?? ??", 0, 0, false, -0x10},
    // {"lua_setfield", "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f4 03 02 aa 3f 04 00 71 f3 03 00 aa ?? ?? ?? 54 69 a2 ?? a9 08 51 21 8b 08 41 00 d1 1f 01 09 eb ?? ?? ?? ?? ?? ?? ?? ?? 15 31 89 9a", 0, 0, false, 0},
    {"lua_getint",                 "", "ff 43 01 d1 fd 7b 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 83 00 91 ?? ?? ?? ?? f3 03 01 aa ?? ?? ?? ?? c8 02 40 f9 a8 83 1f f8 48 04 00 51 29 08 40 b9 1f 01 09 6b", 0, 0, false, 0},
    {"lua_rawgeti",                 "", "4B 0D 40 B9 EB 02 00 35 94 06 00 11 4A 41 00 91 1F 01 14 6B 68 FF FF 54", 0, 0, false, 0},
    {"luaH_getstr",                 "", "?? ?? 40 39 ?? ?? 40 b9 ?? ?? ?? 1a ?? ?? 40 f9 ?? ?? ?? 0a ?? ?? ?? 8b ?? ?? 40 b9 ?? ?? ?? 12 ?? ?? ?? 71 ?? ?? ?? 54 0a 09 40 f9 5f 01 02 eb", 0, 0, false, 0},
    {"luaH_get",                      "", "08 00 40 B9 ?? ?? ?? 34 FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 E2 03 1F 2A F3 03 00 AA ?? ?? ?? 94 20 01 00 B7 68 AA 40 A9 69 1A 40 B9 08 59 60 B8 28 01 08 0A 40 51 28 8B ?? ?? ?? 14 E0 03 1F AA C0 03 5F D6 E0 03 1F AA F3 0B 40 F9 FD 7B C2 A8 C0 03 5F D6", 0, 0, false, 0},
    {"luaH_getnum",          "", "48 0C 40 B9 1F 0D 00 71 A1 01 00 54 40 00 40 FD 08 00 78 1E 01 01 62 1E 00 20 61 1E 01 01 00 54 29 08 40 B9 08 05 00 51 1F 01 09 6B 82 00 00 54 ?? ?? 40 F9 20 D1 28 8B C0 03 5F D6", 0, 0, false, 0},
    // {"ktable",                      "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa ?? ?? ?? ?? 15 14 40 f9 f4 03 00 aa 53 01 00 b4", 0, 0, false, 0}, wrony wrongy nigga
    {"lua_next",                    "invalid key to 'next'",                                                    "", 0, 0, false, 0}, // can be wrong because of stolen xref from macos guides
    {"luagetfield",                 "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f4 03 02 aa 3f 04 00 71 f3 03 00 aa 2b 01 00 54 69 a2 43 a9 08 51 21 8b 08 41 00 d1", 0, 0, false, 0},
    {"luasetfield",                 "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f4 03 03 2a f5 03 02 aa 3f 04 00 71 f3 03 00 aa 2b 01 00 54 69 a2 43 a9 08 51 21 8b 08 41 00 d1", 0, 0, false, 0},
    {"luas_newlstr",                "", "", 0, 0, false, 0},
    {"internalstringhash",          "", "FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 E0 03 01 AA F3 03 01 AA ?? ?? ?? ?? A0 01 00 B4 29 37 8F 52", 0, 0, false, 0},
    {"luaO_pushvfstring",           "", "FF 83 01 D1 FD 7B 03 A9 F6 57 04 A9 F4 4F 05 A9 FD C3 00 91 ?? ?? ?? B0 F4 03 02 AA F3 03 00 AA", 0, 0, false, 0},
    {"luaO_rawequalobj",            "", "08 0c 40 b9 29 0c 40 b9 08 0d 00 12 1f 01 09 6b 61 05 00 54 1f 09 00 71 ac 01 00 54 48 03 00 34 1f 05 00 71 00 05 00 54 1f 09 00 71 41 02 00 54 08 00 40 f9 29 00 40 f9 1f 01 09 eb 01 04 00 54", 0, 0, false, 0},
    {"newindex",                    "__newindex",                                                                "", 0, 0, false, 0},
    {"namecallhandler",             "__namecall",                                                               "", 0, 0, false, 0},
    // {"hashtablelookup",             "Unable to query property {}. It is not scriptable",                        "", 0, 0, false, 0}, luaH_get
    {"luaT_getobjname",             "", "FD 7B BE A9 F3 0B 00 F9 FD 03 00 91 29 0C 40 B9 3F 09 00 71 ?? ?? ?? 54 3F 25 00 71", 0, 0, false, 0},
    {"luaT_gettmbyobj", "", "28 0c 40 b9 1f 2d 00 71 ?? ?? ?? ?? 1f 1d 00 71 ?? ?? ?? ?? 1f 25 00 71 ?? ?? ?? ?? 28 00 40 f9 08 21 00 91 ?? ?? ?? ?? 1f 31 00 71 ?? ?? ?? ?? 1f 35 00 71", 0, 0, false, 0},
    {"luaT_objtypename",            "", "FD 7B BF A9 FD 03 00 91 ?? ?? ?? 97 00 60 00 91 FD 7B C1 A8 C0 03 5F D6", 0, 0, false, 0}, // avitamin
    {"stackoverflow",               "stack overflow (%s)",                                                      "", 0, 0, false, 0},
    {"luaG_typeerror",              "attempt to index %s with '%s'",                                            "", 0, 0, false, 0},
    {"luaG_aritherror",             "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f5 03 03 2a f6 03 02 aa f3 03 00 aa ?? ?? ?? ?? f4 03 00 aa e0 03 13 aa e1 03 16 aa", 0, 0, false, 0},
    {"luaG_runerror",               "", "01 40 80 52 e2 0f 01 ad e2 03 08 aa e4 17 02 ad ?? ?? ?? f9 e6 1f 03 ad ?? 01 40 f9", 0, 0, false, 0},
    {"luaL_error",                  "", "FF C3 04 D1 FD 7B 10 A9 FC 57 11 A9 F4 4F 12 A9 FD 03 04 91 E2 0F 08 A9 ?? ?? ?? F0 E9 03 00 91 E4 17 09 A9", 0, 0, false, 0},
    {"luaL_argerror",               "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 02 aa f4 03 01 2a f5 03 00 aa ?? ?? ?? 97 f6 03 00 aa e0 03 15 aa e1 03 14 2a", 0, 0, false, 0},
    {"luaL_typerror",               "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 F3 03 01 2A E1 03 02 2A F4 03 00 AA ?? ?? ?? 97 E2 03 00 AA E0 03 14 AA E1 03 13 2A ?? ?? ?? 97", 0, 0, false, 0},
    {"luau_pushstringerror",               "", "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 ?? ?? ?? ?? f3 03 00 aa f4 03 01 aa 15 d1 22 cb ?? ?? ?? ?? e0 03 01 aa ?? ?? ?? ?? e2 03 00 aa e0 03 13 aa e1 03 14 aa ?? ?? ?? ?? a0 02 00 f9", 0, 0, false, 0},
    {"rbx_raiseluaexception",       "", "FD 7B BE A9 F4 4F 01 A9 FD 03 00 91 F4 03 00 AA 00 03 80 52 F3 03 01 2A ?? ?? ?? 97", 0, 0, false, 0},
    {"luaL_register",               "", "?? ?? ?? ?? ?? ?? ?? 39 ?? ?? ?? 34 fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 08 30 40 f9 09 06 88 52", 0, 0, false, 0},
    {"luaL_checkinteger",           "", "FF 03 01 D1 FD 7B 01 A9 F5 13 00 F9 F4 4F 03 A9 FD 43 00 91 ?? ?? ?? F0 E2 13 00 91 F3 03 01 2A ?? ?? ?? F9 F4 03 00 AA", 0, 0, false, 0},
    {"luaL_sandboxthread", "", "FF C3 01 D1 FD 7B 02 A9 F9 1B 00 F9 F8 5F 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 83 00 91 ?? ?? ?? ?? F5 03 03 AA F6 03 02 AA ?? ?? ?? ?? F3 03 01 AA F4 03 00 AA", 0, 0, false, 0},
    {"luaL_checkfunction",          "", "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 f3 03 01 2a f4 03 00 aa ?? ?? ?? 97 80 00 00 b4 f4 4f 41 a9 fd 7b c2 a8 c0 03 5f d6 e0 03 14 aa e1 03 13 2a a2 00 80 52", 0, 0, false, 0},
    {"luaL_optinteger",             "", "FD 7B BD A9 F5 0B 00 F9 F4 4F 02 A9 FD 03 00 91 F4 03 02 2A F3 03 01 2A F5 03 00 AA ?? ?? ?? 97 1F 04 00 71", 0, 0, false, 0},
    {"luaL_checkudata",             "", "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 f3 03 01 2a f4 03 00 aa ?? ?? ?? 97 1f 10 00 71 e1 00 00 54", 0, 0, false, 0},
    {"lua_getinfo",                 "", "6A 55 95 52 4A 55 B5 72 09 01 09 CB 29 FD 44 D3 29 7D 0A 1B 3F 01 01 6B ?? ?? ?? ?? E9 03 01 2A 0A 06 80 52", 0, 0, false, 0},
    {"luau_load",                   "%s: bytecode version mismatch (expected [%d..%d], got %d)",               "", 0, 0, false, 0}, // for stupid niggers - luau_load is roblox made wrapper, lua_load is low-level
    {"lua_load",                    "", "", 0, 0, false, 0},
    {"luau_bytecodeload",           "", "ff 03 02 d1 fd 7b 05 a9 f6 57 06 a9 f4 4f 07 a9 fd 43 01 91 ?? ?? ?? ?? 08 00 80 12 f4 03 00 aa", 0, 0, false, 0},
    {"luau_deserialize",           "", "", 0, 0, false, 0},
    {"luau_validateheader",         "", "ff c3 01 d1 fd 7b 03 a9 f8 5f 04 a9 f6 57 05 a9 f4 4f 06 a9 fd c3 00 91 ?? ?? ?? ?? ?? ?? ?? ?? e8 02 40 f9 a8 83 1f f8 28 08 40 f9 1f 61 04 f1 63 0a 00 54 f4 03 01 aa ?? ?? ?? ?? 01 0a 00 b4 29 00 40 39 c9 09 00 34 f3 03 02 aa e2 03 08 aa ?? ?? ?? ?? 60 02 00 b9", 0, 0, false, 0},
    {"rbx_reportbytecode",          "", "fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 03 00 91 ff 83 13 d1 ?? ?? ?? ?? f3 03 04 2a f5 03 03 2a ?? ?? ?? f9 f4 03 02 aa f7 03 01 aa 68 03 40 f9 a8 83 1f f8", 0, 0, false, 0},
    {"luau_toobject",               "", "fd 7b bf a9 fd 03 00 91 3f 04 00 71 2b 01 00 54 09 a0 ?? a9 08 51 21 8b 08 41 00 d1 1f 01 09 eb ?? ?? ?? ?? ?? ?? ?? ?? 00 31 89 9a 08 00 00 14 c8 e1 84 12 3f 00 08 6b 8b 00 00 54 08 ?? 40 f9 00 d1 21 8b 02 00 00 14 ?? ?? ?? ?? 08 0c 40 b9 1f 29 00 71", 0, 0, false, 0},
    {"loadstring",                  "loadstring() is not available",                                            "", 0, 0, false, 0},
    {"lazyinitializercore", "", "28 FD 46 D3 95 C2 0F 91 A8 7A 68 F8 08 25 C9 9A C8 00 00 36", 0, 0, false, 0},
    {"getreflectionschema", "", "", 0, 0, false, 0},
    {"scriptstart",                 "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f3 03 04 aa f4 03 03 aa f5 03 02 aa f6 03 01 aa f7 03 08 aa ?? ?? ?? ?? e8 03 17 aa", 0, 0, false, 0},
    {"luauloadcorescripts",         "", "fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9 f6 57 04 a9 f4 4f 05 a9 fd 03 00 91 ff 83 06 d1", 0, 0, false, 0},
    {"validateandsetupcaps",        "", "ff 83 02 d1 fd 7b 06 a9 f8 5f 07 a9 f6 57 08 a9 f4 4f 09 a9", 0, 0, false, 0},
    {"executeModule",               "", "E0 03 14 AA 01 00 80 12 E2 03 15 AA ?? ?? ?? 97 E0 03 13 AA 21 00 80 12 35 00 80 12 ?? ?? ?? 97", 0, 0, false, 0}, // scriptcontext::executemodulescript
    {"requireModule",               "", "21 E2 84 12 22 00 80 52 ?? ?? ?? ?? ?? ?? ?? 97 ?? ?? ?? ?? ?? ?? ?? 91 A0 C3 02 D1 ?? ?? ?? 97", 0, 0, false, 0},
    {"enableloadmodule",            "EnableLoadModule",                                                         "", 0, 0, false, 0},
    {"rbxspawn",                    "", "0a fd 42 93 5f 01 09 eb 49 81 89 9a 1f 01 0b eb 08 00 fc 92 21 31 88 9a ?? ?? ?? b4 ?? ?? ?? f0 ?? ?? ?? 91 9a ad 29 94", 0, 0, false, 0},
    {"rbxspawnconstructor",         "", "ff 03 02 d1 fd 7b 02 a9 fb 1b 00 f9 fa 67 04 a9 f8 5f 05 a9 f6 57 06 a9 f4 4f 07 a9 fd 83 00 91 ?? ?? ?? ?? ba 83 41 39", 0, 0, false, 0},
    {"lua_rawget",  "", "?? ?? ?? 97 e8 03 00 aa 20 00 80 52 00 01 c0 3d 60 02 80 3d f3 0b 40 f9 fd 7b c2 a8 c0 03 5f d6", 0, 0, false, 0},
    {"lua_rawset", "", "fd 7b bd a9 f5 0b 00 f9 f4 4f 02 a9 fd 03 00 91 3f 04 00 71 f3 03 00 aa ?? ?? ?? 54 69 a2 ?? a9 08 51 21 8b 08 41 00 d1 1f 01 09 eb ?? ?? ?? ?? ?? ?? ?? ?? 14 31 89 9a", 0, 0, false, 0},
    {"lua_rawseti", "", "fd 7b bc a9 f7 0b 00 f9 f6 57 02 a9 f4 4f 03 a9 fd 03 00 91 f4 03 03 2a f5 03 02 aa 3f 04 00 71 f3 03 00 aa ?? ?? ?? 54 69 a2 ?? a9 08 51 21 8b 08 41 00 d1 1f 01 09 eb ?? ?? ?? ?? ?? ?? ?? ?? 16 31 89 9a", 0, 0, false, 0},
    {"jobstart",                    "[FLog::TaskSchedulerRun] JobStart %s",                                     "", 0, 0, false, 0},
    {"jobstop",                     "[FLog::TaskSchedulerRun] JobStop %s",                                      "", 0, 0, false, 0},
    {"firetouchinterest",           "new overlap in different world",                                           "", 0, 0, false, 0},
    {"fireserver",                  "FireServer can only be called from the client",                            "", 0, 0, false, 0},
    {"invokeserver",                "InvokeServer can only be called from the client",                          "", 0, 0, false, 0},
    {"fireallclients",              "FireAllClients can only be called from the server",                        "", 0, 0, false, 0},
    {"invokeclient",                "InvokeClient can only be called from the server",                          "", 0, 0, false, 0},
    {"fireserver_bridge",           "", "ff 03 04 d1 fd 7b 0c a9 f8 5f 0d a9 f6 57 0e a9 f4 4f 0f a9 fd 03 03 91 ?? ?? ?? ?? f4 03 02 aa f5 03 01 aa", 0, 0, false, 0},
    {"fireevent",                   "", "ff 83 04 d1 fd 7b 10 a9 fc 4f 11 a9 fd 03 04 91 a3 93 38 a9 ?? ?? ?? ?? a9 e3 01 d1 a5 9b 39 a9 ea 03 00 91 a3 43 01 d1 a7 83 1a f8 4a 01 02 91 e0 07 00 ad e2 0f 01 ad e4 17 02 ad ?? ?? ?? ?? e6 1f 03 ad 68 02 40 f9 a8 83 1f f8 28 a1 00 91 a9 83 00 91 a9 a3 3d a9 e8 04 80 92 a9 a3 00 d1 08 f0 df f2 aa a3 3e a9 08 00 40 f9 20 05 40 ad 08 39 42 f9 a0 87 3d ad 00 01 3f d6", 0, 0, false, 0},
    {"instance_getproperty",        "Unable to query property {}. It is not scriptable",                       "", 0, 0, false, 0},
    {"getfenv",                     "", "fd 7b be a9 f4 4f 01 a9 fd 03 00 91 08 ?? 40 39 f3 03 00 aa f4 03 01 2a a8 00 10 36", 0, 0, false, 0},
    {"getfenv_thread",              "", "FF C3 05 D1 FD 7B ?? A9 FC 57 ?? A9 F4 4F ?? A9 FD 03 05 91 ?? ?? ?? D0 F4 03 01 2A 21 00 80 52 ?? ?? ?? F9 F3 03 00 AA ?? ?? ?? F9 ?? ?? ?? F8 ?? ?? ?? 97 1F 20 00 71 81 01 00 54", 0, 0, false, 0},
    {"setfenv",                     "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 3f 04 00 71 f3 03 00 aa ?? ?? ?? 54 69 a2 ?? a9 08 51 21 8b 08 41 00 d1 1f 01 09 eb ?? ?? ?? ?? ?? ?? ?? ?? 00 31 89 9a", 0, 0, false, 0},
    {"newproxy",                    "", "fd 7b be a9 f3 0b 00 f9 fd 03 00 91 21 00 80 52 f3 03 00 aa ?? ?? ?? ?? 08 78 1f 12 1f 19 00 71", 0, 0, false, 0},
    {"lockviolationcrash",          "LockViolationInstanceCrash",                                              "", 0, 0, false, 0},
    {"lockviolationscriptcrash",    "LockViolationScriptCrash",                                                "", 0, 0, false, 0},
    {"luastepinternaloverride",     "LuaStepIntervalMsOverrideEnabled",                                       "", 0, 0, false, 0},
    {"rbx_abortlogger",             "", "81 C2 04 91 40 01 80 52", 0, 0, false, 0},
    // {"robloxlogcrash",           "", "", 0, 0, false, 0},
    {"rbx_robloxextraspaceinit",    "", "08 08 40 B9 E1 03 14 AA E2 03 13 AA 08 05 00 11 08 08 00 B9", 0, 0, false, 0}, // body of func
    {"rbx_robloxextraspacesetup",   "", "08 60 85 D2 1F 20 03 D5 ?? ?? ?? ?? 68 65 A8 F2 B4 4E 39 A9 E8 C8 C9 F2 A0 82 1A F8 88 69 E8 F2 A8 26 3E A9", 0, 0, false, 0},
    {"rbx_robloxextraspacecookiecheck", "", "68 E8 A8 F2 C8 89 C9 F2 68 08 E0 F2 1F 21 54 EB", 0, 0, false, 0},
    {"stdstringconstructor",        "", "fd 7b bd a9 f6 57 01 a9 f4 4f 02 a9 fd 03 00 91 f3 03 00 aa 00 00 40 f9 f5 03 01 aa 74 0a 40 f9 60 02 00 b4 00 00 80 f9 40 03 00 37", 0, 0, false, 0},
    {"telemetry_buffer",            "", "", 0, 0, true, 0},
    {"telemetry_size",              "", "", 0, 0, true, 0},
};

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
    
    if (s.byte_offset != 0)
        return addr + s.byte_offset;
    
    if (s.offset)
        return addr;
    
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

static uint64_t decode_adrp(uint32_t insn, uint64_t pc) {
    uint64_t immhi = (insn >> 5) & 0x7FFFF;
    uint64_t immlo = (insn >> 29) & 3;
    int64_t imm = (int64_t)((immhi << 2) | immlo);
    if (imm & 0x100000) {
        imm |= ~0x1FFFFFULL;
    }
    return (pc & ~0xFFFULL) + (imm << 12);
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

static uint64_t decode_adrp_add_local(uint32_t ins1, uint32_t ins2, uint64_t pc) {
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
            uint64_t target = decode_adrp_add_local(insn1, insn2, i);
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
            resolved_target = decode_adrp_add_local(ins1, ins2, i);
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

void resolve_lua_index2addr(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t pseudo2addr = 0;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "pseudo2addr" && results[i]) {
            pseudo2addr = results[i];
            break;
        }
    }
    if (!pseudo2addr) return;

    uintptr_t top_offset = 0x38;
    uintptr_t base_offset = 0x40;
    uintptr_t g_offset = 0x60;
    uintptr_t f_end = next_func_addr_vm(pseudo2addr);
    for (uintptr_t pc = pseudo2addr; pc < f_end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if ((insn & 0xFFC00000) == 0xA9400000) {
            uint32_t offset = ((insn >> 15) & 0x7F) << 3;
            if (offset == 0x38 || offset == 0x30 || offset == 0x40) {
                top_offset = offset;
                base_offset = offset + 8;
                break;
            }
        }
    }

    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "lua_state_top") results[i] = top_offset;
        else if (scans[i].name == "lua_state_base") results[i] = base_offset;
        else if (scans[i].name == "lua_state_global_state") results[i] = g_offset;
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
    uintptr_t pseudo2addr = 0;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "pseudo2addr" && results[i]) {
            pseudo2addr = results[i];
            break;
        }
    }
    if (!pseudo2addr) return;

    uintptr_t luaS_newlstr = 0;
    int bl_count = 0;
    for (uintptr_t i = addr_setfield; i < addr_setfield + 200; i += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + i);
        if (is_bl(insn)) {
            bl_count++;
            if (bl_count == 3) {
                luaS_newlstr = decode_bl(insn, i);
                break;
            }
        }
    }
    if (!luaS_newlstr) return;

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
                if (first_bl == pseudo2addr) {
                    addr_getfield = f_start;
                    break;
                }
            }
        }
    }

    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luasetfield") results[i] = addr_setfield;
        else if (scans[i].name == "luagetfield") results[i] = addr_getfield;
    }
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
                uint64_t target = decode_adrp_add_local(ins1, ins2, pc);
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
        if (scans[i].name == "taskschedulerinlinerawjob") caller_idx = i;
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

void resolvegetfenv(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    size_t getfenv_idx = (size_t)-1;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "getfenv") {
            getfenv_idx = i;
            break;
        }
    }
    if (getfenv_idx == (size_t)-1) return;
    const char* pattern = "?? 00 40 f9 ?? ?? ?? f8 ?? ?? ?? f9 ?? 00 80 52"; // 200iq resolve
    uintptr_t hit = mem::find_bytes(pattern);
    if (hit) {
        uintptr_t func_start = mem::find_func(hit);
        if (func_start) {
            results[getfenv_idx] = func_start;
        }
    }
}

void resolve_reflection_thunk(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    uintptr_t getprop_fn = 0;
    size_t thunk_idx = -1;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "instance_getproperty") getprop_fn = results[i];
        if (scans[i].name == "getreflectionschema") thunk_idx = i;
    }

    if (!getprop_fn || thunk_idx == -1) return;
    uintptr_t f_end = getprop_fn + 300;
    int bl_counter = 0;
    for (uintptr_t pc = getprop_fn; pc < f_end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_bl(insn)) {
            bl_counter++;
            if (bl_counter == 2) {
                results[thunk_idx] = decode_bl(insn, pc);
                return;
            }
        }
    }
}

void resolve_rawscheduler(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t init_inline_func = 0;
    size_t rawscheduler_ptr_idx = -1;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "taskscheduler_init_inline") {
            init_inline_func = results[i];
        }
        if (scans[i].name == "rawschedulerptr") {
            rawscheduler_ptr_idx = i;
        }
    }

    if (!init_inline_func || rawscheduler_ptr_idx == -1) return;
    uintptr_t match_addr = 0;
    for (uintptr_t pc = init_inline_func; pc < init_inline_func + 0x150; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (insn == 0x52804000) {
            match_addr = pc;
            break;
        }
    }

    if (!match_addr) return;
    uint32_t* code = (uint32_t*)(mem::data + match_addr + 0x10);
    uint32_t insn1 = code[0];
    uint32_t insn2 = code[1];

    if (is_adrp(insn1)) {
        uint64_t init_flag_address = decode_adrp_add_local(insn1, insn2, match_addr + 0x10);
        
        if (init_flag_address) {
            results[rawscheduler_ptr_idx] = init_flag_address - 0x8;
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

void resolve_script_helpers(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    uintptr_t scriptcontextresume = 0;
    uintptr_t requiremodule = 0;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "scriptcontextresume") scriptcontextresume = results[i];
        else if (scans[i].name == "requireModule") requiremodule = results[i];
    }
    uintptr_t lua_getscript = 0;
    uintptr_t getscriptcontext = 0;
    uintptr_t getscriptcapabilities = 0;
    if (scriptcontextresume) {
        uintptr_t end = next_func_addr_vm(scriptcontextresume);
        for (uintptr_t pc = scriptcontextresume; pc < end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if (!is_bl(insn)) continue;
            uintptr_t callee = decode_bl(insn, pc);
            if (callee < mem::text_start || callee >= mem::text_end) continue;
            uint32_t i1 = *(uint32_t*)(mem::data + callee);
            uint32_t i2 = *(uint32_t*)(mem::data + callee + 4);
            if (i2 != 0xD65F03C0) continue;
            if ((i1 & 0xFFC003FF) != 0xF9400000) continue;

            lua_getscript = callee;
            break;
        }
    }
    if (!lua_getscript && requiremodule) {
        uintptr_t end = next_func_addr_vm(requiremodule);
        for (uintptr_t pc = requiremodule; pc < end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if (!is_bl(insn)) continue;
            uintptr_t callee = decode_bl(insn, pc);
            if (callee < mem::text_start || callee >= mem::text_end) continue;

            uint32_t i1 = *(uint32_t*)(mem::data + callee);
            uint32_t i2 = *(uint32_t*)(mem::data + callee + 4);

            if (i2 != 0xD65F03C0) continue;
            if ((i1 & 0xFFC003FF) != 0xF9400000) continue;

            lua_getscript = callee;
            break;
        }
    }
    if (lua_getscript) {
        auto xrefs = mem::find_bl_xrefs(lua_getscript, 64);
        for (uintptr_t site : xrefs) {
            if (site + 12 >= mem::text_end) continue;
            uint32_t n1 = *(uint32_t*)(mem::data + site + 4);
            uint32_t n2 = *(uint32_t*)(mem::data + site + 8);
            uint32_t n3 = *(uint32_t*)(mem::data + site + 12);
            if (!getscriptcontext) {
                bool n1_ldr_x8_x0 = (n1 & 0xFFC003FF) == 0xF9400008;
                bool n2_ldr_x0_x8 = (n2 & 0xFFC003FF) == 0xF9400100;
                bool n3_epilog = (n3 == 0xD65F03C0) ||
                                 (n3 & 0xFFC00000) == 0xA8C00000 ||
                                 (n3 & 0xFFC00000) == 0x28C00000;

                if (n1_ldr_x8_x0 && n2_ldr_x0_x8 && n3_epilog) {
                    getscriptcontext = mem::find_func(site);
                }
            }
            if (!getscriptcapabilities) {
                bool n1_ldr_x8_x0 = (n1 & 0xFFC003FF) == 0xF9400008;
                bool n2_ldr_x8_x8 = (n2 & 0xFFC003FF) == 0xF9400108;
                bool n3_add_x0_x8 = (n3 & 0xFFC003FF) == 0x91000100;

                if (n1_ldr_x8_x0 && n2_ldr_x8_x8 && n3_add_x0_x8) {
                    getscriptcapabilities = mem::find_func(site);
                }
            }

            if (getscriptcontext && getscriptcapabilities) break;
        }
    }
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "lua_getscript")          results[i] = lua_getscript;
        else if (scans[i].name == "getscriptcontext")   results[i] = getscriptcontext;
        else if (scans[i].name == "getscriptcapabilities") results[i] = getscriptcapabilities;
    }
}

void resolve_pushlstring(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t luaS_newlstr = 0;
    size_t pushlstring_idx = -1;

    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luas_newlstr") luaS_newlstr = results[i];
        if (scans[i].name == "lua_pushlstring") pushlstring_idx = i;
    }

    if (!luaS_newlstr || pushlstring_idx == -1) return;

    auto sites = mem::find_bl_xrefs(luaS_newlstr, 256);

    for (uintptr_t site : sites) {
        uintptr_t parent = mem::find_func(site);
        if (!parent) continue;
        bool skip = false;
        for (size_t i = 0; i < scans.size(); ++i) {
            if (results[i] && results[i] == parent && scans[i].name != "lua_pushlstring") {
                skip = true;
                break;
            }
        }
        if (skip) continue;

        size_t p_end = next_func_addr_vm(parent);
        size_t sz = p_end - parent;
        if (sz < 0x50 || sz > 0x130) continue;
        bool has_other_bl = false;
        for (uintptr_t pc = site + 4; pc < p_end; pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if (is_bl(insn)) {
                has_other_bl = true;
                break;
            }
            if (insn == 0xD65F03C0) break;
            if ((insn & 0xFC000000) == 0x14000000) break;
        }
        if (has_other_bl) continue;
        bool has_str_tstring = false;
        bool has_str_type    = false;
        bool has_inc_top     = false;
        bool has_save_top    = false;

        uint32_t top_base_reg = 0xFF;

        for (uintptr_t pc = site + 4; pc < std::min(site + 0x30, p_end); pc += 4) {
            uint32_t insn = *(uint32_t*)(mem::data + pc);
            if ((insn & 0xFFC00000) == 0xF9000000 && (insn & 0x1F) == 0) {
                has_str_tstring = true;
                top_base_reg = (insn >> 5) & 0x1F;
            }
            if ((insn & 0xFFC00000) == 0xB9000000 && top_base_reg != 0xFF) {
                uint32_t rn  = (insn >> 5) & 0x1F;
                uint32_t imm = (insn >> 10) & 0xFFF;
                if (rn == top_base_reg && (imm << 2) == 0xC)
                    has_str_type = true;
            }
            if ((insn & 0xFF800000) == 0x91000000) {
                uint32_t imm = (insn >> 10) & 0xFFF;
                if (imm == 0x10) has_inc_top = true;
            }
            if ((insn & 0xFFC00000) == 0xF9000000) {
                uint32_t imm = ((insn >> 10) & 0xFFF) << 3;
                if (imm >= 0x30 && imm <= 0x80)
                    has_save_top = true;
            }
        }

        if (has_str_tstring && has_str_type && has_inc_top && has_save_top) {
            results[pushlstring_idx] = parent;
            return;
        }
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
            if (decode_adrp_add_local(insn, insn2, i) == luau_load_addr) {
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
    size_t newlstr_idx = -1;
    
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luagetfield") getfield_addr = results[i];
        if (scans[i].name == "luas_newlstr") newlstr_idx = i;
    }

    if (!getfield_addr || newlstr_idx == -1) return;

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
                    break;
                }
            }
        }
    }

    if (luaS_newlstr_addr) {
        results[newlstr_idx] = luaS_newlstr_addr;
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

static bool is_likely_poscall(uintptr_t addr, uintptr_t luau_precall_addr) {
    if (!addr || addr == luau_precall_addr) return false;
    if (addr < mem::text_start || addr >= mem::text_end) return false;

    uintptr_t end = next_func_addr_vm(addr);
    size_t sz = end - addr;
    if (sz < 0x14 || sz > 0xA0) return false;

    int adrp_count = 0;
    int bl_count   = 0;
    for (uintptr_t pc = addr; pc < end; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        if (is_adrp(insn)) adrp_count++;
        if (is_bl(insn))   bl_count++;
    }

    if (adrp_count > 1) return false;
    if (bl_count > 3)   return false;

    return true;
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
     //   else if (scans[i].name == "luaD_resume" && luaD_resume_addr) results[i] = luaD_resume_addr;, nigger
     //   else if (scans[i].name == "luaresumefromsuspended" && luaresumefromsuspended_addr) results[i] = luaresumefromsuspended_addr;
    }
}

void resolve_luau_deserialize(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;
    uintptr_t bytecodeload_addr = 0;
    size_t deserialize_idx = -1;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luau_bytecodeload") {
            bytecodeload_addr = results[i];
        }
        if (scans[i].name == "luau_deserialize") {
            deserialize_idx = i;
        }
    }
    if (!bytecodeload_addr || deserialize_idx == -1) return;
    auto bl_sites = mem::find_bl_xrefs(bytecodeload_addr, 1); 
    if (!bl_sites.empty()) {
        results[deserialize_idx] = bl_sites[0]; 
    }
}

static inline bool is_mov_w_0xa(uint32_t insn) {
    return (insn & 0xFFFFFFE0) == 0x52800140;
}

void resolve_luaE_newthread(const std::vector<scan>& scans, std::vector<uintptr_t>& results) {
    if (!mem::is_arm64) return;

    uintptr_t lua_newthread_addr = 0;
    size_t luaE_idx = -1;
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "lua_newthread") lua_newthread_addr = results[i];
        if (scans[i].name == "luaE_newthread") luaE_idx = i;
    }

    if (!lua_newthread_addr || luaE_idx == -1) return;
    uintptr_t f_end = next_func_addr_vm(lua_newthread_addr);
    for (uintptr_t pc = lua_newthread_addr; pc < f_end - 16; pc += 4) {
        uint32_t insn = *(uint32_t*)(mem::data + pc);
        
        if (is_bl(insn)) {
            for (int offset = 1; offset <= 3; ++offset) {
                uint32_t next_insn = *(uint32_t*)(mem::data + pc + (offset * 4));
                if (is_mov_w_0xa(next_insn)) {
                    results[luaE_idx] = decode_bl(insn, pc);
                    return;
                }
            }
        }
    }
}

static inline bool is_sub_sp_imm(uint32_t insn) {
    return (insn & 0xFFC003FF) == 0xD10003FF;
}

static inline uint32_t decode_sub_sp_imm(uint32_t insn) {
    return (insn >> 10) & 0xFFF;
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
    for (size_t i = 0; i < scans.size(); ++i) {
        if (scans[i].name == "luau_execute") results[i] = luau_execute;
    //    else if (scans[i].name == "luaD_throw") results[i] = luaD_throw; very ass resolv, boutta find sig for it???
        else if (scans[i].name == "luaC_step") results[i] = luaC_step;
    //    else if (scans[i].name == "luaE_newthread") results[i] = luaE_newthread; new resolver ;0
        else if (scans[i].name == "lua_newthread") results[i] = lua_newthread;
    }

    resolve_getcapabilities(scans, results);
    resolve_tsconstrctor(scans, results);
    resolve_tsdecoffsets(scans, results);
    resolvejobevents(scans, results);
    resolve_network_telemetry(scans, results);
    resolve_lua_index2addr(scans, results);
    resolve_luau_push_helpers(scans, results);
    resolve_pushlstring(scans, results);
    resolve_miscstuff(scans, results);
    resolve_luauyeildoffsets(scans, results);
    resolve_lua_load(scans, results);
    resolve_rawscheduler(scans, results);
    resolve_luaE_newthread(scans, results);
    resolve_reflection_thunk(scans, results);
    resolve_script_helpers(scans, results);
    resolve_fields(scans, results);
    resolvegetfenv(scans, results);
    resolve_luau_deserialize(scans, results);
} // six seeeveeen
