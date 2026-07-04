#pragma once
#include <cstdint>

enum LuaType : int {
    LUA_TNIL           = 0,
    LUA_TBOOLEAN       = 1,
    LUA_TLIGHTUSERDATA = 2,
    LUA_TNUMBER        = 3,
    LUA_TSTRING        = 4,
    LUA_TTABLE         = 5,
    LUA_TFUNCTION      = 6,
    LUA_TUSERDATA      = 7,
    LUA_TTHREAD        = 8,
    LUA_TVECTOR        = 9,
};

enum LuaStatus : uint8_t {
    LUA_STATUS_OK      = 0,
    LUA_STATUS_SUSPEND = 1,
    LUA_STATUS_DEAD    = 6,
};

// TValue - 0x10

union LuaValue {
    struct GCObject* gc;
    void*   p;
    double  n;
    int     b;
};

struct TValue {
    LuaValue value;  // 0x00
    int      pad;    // 0x08
    int      tt;     // 0x0C
};                   // sizeof = 0x10

struct GCObject {
    GCObject* next;    // 0x00
    uint8_t   tt;      // 0x08
    uint8_t   marked;  // 0x09
    uint8_t   pad[6];
    void*     field14; // 0x14
};

// TString - header 0x38

struct TString {
    GCObject* next;     // 0x00
    uint8_t   tt;       // 0x08 = LUA_TSTRING
    uint8_t   marked;   // 0x09
    uint8_t   reserved; // 0x0A
    uint8_t   pad;      // 0x0B
    uint32_t  hash;     // 0x0C
    char      p[0x28];  // 0x10
    // char data[];     // 0x38
};

// CallInfo - sizeof = 0x78

struct CallInfo {
    TValue*  func;      // 0x00 = NULL
    TValue*  base;      // 0x08 = L to base
    uint16_t nresults;  // 0x10 = L to field_6c
    char     pad0[6];   // 0x12
    TValue*  top;       // 0x18
    void*    savedpc;   // 0x20
    void*    prev_base; // 0x28 = -1 (sent)
    void*    cont;      // 0x30
    char     zeros[0x30]; // 0x38..0x67 ig
    void*    field_68;  // 0x68 = 0
    uint16_t flags;     // 0x70
    char     pad1[6];   // 0x72
};                      // sizeof = 0x78

// Table - sizeof = 0x80

struct Table {
    GCObject* next;     // 0x00
    uint8_t   tt;       // 0x08 = LUA_TTABLE
    uint8_t   marked;   // 0x09
    uint8_t   readonly; // 0x0A
    uint8_t   safeenv;  // 0x0B
    char      pad[0x74];
};                      // sizeof = 0x80

// LClosure - sizeof = 0x50

struct LClosure {
    GCObject* next;      // 0x00
    uint8_t   tt;        // 0x08 = LUA_TFUNCTION
    uint8_t   marked;    // 0x09
    uint8_t   isC;       // 0x0A = 0
    uint8_t   nupvalues; // 0x0B
    char      pad[0x44];
};                       // sizeof = 0x50

// UpVal - sizeof = 0x60

struct UpVal {
    GCObject* next;    // 0x00
    uint8_t   tt;      // 0x08
    uint8_t   marked;  // 0x09
    char      pad[0x26];
    TValue*   v;       // 0x38
    char      pad2[0x20];
};                     // sizeof = 0x60

// lua_State — sizeof = 0x2C0

struct global_State;

struct lua_State {
    GCObject*     next;        // 0x00
    uint8_t       tt;          // 0x08 = LUA_TTHREAD
    uint8_t       marked;      // 0x09
    uint8_t       pad0;        // 0x0A
    uint8_t       status;      // 0x03
    char          p0[0x0C];
    lua_State*    next_thread; // 0x10
    char          p1[0x0E];
    uint16_t      nCcalls;     // 0x20
    char          p2[0x0E];
    TValue*       base_ci;     // 0x30, All shi is confirmed
    TValue*       top;         // 0x38
    TValue*       base;        // 0x40
    CallInfo*     ci;          // 0x48
    char          p3[0x10];
    global_State* global;      // 0x60
    uint16_t      field_6c;    // 0x6C
    char          p4[0x131];
    TValue        stack[8];    // 0x1A0
    char          p5[0x30];
    CallInfo      ci_buf[2];   // 0x1D0 (2 * 0x78 = 0xF0)
    char          p6[0x30];
    void*         field_290;   // 0x290
    void*         field_298;   // 0x298 = NULL
    TValue        gt;          // 0x2A0
    uint64_t      field_2b0;   // 0x2B0 = 2
    uint8_t       field_2b8;   // 0x2B8
    char          pad2[0x07];
};                             // sizeof = 0x2C0

struct global_State {
    char     p0[0x30];
    void*    gc_allgc;       // 0x30
    void*    gc_threshold;   // 0x38
    char     p1[0x468];
    TValue   l_gt;           // 0x4B0
    TValue   registry;       // 0x4C0
    char     p2[0x45F];
    uint8_t  strhash_seed;   // 0xA72
    char     p3[0xB5];
    char     stringtable[0xA0]; // 0x928
};

// Macro shit

#define L_TOP(L)    (*(TValue**)    ((uintptr_t)(L) + 0x38))
#define L_BASE(L)   (*(TValue**)    ((uintptr_t)(L) + 0x40))
#define L_CI(L)     (*(CallInfo**)  ((uintptr_t)(L) + 0x48))
#define L_GLOBAL(L) (*(global_State**)((uintptr_t)(L) + 0x60))
#define L_STATUS(L) (*(uint8_t*)    ((uintptr_t)(L) + 0x03))
#define TTYPE(tv)   ((tv)->tt)
#define TNUM(tv)    ((tv)->value.n)
#define TGC(tv)     ((tv)->value.gc)
