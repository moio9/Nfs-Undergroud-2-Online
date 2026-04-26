#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// U2Online transport shim.
// Scope:
// - redirect TCP connects to the configured lobby server
// - relay UDP race packets through the configured/advertised race relay
// - decode relay source wrappers on receive
// No bind forcing, ResetRoom hooks, closesocket preservation, or race lifecycle patches.

static HINSTANCE gSelf = nullptr;
static char gLogPath[MAX_PATH] = {};
static volatile LONG gLogEnabled = 1;
static volatile LONG gLoggedStart = 0;
static volatile LONG gHooksInstalled = 0;
static volatile LONG gBasePatchesApplied = 0;

struct Endpoint {
    char host[128];
    uint16_t port;
};

static Endpoint gBootstrap = {"127.0.0.1", 20921};
static Endpoint gLobby = {"127.0.0.1", 20922};
static Endpoint gControl = {"127.0.0.1", 20923};
static Endpoint gControlAlias = {"127.0.0.1", 13505};
static Endpoint gRace = {"127.0.0.1", 2000};
static Endpoint gLan = {"127.0.0.1", 20922};
static Endpoint gLanControl = {"127.0.0.1", 20923};
static Endpoint gLanControlAlias = {"127.0.0.1", 13505};

static sockaddr_in gBootstrapAddr = {};
static sockaddr_in gLobbyAddr = {};
static sockaddr_in gControlAddr = {};
static sockaddr_in gControlAliasAddr = {};
static sockaddr_in gRaceAddr = {};
static sockaddr_in gLanAddr = {};
static sockaddr_in gLanControlAddr = {};
static sockaddr_in gLanControlAliasAddr = {};
static char gHostBuf[0x3c] = {};
static volatile LONG gLanOverrideEnabled = 0;
static volatile LONG gLanInjectEnabled = 1;
static volatile LONG gLanF3040Installed = 0;
static volatile LONG gLoggedLanF3040Inject = 0;
static volatile LONG gLoggedLanF3040InjectFail = 0;
static volatile LONG gUdpSendLogCount = 0;
static volatile LONG gUdpSendErrorLogCount = 0;
static volatile LONG gUdpRecvLogCount = 0;
static volatile LONG gUdpRecvRejectLogCount = 0;
static void* gLanF3040Trampoline = nullptr;

#if defined(__GNUC__) || defined(__clang__)
#define OL_THISCALL __attribute__((thiscall))
#define OL_FASTCALL __attribute__((fastcall))
#else
#define OL_THISCALL __thiscall
#define OL_FASTCALL __fastcall
#endif

static CRITICAL_SECTION gPeerLock;
static bool gPeerLockReady = false;

struct PeerEntry {
    SOCKET s;
    sockaddr_in peer;
};
static PeerEntry gPeers[64] = {};

typedef FARPROC (WINAPI *GetProcAddressFn)(HMODULE, LPCSTR);
typedef int (WSAAPI *ConnectFn)(SOCKET, const sockaddr*, int);
typedef int (WSAAPI *SendToFn)(SOCKET, const char*, int, int, const sockaddr*, int);
typedef int (WSAAPI *RecvFromFn)(SOCKET, char*, int, int, sockaddr*, int*);
typedef int (WSAAPI *SendFn)(SOCKET, const char*, int, int);
typedef int (WSAAPI *RecvFn)(SOCKET, char*, int, int);
typedef int (WSAAPI *CloseSocketFn)(SOCKET);
typedef int (WSAAPI *WSAConnectFn)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
typedef int (WSAAPI *WSASendToFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSARecvFromFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSASendFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSARecvFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static GetProcAddressFn gRealGetProcAddress = nullptr;
static ConnectFn gRealConnect = nullptr;
static SendToFn gRealSendTo = nullptr;
static RecvFromFn gRealRecvFrom = nullptr;
static SendFn gRealSend = nullptr;
static RecvFn gRealRecv = nullptr;
static CloseSocketFn gRealCloseSocket = nullptr;
static WSAConnectFn gRealWSAConnect = nullptr;
static WSASendToFn gRealWSASendTo = nullptr;
static WSARecvFromFn gRealWSARecvFrom = nullptr;
static WSASendFn gRealWSASend = nullptr;
static WSARecvFn gRealWSARecv = nullptr;

static void LogLine(const char* fmt, ...)
{
    if (InterlockedCompareExchange(&gLogEnabled, 0, 0) == 0 || !gLogPath[0])
        return;

    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(body, sizeof(body) - 1, fmt, ap);
    va_end(ap);
    body[sizeof(body) - 1] = 0;

    char line[1200];
    _snprintf(line, sizeof(line) - 1, "[ONLINE pid=%lu] %s\r\n", (unsigned long)GetCurrentProcessId(), body);
    line[sizeof(line) - 1] = 0;

    HANDLE h = CreateFileA(gLogPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return;
    DWORD written = 0;
    WriteFile(h, line, (DWORD)strlen(line), &written, nullptr);
    CloseHandle(h);
}

static void Trim(char* s)
{
    if (!s) return;
    char* p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) {
        s[--n] = 0;
    }
}

static bool NameEq(const char* a, const char* b)
{
    return a && b && lstrcmpiA(a, b) == 0;
}

static int ParseBoolLike(const char* v)
{
    if (!v || !v[0]) return -1;
    if (NameEq(v, "1") || NameEq(v, "on") || NameEq(v, "true") || NameEq(v, "yes"))
        return 1;
    if (NameEq(v, "0") || NameEq(v, "off") || NameEq(v, "false") || NameEq(v, "no"))
        return 0;
    return -1;
}

static void SetEndpointHost(Endpoint* ep, const char* host)
{
    if (!ep || !host || !host[0])
        return;
    lstrcpynA(ep->host, host, sizeof(ep->host));
}

static void SetEndpointPort(Endpoint* ep, int port)
{
    if (!ep || port <= 0 || port > 65535)
        return;
    ep->port = (uint16_t)port;
}

static bool ProtectWrite(void* dst, const void* src, size_t sz)
{
    DWORD oldProt = 0;
    if (!VirtualProtect(dst, sz, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;
    memcpy(dst, src, sz);
    DWORD tmp = 0;
    VirtualProtect(dst, sz, oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), dst, sz);
    return true;
}

static bool ParseSig(const char* sig, uint8_t* outBytes, uint8_t* outMask, size_t* outLen)
{
    size_t n = 0;
    const char* p = sig;
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        return -1;
    };

    while (*p) {
        while (*p == ' ') ++p;
        if (!*p) break;
        if (*p == '?') {
            outBytes[n] = 0;
            outMask[n] = 0;
            ++n;
            ++p;
            if (*p == '?') ++p;
            continue;
        }
        int hi = hex(*p++);
        int lo = hex(*p++);
        if (hi < 0 || lo < 0 || n >= 256)
            return false;
        outBytes[n] = (uint8_t)((hi << 4) | lo);
        outMask[n] = 0xFF;
        ++n;
    }

    *outLen = n;
    return n > 0;
}

static uint8_t* FindPattern(uint8_t* base, size_t size, const char* sig, size_t startAt)
{
    uint8_t bytes[256] = {};
    uint8_t mask[256] = {};
    size_t len = 0;
    if (!ParseSig(sig, bytes, mask, &len) || len > size)
        return nullptr;

    for (size_t i = startAt; i + len <= size; ++i) {
        bool ok = true;
        for (size_t j = 0; j < len; ++j) {
            if (mask[j] && base[i + j] != bytes[j]) {
                ok = false;
                break;
            }
        }
        if (ok)
            return base + i;
    }
    return nullptr;
}

static bool ApplyBasePatches()
{
    if (InterlockedCompareExchange(&gBasePatchesApplied, 1, 0) != 0)
        return true;

    uint8_t* base = (uint8_t*)GetModuleHandleA(nullptr);
    if (!base) {
        LogLine("base patches skipped: exe base missing");
        return false;
    }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        LogLine("base patches skipped: bad dos header");
        return false;
    }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        LogLine("base patches skipped: bad nt header");
        return false;
    }
    size_t size = nt->OptionalHeader.SizeOfImage;

    memset(gHostBuf, 0, sizeof(gHostBuf));
    gHostBuf[0] = 0x2A;
    lstrcpynA(&gHostBuf[1], gBootstrap.host, (int)sizeof(gHostBuf) - 2);

    const char* PAT_EA_URL =
        "68 ? ? ? ? 50 E8 ? ? ? ? 8B F8 83 C4 ? 85 FF 7D";
    const char* PAT_MULTI =
        "6A ? E8 ? ? ? ? 8B 44 24 ? 8B 4C 24 ? 50";
    const char* PAT_MULTI_PATCHED =
        "90 90 90 90 90 90 90 8B 44 24 ? 8B 4C 24 ? 50";
    const char* PAT_SSL =
        "7D ? C7 86 ? ? ? ? ? ? ? ? EB ? 03 7C 24";
    const char* PAT_SSL_PATCHED =
        "7E ? C7 86 ? ? ? ? ? ? ? ? EB ? 03 7C 24";
    const char* PAT_YEAR =
        "B8 ? ? ? ? C3 90 90 90 90 90 90 90 90 90 90 56 57 8B 7C 24 ? 81 FF";

    uint8_t* mEA = FindPattern(base, size, PAT_EA_URL, 0);
    uint8_t* mMulti = FindPattern(base, size, PAT_MULTI, 0);
    if (!mMulti) mMulti = FindPattern(base, size, PAT_MULTI_PATCHED, 0);
    uint8_t* mSSL = FindPattern(base, size, PAT_SSL, 0);
    if (!mSSL) mSSL = FindPattern(base, size, PAT_SSL_PATCHED, 0);
    uint8_t* mYear = FindPattern(base, size, PAT_YEAR, 0);

    if (!mEA || !mMulti || !mSSL || !mYear) {
        LogLine("base patches missing: ea=%p multi=%p ssl=%p year=%p", mEA, mMulti, mSSL, mYear);
        return false;
    }

    uint8_t nops7[7] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    uint8_t sslJmp = 0x7E;
    uint32_t hostPtr = (uint32_t)(uintptr_t)gHostBuf;
    uint32_t year = 0x802;

    bool ok = true;
    if (mMulti[0] != 0x90)
        ok = ProtectWrite(mMulti, nops7, sizeof(nops7)) && ok;
    if (mSSL[0] != 0x7E)
        ok = ProtectWrite(mSSL, &sslJmp, 1) && ok;
    ok = ProtectWrite(mEA + 1, &hostPtr, sizeof(hostPtr)) && ok;
    ok = ProtectWrite(mYear + 1, &year, sizeof(year)) && ok;

    LogLine("base patches %s: bootstrap=%s:%u ea=%p multi=%p ssl=%p year=%p", ok ? "applied" : "failed", gBootstrap.host, (unsigned)gBootstrap.port, mEA, mMulti, mSSL, mYear);
    return ok;
}

static void LoadConfigPath(const char* path)
{
    FILE* f = fopen(path, "rb");
    if (!f)
        return;

    char serverHost[128] = {};
    char bootstrapHost[128] = {};
    char lobbyHost[128] = {};
    char controlHost[128] = {};
    char controlAliasHost[128] = {};
    char raceHost[128] = {};
    char lanHost[128] = {};
    int bootstrapPort = 0;
    int lobbyPort = 0;
    int controlPort = 0;
    int controlAliasPort = 0;
    int racePort = 0;
    int lanPort = 0;
    int lanControlPort = 0;
    int lanControlAliasPort = 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* comment = strchr(line, '#');
        if (comment) *comment = 0;
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char key[128];
        char val[256];
        lstrcpynA(key, line, sizeof(key));
        lstrcpynA(val, eq + 1, sizeof(val));
        Trim(key);
        Trim(val);
        if (!key[0] || !val[0]) continue;

        if (NameEq(key, "server_host") || NameEq(key, "main_host") || NameEq(key, "relay_host") || NameEq(key, "host") || NameEq(key, "online_host")) {
            lstrcpynA(serverHost, val, sizeof(serverHost));
        } else if (NameEq(key, "bootstrap_host")) {
            lstrcpynA(bootstrapHost, val, sizeof(bootstrapHost));
        } else if (NameEq(key, "lobby_host") || NameEq(key, "lobby_tcp_host")) {
            lstrcpynA(lobbyHost, val, sizeof(lobbyHost));
        } else if (NameEq(key, "control_host") || NameEq(key, "buddy_host")) {
            lstrcpynA(controlHost, val, sizeof(controlHost));
        } else if (NameEq(key, "control_alias_host") || NameEq(key, "buddy_alias_host")) {
            lstrcpynA(controlAliasHost, val, sizeof(controlAliasHost));
        } else if (NameEq(key, "race_host") || NameEq(key, "race_udp_host")) {
            lstrcpynA(raceHost, val, sizeof(raceHost));
        } else if (NameEq(key, "lan_host")) {
            lstrcpynA(lanHost, val, sizeof(lanHost));
        } else if (NameEq(key, "relay_port") || NameEq(key, "port") || NameEq(key, "online_port") || NameEq(key, "race_port") || NameEq(key, "race_udp_port")) {
            racePort = atoi(val);
        } else if (NameEq(key, "bootstrap_port")) {
            bootstrapPort = atoi(val);
        } else if (NameEq(key, "relay_tcp_port") || NameEq(key, "tcp_port") || NameEq(key, "online_tcp_port") || NameEq(key, "lobby_port") || NameEq(key, "lobby_tcp_port")) {
            lobbyPort = atoi(val);
        } else if (NameEq(key, "control_port") || NameEq(key, "buddy_port")) {
            controlPort = atoi(val);
        } else if (NameEq(key, "control_alias_port") || NameEq(key, "buddy_alias_port")) {
            controlAliasPort = atoi(val);
        } else if (NameEq(key, "lan_port")) {
            lanPort = atoi(val);
        } else if (NameEq(key, "lan_control_port")) {
            lanControlPort = atoi(val);
        } else if (NameEq(key, "lan_control_alias_port")) {
            lanControlAliasPort = atoi(val);
        } else if (NameEq(key, "lan_override_host") || NameEq(key, "lan_override")) {
            int b = ParseBoolLike(val);
            if (b != -1)
                InterlockedExchange(&gLanOverrideEnabled, b ? 1 : 0);
        } else if (NameEq(key, "lan_provider_seed") || NameEq(key, "lan_inject") || NameEq(key, "lan_server_inject")) {
            int b = ParseBoolLike(val);
            if (b != -1)
                InterlockedExchange(&gLanInjectEnabled, b ? 1 : 0);
        } else if (NameEq(key, "debug")) {
            if (NameEq(val, "off") || NameEq(val, "false") || NameEq(val, "0"))
                InterlockedExchange(&gLogEnabled, 0);
        }
    }
    fclose(f);

    if (serverHost[0]) {
        SetEndpointHost(&gBootstrap, serverHost);
        SetEndpointHost(&gLobby, serverHost);
        SetEndpointHost(&gControl, serverHost);
        SetEndpointHost(&gControlAlias, serverHost);
        SetEndpointHost(&gRace, serverHost);
        SetEndpointHost(&gLan, serverHost);
        SetEndpointHost(&gLanControl, serverHost);
        SetEndpointHost(&gLanControlAlias, serverHost);
    }
    if (bootstrapHost[0]) SetEndpointHost(&gBootstrap, bootstrapHost);
    if (lobbyHost[0]) SetEndpointHost(&gLobby, lobbyHost);
    if (controlHost[0]) SetEndpointHost(&gControl, controlHost);
    if (controlAliasHost[0]) SetEndpointHost(&gControlAlias, controlAliasHost);
    if (raceHost[0]) SetEndpointHost(&gRace, raceHost);
    if (lanHost[0]) {
        SetEndpointHost(&gLan, lanHost);
        SetEndpointHost(&gLanControl, lanHost);
        SetEndpointHost(&gLanControlAlias, lanHost);
    }

    SetEndpointPort(&gBootstrap, bootstrapPort);
    SetEndpointPort(&gLobby, lobbyPort);
    SetEndpointPort(&gControl, controlPort);
    SetEndpointPort(&gControlAlias, controlAliasPort);
    SetEndpointPort(&gRace, racePort);
    SetEndpointPort(&gLan, lanPort);
    SetEndpointPort(&gLanControl, lanControlPort > 0 ? lanControlPort : gControl.port);
    SetEndpointPort(&gLanControlAlias, lanControlAliasPort > 0 ? lanControlAliasPort : gControlAlias.port);
}

static void LoadConfig()
{
    char exe[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, exe, MAX_PATH)) {
        for (int i = (int)strlen(exe) - 1; i >= 0; --i) {
            if (exe[i] == '\\' || exe[i] == '/') {
                exe[i + 1] = 0;
                break;
            }
        }
        char cfg[MAX_PATH] = {};
        lstrcpynA(cfg, exe, sizeof(cfg));
        lstrcatA(cfg, "ONLINE.cfg");
        LoadConfigPath(cfg);
    }

    char asi[MAX_PATH] = {};
    if (GetModuleFileNameA(gSelf, asi, MAX_PATH)) {
        for (int i = (int)strlen(asi) - 1; i >= 0; --i) {
            if (asi[i] == '\\' || asi[i] == '/') {
                asi[i + 1] = 0;
                break;
            }
        }
        char cfg[MAX_PATH] = {};
        lstrcpynA(cfg, asi, sizeof(cfg));
        lstrcatA(cfg, "ONLINE.cfg");
        LoadConfigPath(cfg);
    }
}

static bool ResolveTo(const char* host, uint16_t port, sockaddr_in* out)
{
    if (!host || !*host || !out || port == 0)
        return false;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons(port);
    unsigned long direct = inet_addr(host);
    if (direct != INADDR_NONE) {
        out->sin_addr.s_addr = direct;
        return true;
    }
    hostent* he = gethostbyname(host);
    if (!he || !he->h_addr_list || !he->h_addr_list[0])
        return false;
    memcpy(&out->sin_addr, he->h_addr_list[0], 4);
    return true;
}

static void RefreshAddrs()
{
    ResolveTo(gBootstrap.host, gBootstrap.port, &gBootstrapAddr);
    ResolveTo(gLobby.host, gLobby.port, &gLobbyAddr);
    ResolveTo(gControl.host, gControl.port, &gControlAddr);
    ResolveTo(gControlAlias.host, gControlAlias.port, &gControlAliasAddr);
    ResolveTo(gRace.host, gRace.port, &gRaceAddr);
    ResolveTo(gLan.host, gLan.port, &gLanAddr);
    ResolveTo(gLanControl.host, gLanControl.port, &gLanControlAddr);
    ResolveTo(gLanControlAlias.host, gLanControlAlias.port, &gLanControlAliasAddr);
}

static bool IsTcpSocket(SOCKET s)
{
    int type = 0;
    int len = sizeof(type);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &len) == 0 && type == SOCK_STREAM;
}

static bool IsUdpSocket(SOCKET s)
{
    int type = 0;
    int len = sizeof(type);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&type, &len) == 0 && type == SOCK_DGRAM;
}

static bool IsLoopbackAddr(unsigned long addr)
{
    return (ntohl(addr) & 0xFF000000u) == 0x7F000000u;
}

static bool IsReadableRange(const void* ptr, size_t len)
{
    if (!ptr || len == 0)
        return false;
    const uint8_t* cur = (const uint8_t*)ptr;
    const uint8_t* end = cur + len;
    if (end < cur)
        return false;
    while (cur < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(cur, &mbi, sizeof(mbi)) != sizeof(mbi))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return false;
        uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd <= (uintptr_t)cur)
            return false;
        cur = (const uint8_t*)regionEnd;
    }
    return true;
}

static bool IsWritableRange(void* ptr, size_t len)
{
    if (!ptr || len == 0)
        return false;
    const uint8_t* cur = (const uint8_t*)ptr;
    const uint8_t* end = cur + len;
    if (end < cur)
        return false;
    while (cur < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(cur, &mbi, sizeof(mbi)) != sizeof(mbi))
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return false;
        DWORD prot = mbi.Protect & 0xFFu;
        if (prot != PAGE_READWRITE && prot != PAGE_WRITECOPY &&
            prot != PAGE_EXECUTE_READWRITE && prot != PAGE_EXECUTE_WRITECOPY)
            return false;
        uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd <= (uintptr_t)cur)
            return false;
        cur = (const uint8_t*)regionEnd;
    }
    return true;
}

static uint32_t MakeLanSyntheticHandle(const char* name, uint16_t port)
{
    uint32_t h = 2166136261u;
    if (name) {
        for (const unsigned char* p = (const unsigned char*)name; *p; ++p) {
            unsigned char c = *p;
            if (c >= 'A' && c <= 'Z')
                c = (unsigned char)(c - 'A' + 'a');
            h ^= (uint32_t)c;
            h *= 16777619u;
        }
    }
    h ^= (uint32_t)port;
    h *= 16777619u;
    if (h == 0 || h == 0xFFFFFFFFu)
        h = 0x01020304u ^ (uint32_t)port;
    return h;
}

static bool LanInjectionReady()
{
    return InterlockedCompareExchange(&gLanOverrideEnabled, 0, 0) != 0 &&
        InterlockedCompareExchange(&gLanInjectEnabled, 0, 0) != 0 &&
        gLan.host[0] != 0 &&
        gLan.port != 0;
}

static void PeerSet(SOCKET s, const sockaddr_in* peer)
{
    if (!gPeerLockReady || s == INVALID_SOCKET || !peer || peer->sin_family != AF_INET)
        return;
    EnterCriticalSection(&gPeerLock);
    int freeSlot = -1;
    for (int i = 0; i < 64; ++i) {
        if (gPeers[i].s == s) {
            gPeers[i].peer = *peer;
            LeaveCriticalSection(&gPeerLock);
            return;
        }
        if (freeSlot < 0 && (gPeers[i].s == INVALID_SOCKET || gPeers[i].s == 0))
            freeSlot = i;
    }
    if (freeSlot >= 0) {
        gPeers[freeSlot].s = s;
        gPeers[freeSlot].peer = *peer;
    }
    LeaveCriticalSection(&gPeerLock);
}

static bool PeerGet(SOCKET s, sockaddr_in* peer)
{
    if (!gPeerLockReady || s == INVALID_SOCKET || !peer)
        return false;
    EnterCriticalSection(&gPeerLock);
    for (int i = 0; i < 64; ++i) {
        if (gPeers[i].s == s) {
            *peer = gPeers[i].peer;
            LeaveCriticalSection(&gPeerLock);
            return true;
        }
    }
    LeaveCriticalSection(&gPeerLock);
    return false;
}

static void PeerClear(SOCKET s)
{
    if (!gPeerLockReady || s == INVALID_SOCKET)
        return;
    EnterCriticalSection(&gPeerLock);
    for (int i = 0; i < 64; ++i) {
        if (gPeers[i].s == s) {
            memset(&gPeers[i], 0, sizeof(gPeers[i]));
            break;
        }
    }
    LeaveCriticalSection(&gPeerLock);
}

static bool LooksWrapped(const char* buf, int len)
{
    if (!buf || len <= 6)
        return false;
    const uint8_t* p = (const uint8_t*)buf;
    uint16_t port = ((uint16_t)p[0] << 8) | (uint16_t)p[1];
    if (port == 0)
        return false;
    if (p[2] == 0 || p[2] >= 224)
        return false;
    if (p[2] == 255 && p[3] == 255 && p[4] == 255 && p[5] == 255)
        return false;
    uint8_t version = (uint8_t)(p[0] >> 4);
    if (version == 4 && len >= 20) {
        uint8_t ihl = (uint8_t)((p[0] & 0x0F) * 4);
        uint16_t totalLen = ((uint16_t)p[2] << 8) | (uint16_t)p[3];
        if (ihl >= 20 && totalLen >= ihl && totalLen <= (uint16_t)len)
            return false;
    }
    return true;
}

static bool IsFromRaceRelay(const sockaddr_in* from)
{
    if (!from || from->sin_family != AF_INET)
        return false;
    if (from->sin_addr.s_addr != gRaceAddr.sin_addr.s_addr)
        return false;
    uint16_t p = ntohs(from->sin_port);
    return p == 0 || p == gRace.port;
}

static int WrappedSendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr_in* origPeer)
{
    if (!gRealSendTo || !buf || len <= 0 || !origPeer || origPeer->sin_family != AF_INET)
        return SOCKET_ERROR;
    if (gRaceAddr.sin_family != AF_INET || gRaceAddr.sin_port == 0)
        return gRealSendTo(s, buf, len, flags, (const sockaddr*)origPeer, sizeof(sockaddr_in));

    char stackBuf[2048];
    int total = len + 6;
    char* out = (total <= (int)sizeof(stackBuf)) ? stackBuf : (char*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)total);
    if (!out)
        return SOCKET_ERROR;

    memcpy(out + 0, &origPeer->sin_port, 2);
    memcpy(out + 2, &origPeer->sin_addr.s_addr, 4);
    memcpy(out + 6, buf, (size_t)len);

    int r = gRealSendTo(s, out, total, flags, (const sockaddr*)&gRaceAddr, sizeof(sockaddr_in));
    int err = (r == SOCKET_ERROR) ? WSAGetLastError() : 0;
    if (out != stackBuf)
        HeapFree(GetProcessHeap(), 0, out);
    if (r == SOCKET_ERROR) {
        LONG n = InterlockedIncrement(&gUdpSendErrorLogCount);
        if (n <= 20) {
            LogLine(
                "udp send relay failed orig=%u.%u.%u.%u:%u relay=%s:%u len=%d wsa=%d",
                (unsigned)((ntohl(origPeer->sin_addr.s_addr) >> 24) & 255),
                (unsigned)((ntohl(origPeer->sin_addr.s_addr) >> 16) & 255),
                (unsigned)((ntohl(origPeer->sin_addr.s_addr) >> 8) & 255),
                (unsigned)(ntohl(origPeer->sin_addr.s_addr) & 255),
                (unsigned)ntohs(origPeer->sin_port),
                gRace.host,
                (unsigned)gRace.port,
                len,
                err);
        }
        return SOCKET_ERROR;
    }
    LONG n = InterlockedIncrement(&gUdpSendLogCount);
    if (n <= 20 || (n % 100) == 0) {
        LogLine(
            "udp send relay orig=%u.%u.%u.%u:%u relay=%s:%u len=%d wrapped=%d sent=%d count=%ld",
            (unsigned)((ntohl(origPeer->sin_addr.s_addr) >> 24) & 255),
            (unsigned)((ntohl(origPeer->sin_addr.s_addr) >> 16) & 255),
            (unsigned)((ntohl(origPeer->sin_addr.s_addr) >> 8) & 255),
            (unsigned)(ntohl(origPeer->sin_addr.s_addr) & 255),
            (unsigned)ntohs(origPeer->sin_port),
            gRace.host,
            (unsigned)gRace.port,
            len,
            total,
            r,
            (long)n);
    }
    PeerSet(s, origPeer);
    return (r >= 6) ? (r - 6) : r;
}

static int DecodeRecv(SOCKET s, char* buf, int r, sockaddr* from, int* fromlen)
{
    if (r <= 6 || !buf || !from || !fromlen || *fromlen < (int)sizeof(sockaddr_in))
        return r;
    sockaddr_in* si = (sockaddr_in*)from;
    if (!IsFromRaceRelay(si))
        return r;
    if (!LooksWrapped(buf, r)) {
        LONG n = InterlockedIncrement(&gUdpRecvRejectLogCount);
        if (n <= 20 || (n % 100) == 0) {
            LogLine(
                "udp recv relay unwrapped relay=%u.%u.%u.%u:%u len=%d count=%ld",
                (unsigned)((ntohl(si->sin_addr.s_addr) >> 24) & 255),
                (unsigned)((ntohl(si->sin_addr.s_addr) >> 16) & 255),
                (unsigned)((ntohl(si->sin_addr.s_addr) >> 8) & 255),
                (unsigned)(ntohl(si->sin_addr.s_addr) & 255),
                (unsigned)ntohs(si->sin_port),
                r,
                (long)n);
        }
        return r;
    }

    sockaddr_in decoded = {};
    decoded.sin_family = AF_INET;
    memcpy(&decoded.sin_port, buf + 0, 2);
    memcpy(&decoded.sin_addr.s_addr, buf + 2, 4);

    int payloadLen = r - 6;
    memmove(buf, buf + 6, (size_t)payloadLen);
    *si = decoded;
    *fromlen = sizeof(sockaddr_in);
    PeerSet(s, &decoded);
    LONG n = InterlockedIncrement(&gUdpRecvLogCount);
    if (n <= 20 || (n % 100) == 0) {
        LogLine(
            "udp recv relay decoded src=%u.%u.%u.%u:%u payload=%d wrapped=%d count=%ld",
            (unsigned)((ntohl(decoded.sin_addr.s_addr) >> 24) & 255),
            (unsigned)((ntohl(decoded.sin_addr.s_addr) >> 16) & 255),
            (unsigned)((ntohl(decoded.sin_addr.s_addr) >> 8) & 255),
            (unsigned)(ntohl(decoded.sin_addr.s_addr) & 255),
            (unsigned)ntohs(decoded.sin_port),
            payloadLen,
            r,
            (long)n);
    }
    return payloadLen;
}

static int CopyField(const char* buf, int len, const char* key, char* out, size_t outSize)
{
    if (!buf || len <= 0 || !key || !out || outSize == 0)
        return 0;
    out[0] = 0;
    size_t keyLen = strlen(key);
    for (int i = 0; i <= len - (int)keyLen; ++i) {
        if (_strnicmp(buf + i, key, keyLen) != 0)
            continue;
        int j = i + (int)keyLen;
        size_t k = 0;
        while (j < len && k + 1 < outSize) {
            char c = buf[j++];
            if (c == '\r' || c == '\n' || c == '\t' || c == '\0' || c == '|' || c == '&')
                break;
            out[k++] = c;
        }
        out[k] = 0;
        Trim(out);
        return out[0] ? 1 : 0;
    }
    return 0;
}

static int CopyAnyField(const char* buf, int len, const char* const* keys, char* out, size_t outSize)
{
    if (!keys)
        return 0;
    for (int i = 0; keys[i]; ++i) {
        if (CopyField(buf, len, keys[i], out, outSize))
            return 1;
    }
    return 0;
}

static void MaybeApplyAdvertisedEndpoint(
    const char* buf,
    int len,
    const char* tag,
    const char* service,
    Endpoint* ep,
    const char* const* hostKeys,
    const char* const* portKeys)
{
    char host[128] = {};
    char portTxt[32] = {};
    int gotHost = CopyAnyField(buf, len, hostKeys, host, sizeof(host));
    int gotPort = CopyAnyField(buf, len, portKeys, portTxt, sizeof(portTxt));
    if (!gotHost && !gotPort)
        return;

    int oldPort = ep ? ep->port : 0;
    char oldHost[128] = {};
    if (ep)
        lstrcpynA(oldHost, ep->host, sizeof(oldHost));

    if (host[0])
        SetEndpointHost(ep, host);
    if (portTxt[0])
        SetEndpointPort(ep, atoi(portTxt));
    RefreshAddrs();

    if (ep && (lstrcmpiA(oldHost, ep->host) != 0 || oldPort != (int)ep->port)) {
        LogLine("advertised %s applied from %s: %s:%u", service ? service : "endpoint", tag ? tag : "?", ep->host, (unsigned)ep->port);
    }
}

static void MaybeConsumeAdvertisedEndpoints(const char* buf, int len, const char* tag)
{
    static const char* const lobbyHosts[] = {"LOBBYHOST=", "LOBBY_HOST=", "LOBBYTCPHOST=", nullptr};
    static const char* const lobbyPorts[] = {"LOBBYTCP=", "LOBBYPORT=", "LOBBY_PORT=", "LOBBY_TCP_PORT=", nullptr};
    static const char* const bootstrapHosts[] = {"BOOTSTRAPHOST=", "BOOTSTRAP_HOST=", nullptr};
    static const char* const bootstrapPorts[] = {"BOOTSTRAPPORT=", "BOOTSTRAP_PORT=", nullptr};
    static const char* const controlHosts[] = {"CONTROLHOST=", "CONTROL_HOST=", "BUDDY_SERVER=", nullptr};
    static const char* const controlPorts[] = {"CONTROLPORT=", "CONTROL_PORT=", "BUDDY_PORT=", nullptr};
    static const char* const aliasHosts[] = {"CONTROLALIASHOST=", "CONTROL_ALIAS_HOST=", "CONTROLALIAS_HOST=", "BUDDY_ALIAS_SERVER=", nullptr};
    static const char* const aliasPorts[] = {"CONTROLALIASPORT=", "CONTROL_ALIAS_PORT=", "CONTROLALIAS_PORT=", "BUDDY_ALIAS_PORT=", nullptr};
    static const char* const raceHosts[] = {"UDPHOST=", "RLYHOST=", "RACEHOST=", "RACE_HOST=", nullptr};
    static const char* const racePorts[] = {"UDPPORT=", "RLYPORT=", "RACEPORT=", "RACE_PORT=", nullptr};

    MaybeApplyAdvertisedEndpoint(buf, len, tag, "bootstrap", &gBootstrap, bootstrapHosts, bootstrapPorts);
    MaybeApplyAdvertisedEndpoint(buf, len, tag, "lobby", &gLobby, lobbyHosts, lobbyPorts);
    MaybeApplyAdvertisedEndpoint(buf, len, tag, "control", &gControl, controlHosts, controlPorts);
    MaybeApplyAdvertisedEndpoint(buf, len, tag, "control_alias", &gControlAlias, aliasHosts, aliasPorts);
    MaybeApplyAdvertisedEndpoint(buf, len, tag, "race", &gRace, raceHosts, racePorts);
}

static void MaybeConsumeAdvertisedRaceEndpoint(const char* buf, int len, const char* tag)
{
    static const char* const raceHosts[] = {"UDPHOST=", "RLYHOST=", "RACEHOST=", "RACE_HOST=", nullptr};
    static const char* const racePorts[] = {"UDPPORT=", "RLYPORT=", "RACEPORT=", "RACE_PORT=", nullptr};
    MaybeApplyAdvertisedEndpoint(buf, len, tag, "race", &gRace, raceHosts, racePorts);
}

static bool BuildTcpRedirect(const sockaddr_in* original, sockaddr_in* out, const char** outName)
{
    if (!original || !out)
        return false;
    uint16_t oldPort = ntohs(original->sin_port);
    Endpoint* ep = nullptr;
    const char* name = "";
    if (InterlockedCompareExchange(&gLanOverrideEnabled, 0, 0) != 0 &&
        (oldPort == 9900 || oldPort == gLan.port ||
         oldPort == 20923 || oldPort == gLanControl.port ||
         oldPort == 13505 || oldPort == gLanControlAlias.port)) {
        if (oldPort == 9900 || oldPort == gLan.port) {
            ep = &gLan;
            name = "lan";
        } else if (oldPort == 20923 || oldPort == gLanControl.port) {
            ep = &gLanControl;
            name = "lan_control";
        } else {
            ep = &gLanControlAlias;
            name = "lan_control_alias";
        }
    } else if (oldPort == 20921 || oldPort == gBootstrap.port) {
        ep = &gBootstrap;
        name = "bootstrap";
    } else if (oldPort == 20922 || oldPort == gLobby.port) {
        ep = &gLobby;
        name = "lobby";
    } else if (oldPort == 20923 || oldPort == gControl.port) {
        ep = &gControl;
        name = "control";
    } else if (oldPort == 13505 || oldPort == gControlAlias.port) {
        ep = &gControlAlias;
        name = "control_alias";
    } else {
        return false;
    }

    sockaddr_in dst = {};
    if (!ResolveTo(ep->host, ep->port, &dst))
        return false;
    if (InterlockedCompareExchange(&gLanOverrideEnabled, 0, 0) != 0 &&
        (ep == &gLanControl || ep == &gLanControlAlias) &&
        !IsLoopbackAddr(original->sin_addr.s_addr) &&
        original->sin_addr.s_addr != dst.sin_addr.s_addr) {
        return false;
    }
    if (dst.sin_addr.s_addr == original->sin_addr.s_addr && dst.sin_port == original->sin_port)
        return false;

    *out = dst;
    if (outName)
        *outName = name;
    return true;
}

static bool IsInterestingTcpPort(uint16_t port)
{
    return port == 9900 || port == 20921 || port == 20922 || port == gLan.port ||
        port == gBootstrap.port || port == gLobby.port || port == gControl.port ||
        port == gLanControl.port || port == gControlAlias.port || port == gLanControlAlias.port;
}

static bool IsLanTcpPeer(SOCKET s)
{
    if (s == INVALID_SOCKET || s == 0)
        return false;
    sockaddr_in peer = {};
    if (!PeerGet(s, &peer)) {
        int plen = sizeof(peer);
        if (getpeername(s, (sockaddr*)&peer, &plen) != 0 || peer.sin_family != AF_INET)
            return false;
    }
    if (ntohs(peer.sin_port) != gLan.port && ntohs(peer.sin_port) != 9900)
        return false;
    sockaddr_in lan = {};
    if (!ResolveTo(gLan.host, gLan.port, &lan))
        return false;
    return peer.sin_addr.s_addr == lan.sin_addr.s_addr;
}

static void MaybeConsumeAdvertisedEndpointsForSocket(SOCKET s, const char* buf, int len, const char* tag)
{
    if (IsLanTcpPeer(s)) {
        MaybeConsumeAdvertisedRaceEndpoint(buf, len, tag);
        LogLine("advertised tcp endpoints ignored from %s on LAN tcp peer", tag ? tag : "?");
        return;
    }
    MaybeConsumeAdvertisedEndpoints(buf, len, tag);
}

static void SeedLanProviderEntry(uintptr_t selfValue)
{
    if (!LanInjectionReady() || selfValue < 0x10000u)
        return;

    uint8_t* base = (uint8_t*)GetModuleHandleA(nullptr);
    if (!base)
        return;

    typedef void* (__cdecl* Game50160Fn)(int count);
    typedef void (__cdecl* Game4B7E0Fn)(int provider);
    typedef void (__cdecl* Game4B870Fn)(int provider);
    Game50160Fn fn50160 = (Game50160Fn)(base + 0x00350160u);
    Game4B7E0Fn fn4B7E0 = (Game4B7E0Fn)(base + 0x0034B7E0u);
    Game4B870Fn fn4B870 = (Game4B870Fn)(base + 0x0034B870u);
    if (!fn50160 || !fn4B7E0 || !fn4B870)
        return;

    if (!IsReadableRange((const void*)(selfValue + 0xFCu), sizeof(uint32_t)) ||
        !IsReadableRange((const void*)(selfValue + 0x918u), 1))
        return;

    uint32_t owner = *(uint32_t*)(selfValue + 0xFCu);
    if (owner < 0x10000u ||
        !IsReadableRange((const void*)(uintptr_t)owner, 0x68) ||
        !IsWritableRange((void*)(uintptr_t)(owner + 100u), sizeof(uint32_t)))
        return;

    const char* tag = (const char*)(selfValue + 0x918u);
    if (!tag || !*tag)
        tag = "GmUtil";

    char displayName[13] = {};
    lstrcpynA(displayName, gLan.host, (int)sizeof(displayName));
    if (!displayName[0])
        return;

    uint32_t provider = *(uint32_t*)(owner + 100u);
    if (provider == 0) {
        provider = (uint32_t)(uintptr_t)fn50160(0x10);
        *(uint32_t*)(owner + 100u) = provider;
    }
    if (provider < 0x10000u || !IsReadableRange((const void*)(uintptr_t)provider, 0x30))
        return;

    uint32_t start = *(uint32_t*)(provider + 0x28u);
    uint32_t end = *(uint32_t*)(provider + 0x2Cu);
    if (start < 0x10000u || end <= start ||
        !IsReadableRange((const void*)(uintptr_t)start, end - start) ||
        !IsWritableRange((void*)(uintptr_t)start, end - start))
        return;

    uint32_t existing = 0;
    uint32_t freeEntry = 0;

    fn4B7E0((int)provider);
    for (uint32_t cur = start; cur + 0x1A4u <= end; cur += 0x1A4u) {
        const char* curTag = (const char*)(uintptr_t)(cur + 0x08u);
        const char* curName = (const char*)(uintptr_t)(cur + 0x28u);
        if (!freeEntry && IsReadableRange((const void*)(uintptr_t)(cur + 0x28u), 1) && *curName == '\0')
            freeEntry = cur;
        if (!IsReadableRange(curTag, 1) || !IsReadableRange(curName, 1))
            continue;
        if (_stricmp(curTag, tag) == 0 && _stricmp(curName, displayName) == 0) {
            existing = cur;
            break;
        }
    }

    uint32_t entry = existing ? existing : freeEntry;
    if (entry != 0) {
        if (!existing)
            ZeroMemory((void*)(uintptr_t)entry, 0x1A4u);

        char portField[32] = {};
        _snprintf(portField, sizeof(portField) - 1, "%u|0", (unsigned)gLan.port);
        portField[sizeof(portField) - 1] = 0;
        const uint32_t handle = MakeLanSyntheticHandle(displayName, gLan.port);

        lstrcpynA((LPSTR)(uintptr_t)(entry + 0x08u), tag, 0x20);
        lstrcpynA((LPSTR)(uintptr_t)(entry + 0x28u), displayName, 0x20);
        lstrcpynA((LPSTR)(uintptr_t)(entry + 0x48u), portField, 0xC0);
        lstrcpynA((LPSTR)(uintptr_t)(entry + 0x108u), "TCP:1", 0x78);
        *(uint32_t*)(entry + 0x180u) = GetTickCount() + 3600000u;
        *(uint32_t*)(entry + 0x194u) = handle;
        *(uint32_t*)(entry + 0x198u) = handle;
        *(uint32_t*)(entry + 0x19Cu) = 0;

        LogLine(
            "lan provider seed owner=0x%08X provider=0x%08X tag='%s' name='%s' field='%s' handle=0x%08X",
            (unsigned)owner,
            (unsigned)provider,
            tag,
            displayName,
            portField,
            (unsigned)handle);
    } else if (InterlockedExchange(&gLoggedLanF3040InjectFail, 1) == 0) {
        LogLine("lan provider seed failed: no free provider entry owner=0x%08X provider=0x%08X", (unsigned)owner, (unsigned)provider);
    }
    fn4B870((int)provider);
}

static void HandleLanF3040(uintptr_t selfValue)
{
    if (!LanInjectionReady() || selfValue < 0x10000u)
        return;

    uint8_t* base = (uint8_t*)GetModuleHandleA(nullptr);
    if (!base)
        return;

    typedef int (__cdecl* Game43AA0Fn)(int param1, int param2, void* param3, int param4);
    typedef int (__cdecl* Game43A50Fn)(int param1, int param2, void* param3);
    typedef void (__cdecl* Game540A60Fn)(int ptr);
    typedef void (OL_THISCALL *GameE8A00Fn)(int selfPtr);
    Game43AA0Fn fn43AA0 = (Game43AA0Fn)(base + 0x00343AA0u);
    Game43A50Fn fn43A50 = (Game43A50Fn)(base + 0x00343A50u);
    Game540A60Fn fn540A60 = (Game540A60Fn)(base + 0x00140A60u);
    GameE8A00Fn fnE8A00 = (GameE8A00Fn)(base + 0x000E8A00u);
    if (!fn43AA0 || !fn43A50 || !fn540A60 || !fnE8A00)
        return;

    if (!IsReadableRange((const void*)(selfValue + 0xFCu), sizeof(int)) ||
        !IsReadableRange((const void*)(selfValue + 0x908u), sizeof(int) * 4) ||
        !IsReadableRange((const void*)(selfValue + 0x100u), 0x800) ||
        !IsWritableRange((void*)(selfValue + 0x100u), 0x81Cu) ||
        !IsReadableRange((const void*)(selfValue + 0x900u), sizeof(int) * 2))
        return;

    char displayName[13] = {};
    lstrcpynA(displayName, gLan.host, (int)sizeof(displayName));
    if (!displayName[0])
        return;

    char blob[0x800] = {};
    int count = fn43AA0(*(int*)(selfValue + 0xFCu), (int)(selfValue + 0x918u), blob, (int)sizeof(blob));
    if (count < 0)
        count = 0;

    bool alreadyPresent = false;
    char* lineCur = blob;
    while (*lineCur) {
        char* tab = strchr(lineCur, '\t');
        if (!tab)
            break;
        char saved = *tab;
        *tab = '\0';
        alreadyPresent = (_stricmp(lineCur, displayName) == 0);
        *tab = saved;
        if (alreadyPresent)
            break;
        char* nl = strchr(tab + 1, '\n');
        if (!nl)
            break;
        lineCur = nl + 1;
    }

    if (!alreadyPresent) {
        size_t curLen = strlen(blob);
        if (curLen != 0 && blob[curLen - 1] != '\n') {
            if (curLen + 1 >= sizeof(blob)) {
                if (InterlockedExchange(&gLoggedLanF3040InjectFail, 1) == 0)
                    LogLine("lan inject failed: provider blob full before newline");
                return;
            }
            blob[curLen++] = '\n';
            blob[curLen] = '\0';
        }

        char line[64] = {};
        _snprintf(line, sizeof(line) - 1, "%s\t%u|0\t\n", displayName, (unsigned)gLan.port);
        line[sizeof(line) - 1] = 0;
        size_t lineLen = strlen(line);
        if (curLen + lineLen + 1 >= sizeof(blob)) {
            if (InterlockedExchange(&gLoggedLanF3040InjectFail, 1) == 0)
                LogLine("lan inject failed: provider blob full appending host=%s", displayName);
            return;
        }
        memcpy(blob + curLen, line, lineLen + 1);
        ++count;
        LogLine("lan inject append line='%s' host=%s port=%u", line, displayName, (unsigned)gLan.port);
    }

    int oldCount = *(int*)(selfValue + 0x914u);
    if (count == oldCount && memcmp((const void*)(selfValue + 0x100u), blob, sizeof(blob)) == 0)
        return;

    memcpy((void*)(selfValue + 0x100u), blob, sizeof(blob));
    *(int*)(selfValue + 0x914u) = count;

    int* listHead = (int*)(selfValue + 0x908u);
    int* node = (int*)*listHead;
    while (node != listHead) {
        int next = *node;
        int* prev = (int*)node[1];
        *prev = next;
        *(int**)(next + 4) = prev;
        free(node);
        node = (int*)*listHead;
    }

    lineCur = blob;
    for (int idx = 0; idx < count && *lineCur; ++idx) {
        char* firstTab = strchr(lineCur, '\t');
        if (!firstTab)
            break;

        int* entry = (int*)malloc(0x24);
        if (!entry) {
            if (InterlockedExchange(&gLoggedLanF3040InjectFail, 1) == 0)
                LogLine("lan inject failed: malloc provider list entry");
            break;
        }
        ZeroMemory(entry, 0x24);

        int nameLen = (int)(firstTab - lineCur);
        if (nameLen > 12)
            nameLen = 12;
        if (nameLen > 0)
            memcpy((void*)(entry + 2), lineCur, (size_t)nameLen);
        *((char*)(entry + 2) + nameLen) = '\0';

        char* secondStart = firstTab + 1;
        char* secondTab = strchr(secondStart, '\t');
        if (!secondTab) {
            free(entry);
            break;
        }

        char fieldBuf[64] = {};
        int fieldLen = (int)(secondTab - secondStart);
        if (fieldLen >= (int)sizeof(fieldBuf))
            fieldLen = (int)sizeof(fieldBuf) - 1;
        if (fieldLen > 0)
            memcpy(fieldBuf, secondStart, (size_t)fieldLen);
        fieldBuf[fieldLen] = '\0';

        char* pipe = strchr(fieldBuf, '|');
        if (pipe) {
            *pipe = '\0';
            *(uint16_t*)(entry + 7) = (uint16_t)atoi(fieldBuf);
            entry[8] = atoi(pipe + 1);
        }

        entry[6] = fn43A50(*(int*)(selfValue + 0xFCu), (int)(selfValue + 0x918u), entry + 2);
        if (entry[6] == 0)
            entry[6] = (int)MakeLanSyntheticHandle((const char*)(entry + 2), *(uint16_t*)(entry + 7));

        int* tail = *(int**)(selfValue + 0x90Cu);
        *tail = (int)entry;
        *(int**)(selfValue + 0x90Cu) = entry;
        entry[1] = (int)tail;
        *entry = (int)listHead;

        char* nl = strchr(secondTab + 1, '\n');
        if (!nl)
            break;
        lineCur = nl + 1;
    }

    fnE8A00((int)selfValue);

    if (*(int*)(selfValue + 0x904u) != 0) {
        fn540A60(*(int*)(selfValue + 0x904u));
        *(int*)(selfValue + 0x904u) = 0;
        *(int*)(selfValue + 0x900u) = 0;
    }

    if (InterlockedExchange(&gLoggedLanF3040Inject, 1) == 0) {
        LogLine(
            "lan injected host=%s display=%s port=%u count=%d self=0x%08X",
            gLan.host,
            displayName,
            (unsigned)gLan.port,
            *(int*)(selfValue + 0x914u),
            (unsigned)selfValue);
    }
}

static void OL_FASTCALL MyLanF3040Detour(uintptr_t selfValue)
{
    typedef void (OL_THISCALL *LanF3040OrigFn)(int selfPtr);
    LanF3040OrigFn fn = (LanF3040OrigFn)gLanF3040Trampoline;
    SeedLanProviderEntry(selfValue);
    if (fn)
        fn((int)selfValue);
    HandleLanF3040(selfValue);
}

static int WSAAPI MyConnect(SOCKET s, const sockaddr* name, int namelen)
{
    if (!gRealConnect)
        return SOCKET_ERROR;
    if (name && namelen >= (int)sizeof(sockaddr_in) && name->sa_family == AF_INET) {
        const sockaddr_in* si = (const sockaddr_in*)name;
        if (IsUdpSocket(s)) {
            PeerSet(s, si);
            if (gRaceAddr.sin_family == AF_INET) {
                LogLine("udp connect redirect to race relay %s:%u", gRace.host, (unsigned)gRace.port);
                return gRealConnect(s, (const sockaddr*)&gRaceAddr, sizeof(sockaddr_in));
            }
        } else if (IsTcpSocket(s)) {
            uint16_t oldPort = ntohs(si->sin_port);
            sockaddr_in redirect = {};
            const char* epName = "";
            if (BuildTcpRedirect(si, &redirect, &epName)) {
                LogLine("tcp connect redirect %s %u -> %s:%u", epName, (unsigned)oldPort, inet_ntoa(redirect.sin_addr), (unsigned)ntohs(redirect.sin_port));
                int rr = gRealConnect(s, (const sockaddr*)&redirect, sizeof(sockaddr_in));
                LogLine("tcp connect result %s -> %s:%u rr=%d wsa=%d", epName, inet_ntoa(redirect.sin_addr), (unsigned)ntohs(redirect.sin_port), rr, rr == SOCKET_ERROR ? WSAGetLastError() : 0);
                return rr;
            }
            if (IsInterestingTcpPort(oldPort)) {
                LogLine(
                    "tcp connect passthrough %u.%u.%u.%u:%u",
                    (unsigned)((ntohl(si->sin_addr.s_addr) >> 24) & 255),
                    (unsigned)((ntohl(si->sin_addr.s_addr) >> 16) & 255),
                    (unsigned)((ntohl(si->sin_addr.s_addr) >> 8) & 255),
                    (unsigned)(ntohl(si->sin_addr.s_addr) & 255),
                    (unsigned)oldPort);
                int rr = gRealConnect(s, name, namelen);
                LogLine("tcp connect passthrough result port=%u rr=%d wsa=%d", (unsigned)oldPort, rr, rr == SOCKET_ERROR ? WSAGetLastError() : 0);
                return rr;
            }
        }
    }
    return gRealConnect(s, name, namelen);
}

static int WSAAPI MyWSAConnect(SOCKET s, const sockaddr* name, int namelen, LPWSABUF caller, LPWSABUF callee, LPQOS sqos, LPQOS gqos)
{
    if (!gRealWSAConnect)
        return SOCKET_ERROR;
    if (name && namelen >= (int)sizeof(sockaddr_in) && name->sa_family == AF_INET) {
        const sockaddr_in* si = (const sockaddr_in*)name;
        if (IsUdpSocket(s)) {
            PeerSet(s, si);
            if (gRaceAddr.sin_family == AF_INET)
                return gRealWSAConnect(s, (const sockaddr*)&gRaceAddr, sizeof(sockaddr_in), caller, callee, sqos, gqos);
        } else if (IsTcpSocket(s)) {
            uint16_t oldPort = ntohs(si->sin_port);
            sockaddr_in redirect = {};
            const char* epName = "";
            if (BuildTcpRedirect(si, &redirect, &epName)) {
                LogLine("tcp WSAConnect redirect %s %u -> %s:%u", epName, (unsigned)oldPort, inet_ntoa(redirect.sin_addr), (unsigned)ntohs(redirect.sin_port));
                int rr = gRealWSAConnect(s, (const sockaddr*)&redirect, sizeof(sockaddr_in), caller, callee, sqos, gqos);
                LogLine("tcp WSAConnect result %s -> %s:%u rr=%d wsa=%d", epName, inet_ntoa(redirect.sin_addr), (unsigned)ntohs(redirect.sin_port), rr, rr == SOCKET_ERROR ? WSAGetLastError() : 0);
                return rr;
            }
            if (IsInterestingTcpPort(oldPort)) {
                LogLine(
                    "tcp WSAConnect passthrough %u.%u.%u.%u:%u",
                    (unsigned)((ntohl(si->sin_addr.s_addr) >> 24) & 255),
                    (unsigned)((ntohl(si->sin_addr.s_addr) >> 16) & 255),
                    (unsigned)((ntohl(si->sin_addr.s_addr) >> 8) & 255),
                    (unsigned)(ntohl(si->sin_addr.s_addr) & 255),
                    (unsigned)oldPort);
                int rr = gRealWSAConnect(s, name, namelen, caller, callee, sqos, gqos);
                LogLine("tcp WSAConnect passthrough result port=%u rr=%d wsa=%d", (unsigned)oldPort, rr, rr == SOCKET_ERROR ? WSAGetLastError() : 0);
                return rr;
            }
        }
    }
    return gRealWSAConnect(s, name, namelen, caller, callee, sqos, gqos);
}

static int WSAAPI MySendTo(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    if (!gRealSendTo)
        return SOCKET_ERROR;
    if (!IsUdpSocket(s) || !buf || len <= 0)
        return gRealSendTo(s, buf, len, flags, to, tolen);

    sockaddr_in peer = {};
    if (to && tolen >= (int)sizeof(sockaddr_in) && to->sa_family == AF_INET) {
        peer = *(const sockaddr_in*)to;
    } else if (!PeerGet(s, &peer)) {
        int plen = sizeof(peer);
        if (getpeername(s, (sockaddr*)&peer, &plen) != 0 || peer.sin_family != AF_INET)
            return gRealSendTo(s, buf, len, flags, to, tolen);
    }

    if (peer.sin_addr.s_addr == gRaceAddr.sin_addr.s_addr && peer.sin_port == gRaceAddr.sin_port) {
        sockaddr_in cached = {};
        if (PeerGet(s, &cached))
            peer = cached;
        else
            return gRealSendTo(s, buf, len, flags, (const sockaddr*)&gRaceAddr, sizeof(sockaddr_in));
    }
    return WrappedSendTo(s, buf, len, flags, &peer);
}

static int WSAAPI MySend(SOCKET s, const char* buf, int len, int flags)
{
    if (!gRealSend)
        return SOCKET_ERROR;
    if (!IsUdpSocket(s) || !buf || len <= 0)
        return gRealSend(s, buf, len, flags);
    sockaddr_in peer = {};
    if (!PeerGet(s, &peer))
        return gRealSend(s, buf, len, flags);
    return WrappedSendTo(s, buf, len, flags, &peer);
}

static int WSAAPI MyRecvFrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
    if (!gRealRecvFrom)
        return SOCKET_ERROR;
    int r = gRealRecvFrom(s, buf, len, flags, from, fromlen);
    if (r > 0 && !IsUdpSocket(s))
        MaybeConsumeAdvertisedEndpointsForSocket(s, buf, r, "recvfrom-tcp");
    if (r > 0 && IsUdpSocket(s))
        r = DecodeRecv(s, buf, r, from, fromlen);
    return r;
}

static int WSAAPI MyRecv(SOCKET s, char* buf, int len, int flags)
{
    if (!gRealRecv)
        return SOCKET_ERROR;
    int r = gRealRecv(s, buf, len, flags);
    if (r > 0 && !IsUdpSocket(s))
        MaybeConsumeAdvertisedEndpointsForSocket(s, buf, r, "recv-tcp");
    if (r > 0 && IsUdpSocket(s)) {
        sockaddr_in relay = gRaceAddr;
        int fl = sizeof(relay);
        r = DecodeRecv(s, buf, r, (sockaddr*)&relay, &fl);
    }
    return r;
}

static int WSAAPI MyCloseSocket(SOCKET s)
{
    PeerClear(s);
    return gRealCloseSocket ? gRealCloseSocket(s) : SOCKET_ERROR;
}

static int WSAAPI MyWSASendTo(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD flags, const sockaddr* to, int tolen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
{
    if (!gRealWSASendTo)
        return SOCKET_ERROR;
    if (ov || comp || count != 1 || !bufs || !bufs[0].buf)
        return gRealWSASendTo(s, bufs, count, sent, flags, to, tolen, ov, comp);
    int r = MySendTo(s, bufs[0].buf, (int)bufs[0].len, (int)flags, to, tolen);
    if (r == SOCKET_ERROR)
        return SOCKET_ERROR;
    if (sent) *sent = (DWORD)r;
    return 0;
}

static int WSAAPI MyWSASend(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
{
    if (!gRealWSASend)
        return SOCKET_ERROR;
    if (ov || comp || count != 1 || !bufs || !bufs[0].buf)
        return gRealWSASend(s, bufs, count, sent, flags, ov, comp);
    int r = MySend(s, bufs[0].buf, (int)bufs[0].len, (int)flags);
    if (r == SOCKET_ERROR)
        return SOCKET_ERROR;
    if (sent) *sent = (DWORD)r;
    return 0;
}

static int WSAAPI MyWSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD recvd, LPDWORD flags, sockaddr* from, LPINT fromlen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
{
    if (!gRealWSARecvFrom)
        return SOCKET_ERROR;
    int r = gRealWSARecvFrom(s, bufs, count, recvd, flags, from, fromlen, ov, comp);
    if (r == 0 && recvd && *recvd > 0 && count == 1 && bufs && bufs[0].buf) {
        if (!IsUdpSocket(s))
            MaybeConsumeAdvertisedEndpointsForSocket(s, bufs[0].buf, (int)*recvd, "wsarecvfrom-tcp");
        else {
            int got = (int)*recvd;
            got = DecodeRecv(s, bufs[0].buf, got, from, fromlen);
            *recvd = (DWORD)got;
        }
    }
    return r;
}

static int WSAAPI MyWSARecv(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD recvd, LPDWORD flags, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
{
    if (!gRealWSARecv)
        return SOCKET_ERROR;
    int r = gRealWSARecv(s, bufs, count, recvd, flags, ov, comp);
    if (r == 0 && recvd && *recvd > 0 && count == 1 && bufs && bufs[0].buf) {
        if (!IsUdpSocket(s))
            MaybeConsumeAdvertisedEndpointsForSocket(s, bufs[0].buf, (int)*recvd, "wsarecv-tcp");
        else {
            sockaddr_in relay = gRaceAddr;
            int fl = sizeof(relay);
            int got = DecodeRecv(s, bufs[0].buf, (int)*recvd, (sockaddr*)&relay, &fl);
            *recvd = (DWORD)got;
        }
    }
    return r;
}

static FARPROC WINAPI MyGetProcAddress(HMODULE mod, LPCSTR name)
{
    FARPROC p = gRealGetProcAddress ? gRealGetProcAddress(mod, name) : nullptr;
    if (!name || (((uintptr_t)name) >> 16) == 0) {
        WORD ord = (WORD)(uintptr_t)name;
        if (ord == 3) return (FARPROC)MyCloseSocket;
        if (ord == 4) return (FARPROC)MyConnect;
        if (ord == 16) return (FARPROC)MyRecv;
        if (ord == 17) return (FARPROC)MyRecvFrom;
        if (ord == 19) return (FARPROC)MySend;
        if (ord == 20) return (FARPROC)MySendTo;
        return p;
    }
    if (NameEq(name, "closesocket")) return (FARPROC)MyCloseSocket;
    if (NameEq(name, "connect")) return (FARPROC)MyConnect;
    if (NameEq(name, "WSAConnect")) return (FARPROC)MyWSAConnect;
    if (NameEq(name, "sendto")) return (FARPROC)MySendTo;
    if (NameEq(name, "recvfrom")) return (FARPROC)MyRecvFrom;
    if (NameEq(name, "send")) return (FARPROC)MySend;
    if (NameEq(name, "recv")) return (FARPROC)MyRecv;
    if (NameEq(name, "WSASendTo")) return (FARPROC)MyWSASendTo;
    if (NameEq(name, "WSARecvFrom")) return (FARPROC)MyWSARecvFrom;
    if (NameEq(name, "WSASend")) return (FARPROC)MyWSASend;
    if (NameEq(name, "WSARecv")) return (FARPROC)MyWSARecv;
    return p;
}

static bool PatchThunk(uintptr_t* slot, void* mine, void** oldOut)
{
    if (!slot || !mine)
        return false;
    void* cur = (void*)(uintptr_t)*slot;
    if (cur == mine)
        return false;
    DWORD oldProt = 0;
    if (!VirtualProtect(slot, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProt))
        return false;
    if (oldOut && !*oldOut)
        *oldOut = cur;
    *slot = (uintptr_t)mine;
    DWORD tmp = 0;
    VirtualProtect(slot, sizeof(uintptr_t), oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(uintptr_t));
    return true;
}

static bool HookIAT(HMODULE module, const char* dll, const char* name, WORD ordinal, void* mine, void** oldOut)
{
    if (!module || !dll || !mine)
        return false;
    uint8_t* base = (uint8_t*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress)
        return false;
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
    bool hit = false;
    for (; imp->Name; ++imp) {
        const char* modName = (const char*)(base + imp->Name);
        if (!modName || lstrcmpiA(modName, dll) != 0)
            continue;
        IMAGE_THUNK_DATA* first = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        IMAGE_THUNK_DATA* orig = imp->OriginalFirstThunk ? (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk) : first;
        for (; orig->u1.AddressOfData; ++orig, ++first) {
            bool match = false;
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                match = ordinal != 0 && (WORD)(orig->u1.Ordinal & 0xFFFF) == ordinal;
            } else if (name) {
                IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
                match = ibn && lstrcmpiA((const char*)ibn->Name, name) == 0;
            }
            if (match)
                hit = PatchThunk((uintptr_t*)&first->u1.Function, mine, oldOut) || hit;
        }
    }
    return hit;
}

static size_t ModRMExtraLen(const uint8_t* p, size_t maxLen, uint8_t modrm)
{
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t rm = modrm & 7;
    size_t extra = 0;
    if (mod != 3 && rm == 4) {
        if (maxLen < 1)
            return 0;
        uint8_t sib = p[0];
        extra += 1;
        if (mod == 0 && (sib & 7) == 5)
            extra += 4;
    }
    if (mod == 0) {
        if (rm == 5)
            extra += 4;
    } else if (mod == 1) {
        extra += 1;
    } else if (mod == 2) {
        extra += 4;
    }
    return extra;
}

static size_t InstrLen32(const uint8_t* p, size_t maxLen, bool* outHasRel)
{
    if (outHasRel)
        *outHasRel = false;
    if (!p || maxLen == 0)
        return 0;

    size_t i = 0;
    for (;;) {
        if (i >= maxLen)
            return 0;
        uint8_t b = p[i];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67) {
            ++i;
            continue;
        }
        break;
    }

    if (i >= maxLen)
        return 0;
    uint8_t op = p[i++];

    if (op == 0x55 || op == 0x53 || op == 0x56 || op == 0x57 ||
        op == 0x50 || op == 0x51 || op == 0x52 ||
        op == 0x5D || op == 0x5B || op == 0x5E || op == 0x5F ||
        op == 0x90 || op == 0xC3 || op == 0xCC)
        return i;

    if (op == 0x6A)
        return (i + 1 <= maxLen) ? i + 1 : 0;
    if (op == 0x68)
        return (i + 4 <= maxLen) ? i + 4 : 0;
    if (op == 0xC2)
        return (i + 2 <= maxLen) ? i + 2 : 0;

    if (op == 0xE8 || op == 0xE9) {
        if (outHasRel)
            *outHasRel = true;
        return (i + 4 <= maxLen) ? i + 4 : 0;
    }
    if (op == 0xEB || (op >= 0x70 && op <= 0x7F)) {
        if (outHasRel)
            *outHasRel = true;
        return (i + 1 <= maxLen) ? i + 1 : 0;
    }

    if (op == 0x0F) {
        if (i >= maxLen)
            return 0;
        uint8_t op2 = p[i++];
        if (op2 >= 0x80 && op2 <= 0x8F) {
            if (outHasRel)
                *outHasRel = true;
            return (i + 4 <= maxLen) ? i + 4 : 0;
        }
        if (i >= maxLen)
            return 0;
        uint8_t modrm = p[i++];
        size_t extra = ModRMExtraLen(p + i, maxLen - i, modrm);
        return (i + extra <= maxLen) ? i + extra : 0;
    }

    bool hasModRM = false;
    size_t imm = 0;
    switch (op) {
        case 0x8B:
        case 0x89:
        case 0x8D:
        case 0x85:
        case 0x84:
        case 0x33:
        case 0x31:
        case 0xFF:
        case 0xF7:
        case 0xC7:
            hasModRM = true;
            break;
        case 0x83:
            hasModRM = true;
            imm = 1;
            break;
        case 0x81:
            hasModRM = true;
            imm = 4;
            break;
        default:
            return 0;
    }

    if (!hasModRM || i >= maxLen)
        return 0;
    uint8_t modrm = p[i++];
    size_t extra = ModRMExtraLen(p + i, maxLen - i, modrm);
    return (i + extra + imm <= maxLen) ? i + extra + imm : 0;
}

static bool Detour32(void* target, void* detour, void** outTrampoline)
{
    if (!target || !detour || !outTrampoline)
        return false;
    uint8_t* t = (uint8_t*)target;
    if (t[0] == 0xE9)
        return false;

    size_t copied = 0;
    while (copied < 5) {
        bool hasRel = false;
        size_t len = InstrLen32(t + copied, 32 - copied, &hasRel);
        if (len == 0 || hasRel)
            return false;
        copied += len;
        if (copied > 32)
            return false;
    }

    uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, copied + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp)
        return false;
    memcpy(tramp, t, copied);
    tramp[copied] = 0xE9;
    *(int32_t*)(tramp + copied + 1) = (int32_t)((t + copied) - (tramp + copied + 5));

    DWORD oldProt = 0;
    if (!VirtualProtect(t, copied, PAGE_EXECUTE_READWRITE, &oldProt)) {
        VirtualFree(tramp, 0, MEM_RELEASE);
        return false;
    }
    t[0] = 0xE9;
    *(int32_t*)(t + 1) = (int32_t)((uint8_t*)detour - (t + 5));
    for (size_t i = 5; i < copied; ++i)
        t[i] = 0x90;
    DWORD tmp = 0;
    VirtualProtect(t, copied, oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), t, copied);

    *outTrampoline = tramp;
    return true;
}

static bool InstallLanInjectionDetour()
{
    if (!LanInjectionReady())
        return false;
    if (InterlockedCompareExchange(&gLanF3040Installed, 1, 0) != 0)
        return true;

    uint8_t* base = (uint8_t*)GetModuleHandleA(nullptr);
    if (!base) {
        InterlockedExchange(&gLanF3040Installed, 0);
        return false;
    }

    void* target = base + 0x000F3040u;
    void* tramp = nullptr;
    if (!Detour32(target, (void*)MyLanF3040Detour, &tramp)) {
        InterlockedExchange(&gLanF3040Installed, 0);
        LogLine("lan inject detour failed: LAN_F3040 target=%p", target);
        return false;
    }

    gLanF3040Trampoline = tramp;
    LogLine("lan inject detour installed: LAN_F3040 target=%p tramp=%p", target, tramp);
    return true;
}

static void ResolveRealFns()
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    gRealGetProcAddress = k32 ? (GetProcAddressFn)GetProcAddress(k32, "GetProcAddress") : nullptr;
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2)
        ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2)
        return;
    gRealConnect = (ConnectFn)GetProcAddress(ws2, "connect");
    gRealSendTo = (SendToFn)GetProcAddress(ws2, "sendto");
    gRealRecvFrom = (RecvFromFn)GetProcAddress(ws2, "recvfrom");
    gRealSend = (SendFn)GetProcAddress(ws2, "send");
    gRealRecv = (RecvFn)GetProcAddress(ws2, "recv");
    gRealCloseSocket = (CloseSocketFn)GetProcAddress(ws2, "closesocket");
    gRealWSAConnect = (WSAConnectFn)GetProcAddress(ws2, "WSAConnect");
    gRealWSASendTo = (WSASendToFn)GetProcAddress(ws2, "WSASendTo");
    gRealWSARecvFrom = (WSARecvFromFn)GetProcAddress(ws2, "WSARecvFrom");
    gRealWSASend = (WSASendFn)GetProcAddress(ws2, "WSASend");
    gRealWSARecv = (WSARecvFn)GetProcAddress(ws2, "WSARecv");
}

static void HookModule(HMODULE mod)
{
    HookIAT(mod, "ws2_32.dll", "closesocket", 3, (void*)MyCloseSocket, (void**)&gRealCloseSocket);
    HookIAT(mod, "wsock32.dll", "closesocket", 3, (void*)MyCloseSocket, (void**)&gRealCloseSocket);
    HookIAT(mod, "ws2_32.dll", "connect", 4, (void*)MyConnect, (void**)&gRealConnect);
    HookIAT(mod, "wsock32.dll", "connect", 4, (void*)MyConnect, (void**)&gRealConnect);
    HookIAT(mod, "ws2_32.dll", "recv", 16, (void*)MyRecv, (void**)&gRealRecv);
    HookIAT(mod, "wsock32.dll", "recv", 16, (void*)MyRecv, (void**)&gRealRecv);
    HookIAT(mod, "ws2_32.dll", "recvfrom", 17, (void*)MyRecvFrom, (void**)&gRealRecvFrom);
    HookIAT(mod, "wsock32.dll", "recvfrom", 17, (void*)MyRecvFrom, (void**)&gRealRecvFrom);
    HookIAT(mod, "ws2_32.dll", "send", 19, (void*)MySend, (void**)&gRealSend);
    HookIAT(mod, "wsock32.dll", "send", 19, (void*)MySend, (void**)&gRealSend);
    HookIAT(mod, "ws2_32.dll", "sendto", 20, (void*)MySendTo, (void**)&gRealSendTo);
    HookIAT(mod, "wsock32.dll", "sendto", 20, (void*)MySendTo, (void**)&gRealSendTo);
    HookIAT(mod, "ws2_32.dll", "WSAConnect", 0, (void*)MyWSAConnect, (void**)&gRealWSAConnect);
    HookIAT(mod, "ws2_32.dll", "WSASendTo", 0, (void*)MyWSASendTo, (void**)&gRealWSASendTo);
    HookIAT(mod, "ws2_32.dll", "WSARecvFrom", 0, (void*)MyWSARecvFrom, (void**)&gRealWSARecvFrom);
    HookIAT(mod, "ws2_32.dll", "WSASend", 0, (void*)MyWSASend, (void**)&gRealWSASend);
    HookIAT(mod, "ws2_32.dll", "WSARecv", 0, (void*)MyWSARecv, (void**)&gRealWSARecv);
    HookIAT(mod, "kernel32.dll", "GetProcAddress", 0, (void*)MyGetProcAddress, (void**)&gRealGetProcAddress);
    HookIAT(mod, "kernelbase.dll", "GetProcAddress", 0, (void*)MyGetProcAddress, (void**)&gRealGetProcAddress);
}

static void HookAllModules()
{
    DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        HookModule(GetModuleHandleA(nullptr));
        return;
    }
    MODULEENTRY32 me = {};
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            if ((HMODULE)me.hModule != gSelf)
                HookModule((HMODULE)me.hModule);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
}

static DWORD WINAPI MainThread(LPVOID)
{
    WSADATA wsa = {};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    if (!gPeerLockReady) {
        InitializeCriticalSection(&gPeerLock);
        gPeerLockReady = true;
        for (int i = 0; i < 64; ++i)
            gPeers[i].s = INVALID_SOCKET;
    }

    LoadConfig();
    RefreshAddrs();
    if (InterlockedExchange(&gLoggedStart, 1) == 0) {
        LogLine(
            "online start bootstrap=%s:%u lobby=%s:%u control=%s:%u alias=%s:%u race=%s:%u lan_override=%ld lan=%s:%u",
            gBootstrap.host, (unsigned)gBootstrap.port,
            gLobby.host, (unsigned)gLobby.port,
            gControl.host, (unsigned)gControl.port,
            gControlAlias.host, (unsigned)gControlAlias.port,
            gRace.host, (unsigned)gRace.port,
            (long)InterlockedCompareExchange(&gLanOverrideEnabled, 0, 0),
            gLan.host, (unsigned)gLan.port);
    }
    ApplyBasePatches();
    InstallLanInjectionDetour();

    ResolveRealFns();
    for (int i = 0; i < 200; ++i) {
        HookAllModules();
        InterlockedExchange(&gHooksInstalled, 1);
        Sleep(100);
    }
    for (;;) {
        HookAllModules();
        Sleep(1000);
    }
}

extern "C" __declspec(dllexport) void InitializeASI()
{
    HANDLE h = CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        gSelf = hinst;
        DisableThreadLibraryCalls(hinst);
        char path[MAX_PATH] = {};
        if (GetModuleFileNameA(gSelf, path, MAX_PATH)) {
            for (int i = (int)strlen(path) - 1; i >= 0; --i) {
                if (path[i] == '\\' || path[i] == '/') {
                    path[i + 1] = 0;
                    break;
                }
            }
            lstrcpynA(gLogPath, path, sizeof(gLogPath));
            lstrcatA(gLogPath, "ONLINE.LOG");
        }
        InitializeASI();
    } else if (reason == DLL_PROCESS_DETACH) {
        if (gPeerLockReady) {
            DeleteCriticalSection(&gPeerLock);
            gPeerLockReady = false;
        }
    }
    return TRUE;
}
