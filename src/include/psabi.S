/* RISC-V psABI register name aliases (per ADR-0001).
 *
 * Included by every assembly file via `.include "psabi.S"`. Provides the
 * symbolic register names (sp, ra, a0, ...) so source uses ABI names
 * uniformly rather than mixing in raw `xN` numbers. The Espressif and
 * vanilla GNU assemblers both accept `sp`, `ra`, etc. natively, but
 * declaring them here makes the ABI dependency explicit and gives us a
 * single point to add new aliases (e.g., callee-save grouping macros)
 * later without touching every source file.
 *
 * No instructions; all directives.
 */

/* zero is x0 — hard-wired to 0; redeclaring keeps the alias visible to
   tools that look at this file in isolation. */
        .equ zero, 0
        .equ ra,   1   /* return address                       */
        .equ sp,   2   /* stack pointer                        */
        .equ gp,   3   /* global pointer                       */
        .equ tp,   4   /* thread pointer; reserved on no-OS    */
        .equ t0,   5
        .equ t1,   6
        .equ t2,   7
        .equ s0,   8   /* saved register / frame pointer       */
        .equ fp,   8   /* alias                                */
        .equ s1,   9
        .equ a0,  10
        .equ a1,  11
        .equ a2,  12
        .equ a3,  13
        .equ a4,  14
        .equ a5,  15
        .equ a6,  16
        .equ a7,  17
        .equ s2,  18
        .equ s3,  19
        .equ s4,  20
        .equ s5,  21
        .equ s6,  22
        .equ s7,  23
        .equ s8,  24
        .equ s9,  25
        .equ s10, 26
        .equ s11, 27
        .equ t3,  28
        .equ t4,  29
        .equ t5,  30
        .equ t6,  31
