/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
 * Copyright (c) 2008-2009 VMware, Inc.  All rights reserved.
 * ********************************************************** */

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _ASM_DEFINES_ASM_
#define _ASM_DEFINES_ASM_ 1

/* Preprocessor macro definitions shared among all .asm files.
 * Since cpp macros can't generate newlines we have a later
 * script replace @N@ for us.
 */

#include "configure.h"

#if defined(X86_64) && !defined(X64)
# define X64
#endif

/****************************************************/
#if defined(ASSEMBLE_WITH_GAS)   /* SJF Assume assembling with gas. Def not masm as arm ignore nasm for now. */ 
# define START_FILE .text
# define END_FILE /* nothing */
# define DECLARE_FUNC(symbol) \
.align 0 @N@\
.global symbol @N@\
.hidden symbol @N@\
.type symbol, %function
# define DECLARE_EXPORTED_FUNC(symbol) \
.align 0 @N@\
.global symbol @N@\
.type symbol, %function
# define END_FUNC(symbol) /* nothing */
# define DECLARE_GLOBAL(symbol) \
.global symbol @N@\
.hidden symbol
# define GLOBAL_LABEL(label) label
# define ADDRTAKEN_LABEL(label) label
# define BYTE byte ptr
# define WORD word ptr
# define DWORD dword ptr
# define QWORD qword ptr
# ifdef X64
/* w/o the rip, gas won't use rip-rel and adds relocs that ld trips over */
#  define SYMREF(sym) [rip + sym]
# else
#  define SYMREF(sym) [sym]
# endif
# define HEX(n) 0x##n
# define SEGMEM(seg,mem) [seg:mem]
# define DECL_EXTERN(symbol) /* nothing */
/* include newline so we can put multiple on one line */
# define RAW(n) .byte HEX(n) @N@
# define DECLARE_FUNC_SEH(symbol) DECLARE_FUNC(symbol)
# define PUSH_SEH(reg) push reg
# define PUSH_NONCALLEE_SEH(reg) push reg
# define END_PROLOG /* nothing */
/* PR 212290: avoid text relocations.
 * @GOT returns the address and is for extern vars; @GOTOFF gets the value.
 * Note that using ## to paste => 
 *   "error: pasting "initstack_mutex" and "@" does not give a valid preprocessing token"
 * but whitespace separation seems fine.
 */
# define ADDR_VIA_GOT(base, sym) [sym @GOT + base]
# define VAR_VIA_GOT(base, sym) [sym @GOTOFF + base]
/****************************************************/
#else
# error Unknown assembler: set one of the ASSEMBLE_WITH_{GAS,MASM,NASM} defines
#endif

/****************************************************/
#ifdef ARM

# define REG_R0 r0 
# define REG_R1 r1
# define REG_R2 r2
# define REG_R3 r3
# define REG_R4 r4
# define REG_R5 r5
# define REG_R6 r6
# define REG_R7 r7
# define REG_R8 r8
# define REG_R9 r9
# define REG_R10 r10
# define REG_R11 r11 
# define REG_R12 r12
# define REG_R13 r13
# define REG_R14 r14
# define REG_R15 r15

# define SEG_TLS fs /* keep in sync w/ {linux,win32}/os_exports.h defines */
# define ARG_SZ 4
# define PTRSZ DWORD

/* Arguments are passed on stack right-to-left. */
# define ARG1 REG_R0
# define ARG2 REG_R1
# define ARG3 REG_R2
# define ARG4 REG_R3
# define ARG5 DWORD [4 + r13]
# define ARG6 DWORD [8 + r13]
# define ARG7 DWORD [12 + r13]
#endif

/* Keep in sync with arch_exports.h. */
#define FRAME_ALIGNMENT 16

/* From globals_shared.h, but we can't include that into asm code. */
# define IF_X64(x)
# define IF_X64_ELSE(x, y) y
# define IF_NOT_X64(x) x

#  define STACK_PAD(tot, gt4) /* nothing */
#  define STACK_UNPAD(tot, gt4) \
        mov    REG_R5, tot \
        mov    REG_R6, ARG_SZ \
        mul    REG_R6, REG_R5, REG_R6 \ 
        add    REG_R13, REG_R6 

#  define STACK_PAD_LE4 /* nothing */
#  define STACK_UNPAD_LE4(tot) STACK_UNPAD(tot, 0)
/* ARM defines a different calling convention from x86. 
   Args 1-4 are stored in regsiters 0-3 and then evrything else is pushed onto the stack.
 */
#  define SETARGREG(argreg, p) \
       mov     argreg, p

#  define SETARGSTACK(argreg, p) \
       str     p,  [REG_R13]!


/* CALLC* are for C calling convention callees only.
 * Caller must ensure that if params are passed in regs there are no conflicts.
 * Caller can rely on us storing each parameter in reverse order.
 *
 * SJF: ARM changes
 * ARM wants args passed in registers 0-3 and then on the stack.
 */
#define CALLC0(callee)     \
        STACK_PAD_LE4   @N@\
        call     callee @N@\
        STACK_UNPAD_LE4(0)
#define CALLC1(callee, p1)    \
        STACK_PAD_LE4      @N@\
        SETARGREG(ARG1, p1)   @N@\
        call     callee    @N@\
        STACK_UNPAD_LE4(0)
#define CALLC2(callee, p1, p2)    \
        STACK_PAD_LE4          @N@\
        SETARGREG(ARG2, p2)       @N@\
        SETARGREG(ARG1, p1)       @N@\
        call     callee        @N@\
        STACK_UNPAD_LE4(0)
#define CALLC3(callee, p1, p2, p3)    \
        STACK_PAD_LE4              @N@\
        SETARGREG(ARG3, p3)           @N@\
        SETARGREG(ARG2, p2)           @N@\
        SETARGREG(ARG1, p1)           @N@\
        call     callee            @N@\
        STACK_UNPAD_LE4(0)
#define CALLC4(callee, p1, p2, p3, p4)    \
        STACK_PAD_LE4                  @N@\
        SETARGREG(ARG4, p4)               @N@\
        SETARGREG(ARG3, p3)               @N@\
        SETARGREG(ARG2, p2)               @N@\
        SETARGREG(ARG1, p1)               @N@\
        call     callee                @N@\
        STACK_UNPAD_LE4(0)
#define CALLC5(callee, p1, p2, p3, p4, p5)    \
        STACK_PAD(5, 1)                    @N@\
        SETARGSTACK(ARG5_NORETADDR, p5)         @N@\
        SETARGREG(ARG4, p4)                   @N@\
        SETARGREG(ARG3, p3)                   @N@\
        SETARGREG(ARG2, p2)                   @N@\
        SETARGREG(ARG1, p1)                   @N@\
        call     callee                    @N@\
        STACK_UNPAD_LE4(1)
#define CALLC6(callee, p1, p2, p3, p4, p5, p6)\
        STACK_PAD(6, 2)                    @N@\
        SETARGSTACK(ARG6_NORETADDR, p6)         @N@\
        SETARGSTACK(ARG5_NORETADDR, p5)         @N@\
        SETARGREG(ARG4, p4)                   @N@\
        SETARGREG(ARG3, p3)                   @N@\
        SETARGREG(ARG2, p2)                   @N@\
        SETARGREG(ARG1, p1)                   @N@\
        call     callee                    @N@\
        STACK_UNPAD_LE4(2)

/* For stdcall callees */
/* TODO Need??? */
# define CALLWIN0(callee)     \
        STACK_PAD_LE4   @N@\
        call     callee
# define CALLWIN1(callee, p1)    \
        STACK_PAD_LE4      @N@\
        SETARG(ARG1, p1)   @N@\
        call     callee
# define CALLWIN2(callee, p1, p2)    \
        STACK_PAD_LE4          @N@\
        SETARG(ARG2, p2)       @N@\
        SETARG(ARG1, p1)       @N@\
        call     callee


#endif /* _ASM_DEFINES_ASM_ */
