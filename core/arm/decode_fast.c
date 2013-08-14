/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
 * Copyright (c) 2001-2010 VMware, Inc.  All rights reserved.
 * **********************************************************/

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

/* Copyright (c) 2003-2007 Determina Corp. */
/* Copyright (c) 2001-2003 Massachusetts Institute of Technology */
/* Copyright (c) 2001 Hewlett-Packard Company */

/* decode_fast.c -- a partial but fast x86 decoder */

#include "../globals.h"
#include "decode_fast.h"
#include "../link.h"
#include "arch.h"
#include "instr.h"
#include "instr_create.h"
#include "decode.h"
#include "disassemble.h"

#ifdef DEBUG
/* case 10450: give messages to clients */
# undef ASSERT_TRUNCATE
# undef ASSERT_BITFIELD_TRUNCATE
# undef ASSERT_NOT_REACHED
# define ASSERT_TRUNCATE DO_NOT_USE_ASSERT_USE_CLIENT_ASSERT_INSTEAD
# define ASSERT_BITFIELD_TRUNCATE DO_NOT_USE_ASSERT_USE_CLIENT_ASSERT_INSTEAD
# define ASSERT_NOT_REACHED DO_NOT_USE_ASSERT_USE_CLIENT_ASSERT_INSTEAD
#endif

/* This file contains tables and functions that help decode x86
   instructions so that we can determine the length of the decode
   instruction.  All code below based on tables in the ``Intel
   Architecture Software Developer's Manual,'' Volume 2: Instruction
   Set Reference, 1999. 
   This decoder assumes that we are running in 32-bit, flat-address mode.  
*/

/* NOTE that all of the tables in this file are indexed by the (primary
   or secondary) opcode byte.  The upper opcode nibble defines the rows,
   starting with 0 at the top.  The lower opcode nibble defines the
   columns, starting with 0 at left. */

/* Data table for fixed part of an x86 instruction.  The table is
   indexed by the 1st (primary) opcode byte.  Zero entries are
   reserved opcodes. */
static const byte fixed_length[256] = {
    1,1,1,1, 2,5,1,1, 1,1,1,1, 2,5,1,1,  /* 0 */
    1,1,1,1, 2,5,1,1, 1,1,1,1, 2,5,1,1,  /* 1 */
    1,1,1,1, 2,5,1,1, 1,1,1,1, 2,5,1,1,  /* 2 */
    1,1,1,1, 2,5,1,1, 1,1,1,1, 2,5,1,1,  /* 3 */
                                                
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* 4 */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* 5 */
    1,1,1,1, 1,1,1,1, 5,5,2,2, 1,1,1,1,  /* 6 */
    2,2,2,2, 2,2,2,2, 2,2,2,2, 2,2,2,2,  /* 7 */
                                                
    2,5,2,2, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* 8 */
    1,1,1,1, 1,1,1,1, 1,1,7,1, 1,1,1,1,  /* 9 */
    5,5,5,5, 1,1,1,1, 2,5,1,1, 1,1,1,1,  /* A */
    2,2,2,2, 2,2,2,2, 5,5,5,5, 5,5,5,5,  /* B */
                                                
    2,2,3,1, 1,1,2,5, 4,1,3,1, 1,2,1,1,  /* C */
    1,1,1,1, 2,2,1,1, 1,1,1,1, 1,1,1,1,  /* D */
    2,2,2,2, 2,2,2,2, 5,5,7,2, 1,1,1,1,  /* E */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1   /* F */
    /* f6 and f7 OP_test immeds are handled specially in decode_sizeof() */
};

/* Data table for fixed immediate part of an x86 instruction that
   depends upon the existence of an operand-size byte.  The table is
   indexed by the 1st (primary) opcode byte.  Entries with non-zero
   values indicate opcodes with a variable-length immediate field.  We
   use this table if we've seen a operand-size prefix byte to adjust
   the fixed_length from dword to word. 
 */
static const signed char immed_adjustment[256] = {
     0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  /* 0 */
     0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  /* 1 */
     0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  /* 2 */
     0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  /* 3 */
                                                                
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
     0, 0, 0, 0,  0, 0, 0, 0, -2,-2, 0, 0,  0, 0, 0, 0,  /* 6 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */
                                                                
     0,-2, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0,-2, 0,  0, 0, 0, 0,  /* 9 */
     0, 0, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  /* A */
     0, 0, 0, 0,  0, 0, 0, 0, -2,-2,-2,-2, -2,-2,-2,-2,  /* B */
                                                                
     0, 0, 0, 0,  0, 0, 0,-2,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
     0, 0, 0, 0,  0, 0, 0, 0, -2,-2,-2,-2,  0, 0, 0, 0,  /* E */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0   /* F */
};

#ifdef X64
/* for x64 Intel, Jz is always a 64-bit addr ("f64" in Intel table) */
static const signed char immed_adjustment_intel64[256] = {
     0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  /* 0 */
     0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  /* 1 */
     0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  /* 2 */
     0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  /* 3 */
                                                                
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
     0, 0, 0, 0,  0, 0, 0, 0, -2,-2, 0, 0,  0, 0, 0, 0,  /* 6 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */
                                                                
     0,-2, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0,-2, 0,  0, 0, 0, 0,  /* 9 */
     0, 0, 0, 0,  0, 0, 0, 0,  0,-2, 0, 0,  0, 0, 0, 0,  /* A */
     0, 0, 0, 0,  0, 0, 0, 0, -2,-2,-2,-2, -2,-2,-2,-2,  /* B */
                                                                
     0, 0, 0, 0,  0, 0, 0,-2,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0,-2,-2,  0, 0, 0, 0,  /* E */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0   /* F */
};
#endif

/* Data table for fixed immediate part of an x86 instruction that
 * depends upon the existence of an address-size byte.  The table is
 * indexed by the 1st (primary) opcode byte.
 * The value here is doubled for x64 mode.
 */
static const signed char disp_adjustment[256] = {
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 0 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */
                                                                
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */
                                                                
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    -2,-2,-2,-2,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */
                                                                
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0   /* F */
};

#ifdef X64
/* Data table for immediate adjustments that only apply when
 * in x64 mode.  We fit two types of adjustments in here:
 * default-size adjustments (positive numbers) and rex.w-prefix-based
 * adjustments (negative numbers, to be made positive when applied).
 */
static const char x64_adjustment[256] = {
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 0 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */
                                                                
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */
                                                                
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
     4, 4, 4, 4,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
     0, 0, 0, 0,  0, 0, 0, 0, -4,-4,-4,-4, -4,-4,-4,-4,  /* B */
                                                                
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
     0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0   /* F */
};
#endif

/* Prototypes for the functions that calculate the variable
 * part of the x86 instruction length. */
static int sizeof_modrm(dcontext_t *dcontext, byte *pc, bool addr16
                        _IF_X64(byte **rip_rel_pc));
static int sizeof_fp_op(dcontext_t *dcontext, byte *pc, bool addr16
                        _IF_X64(byte **rip_rel_pc));
static int sizeof_escape(dcontext_t *dcontext, byte *pc, bool addr16
                         _IF_X64(byte **rip_rel_pc));
static int sizeof_3byte_38(dcontext_t *dcontext, byte *pc, bool addr16, bool vex
                           _IF_X64(byte **rip_rel_pc));
static int sizeof_3byte_3a(dcontext_t *dcontext, byte *pc, bool addr16
                           _IF_X64(byte **rip_rel_pc));

enum {
    VARLEN_NONE,
    VARLEN_MODRM,
    VARLEN_FP_OP,
    VARLEN_ESCAPE, /* 2-byte opcodes */
    VARLEN_3BYTE_38_ESCAPE, /* 3-byte opcodes 0f 38 */
    VARLEN_3BYTE_3A_ESCAPE, /* 3-byte opcodes 0f 3a */
};

/* Some macros to make the following table look better. */
#define m VARLEN_MODRM
#define f VARLEN_FP_OP
#define e VARLEN_ESCAPE

/* Data table indicating what function to use to calculate
   the variable part of the x86 instruction.  This table
   is indexed by the primary opcode.  */
static const byte variable_length[256] = {
    m,m,m,m, 0,0,0,0, m,m,m,m, 0,0,0,e,   /* 0 */
    m,m,m,m, 0,0,0,0, m,m,m,m, 0,0,0,0,   /* 1 */
    m,m,m,m, 0,0,0,0, m,m,m,m, 0,0,0,0,   /* 2 */
    m,m,m,m, 0,0,0,0, m,m,m,m, 0,0,0,0,   /* 3 */
                                                 
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   /* 4 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   /* 5 */
    0,0,m,m, 0,0,0,0, 0,m,0,m, 0,0,0,0,   /* 6 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   /* 7 */
                                                 
    m,m,m,m, m,m,m,m, m,m,m,m, m,m,m,m,   /* 8 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   /* 9 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   /* A */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   /* B */
                                                 
    m,m,0,0, m,m,m,m, 0,0,0,0, 0,0,0,0,   /* C */
    m,m,m,m, 0,0,0,0, f,f,f,f, f,f,f,f,   /* D */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,   /* E */
    0,0,0,0, 0,0,m,m, 0,0,0,0, 0,0,m,m    /* F */
};

/* eliminate the macros */
#undef m
#undef f
#undef e


/* Data table for the additional fixed part of a two-byte opcode.
 * This table is indexed by the 2nd opcode byte.  Zero entries are
 * reserved/bad opcodes. 
 * N.B.: none of these (except IA32_ON_IA64) need adjustment
 * for data16 or addr16.
 */
static const byte escape_fixed_length[256] = {
    1,1,1,1, 0,1,1,1, 1,1,0,1, 0,1,1,2,  /* 0 */ /* 0f0f has extra suffix opcode byte */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* 1 */
    1,1,1,1, 0,0,0,0, 1,1,1,1, 1,1,1,1,  /* 2 */
    1,1,1,1, 1,1,0,0, 1,0,1,0, 0,0,0,0,  /* 3 */ 
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* 4 */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* 5 */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* 6 */
    2,2,2,2, 1,1,1,1, 1,1,0,0, 1,1,1,1,  /* 7 */
                                                
    5,5,5,5, 5,5,5,5, 5,5,5,5, 5,5,5,5,  /* 8 */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* 9 */
    1,1,1,1, 2,1,0,0, 1,1,1,1, 2,1,1,1,  /* A */
#ifdef IA32_ON_IA64
    /* change is the 5, could also be 3 depending on which mode we are */
    /* FIXME : no modrm byte so the standard variable thing won't work */
    /* (need a escape_disp_adjustment table) */
    1,1,1,1, 1,1,1,1, 5,1,2,1, 1,1,1,1,  /* B */
#else
    1,1,1,1, 1,1,1,1, 1,1,2,1, 1,1,1,1,  /* B */
#endif
                
    1,1,2,1, 2,2,2,1, 1,1,1,1, 1,1,1,1,  /* C */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* D */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,  /* E */
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,0   /* F */
    /* 0f78 has immeds depending on prefixes: handled in decode_sizeof() */
};


/* Some macros to make the following table look better. */
#define m VARLEN_MODRM
#define e1 VARLEN_3BYTE_38_ESCAPE
#define e2 VARLEN_3BYTE_3A_ESCAPE

/* Data table indicating what function to use to calcuate
   the variable part of the escaped x86 instruction.  This table
   is indexed by the 2nd opcode byte.  */
static const byte escape_variable_length[256] = {
    m,m,m,m, 0,0,0,0, 0,0,0,0, 0,m,0,m, /* 0 */
    m,m,m,m, m,m,m,m, m,m,m,m, m,m,m,m, /* 1 */
    m,m,m,m, 0,0,0,0, m,m,m,m, m,m,m,m, /* 2 */
    0,0,0,0, 0,0,0,0, e1,0,e2,0, 0,0,0,0, /* 3 */

    m,m,m,m, m,m,m,m, m,m,m,m, m,m,m,m, /* 4 */
    m,m,m,m, m,m,m,m, m,m,m,m, m,m,m,m, /* 5 */
    m,m,m,m, m,m,m,m, m,m,m,m, m,m,m,m, /* 6 */
    m,m,m,m, m,m,m,0, m,m,0,0, m,m,m,m, /* 7 */

    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, /* 8 */
    m,m,m,m, m,m,m,m, m,m,m,m, m,m,m,m, /* 9 */
    0,0,0,m, m,m,0,0, 0,0,0,m, m,m,m,m, /* A */
#ifdef IA32_ON_IA64
    m,m,m,m, m,m,m,m, 0,0,m,m, m,m,m,m, /* B */
#else
    m,m,m,m, m,m,m,m, m,0,m,m, m,m,m,m, /* B */
#endif
    m,m,m,m, m,m,m,m, 0,0,0,0, 0,0,0,0, /* C */
    m,m,m,m, m,m,m,m, m,m,m,m, m,m,m,m, /* D */
    m,m,m,m, m,m,m,m, m,m,m,m, m,m,m,m, /* E */
    m,m,m,m, m,m,m,m, m,m,m,m, m,m,m,0  /* F */
};

/* eliminate the macros */
#undef m
#undef e

/* Data table for the additional fixed part of a three-byte opcode 0f 38.
 * This table is indexed by the 3rd opcode byte.  Zero entries are
 * reserved/bad opcodes.
 * N.B.: ALL of these have modrm bytes, and NONE of these need adjustment for data16
 * or addr16.
 */
#if 0 /* to be robust wrt future additions we assume all entries are 1 */
static const byte threebyte_38_fixed_length[256] = {
    1,1,1,1, 1,1,1,1, 1,1,1,1, 0,0,0,0,  /* 0 */
    1,0,0,0, 1,1,0,1, 0,0,0,0, 1,1,1,0,  /* 1 */
    1,1,1,1, 1,1,0,0, 1,1,1,1, 0,0,0,0,  /* 2 */
    1,1,1,1, 1,1,0,1, 1,1,1,1, 1,1,1,1,  /* 3 */ 
    1,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 4 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 5 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 6 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 7 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 8 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 9 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* A */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* B */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* C */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* D */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* E */
    1,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0   /* F */
};
#endif
/* Three-byte 0f 3a: all are assumed to have a 1-byte immediate as well! */
#if 0 /* to be robust wrt future additions we assume all entries are 1 */
static const byte threebyte_3a_fixed_length[256] = {
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1,  /* 0 */
    0,0,0,0, 1,1,1,1, 1,1,1,1, 1,1,1,0,  /* 1 */
    1,1,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 2 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 3 */ 
    0,1,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 4 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 5 */
    1,1,1,1, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 6 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 7 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 8 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 9 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* A */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* B */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* C */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* D */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* E */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0   /* F */
};
#endif

/* Extra size when vex-encoded (from immeds) */
static const byte threebyte_38_vex_extra[256] = {
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 0 */
    1,0,0,0, 1,1,0,0, 0,0,0,0, 0,0,0,0,  /* 1 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 2 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 3 */ 
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 4 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 5 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 6 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 7 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 8 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* 9 */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* A */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* B */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* C */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* D */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,  /* E */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0   /* F */
};

/* Returns the length of the instruction at pc.
 * SJF Note: All arm instructions are 4 bytes/32 bits.
 * Will need to change this for Thumb interleaving
 */
int
decode_sizeof(dcontext_t *dcontext, byte *start_pc, int *num_prefixes
              _IF_X64(uint *rip_rel_pos))
{
    byte *pc = start_pc;
    uint opc = (uint)*pc;
    int sz = 0;
    ushort varlen;
    bool word_operands = false; /* data16 */
    bool qword_operands = false; /* rex.w */
    bool addr16 = false; /* really "addr32" for x64 mode */
    bool found_prefix = true;
    bool rep_prefix = false;
    byte reg_opcode;    /* reg_opcode field of modrm byte */

    sz = 4; //SJF ARM all 32 bits

    return sz;

}

static int
sizeof_3byte_38(dcontext_t *dcontext, byte *pc, bool addr16, bool vex
                _IF_X64(byte **rip_rel_pc))
{
    int sz = 1; /* opcode past 0x0f 0x38 */
    uint opc = *(++pc);
    /* so far all 3-byte instrs have modrm bytes */
    /* to be robust for future additions we don't actually
     * use the threebyte_38_fixed_length[opc] entry and assume 1 */
    if (vex)
        sz += threebyte_38_vex_extra[opc];
    sz += sizeof_modrm(dcontext, pc+1, addr16 _IF_X64(rip_rel_pc));
    return sz;
}

static int
sizeof_3byte_3a(dcontext_t *dcontext, byte *pc, bool addr16 _IF_X64(byte **rip_rel_pc))
{
    pc++;
    /* so far all 0f 3a 3-byte instrs have modrm bytes and 1-byte immeds */
    /* to be robust for future additions we don't actually
     * use the threebyte_3a_fixed_length[opc] entry and assume 1 */
    return 1 + sizeof_modrm(dcontext, pc+1, addr16 _IF_X64(rip_rel_pc)) + 1;
}

/* Two-byte opcode map (Tables A-4 and A-5).  You use this routine
 * when you have identified the primary opcode as 0x0f.  You pass this
 * routine the next byte to determine the number of extra bytes in the
 * entire instruction. 
 * May return 0 size for certain invalid instructions.
 */
static int
sizeof_escape(dcontext_t *dcontext, byte *pc, bool addr16 _IF_X64(byte **rip_rel_pc))
{
    uint opc = (uint)*pc;
    int sz = escape_fixed_length[opc];
    ushort varlen = escape_variable_length[opc];

    /* for a valid instr, sz must be > 0 here, but we don't want to assert
     * since we need graceful failure
     */

    if (varlen == VARLEN_MODRM)
        return sz + sizeof_modrm(dcontext, pc+1, addr16 _IF_X64(rip_rel_pc));
    else if (varlen == VARLEN_3BYTE_38_ESCAPE) {
        return sz + sizeof_3byte_38(dcontext, pc, addr16, false _IF_X64(rip_rel_pc));
    }
    else if (varlen == VARLEN_3BYTE_3A_ESCAPE) {
        return sz + sizeof_3byte_3a(dcontext, pc, addr16 _IF_X64(rip_rel_pc));
    }
    else
        CLIENT_ASSERT(varlen == VARLEN_NONE, "internal decoding error");

    return sz;
}


/* 32-bit addressing forms with the ModR/M Byte (Table 2-2).  You call
 * this routine with the byte following the primary opcode byte when you
 * know that the operation's next byte is a ModR/M byte.  This routine
 * passes back the size of the Eaddr specification in bytes based on the
 * following encoding of Table 2-2.
 *
 *   Mod        R/M
 *        0 1 2 3 4 5 6 7
 *    0   1 1 1 1 * 5 1 1
 *    1   2 2 2 2 3 2 2 2
 *    2   5 5 5 5 6 5 5 5
 *    3   1 1 1 1 1 1 1 1
 *   where (*) is 6 if base==5 and 2 otherwise.
 */
static int
sizeof_modrm(dcontext_t *dcontext, byte *pc, bool addr16 _IF_X64(byte **rip_rel_pc))
{
    int l = 0;          /* return value for sizeof(eAddr) */

    uint modrm = (uint)*pc;
    int r_m = modrm & 0x7;
    uint mod = modrm >> 6;
    uint sib;

#ifdef X64
    if (rip_rel_pc != NULL && X64_MODE_DC(dcontext) && mod == 0 && r_m == 5) {
        *rip_rel_pc = pc + 1; /* no sib: next 4 bytes are disp */
    }
#endif

    if (addr16 && !X64_MODE_DC(dcontext)) {
        if (mod == 1)
            return 2; /* modrm + disp8 */
        else if (mod == 2)
            return 3; /* modrm + disp16 */
        else if (mod == 3)
            return 1; /* just modrm */
        else {
            CLIENT_ASSERT(mod == 0, "internal decoding error on addr16 prefix");
            if (r_m == 6)
                return 3; /* modrm + disp16 */
            else
                return 1; /* just modrm */
        }
        CLIENT_ASSERT(false, "internal decoding error on addr16 prefix");
    }
    
    /* for x64, addr16 simply truncates the computed address: there is
     * no change in disp sizes */
    
    if (mod == 3)       /* register operand */
        return 1;

    switch (mod) {      /* memory or immediate operand */
      case 0: l = (r_m == 5) ? 5 : 1; break;
      case 1: l = 2; break;
      case 2: l = 5; break;
    }
    if (r_m == 4) {
        l += 1;         /* adjust for sib byte */
        sib = (uint)(*(pc+1));
        if ((sib & 0x7) == 5) {
            if (mod == 0)
                l += 4; /* disp32(,index,s) */
        }
    }   

    return l;
}

/* General floating-point instruction formats (Table B-22).  You use
 * this routine when you have identified the primary opcode as one in
 * the range 0xb8 through 0xbf.  You pass this routine the next byte
 * to determine the number of extra bytes in the entire
 * instruction. */
static int
sizeof_fp_op(dcontext_t *dcontext, byte *pc, bool addr16 _IF_X64(byte **rip_rel_pc))
{
    if (*pc > 0xbf)
        return 1;       /* entire ModR/M byte is an opcode extension */

    /* fp opcode in reg/opcode field */
    return sizeof_modrm(dcontext, pc, addr16 _IF_X64(rip_rel_pc));
}


/* Table indicating "interesting" instructions, i.e., ones we
 * would like to decode.  Currently these are control-transfer
 * instructions and interrupts.
 * This table is indexed by the 1st (primary) opcode byte.
 * A 0 indicates we are not interested, a 1 that we are.
 * A 2 indicates a second opcode byte exists, a 3 indicates an opcode
 * extension is present in the modrm byte.
 */
static const byte interesting[256] = {
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,2,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,

    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1, /* jcc_short */

    0,0,0,0, 0,0,0,0, 0,0,0,0, 1,0,1,0, /* mov_seg */
    0,0,0,0, 0,0,0,0, 0,0,1,0, 0,0,0,0, /* call_far */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,

    0,0,1,1, 0,0,0,0, 0,0,1,1, 1,1,1,1, /* ret*, int* */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    1,1,1,1, 0,0,0,0, 1,1,1,1, 0,0,0,0, /* loop*, call, jmp* */
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,3,
};



/* This routine converts a signed 8-bit offset into a target pc.  The
 * formal parameter pc should point to the beginning of the branch
 * instruction containing the offset and having length len in bytes. 
 * The x86 architecture calculates offsets from the beginning of the
 * instruction following the branch. */
static app_pc
convert_8bit_offset(byte *pc, byte offset, uint len)
{
    return ((app_pc)pc) + (((int)(offset << 24)) >> 24) + len;
}

/* Decodes only enough of the instruction at address pc to determine
 * its size, its effects on the 6 arithmetic eflags, and whether it is
 * a control-transfer instruction.  If it is, the operands fields of
 * instr are filled in.  If not, only the raw bits fields of instr are
 * filled in.  This corresponds to a Level 3 decoding for control
 * transfer instructions but a Level 1 decoding plus arithmetic eflags
 * information for all other instructions.
 *
 * Fills in the PREFIX_SEG_GS and PREFIX_SEG_FS prefix flags for all instrs.
 * Does NOT fill in any other prefix flags unless this is a cti instr
 * and the flags affect the instr.
 *
 * Assumes that instr is already initialized, but uses the x86/x64 mode
 * for the current thread rather than that set in instr.
 * If caller is re-using same instr struct over multiple decodings,
 * should call instr_reset or instr_reuse.
 * Returns the address of the byte following the instruction.  
 * Returns NULL on decoding an invalid instr and sets opcode to OP_INVALID.
 */
byte *
decode_cti(dcontext_t *dcontext, byte *pc, instr_t *instr)
{
    byte byte0, byte1;
    byte *start_pc = pc;
    opnd_t dsts[3];
    opnd_t srcs[2];
    int instr_num_dsts, instr_num_srcs;
    decode_info_t di = {0};
    instr_info_t info = {0};

    /* find and remember the instruction and its size */
    int prefixes = 0;
    byte modrm = 0;    /* used only for EFLAGS_6_SPECIAL */
    int sz = decode_sizeof(dcontext, pc, &prefixes _IF_X64(&rip_rel_pos));
    if (sz == 0) {
        /* invalid instruction! */
        instr_set_opcode(instr, OP_INVALID);
        return NULL;
    }
    instr_set_opcode(instr, OP_UNDECODED);
    IF_X64(instr_set_x86_mode(instr, get_x86_mode(dcontext)));

    /* we call instr_set_raw_bits on every return from here, not up
     * front, because any instr_set_src, instr_set_dst, or
     * instr_set_opcode will kill original bits state */

    byte0 = *pc;
    byte1 = *(pc + 1);

/* SJF 
   decode the instruction opcode. 
   If it is a cti or a syscall then decode it fully.
   return pc after instr
 */

    pc = decode_opcode( dcontext, pc, instr );

    if( opcode_is_cti( instr->opcode ))
    {
      //Reset the instr to allow a full decode
      instr_reset( dcontext, instr );

      //Roll back the pc to get the same instruction again
      pc -= sz;

      //decode fully only call decode_common.
      pc = decode( dcontext, pc, instr );

      CLIENT_ASSERT( (pc == (start_pc + sz)), "decode_cti: pc != (start_pc + sz)" );

      return pc;
    } 
    else if( opcode_is_relative_load( instr->opcode ) ||
             opcode_is_other_relative( instr->opcode ))
    {
      /* To allow a relative instr to be covnerted to an absolute one later
         then decode it fully here
         Make sure not to set the raw bits to valid as it will ignore the 
         changed instr
         Reset the instr to allow a full decode */
      instr_reset( dcontext, instr );

      //Roll back the pc to get the same instruction again
      pc -= sz;

      //decode fully only call decode_common.
      pc = decode( dcontext, pc, instr );
      //Set the pc so the abs value can be calcd
      instr->bytes = (pc - sz);

      CLIENT_ASSERT( (instr != NULL), "decode_cti: invalid instr rewrite" );

      return pc;
    }
    else
    {
      /* all non-pc-relative instructions */
      /* assumption: opcode already OP_UNDECODED */
      instr_set_raw_bits(instr, start_pc, sz);

      CLIENT_ASSERT( (pc == (start_pc + sz)), "decode_cti: pc != (start_pc + sz)" );

      return pc;
    }
}

/* Returns a pointer to the pc of the next instruction
 * Returns NULL on decoding an invalid instruction.
 */
byte *
decode_next_pc(dcontext_t *dcontext, byte *pc)
{
    int sz = decode_sizeof(dcontext, pc, NULL _IF_X64(NULL));
    if (sz == 0)
        return NULL;
    else
        return pc + sz;
}

/* Decodes the size of the instruction at address pc and points instr
 * at the raw bits for the instruction.
 * This corresponds to a Level 1 decoding.
 * Assumes that instr is already initialized, but uses the x86/x64 mode
 * for the current thread rather than that set in instr.
 * If caller is re-using same instr struct over multiple decodings,
 * should call instr_reset or instr_reuse.
 * Returns the address of the next byte after the decoded instruction.
 * Returns NULL on decoding an invalid instr and sets opcode to OP_INVALID.
 */
byte *
decode_raw(dcontext_t *dcontext, byte *pc, instr_t *instr)
{
    int sz = decode_sizeof(dcontext, pc, NULL _IF_X64(NULL));
    IF_X64(instr_set_x86_mode(instr, get_x86_mode(dcontext)));
    if (sz == 0) {
        /* invalid instruction! */
        instr_set_opcode(instr, OP_INVALID);
        return NULL;
    }
    instr_set_opcode(instr, OP_UNDECODED);
    instr_set_raw_bits(instr, pc, sz);
    /* assumption: operands are already marked invalid (instr was reset) */
    return (pc + sz);
}

