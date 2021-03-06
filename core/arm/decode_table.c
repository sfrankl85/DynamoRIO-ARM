/* **********************************************************
 * Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
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

/* decode_table.c -- tables for decoding x86 instructions
 */

#include "../globals.h" /* need this to include decode.h (uint, etc.) */
#include "arch.h"    /* need this to include decode.h (byte, etc. */
#include "instr.h" /* for REG_ constants */
#include "decode.h"



/****************************************************************************
 * Macros to make tables legible
 */

/* Jb is defined in dynamo.h, undefine it for this file */
#undef Jb

#define xx  TYPE_NONE, OPSZ_NA

/* from ARM document. Couldnt find a table. Is there one? */
#define Ra  TYPE_REG,    OPSZ_4  /* 32 bit value contained in reg */
#define Rh  TYPE_REG,    OPSZ_4 /* TODO 16 bit array of regs */
#define Ma  TYPE_M,      OPSZ_4  /* Memory address contained in reg *///SJF For now juts leave as a reg
#define Cr  TYPE_CO_REG, OPSZ_4
#define Co  TYPE_CO_REG, OPSZ_4_5
#define Rl  TYPE_S,      OPSZ_4_12 /* Register list. Bits indicate reg flag */
#define Mk  TYPE_O,      OPSZ_4_2  /* 2 bit mask value. for msr/mrs */
#define I3  TYPE_I,      OPSZ_4_3  /* Immediate value contained in instr */
#define I4  TYPE_I,      OPSZ_4_4  /* " */
#define I5  TYPE_I,      OPSZ_4_5  /* " */
#define I6  TYPE_I,      OPSZ_4_6  /* " */
#define I8  TYPE_I,      OPSZ_4_8  /* " */ 
#define I12 TYPE_I,      OPSZ_4_12 /* " */
#define I16 TYPE_I,      OPSZ_4_16 /* " */
#define I24 TYPE_I,      OPSZ_4_24 /* " */

#define A24 TYPE_A,      OPSZ_4_24  //24 bit/3 byte immediate that contains an address
#define J24 TYPE_J,      OPSZ_4_24  //24 bit/3 byte immediate that contains a near address


#define r0  TYPE_REG, REG_RR0
#define r1  TYPE_REG, REG_RR1
#define r2  TYPE_REG, REG_RR2
#define r3  TYPE_REG, REG_RR3
#define r4  TYPE_REG, REG_RR4
#define r5  TYPE_REG, REG_RR5
#define r6  TYPE_REG, REG_RR6
#define r7  TYPE_REG, REG_RR7
#define r8  TYPE_REG, REG_RR8
#define r9  TYPE_REG, REG_RR9
#define r10 TYPE_REG, REG_RR10
#define r11 TYPE_REG, REG_RR11
#define r12 TYPE_REG, REG_RR12
#define r13 TYPE_REG, REG_RR13
#define r14 TYPE_REG, REG_RR14
#define r15 TYPE_REG, REG_RR15

/* Instr_type */
#define dpe 1  // INSTR_TYPE_DATA_PROCESSING_AND_ELS
#define dpi 2  // INSTR_TYPE_DATA_PROCESSING_IMM
#define ls1 3  // INSTR_TYPE_LOAD_STORE1
#define ls2 4  // INSTR_TYPE_LOAD_STORE2_AND_MEDIA
#define lsm 5  // INSTR_TYPE_LOAD_STORE_MULTIPLE
#define bra 6  // INSTR_TYPE_BRANCH
#define cdm 7  // INSTR_TYPE_COPROCESSOR_DATA_MOVEMENT
#define acs 8  // INSTR_TYPE_ADVANCED_COPROCESSOR_AND_SYSCALL



/* flags */
#define no       0

/* cpsr??? SJF */
#define x     0

/* flags affected by OP_int*
 * FIXME: should we add AC and VM flags?
 */

#define NA 0
#define END_LIST  0

/* point at this when you need a canonical invalid instr 
 * type is OP_INVALID so can be copied to instr->opcode
 */
const instr_info_t invalid_instr =
    {OP_INVALID,  0x000000, "(bad)", xx, xx, xx, xx, xx, no, x, NA};

/* KEY: imm=immediate, rsr=register shifted register, reg=register, sp=stackpointer */
/* TODO Add them alphabeticaly for the moment as this is how they are declared inside 
        the ARMv7-A/R tech ref manual. Change to numerical ordering?? <- No point. No advantages */

/* Thumb instrs are 16 bits or two 16 bit instrs. For the 32 bit ones define only one OP_ type */
/* For 16 bit thumbs vvv */
/* opcode is bits[15,10], opcode2 is bits[9,6] */
/* For 32 bit thumbs vvv */
/* opcode1 is bits[15,10] in instr 1. opcode2 is bits[9,4] in instr 1 Ignore instr_type */
const instr_info_t thumb_instrs[] = {
    {OP_T_add_reg,  0x1, 0x1, "T_add_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_add_reg()*/
    {OP_T_adc_reg,  0x1, 0x1, "T_adc_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_adc_reg()*/
    {OP_T_add_low_reg,  0x1, 0x1, "T_add_low_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_add_low_reg()*/
    {OP_T_add_high_reg,  0x1, 0x1, "T_add_high_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_add_high_reg()*/
    {OP_T_add_sp_imm,  0x1, 0x1, "T_add_sp_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_add_sp_imm()*/
    {OP_T_add_imm_3,  0x1, 0x1, "T_add_imm_3",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_add_imm_3()*/
    {OP_T_add_imm_8,  0x1, 0x1, "T_add_imm_8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_add_imm_8()*/
    {OP_T_and_reg,  0x1, 0x1, "T_and_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_and_reg()*/
    {OP_T_asr_imm,  0x1, 0x1, "T_asr_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_asr_imm()*/
    {OP_T_asr_reg,  0x1, 0x1, "T_asr_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_asr_reg()*/
    {OP_T_b,  0x1, 0x1, "T_b",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_b()*/
    {OP_T_bic_reg,  0x1, 0x1, "T_bic_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_bic_reg()*/
    {OP_T_bkpt,  0x1, 0x1, "T_bkpt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_bkpt()*/
    {OP_T_blx_ref,  0x1, 0x1, "T_blx_ref",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_blx_ref()*/
    {OP_T_bx,  0x1, 0x1, "T_bx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_bx()*/
    {OP_T_cbnz,  0x1, 0x1, "T_cbnz",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_cbnz()*/
    {OP_T_cbnz_2,  0x1, 0x1, "T_cbnz_2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_cbnz_2()*/
    {OP_T_cbz,  0x1, 0x1, "T_cbz",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_cbz()*/
    {OP_T_cbz_2,  0x1, 0x1, "T_cbz_2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_cbz_2()*/
    {OP_T_cmn_reg,  0x1, 0x1, "T_cmn_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_cmn_reg()*/
    {OP_T_cmp_high_reg,  0x1, 0x1, "T_cmp_high_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_cmp_high_reg()*/
    {OP_T_cmp_imm,  0x1, 0x1, "T_cmp_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_cmp_imm()*/
    {OP_T_cmp_reg,  0x1, 0x1, "T_cmp_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_cmp_reg()*/
    {OP_T_cps,  0x1, 0x1, "T_cps",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_cps()*/
    {OP_T_eor_reg,  0x1, 0x1, "T_eor_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_eor_reg()*/
    {OP_T_it,  0x1, 0x1, "T_it",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_it()*/
    {OP_T_ldrb_imm,  0x1, 0x1, "T_ldrb_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_ldrb_imm()*/
    {OP_T_ldrb_reg,  0x1, 0x1, "T_ldrb_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_ldrb_reg()*/
    {OP_T_ldrh_imm,  0x1, 0x1, "T_ldrh_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_ldrh_imm()*/
    {OP_T_ldrh_reg,  0x1, 0x1, "T_ldrh_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_ldrh_reg()*/
    {OP_T_ldrsb_reg,  0x1, 0x1, "T_ldrsb_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_ldrsb_reg()*/
    {OP_T_ldrsh_reg,  0x1, 0x1, "T_ldrsh_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_ldrsh_reg()*/
    {OP_T_ldr_imm,  0x1, 0x1, "T_ldr_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_ldr_imm()*/
    {OP_T_ldr_reg,  0x1, 0x1, "T_ldr_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_ldr_reg()*/
    {OP_T_lsl_imm,  0x1, 0x1, "T_lsl_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_lsl_imm()*/
    {OP_T_lsl_reg,  0x1, 0x1, "T_lsl_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_lsl_reg()*/
    {OP_T_lsr_imm,  0x1, 0x1, "T_lsr_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_lsr_imm()*/
    {OP_T_lsr_reg,  0x1, 0x1, "T_lsr_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_lsr_reg()*/
    {OP_T_mov_imm,  0x1, 0x1, "T_mov_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_mov_imm()*/
    {OP_T_mov_high_reg,  0x1, 0x1, "T_mov_high_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_mov_high_reg()*/
    {OP_T_mov_low_reg,  0x1, 0x1, "T_mov_low_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_mov_low_reg()*/
    {OP_T_mvn_reg,  0x1, 0x1, "T_mvn_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_mvn_reg()*/
    {OP_T_mul,  0x1, 0x1, "T_mul",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_mul()*/
    {OP_T_nop,  0x1, 0x1, "T_nop",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_nop()*/
    {OP_T_orr_reg,  0x1, 0x1, "T_orr_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_orr_reg()*/
    {OP_T_pop,  0x1, 0x1, "T_pop",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_pop()*/
    {OP_T_push,  0x1, 0x1, "T_push",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_push()*/
    {OP_T_rev,  0x1, 0x1, "T_rev",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_rev()*/
    {OP_T_rev16,  0x1, 0x1, "T_rev16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_rev16()*/
    {OP_T_revsh,  0x1, 0x1, "T_revsh",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_revsh()*/
    {OP_T_ror_reg,  0x1, 0x1, "T_ror_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_ror_reg()*/
    {OP_T_rsb_imm,  0x1, 0x1, "T_rsb_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_rsb_imm()*/
    {OP_T_sbc_reg,  0x1, 0x1, "T_sbc_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_sbc_reg()*/
    {OP_T_setend,  0x1, 0x1, "T_setend",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_setend()*/
    {OP_T_sev,  0x1, 0x1, "T_sev",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_sev()*/
    {OP_T_str_imm,  0x1, 0x1, "T_str_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_str_imm()*/
    {OP_T_str_reg,  0x1, 0x1, "T_str_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_str_reg()*/
    {OP_T_str_sp,  0x1, 0x1, "T_str_sp",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_str_sp()*/
    {OP_T_strb_imm,  0x1, 0x1, "T_strb_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_strb_imm()*/
    {OP_T_strb_reg,  0x1, 0x1, "T_strb_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_strb_reg()*/
    {OP_T_strh_imm,  0x1, 0x1, "T_strh_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_strh_imm()*/
    {OP_T_strh_reg,  0x1, 0x1, "T_strh_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_strh_reg()*/
    {OP_T_sub_sp_imm,  0x1, 0x1, "T_sub_sp_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_sub_sp_imm()*/
    {OP_T_sub_imm_8,  0x1, 0x1, "T_sub_imm_8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_sub_imm_8()*/
    {OP_T_sub_reg,  0x1, 0x1, "T_sub_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_sub_reg()*/
    {OP_T_sub_imm_3,  0x1, 0x1, "T_sub_imm_3",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_sub_imm_3()*/
    {OP_T_svc,  0x1, 0x1, "T_svc",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_svc()*/
    {OP_T_sxth,  0x1, 0x1, "T_sxth",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_sxth()*/
    {OP_T_sxtb,  0x1, 0x1, "T_sxtb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_sxtb()*/
    {OP_T_tst_reg,  0x1, 0x1, "T_tst_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_tst_reg()*/
    {OP_T_uxtb,  0x1, 0x1, "T_uxtb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_uxtb()*/
    {OP_T_uxth,  0x1, 0x1, "T_uxth",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_uxth()*/
    {OP_T_wfe,  0x1, 0x1, "T_wfe",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_wfe()*/
    {OP_T_wfi,  0x1, 0x1, "T_wfi",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_wfi()*/
    {OP_T_yield,  0x1, 0x1, "T_yield",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_yield()*/
    {OP_T_32_and_imm,  0x1, 0x1, "T_32_and_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_and_imm()*/
    {OP_T_32_tst_imm,  0x1, 0x1, "T_32_tst_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_tst_imm()*/
    {OP_T_32_bic_imm,  0x1, 0x1, "T_32_bic_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_bic_imm()*/
    {OP_T_32_orr_imm,  0x1, 0x1, "T_32_orr_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_orr_imm()*/
    {OP_T_32_mov_imm,  0x1, 0x1, "T_32_mov_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mov_imm()*/
    {OP_T_32_orn_imm,  0x1, 0x1, "T_32_orn_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_orn_imm()*/
    {OP_T_32_mvn_imm,  0x1, 0x1, "T_32_mvn_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mvn_imm()*/
    {OP_T_32_eor_imm,  0x1, 0x1, "T_32_eor_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_eor_imm()*/
    {OP_T_32_teq_imm,  0x1, 0x1, "T_32_teq_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_teq_imm()*/
    {OP_T_32_add_imm,  0x1, 0x1, "T_32_add_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_add_imm()*/
    {OP_T_32_cmn_imm,  0x1, 0x1, "T_32_cmn_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_cmn_imm()*/
    {OP_T_32_adc_imm,  0x1, 0x1, "T_32_adc_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_adc_imm()*/
    {OP_T_32_sbc_imm,  0x1, 0x1, "T_32_sbc_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sbc_imm()*/
    {OP_T_32_sub_imm,  0x1, 0x1, "T_32_sub_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sub_imm()*/
    {OP_T_32_cmp_imm,  0x1, 0x1, "T_32_cmp_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_cmp_imm()*/
    {OP_T_32_rsb_imm,  0x1, 0x1, "T_32_rsb_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_rsb_imm()*/
    {OP_T_32_add_wide,  0x1, 0x1, "T_32_add_wide",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_add_wide()*/
    {OP_T_32_adr,  0x1, 0x1, "T_32_adr",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_adr()*/
    {OP_T_32_mov_wide,  0x1, 0x1, "T_32_mov_wide",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mov_wide()*/
    {OP_T_32_adr_2,  0x1, 0x1, "T_32_adr_2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_adr_2()*/
    {OP_T_32_movt_top,  0x1, 0x1, "T_32_movt_top",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_movt_top()*/
    {OP_T_32_ssat,  0x1, 0x1, "T_32_ssat",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ssat()*/
    {OP_T_32_ssat16,  0x1, 0x1, "T_32_ssat16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ssat16()*/
    {OP_T_32_sbfx,  0x1, 0x1, "T_32_sbfx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sbfx()*/
    {OP_T_32_bfi,  0x1, 0x1, "T_32_bfi",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_bfi()*/
    {OP_T_32_bfc,  0x1, 0x1, "T_32_bfc",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_bfc()*/
    {OP_T_32_usat16,  0x1, 0x1, "T_32_usat16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_usat16()*/
    {OP_T_32_ubfx,  0x1, 0x1, "T_32_ubfx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ubfx()*/
    {OP_T_32_b,  0x1, 0x1, "T_32_b",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_b()*/
    {OP_T_32_msr_reg_app,  0x1, 0x1, "T_32_msr_reg_app",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_msr_reg_app()*/
    {OP_T_32_msr_reg_sys,  0x1, 0x1, "T_32_msr_reg_sys",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_msr_reg_sys()*/
    {OP_T_32_bxj,  0x1, 0x1, "T_32_bxj",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_bxj()*/
    {OP_T_32_subs,  0x1, 0x1, "T_32_subs",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_subs()*/
    {OP_T_32_mrs,  0x1, 0x1, "T_32_mrs",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mrs()*/
    {OP_T_32_smc,  0x1, 0x1, "T_32_smc",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smc()*/
    {OP_T_32_b_2,  0x1, 0x1, "T_32_b_2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_b_2()*/
    {OP_T_32_blx_imm,  0x1, 0x1, "T_32_blx_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_blx_imm()*/
    {OP_T_32_bl,  0x1, 0x1, "T_32_bl",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_bl()*/
    {OP_T_32_cps,  0x1, 0x1, "T_32_cps",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_cps()*/
    {OP_T_32_nop,  0x1, 0x1, "T_32_nop",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_nop()*/
    {OP_T_32_yield,  0x1, 0x1, "T_32_yield",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_yield()*/
    {OP_T_32_wfe,  0x1, 0x1, "T_32_wfe",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_wfe()*/
    {OP_T_32_wfi,  0x1, 0x1, "T_32_wfi",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_wfi()*/
    {OP_T_32_sev,  0x1, 0x1, "T_32_sev",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sev()*/
    {OP_T_32_dbg,  0x1, 0x1, "T_32_dbg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_dbg()*/
    {OP_T_32_enterx,  0x1, 0x1, "T_32_enterx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_enterx()*/
    {OP_T_32_leavex,  0x1, 0x1, "T_32_leavex",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_leavex()*/
    {OP_T_32_clrex,  0x1, 0x1, "T_32_clrex",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_clrex()*/
    {OP_T_32_dsb,  0x1, 0x1, "T_32_dsb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_dsb()*/
    {OP_T_32_dmb,  0x1, 0x1, "T_32_dmb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_dmb()*/
    {OP_T_32_isb,  0x1, 0x1, "T_32_isb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_isb()*/
    {OP_T_32_srs,  0x1, 0x1, "T_32_srs",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_srs()*/
    {OP_T_32_rfe,  0x1, 0x1, "T_32_rfe",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_rfe()*/
    {OP_T_32_stm,  0x1, 0x1, "T_32_stm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_stm()*/
    {OP_T_32_stmia,  0x1, 0x1, "T_32_stmia",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_stmia()*/
    {OP_T_32_stmea,  0x1, 0x1, "T_32_stmea",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_stmea()*/
    {OP_T_32_ldm,  0x1, 0x1, "T_32_ldm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldm()*/
    {OP_T_32_ldmia,  0x1, 0x1, "T_32_ldmia",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldmia()*/
    {OP_T_32_ldmfd,  0x1, 0x1, "T_32_ldmfd",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldmfd()*/
    {OP_T_32_pop,  0x1, 0x1, "T_32_pop",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_pop()*/
    {OP_T_32_stmdb,  0x1, 0x1, "T_32_stmdb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_stmdb()*/
    {OP_T_32_stmfd,  0x1, 0x1, "T_32_stmfd",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_stmfd()*/
    {OP_T_32_push,  0x1, 0x1, "T_32_push",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_push()*/
    {OP_T_32_ldmdb,  0x1, 0x1, "T_32_ldmdb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldmdb()*/
    {OP_T_32_ldmea,  0x1, 0x1, "T_32_ldmea",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldmea()*/
    {OP_T_32_strex,  0x1, 0x1, "T_32_strex",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strex()*/
    {OP_T_32_ldrex,  0x1, 0x1, "T_32_ldrex",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrex()*/
    {OP_T_32_strd_imm,  0x1, 0x1, "T_32_strd_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strd_imm()*/
    {OP_T_32_ldrd_imm,  0x1, 0x1, "T_32_ldrd_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrd_imm()*/
    {OP_T_32_ldrd_lit,  0x1, 0x1, "T_32_ldrd_lit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrd_lit()*/
    {OP_T_32_strexb,  0x1, 0x1, "T_32_strexb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strexb()*/
    {OP_T_32_strexh,  0x1, 0x1, "T_32_strexh",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strexh()*/
    {OP_T_32_strexd,  0x1, 0x1, "T_32_strexd",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strexd()*/
    {OP_T_32_tbb,  0x1, 0x1, "T_32_tbb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_tbb()*/
    {OP_T_32_tbh,  0x1, 0x1, "T_32_tbh",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_tbh()*/
    {OP_T_32_ldrexb,  0x1, 0x1, "T_32_ldrexb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrexb()*/
    {OP_T_32_ldrexh,  0x1, 0x1, "T_32_ldrexh",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrexh()*/
    {OP_T_32_ldrexd,  0x1, 0x1, "T_32_ldrexd",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrexd()*/
    {OP_T_32_ldr_imm,  0x1, 0x1, "T_32_ldr_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldr_imm()*/
    {OP_T_32_ldrt,  0x1, 0x1, "T_32_ldrt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrt()*/
    {OP_T_32_ldr_reg,  0x1, 0x1, "T_32_ldr_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldr_reg()*/
    {OP_T_32_ldr_lit,  0x1, 0x1, "T_32_ldr_lit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldr_lit()*/
    {OP_T_32_ldrh_lit,  0x1, 0x1, "T_32_ldrh_lit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrh_lit()*/
    {OP_T_32_ldrh_imm,  0x1, 0x1, "T_32_ldrh_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrh_imm()*/
    {OP_T_32_ldrht,  0x1, 0x1, "T_32_ldrht",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrht()*/
    {OP_T_32_ldrh_reg,  0x1, 0x1, "T_32_ldrh_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrh_reg()*/
    {OP_T_32_ldrsh_imm,  0x1, 0x1, "T_32_ldrsh_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrsh_imm()*/
    {OP_T_32_ldrsht,  0x1, 0x1, "T_32_ldrsht",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrsht()*/
    {OP_T_32_ldrsh_reg,  0x1, 0x1, "T_32_ldrsh_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrsh_reg()*/
    {OP_T_32_ldrb_lit,  0x1, 0x1, "T_32_ldrb_lit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrb_lit()*/
    {OP_T_32_ldrb_imm,  0x1, 0x1, "T_32_ldrb_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrb_imm()*/
    {OP_T_32_ldrbt,  0x1, 0x1, "T_32_ldrbt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrbt()*/
    {OP_T_32_ldrb_reg,  0x1, 0x1, "T_32_ldrb_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrb_reg()*/
    {OP_T_32_ldrsb_lit,  0x1, 0x1, "T_32_ldrsb_lit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrsb_lit()*/
    {OP_T_32_ldrsb_imm,  0x1, 0x1, "T_32_ldrsb_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrsb_imm()*/
    {OP_T_32_ldrsbt,  0x1, 0x1, "T_32_ldrsbt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrsbt()*/
    {OP_T_32_ldrsb,  0x1, 0x1, "T_32_ldrsb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldrsb()*/
    {OP_T_32_pld_imm,  0x1, 0x1, "T_32_pld_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_pld_imm()*/
    {OP_T_32_pld_lit,  0x1, 0x1, "T_32_pld_lit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_pld_lit()*/
    {OP_T_32_pld_reg,  0x1, 0x1, "T_32_pld_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_pld_reg()*/
    {OP_T_32_pli_imm,  0x1, 0x1, "T_32_pli_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_pli_imm()*/
    {OP_T_32_pli_lit,  0x1, 0x1, "T_32_pli_lit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_pli_lit()*/
    {OP_T_32_pli_reg,  0x1, 0x1, "T_32_pli_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_pli_reg()*/
    {OP_T_32_strb_imm,  0x1, 0x1, "T_32_strb_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strb_imm()*/
    {OP_T_32_strbt,  0x1, 0x1, "T_32_strbt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strbt()*/
    {OP_T_32_strb_reg,  0x1, 0x1, "T_32_strb_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strb_reg()*/
    {OP_T_32_strh_imm,  0x1, 0x1, "T_32_strh_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strh_imm()*/
    {OP_T_32_strht,  0x1, 0x1, "T_32_strht",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strht()*/
    {OP_T_32_strh_reg,  0x1, 0x1, "T_32_strh_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strh_reg()*/
    {OP_T_32_str_imm,  0x1, 0x1, "T_32_str_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_str_imm()*/
    {OP_T_32_strt,  0x1, 0x1, "T_32_strt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_strt()*/
    {OP_T_32_str_reg,  0x1, 0x1, "T_32_str_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_str_reg()*/
    {OP_T_32_and_reg,  0x1, 0x1, "T_32_and_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_and_reg()*/
    {OP_T_32_tst_reg,  0x1, 0x1, "T_32_tst_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_tst_reg()*/
    {OP_T_32_bic_reg,  0x1, 0x1, "T_32_bic_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_bic_reg()*/
    {OP_T_32_orr_reg,  0x1, 0x1, "T_32_orr_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_orr_reg()*/
    {OP_T_32_mov_reg,  0x1, 0x1, "T_32_mov_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mov_reg()*/
    {OP_T_32_orn_reg,  0x1, 0x1, "T_32_orn_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_orn_reg()*/
    {OP_T_32_mvn_reg,  0x1, 0x1, "T_32_mvn_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mvn_reg()*/
    {OP_T_32_eor_reg,  0x1, 0x1, "T_32_eor_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_eor_reg()*/
    {OP_T_32_teq_reg,  0x1, 0x1, "T_32_teq_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_teq_reg()*/
    {OP_T_32_pkh,  0x1, 0x1, "T_32_pkh",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_pkh()*/
    {OP_T_32_add_reg,  0x1, 0x1, "T_32_add_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_add_reg()*/
    {OP_T_32_cmn_reg,  0x1, 0x1, "T_32_cmn_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_cmn_reg()*/
    {OP_T_32_adc_reg,  0x1, 0x1, "T_32_adc_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_adc_reg()*/
    {OP_T_32_sbc_reg,  0x1, 0x1, "T_32_sbc_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sbc_reg()*/
    {OP_T_32_sub_reg,  0x1, 0x1, "T_32_sub_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sub_reg()*/
    {OP_T_32_cmp_reg,  0x1, 0x1, "T_32_cmp_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_cmp_reg()*/
    {OP_T_32_rsb_reg,  0x1, 0x1, "T_32_rsb_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_rsb_reg()*/
    {OP_T_32_lsl_reg,  0x1, 0x1, "T_32_lsl_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_lsl_reg()*/
    {OP_T_32_lsr_reg,  0x1, 0x1, "T_32_lsr_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_lsr_reg()*/
    {OP_T_32_asr_reg,  0x1, 0x1, "T_32_asr_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_asr_reg()*/
    {OP_T_32_ror_reg,  0x1, 0x1, "T_32_ror_reg",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ror_reg()*/
    {OP_T_32_sxtah,  0x1, 0x1, "T_32_sxtah",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sxtah()*/
    {OP_T_32_sxth,  0x1, 0x1, "T_32_sxth",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sxth()*/
    {OP_T_32_uxtah,  0x1, 0x1, "T_32_uxtah",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uxtah()*/
    {OP_T_32_uxth,  0x1, 0x1, "T_32_uxth",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uxth()*/
    {OP_T_32_sxtab16,  0x1, 0x1, "T_32_sxtab16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sxtab16()*/
    {OP_T_32_sxtb16,  0x1, 0x1, "T_32_sxtb16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sxtb16()*/
    {OP_T_32_uxtab16,  0x1, 0x1, "T_32_uxtab16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uxtab16()*/
    {OP_T_32_uxtb16,  0x1, 0x1, "T_32_uxtb16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uxtb16()*/
    {OP_T_32_sxtab,  0x1, 0x1, "T_32_sxtab",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sxtab()*/
    {OP_T_32_sxtb,  0x1, 0x1, "T_32_sxtb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sxtb()*/
    {OP_T_32_uxtab,  0x1, 0x1, "T_32_uxtab",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uxtab()*/
    {OP_T_32_uxtb,  0x1, 0x1, "T_32_uxtb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uxtb()*/
    {OP_T_32_sadd16,  0x1, 0x1, "T_32_sadd16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sadd16()*/
    {OP_T_32_sasx,  0x1, 0x1, "T_32_sasx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sasx()*/
    {OP_T_32_ssax,  0x1, 0x1, "T_32_ssax",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ssax()*/
    {OP_T_32_ssub16,  0x1, 0x1, "T_32_ssub16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ssub16()*/
    {OP_T_32_sadd8,  0x1, 0x1, "T_32_sadd8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sadd8()*/
    {OP_T_32_ssub8,  0x1, 0x1, "T_32_ssub8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ssub8()*/
    {OP_T_32_qadd16,  0x1, 0x1, "T_32_qadd16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qadd16()*/
    {OP_T_32_qasx,  0x1, 0x1, "T_32_qasx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qasx()*/
    {OP_T_32_qsax,  0x1, 0x1, "T_32_qsax",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qsax()*/
    {OP_T_32_qsub16,  0x1, 0x1, "T_32_qsub16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qsub16()*/
    {OP_T_32_qadd8,  0x1, 0x1, "T_32_qadd8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qadd8()*/
    {OP_T_32_qsub8,  0x1, 0x1, "T_32_qsub8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qsub8()*/
    {OP_T_32_shadd16,  0x1, 0x1, "T_32_shadd16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_shadd16()*/
    {OP_T_32_shasx,  0x1, 0x1, "T_32_shasx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_shasx()*/
    {OP_T_32_shsax,  0x1, 0x1, "T_32_shsax",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_shsax()*/
    {OP_T_32_shsub16,  0x1, 0x1, "T_32_shsub16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_shsub16()*/
    {OP_T_32_shadd8,  0x1, 0x1, "T_32_shadd8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_shadd8()*/
    {OP_T_32_shsub8,  0x1, 0x1, "T_32_shsub8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_shsub8()*/
    {OP_T_32_uadd16,  0x1, 0x1, "T_32_uadd16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uadd16()*/
    {OP_T_32_uasx,  0x1, 0x1, "T_32_uasx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uasx()*/
    {OP_T_32_usax,  0x1, 0x1, "T_32_usax",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_usax()*/
    {OP_T_32_usub16,  0x1, 0x1, "T_32_usub16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_usub16()*/
    {OP_T_32_uadd8,  0x1, 0x1, "T_32_uadd8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uadd8()*/
    {OP_T_32_usub8,  0x1, 0x1, "T_32_usub8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_usub8()*/
    {OP_T_32_uqadd16,  0x1, 0x1, "T_32_uqadd16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uqadd16()*/
    {OP_T_32_uqasx,  0x1, 0x1, "T_32_uqasx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uqasx()*/
    {OP_T_32_uqsax,  0x1, 0x1, "T_32_uqsax",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uqsax()*/
    {OP_T_32_uqsub16,  0x1, 0x1, "T_32_uqsub16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uqsub16()*/
    {OP_T_32_uqadd8,  0x1, 0x1, "T_32_uqadd8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uqadd8()*/
    {OP_T_32_uqsub8,  0x1, 0x1, "T_32_uqsub8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uqsub8()*/
    {OP_T_32_uhadd16,  0x1, 0x1, "T_32_uhadd16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uhadd16()*/
    {OP_T_32_uhasx,  0x1, 0x1, "T_32_uhasx",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uhasx()*/
    {OP_T_32_uhsax,  0x1, 0x1, "T_32_uhsax",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uhsax()*/
    {OP_T_32_uhsub16,  0x1, 0x1, "T_32_uhsub16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uhsub16()*/
    {OP_T_32_uhadd8,  0x1, 0x1, "T_32_uhadd8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uhadd8()*/
    {OP_T_32_uhsub8,  0x1, 0x1, "T_32_uhsub8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_uhsub8()*/
    {OP_T_32_qadd,  0x1, 0x1, "T_32_qadd",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qadd()*/
    {OP_T_32_qdadd,  0x1, 0x1, "T_32_qdadd",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qdadd()*/
    {OP_T_32_qsub,  0x1, 0x1, "T_32_qsub",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qsub()*/
    {OP_T_32_qdsub,  0x1, 0x1, "T_32_qdsub",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_qdsub()*/
    {OP_T_32_rev,  0x1, 0x1, "T_32_rev",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_rev()*/
    {OP_T_32_rev16,  0x1, 0x1, "T_32_rev16",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_rev16()*/
    {OP_T_32_rbit,  0x1, 0x1, "T_32_rbit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_rbit()*/
    {OP_T_32_revsh,  0x1, 0x1, "T_32_revsh",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_revsh()*/
    {OP_T_32_sel,  0x1, 0x1, "T_32_sel",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sel()*/
    {OP_T_32_clz,  0x1, 0x1, "T_32_clz",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_clz()*/
    {OP_T_32_mla,  0x1, 0x1, "T_32_mla",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mla()*/
    {OP_T_32_mul,  0x1, 0x1, "T_32_mul",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mul()*/
    {OP_T_32_mls,  0x1, 0x1, "T_32_mls",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mls()*/
    {OP_T_32_smlabb,  0x1, 0x1, "T_32_smlabb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlabb()*/
    {OP_T_32_smlabt,  0x1, 0x1, "T_32_smlabt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlabt()*/
    {OP_T_32_smlatb,  0x1, 0x1, "T_32_smlatb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlatb()*/
    {OP_T_32_smlatt,  0x1, 0x1, "T_32_smlatt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlatt()*/
    {OP_T_32_smulbb,  0x1, 0x1, "T_32_smulbb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smulbb()*/
    {OP_T_32_smulbt,  0x1, 0x1, "T_32_smulbt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smulbt()*/
    {OP_T_32_smultb,  0x1, 0x1, "T_32_smultb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smultb()*/
    {OP_T_32_smultt,  0x1, 0x1, "T_32_smultt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smultt()*/
    {OP_T_32_smlad,  0x1, 0x1, "T_32_smlad",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlad()*/
    {OP_T_32_smuad,  0x1, 0x1, "T_32_smuad",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smuad()*/
    {OP_T_32_smlawb,  0x1, 0x1, "T_32_smlawb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlawb()*/
    {OP_T_32_smlawt,  0x1, 0x1, "T_32_smlawt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlawt()*/
    {OP_T_32_smulwb,  0x1, 0x1, "T_32_smulwb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smulwb()*/
    {OP_T_32_smulwt,  0x1, 0x1, "T_32_smulwt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smulwt()*/
    {OP_T_32_smlsd,  0x1, 0x1, "T_32_smlsd",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlsd()*/
    {OP_T_32_smusd,  0x1, 0x1, "T_32_smusd",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smusd()*/
    {OP_T_32_smmla,  0x1, 0x1, "T_32_smmla",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smmla()*/
    {OP_T_32_smmul,  0x1, 0x1, "T_32_smmul",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smmul()*/
    {OP_T_32_smmls,  0x1, 0x1, "T_32_smmls",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smmls()*/
    {OP_T_32_usad8,  0x1, 0x1, "T_32_usad8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_usad8()*/
    {OP_T_32_usada8,  0x1, 0x1, "T_32_usada8",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_usada8()*/
    {OP_T_32_smull,  0x1, 0x1, "T_32_smull",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smull()*/
    {OP_T_32_sdiv,  0x1, 0x1, "T_32_sdiv",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_sdiv()*/
    {OP_T_32_umull,  0x1, 0x1, "T_32_umull",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_umull()*/
    {OP_T_32_udiv,  0x1, 0x1, "T_32_udiv",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_udiv()*/
    {OP_T_32_smlal,  0x1, 0x1, "T_32_smlal",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlal()*/
    {OP_T_32_smlalbb,  0x1, 0x1, "T_32_smlalbb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlalbb()*/
    {OP_T_32_smlalbt,  0x1, 0x1, "T_32_smlalbt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlalbt()*/
    {OP_T_32_smlaltb,  0x1, 0x1, "T_32_smlaltb",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlaltb()*/
    {OP_T_32_smlaltt,  0x1, 0x1, "T_32_smlaltt",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlaltt()*/
    {OP_T_32_smlald,  0x1, 0x1, "T_32_smlald",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlald()*/
    {OP_T_32_smlsld,  0x1, 0x1, "T_32_smlsld",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_smlsld()*/
    {OP_T_32_umlal,  0x1, 0x1, "T_32_umlal",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_umlal()*/
    {OP_T_32_umaal,  0x1, 0x1, "T_32_umaal",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_umaal()*/
    {OP_T_32_stc,  0x1, 0x1, "T_32_stc",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_stc()*/
    {OP_T_32_stc2,  0x1, 0x1, "T_32_stc2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_stc2()*/
    {OP_T_32_ldc_imm,  0x1, 0x1, "T_32_ldc_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldc_imm()*/
    {OP_T_32_ldc_lit,  0x1, 0x1, "T_32_ldc_lit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldc_lit()*/
    {OP_T_32_ldc2_imm,  0x1, 0x1, "T_32_ldc2_imm",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldc2_imm()*/
    {OP_T_32_ldc2_lit,  0x1, 0x1, "T_32_ldc2_lit",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_ldc2_lit()*/
    {OP_T_32_mcrr,  0x1, 0x1, "T_32_mcrr",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mcrr()*/
    {OP_T_32_mcrr2,  0x1, 0x1, "T_32_mcrr2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mcrr2()*/
    {OP_T_32_mrrc,  0x1, 0x1, "T_32_mrrc",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mrrc()*/
    {OP_T_32_mrrc2,  0x1, 0x1, "T_32_mrrc2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mrrc2()*/
    {OP_T_32_cdp,  0x1, 0x1, "T_32_cdp",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_cdp()*/
    {OP_T_32_cdp2,  0x1, 0x1, "T_32_cdp2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_cdp2()*/
    {OP_T_32_mcr,  0x1, 0x1, "T_32_mcr",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mcr()*/
    {OP_T_32_mcr2,  0x1, 0x1, "T_32_mcr2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mcr2()*/
    {OP_T_32_mrc,  0x1, 0x1, "T_32_mrc",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mrc()*/
    {OP_T_32_mrc2,  0x1, 0x1, "T_32_mrc2",  xx, xx, xx,  xx,  xx,  0x0,  0x0, x, END_LIST}, /*T_32_mrc2()*/
};


/* At intruction F* page A8-100 in ARMv7-A tech manual. */
/* All ARM instructions are fixed length at 32 bits. 
   The opcode is split across multiple bits.*/
const instr_info_t armv7a_instrs[] = {
    /* opcode, instr_type, op, text, Dest1, Dest2, Src1, Src2, Src3, op2, flags, cpsr, code */
    {OP_adc_imm,     dpi, 0xa, "adc_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*adc_imm()*/
    {OP_adc_reg,     dpe, 0xa, "adc_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*adc_reg()*/
    {OP_adc_rsr,     dpe, 0xa, "adc_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*adc_rsr()*/
    {OP_add_imm,     dpi, 0x8, "add_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*add_imm()*/
    {OP_add_reg,     dpe, 0x8, "add_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*add_reg()*/
    {OP_add_rsr,     dpe, 0x8, "add_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*add_rsr()*/
    {OP_add_sp_imm,  dpi, 0x8, "add_sp_imm",Ra, xx,I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*add_sp_imm()*/
    {OP_add_sp_reg,  dpe, 0x8, "add_sp_reg",Ra, xx,Ra,  I5,  xx,  0x0, 0x0,  x, END_LIST}, /*add_sp_reg()*/
    {OP_adr,         dpi, 0x8, "adr",      Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*adr()*/
    {OP_and_imm,     dpi, 0x0, "and_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*and_imm()*/
    {OP_and_reg,     dpe, 0x0, "and_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*and_reg()*/
    {OP_and_rsr,     dpe, 0x0, "and_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*and_rsr()*/
    {OP_asr_imm,     dpe, 0x1a,"asr_imm",  Ra, xx, Ra,  I5,  xx,  0x4, 0x0,  x, END_LIST}, /*asr_imm()*/
    {OP_asr_reg,     dpe, 0x1a,"asr_reg",  Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*asr_reg()*/
    {OP_b,           bra, 0x0, "b",        xx, xx, J24, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*b()*/
    {OP_bfc,         ls2, 0x1c,"bfc",      Ra, xx, I5,  I5,  xx,  0x1, 0x0,  x, END_LIST}, /*bfc()*/
    {OP_bfi,         ls2, 0x1c,"bfi",      Ra, xx, Ra,  I5,  I5,  0x1, 0x0,  x, END_LIST}, /*bfi()*/
    {OP_bic_imm,     dpi, 0x1c,"bic_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*bic_imm()*/
    {OP_bic_reg,     dpe, 0x1c,"bic_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*bic_reg()*/
    {OP_bic_rsr,     dpe, 0x1c,"bic_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*bic_rsr()*/
    {OP_bkpt,        dpe, 0x12,"bkpt",     xx, xx, I12, I4,  xx,  0x7, 0x0,  x, END_LIST}, /*bkpt()*/
    {OP_bl,          bra, 0x10,"bl",       xx, xx, J24, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*bl()*/
    {OP_blx_imm,     bra, 0x10,"blx_imm",  xx, xx, J24, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*blx_imm()*/
    {OP_blx_reg,     dpe, 0x12,"blx_reg",  xx, xx, Ra,  xx,  xx,  0x3, 0x0,  x, END_LIST}, /*blx_reg()*/
    {OP_bx,          dpe, 0x12,"bx",       xx, xx, Ra,  xx,  xx,  0x1, 0x0,  x, END_LIST}, /*bx()*/
    {OP_bxj,         dpe, 0x12,"bxj",      xx, xx, Ra,  xx,  xx,  0x2, 0x0,  x, END_LIST}, /*bxj()*/
    {OP_cbnz,        0x0, 0x0, "cbnz",     xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*cbnz()*/
    {op_cbz,         0x0, 0x0, "cbz",      xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*cbz()*/
    {OP_cdp,         acs, 0x0, "cdp",      xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*cdp()*//* TODO */
    {OP_cdp2,        acs, 0x0, "cdp2",     xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*cdp2()*//* TODO */
    {OP_clrex,       ls1, 0x17,"clrex",    xx, xx, xx,  xx,  xx,  0x1, 0x0,  x, END_LIST}, /*clrex()*/
    {OP_clz,         dpe, 0x16,"clz",      Ra, xx, Ra,  xx,  xx,  0x1, 0x0,  x, END_LIST}, /*clz()*/
    {OP_cmn_imm,     dpi, 0x17,"cmn_imm",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*cmn_imm()*/
    {OP_cmn_reg,     dpe, 0x17,"cmn_reg",  Ra, xx, Ra,  I5,  xx,  0x0, 0x0,  x, END_LIST}, /*cmn_reg()*/
    {OP_cmn_rsr,     dpe, 0x17,"cmn_rsr",  Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*cmn_rsr()*/
    {OP_cmp_imm,     dpi, 0x15,"cmp_imm",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*cmp_imm()*/
    {OP_cmp_reg,     dpe, 0x15,"cmp_reg",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*cmp_reg()*/
    {OP_cmp_rsr,     dpe, 0x15,"cmp_rsr",  Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*cmp_rsr()*/
    {OP_cps,         0x0, 0x0, "cps",      xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*cps()*/
    {OP_dbg,         dpi, 0x12,"dbg",      xx, xx, I4,  xx,  xx,  0xf, 0x0,  x, END_LIST}, /*dbg()*/
    {OP_dmb,         ls1, 0x17,"dmb",      xx, xx, xx,  xx,  xx,  0x5, 0x0,  x, END_LIST}, /*dmb()*/
    {OP_dsb,         ls1, 0x17,"dsb",      xx, xx, I4,  xx,  xx,  0x4, 0x0,  x, END_LIST}, /*dsb()*/
    {OP_eor_imm,     dpi, 0x2, "eor_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*eor_imm()*/
    {OP_eor_reg,     dpe, 0x2, "eor_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*eor_reg()*/
    {OP_eor_rsr,     dpe, 0x2, "eor_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*eor_rsr()*/
    {OP_isb,         ls1, 0x17,"isb",      xx, xx, I4,  xx,  xx,  0x6, 0x0,  x, END_LIST}, /*isb()*/
    {OP_it,          0x0, 0x0, "it",       xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*it()*/
    {OP_ldc_imm,     cdm, 0x1, "ldc_imm",  Ra, xx, Cr,  Co,  I8,  0x0, 0x0,  x, END_LIST}, /*ldc_imm()*/
    {OP_ldc2_imm,    cdm, 0x1, "ldc2_imm", Ra, xx, Cr,  Co,  I8,  0x0, 0x0,  x, END_LIST}, /*ldc2_imm()*/
    {OP_ldc_lit,     cdm, 0x1, "ldc_lit",  xx, xx, Cr,  Co,  I8,  0x0, 0x0,  x, END_LIST}, /*ldc_lit()*/
    {OP_ldc2_lit,    cdm, 0x1, "ldc2_lit", xx, xx, Cr,  Co,  I8,  0x0, 0x0,  x, END_LIST}, /*ldc2_lit()*/
    {OP_ldm,         lsm, 0x9, "ldm",      Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldm()*/
    {OP_ldmia,       lsm, 0x9, "ldmia",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldmia()*/
    {OP_ldmfd,       lsm, 0x9, "ldmfd",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldmfd()*/
    {OP_ldmda,       lsm, 0x1, "ldmda",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldmda()*/
    {OP_ldmfa,       lsm, 0x1, "ldmfa",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldmfa()*/
    {OP_ldmdb,       lsm, 0x11,"ldmdb",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldmdb()*/
    {OP_ldmea,       lsm, 0x11,"ldmea",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldmea()*/
    {OP_ldmib,       lsm, 0x19,"ldmib",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldmib()*/
    {OP_ldmed,       lsm, 0x19,"ldmed",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldmed()*/
    {OP_ldr_imm,     ls1, 0x1, "ldr_imm",  Ra, xx, Ma,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*ldr_imm()*/
    {OP_ldr_lit,     ls1, 0x11,"ldr_lit",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldr_lit()*/
    {OP_ldr_reg,     ls2, 0x1, "ldr_reg",  Ra, xx, Ma,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*ldr_reg()*/
    {OP_ldrb_imm,    ls1, 0x5, "ldrb_imm", Ra, xx, Ma,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*ldrb_imm()*/
    {OP_ldrb_lit,    ls1, 0x15,"ldrb_lit", Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*ldrb_lit()*/
    {OP_ldrb_reg,    ls2, 0x5, "ldrb_reg", Ra, xx, Ma,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*ldrb_reg()*/
    {OP_ldrbt,       ls2, 0x7, "ldrbt",    Ra, xx, Ma,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*ldrbt()*//* TODO */
    {OP_ldrd_imm,    dpe, 0x4, "ldrd_imm", Ra, xx, Ma,  I4,  I4,  0xd, 0x0,  x, END_LIST}, /*ldrd_imm()*/
    {OP_ldrd_lit,    dpe, 0x14,"ldrd_lit", Ra, xx, I4,  I4,  xx,  0xd, 0x0,  x, END_LIST}, /*ldrd_lit()*/
    {OP_ldrd_reg,    dpe, 0x0, "ldrd_reg", Ra, xx, Ma,  Ra,  xx,  0xd, 0x0,  x, END_LIST}, /*ldrd_reg()*/
    {OP_ldrex,       dpe, 0x19,"ldrex",    Ra, xx, Ma,  xx,  xx,  0x9, 0x0,  x, END_LIST}, /*ldrex()*/
    {OP_ldrexb,      dpe, 0x1d,"ldrexb",   Ra, xx, Ma,  xx,  xx,  0x9, 0x0,  x, END_LIST}, /*ldrexb()*/
    {OP_ldrexd,      dpe, 0x1b,"ldrexd",   Ra, xx, Ma,  xx,  xx,  0x9, 0x0,  x, END_LIST}, /*ldrexd()*/
    {OP_ldrexh,      dpe, 0x1f,"ldrexh",   Ra, xx, Ma,  xx,  xx,  0x9, 0x0,  x, END_LIST}, /*ldrexh()*/
    {OP_ldrh_imm,    dpe, 0x5, "ldrh_imm", Ra, xx, Ma,  I4,  I4,  0xb, 0x0,  x, END_LIST}, /*ldrh_imm()*/
    {OP_ldrh_lit,    dpe, 0x15,"ldrh_lit", Ra, xx, I4,  I4,  xx,  0xb, 0x0,  x, END_LIST}, /*ldrh_lit()*/
    {OP_ldrh_reg,    dpe, 0x1, "ldrh_reg", Ra, xx, Ma,  Ra,  xx,  0xb, 0x0,  x, END_LIST}, /*ldrh_reg()*/
    {OP_ldrht,       dpe, 0x3, "ldrht",    Ra, xx, Ma,  Ra,  Ra,  0xb, 0x0,  x, END_LIST}, /*ldrht()*/
    {OP_ldrsb_imm,   dpe, 0x5, "ldrsb_imm",Ra, xx, Ma,  I4,  I4,  0xd, 0x0,  x, END_LIST}, /*ldrsb_imm()*/
    {OP_ldrsb_lit,   dpe, 0x15,"ldrsb_lit",Ra, xx, I4,  I4,  xx,  0xd, 0x0,  x, END_LIST}, /*ldrsb_lit()*/
    {OP_ldrsb_reg,   dpe, 0x1, "ldrsb_reg",Ra, xx, Ma,  Ra,  xx,  0xd, 0x0,  x, END_LIST}, /*ldrsb_reg()*/
    {OP_ldrsbt,      dpe, 0x3, "ldrsbt",   Ra, xx, Ma,  I4,  I4,  0xd, 0x0,  x, END_LIST}, /*ldrsbt()*/
    {OP_ldrsh_imm,   dpe, 0x5, "ldrsh_imm",Ra, xx, Ma,  I4,  I4,  0xf, 0x0,  x, END_LIST}, /*ldrsh_imm()*/
    {OP_ldrsh_lit,   dpe, 0x15,"ldrsh_lit",Ra, xx, I4,  I4,  xx,  0xf, 0x0,  x, END_LIST}, /*ldrsh_lit()*/
    {OP_ldrsh_reg,   dpe, 0x1, "ldrsh_reg",Ra, xx, Ma,  Ra,  xx,  0xf, 0x0,  x, END_LIST}, /*ldrsh_reg()*/
    {OP_ldrsht,      dpe, 0x7, "ldrsht",   Ra, xx, Ma,  I4,  I4,  0xf, 0x0,  x, END_LIST}, /*ldrsht()*/
    {OP_ldrt,        ls2, 0x3, "ldrt",     Ra, xx, Ma,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*ldrt()*/
    {OP_lsl_imm,     dpe, 0x1a,"lsl_imm",  Ra, xx, Ra,  I5,  xx,  0x0, 0x0,  x, END_LIST}, /*lsl_imm()*/
    {OP_lsl_reg,     dpe, 0x1a,"lsl_reg",  Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*lsl_reg()*/
    {OP_lsr_imm,     dpe, 0x1a,"lsr_imm",  Ra, xx, Ra,  I5,  xx,  0x2, 0x0,  x, END_LIST}, /*lsr_imm()*/
    {OP_lsr_reg,     dpe, 0x1a,"lsr_reg",  Ra, xx, Ra,  Ra,  xx,  0x3, 0x0,  x, END_LIST}, /*lsr_reg()*/
    {OP_mcr,         acs, 0x0, "mcr",      xx, xx, xx,  xx,  xx,  0x1, 0x0,  x, END_LIST}, /*mcr()*//* TODO */
    {OP_mcr2,        acs, 0x0, "mcr2",     xx, xx, xx,  xx,  xx,  0x1, 0x0,  x, END_LIST}, /*mcr2()*//* TODO */
    {OP_mcrr,        acs, 0x4, "mcrr",     xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*mcrr()*//* TODO */
    {OP_mcrr2,       acs, 0x4, "mcrr2",    xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*mcrr2()*//* TODO */
    {OP_mla,         dpe, 0x2, "mla",      Ra, xx, Ra,  Ra,  Ra,  0x9, 0x0,  x, END_LIST}, /*mla()*/
    {OP_mls,         dpe, 0x6, "mls",      Ra, xx, Ra,  Ra,  Ra,  0x9, 0x0,  x, END_LIST}, /*mls()*/
    {OP_mov_imm,     dpi, 0x1a,"mov_imm",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*mov_imm()*/
    {OP_mov_reg,     dpe, 0x1a,"mov_reg",  Ra, xx, Ra,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*mov_reg()*/
    {OP_movt,        dpi, 0x14,"movt",     Ra, xx, I4, I12,  xx,  0x0, 0x0,  x, END_LIST}, /*movt()*/
    {OP_mrc,         acs, 0x1, "mrc",      xx, xx, xx,  xx,  xx,  0x1, 0x0,  x, END_LIST}, /*mrc()*//* TODO */
    {OP_mrc2,        acs, 0x1, "mrc2",     xx, xx, xx,  xx,  xx,  0x1, 0x0,  x, END_LIST}, /*mrc2()*//* TODO */
    {OP_mrrc,        cdm, 0x5, "mrrc",     xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*mrrc()*//*TODO */
    {OP_mrrc2,       cdm, 0x5, "mrrc2",    xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*mrrc2()*//* TODO */
    {OP_mrs,         dpe, 0x10,"mrs",      xx, xx, Ra,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*mrs()*//* TODO */
    {OP_msr_imm,     dpi, 0x12,"msr_imm",  xx, xx, I12, Mk,  xx,  0x0, 0x0,  x, END_LIST}, /*msr_imm()*/
    {OP_msr_reg,     dpe, 0x12,"msr_reg",  xx, xx, Ra,  Mk,  xx,  0x0, 0x0,  x, END_LIST}, /*msr_reg()*/
    {OP_mul,         dpe, 0x0, "mul",      Ra, xx, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*mul()*/
    {OP_mvn_imm,     dpi, 0x1e,"mvn_imm",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*mvn_imm()*/
    {OP_mvn_reg,     dpe, 0x1e,"mvn_reg",  Ra, xx, Ra,  I5,  xx,  0x0, 0x0,  x, END_LIST}, /*mvn_reg()*/
    {OP_mvn_rsr,     dpe, 0x1e,"mvn_rsr",  Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*mvn_rsr()*/
    {OP_nop,         dpi, 0x12,"nop",      xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*nop()*/
    {OP_orn_imm,     0x0, 0x0, "orn_imm",  Ra, xx, Ra,  I8,  I3,  0x0, 0x0,  x, END_LIST}, /*orn_imm()*/
    {OP_orn_reg,     0x0, 0x0, "orn_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*orn_reg()*//* TODO */
    {OP_orr_imm,     dpi, 0x18,"orr_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*orr_imm()*/
    {OP_orr_reg,     dpe, 0x18,"orr_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*orr_reg()*/
    {OP_orr_rsr,     dpe, 0x18,"orr_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*orr_rsr()*/
    {OP_pkh,         ls2, 0x8, "pkh",      Ra, xx, Ra,  Ra,  I5,  0x1, 0x0,  x, END_LIST}, /*pkh()*/
    {OP_pld_imm,     ls1, 0x11,"pld_imm",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*pld_imm()*/
    {OP_pldw_imm,    ls2, 0x11,"pldw_imm", xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*pldw_imm()*/
    {OP_pld_lit,     dpi, 0x15,"pld_lit",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*pld_lit()*/
    {OP_pldw_lit,    ls1, 0x0, "pldw_lit", xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*pldw_lit()*/
    {OP_pld_reg,     ls2, 0x11,"pld_reg",  Ra, xx, Ra,  I5,  xx,  0x0, 0x0,  x, END_LIST}, /*pld_reg()*/
    {OP_pldw_reg,    ls2, 0x11,"pldw_reg", xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*pldw_reg()*/
    {OP_pli_imm,     ls1, 0x5, "pli_imm",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*pli_imm()*/
    {OP_pli_lit,     ls1, 0x5, "pli_lit",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*pli_lit()*/
    {OP_pli_reg,     ls2, 0x5, "pli_reg",  Ra, xx, Ra,  I5,  xx,  0x0, 0x0,  x, END_LIST}, /*pli_reg()*/
    {OP_pop,         lsm, 0xb, "pop",      xx, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*pop()*/
    {OP_push,        lsm, 0x12,"push",     xx, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*push()*/
    {OP_qadd,        dpe, 0x10,"qadd",     Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*qadd()*/
    {OP_qadd16,      ls2, 0x2, "qadd16",   Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*qadd16()*/
    {OP_qadd8,       ls2, 0x2, "qadd8",    Ra, xx, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*qadd8()*/
    {OP_qasx,        ls2, 0x2, "qasx",     Ra, xx, Ra,  Ra,  xx,  0x3, 0x0,  x, END_LIST}, /*qasx()*/
    {OP_qdadd,       dpe, 0x14,"qdadd",    Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*qdadd()*/
    {OP_qdsub,       dpe, 0x16,"qdsub",    Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*qdsub()*/
    {OP_qsax,        ls2, 0x2, "qsax",     Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*qsax()*/
    {OP_qsub,        dpe, 0x14,"qsub",     Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*qsub()*/
    {OP_qsub16,      ls2, 0x2, "qsub16",   Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*qsub16()*/
    {OP_qsub8,       ls2, 0x2, "qsub8",    Ra, xx, Ra,  Ra,  xx,  0xf, 0x0,  x, END_LIST}, /*qsub8()*/
    {OP_rbit,        ls2, 0xf, "rbit",     Ra, xx, Ra,  xx,  xx,  0x3, 0x0,  x, END_LIST}, /*rbit()*/
    {OP_rev,         ls2, 0xb, "rev",      Ra, xx, Ra,  xx,  xx,  0x3, 0x0,  x, END_LIST}, /*rev()*/
    {OP_rev16,       ls2, 0xb, "rev16",    Ra, xx, Ra,  xx,  xx,  0xb, 0x0,  x, END_LIST}, /*rev16()*/
    {OP_revsh,       ls2, 0xf, "revsh",    Ra, xx, Ra,  xx,  xx,  0xb, 0x0,  x, END_LIST}, /*revsh()*/
    {OP_rfe,         0x0, 0x0, "rfe",      xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*rfe()*/
    {OP_ror_imm,     dpe, 0x1a,"ror_imm",  Ra, xx, Ra,  I5,  xx,  0x6, 0x0,  x, END_LIST}, /*ror_imm()*/
    {OP_ror_reg,     dpe, 0x1a,"ror_reg",  Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*ror_reg()*/
    {OP_rrx,         dpe, 0x1a,"rrx",      Ra, xx, Ra,  xx,  xx,  0x6, 0x0,  x, END_LIST}, /*rrx()*/
    {OP_rsb_imm,     dpi, 0x6, "rsb_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*rsb_imm()*/
    {OP_rsb_reg,     dpe, 0x6, "rsb_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*rsb_reg()*/
    {OP_rsb_rsr,     dpe, 0x6, "rsb_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*rsb_rsr()*/
    {OP_rsc_imm,     dpi, 0xe, "rsc_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*rsc_imm()*/
    {OP_rsc_reg,     dpe, 0xe, "rsc_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*rsc_reg()*/
    {OP_rsc_rsr,     dpe, 0xe, "rsc_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*rsc_rsr()*/
    {OP_sadd16,      ls2, 0x1, "sadd16",   Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*sadd16()*/
    {OP_sadd8,       ls2, 0x1, "sadd8",    Ra, xx, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*sadd8()*/
    {OP_sasx,        ls2, 0x1, "sasx",     Ra, xx, Ra,  Ra,  xx,  0x3, 0x0,  x, END_LIST}, /*sasx()*/
    {OP_sbc_imm,     dpi, 0xc, "sbc_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*sbc_imm()*/
    {OP_sbc_reg,     dpe, 0xc, "sbc_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*sbc_reg()*/
    {OP_sbc_rsr,     dpe, 0xc, "sbc_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*sbc_rsr()*/
    {OP_sbfx,        ls2, 0x1a,"sbfx",     xx, xx, xx,  xx,  xx,  0x5, 0x0,  x, END_LIST}, /*sbfx()*//*TODO*/
    {OP_sdiv,        0x0, 0x0, "sdiv",     xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*sdiv()*/
    {OP_sel,         ls2, 0x8, "sel",      Ra, xx, Ra,  Ra,  xx,  0xb, 0x0,  x, END_LIST}, /*sel()*/
    {OP_setend,      dpe, 0x10,"setend",   xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*setend()*/
    {OP_sev,         dpi, 0x12,"sev",      xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*sev()*/
    {OP_shadd16,     ls2, 0x3, "shadd16",  Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*shadd16()*/
    {OP_shadd8,      ls2, 0x3, "shadd8",   Ra, xx, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*shadd8()*/
    {OP_shsax,       ls2, 0x3, "shsax",    Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*shsax()*/
    {OP_shsub16,     ls2, 0x3, "shsub16",  Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*shsub16()*/
    {OP_shsub8,      ls2, 0x3, "shsub8",   Ra, xx, Ra,  Ra,  xx,  0xf, 0x0,  x, END_LIST}, /*shsub8()*/
    {OP_smlabb,      dpe, 0x10,"smlabb",   Ra, xx, Ra,  Ra,  Ra,  0x8, 0x0,  x, END_LIST}, /*smlabb()*/
    {OP_smlabt,      dpe, 0x10,"smlabt",   Ra, xx, Ra,  Ra,  Ra,  0x8, 0x0,  x, END_LIST}, /*smlabt()*/
    {OP_smlatb,      dpe, 0x10,"smlatb",   Ra, xx, Ra,  Ra,  Ra,  0x8, 0x0,  x, END_LIST}, /*smlatb()*/
    {OP_smlatt,      dpe, 0x10,"smlatt",   Ra, xx, Ra,  Ra,  Ra,  0x8, 0x0,  x, END_LIST}, /*smlatt()*/
    {OP_smlad,       ls2, 0x10,"smlad",    Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*smlad()*/
    {OP_smlal,       dpe, 0xe, "smlal",    Ra, Ra, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*smlal()*/
    {OP_smlalbb,     dpe, 0x14,"smlalbb",  Ra, Ra, Ra,  Ra,  xx,  0x8, 0x0,  x, END_LIST}, /*smlalbb()*/
    {OP_smlalbt,     dpe, 0x14,"smlalbt",  Ra, Ra, Ra,  Ra,  xx,  0x8, 0x0,  x, END_LIST}, /*smlalbt()*/
    {OP_smlaltb,     dpe, 0x14,"smlaltb",  Ra, Ra, Ra,  Ra,  xx,  0x8, 0x0,  x, END_LIST}, /*smlaltb()*/
    {OP_smlaltt,     dpe, 0x14,"smlaltt",  Ra, Ra, Ra,  Ra,  xx,  0x8, 0x0,  x, END_LIST}, /*smlaltt()*/
    {OP_smlald,      ls2, 0x14,"smlald",   Ra, Ra, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*smlald()*/
    {OP_smlawb,      dpe, 0x12,"smlawb",   Ra, xx, Ra,  Ra,  Ra,  0x8, 0x0,  x, END_LIST}, /*smlawr()*/
    {OP_smlawt,      dpe, 0x12,"smlawt",   Ra, xx, Ra,  Ra,  Ra,  0x8, 0x0,  x, END_LIST}, /*smlawt()*/
    {OP_smlsd,       ls2, 0x10,"smlsd",    Ra, xx, Ra,  Ra,  Ra,  0x5, 0x0,  x, END_LIST}, /*smlsd()*/
    {OP_smlsld,      ls2, 0x14,"smlsld",   Ra, Ra, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*smlsld()*/
    {OP_smmla,       ls2, 0x15,"smmla",    Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*smmla()*/
    {OP_smmls,       ls2, 0x15,"smmls",    Ra, xx, Ra,  Ra,  Ra,  0xd, 0x0,  x, END_LIST}, /*smmls()*/
    {OP_smmul,       ls2, 0x15,"smmul",    Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*smmul()*/
    {OP_smuad,       ls2, 0x10,"smuad",    Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*smuad()*/
    {OP_smulbb,      dpe, 0x16,"smulbb",   Ra, xx, Ra,  Ra,  xx,  0x8, 0x0,  x, END_LIST}, /*smulbb()*/
    {OP_smulbt,      dpe, 0x16,"smulbt",   Ra, xx, Ra,  Ra,  xx,  0x8, 0x0,  x, END_LIST}, /*smulbt()*/
    {OP_smultb,      dpe, 0x16,"smultb",   Ra, xx, Ra,  Ra,  xx,  0x8, 0x0,  x, END_LIST}, /*smultb()*/
    {OP_smultt,      dpe, 0x16,"smultt",   Ra, xx, Ra,  Ra,  xx,  0x8, 0x0,  x, END_LIST}, /*smultt()*/
    {OP_smull,       dpe, 0xc, "smull",    Rh, Rl, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*smull()*/
    {OP_smulwb,      dpe, 0x12,"smulwb",   Ra, xx, Ra,  Ra,  xx,  0xa, 0x0,  x, END_LIST}, /*smulwb()*/
    {OP_smulwt,      dpe, 0x12,"smulwt",   Ra, xx, Ra,  Ra,  xx,  0xa, 0x0,  x, END_LIST}, /*smulwt()*/
    {OP_smusd,       ls2, 0x16,"smusd",    Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*smusd()*/
    {OP_srs,         0x0, 0x0, "srs",      xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*srs()*/
    {OP_ssat,        ls2, 0xa, "ssat",     Ra, xx, Ra,  I5,  I5,  0x1, 0x0,  x, END_LIST}, /*ssat()*/
    {OP_ssat16,      ls2, 0xa, "ssat16",   Ra, xx, Ra,  I5,  xx,  0x3, 0x0,  x, END_LIST}, /*ssat16()*/
    {OP_ssax,        ls2, 0x1, "ssax",     Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*ssax()*/
    {OP_ssub16,      ls2, 0x1, "ssub16",   Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*ssub16()*/
    {OP_ssub8,       ls2, 0x1, "ssub8",    Ra, xx, Ra,  Ra,  xx,  0xf, 0x0,  x, END_LIST}, /*ssub8()*/
    {OP_stc,         cdm, 0x0, "stc",      Ra, xx, Cr,  Co,  I8,  0x0, 0x0,  x, END_LIST}, /*stc()*/
    {OP_stc2,        cdm, 0x0, "stc2",     Ra, xx, Cr,  Co,  I8,  0x0, 0x0,  x, END_LIST}, /*stc2()*/
    {OP_stm,         lsm, 0x8, "stm",      Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*stm()*/
    {OP_stmia,       lsm, 0x8, "stmia",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*stmia()*/
    {OP_stmea,       lsm, 0x8, "stmea",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*stmea()*/
    {OP_stmda,       lsm, 0x0, "stmda",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*stmda()*/
    {OP_stmed,       lsm, 0x0, "stmed",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*stmed()*/
    {OP_stmdb,       lsm, 0x16,"stmdb",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*stmdb()*/
    {OP_stmfd,       lsm, 0x16,"stmfd",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*stmfd()*/
    {OP_stmib,       lsm, 0x18,"stmib",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*stmib()*/
    {OP_stmfa,       lsm, 0x18,"stmfa",    Ma, xx, Rl,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*stmfa()*/
    {OP_str_imm,     ls1, 0x0, "str_imm",  Ra, xx, Ma,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*str_imm()*/
    {OP_str_reg,     ls2, 0x0, "str_reg",  Ra, xx, Ma,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*str_reg()*/
    {OP_strb_imm,    ls1, 0x4, "strb_imm", Ra, xx, Ma,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*strb_imm()*/
    {OP_strb_reg,    ls2, 0x4, "strb_reg", Ra, xx, Ma,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*strb_reg()*/
    {OP_strbt,       ls1, 0x6, "strbt",    Ra, xx, Ma,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*strbt()*/
    {OP_strd_imm,    dpe, 0x4, "strd_imm", Ra, xx, Ma,  I4,  I4,  0xf, 0x0,  x, END_LIST}, /*strd_imm()*/
    {OP_strd_reg,    dpe, 0x0, "strd_reg", Ra, xx, Ma,  Ra,  xx,  0xf, 0x0,  x, END_LIST}, /*strd_reg()*/
    {OP_strex,       dpe, 0x18,"strex",    Ra, xx, Ma,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*strex()*/
    {OP_strexb,      dpe, 0x18,"strexb",   Ra, xx, Ma,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*strexb()*/
    {OP_strexd,      dpe, 0x1a,"strexd",   Ra, xx, Ma,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*strexd()*/
    {OP_strexh,      dpe, 0x1e,"strexh",   Ra, xx, Ma,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*strexh()*/
    {OP_strh_imm,    dpe, 0x4, "strh_imm", Ra, xx, Ma,  I4,  I4,  0xb, 0x0,  x, END_LIST}, /*strh_imm()*/
    {OP_strh_reg,    dpe, 0x0, "strh_reg", Ra, xx, Ma,  Ra,  xx,  0xb, 0x0,  x, END_LIST}, /*strh_reg()*/
    {OP_strht,       dpe, 0x6, "strht",    Ra, xx, Ma,  I4,  I4,  0xb, 0x0,  x, END_LIST}, /*strht()*/
    {OP_strt,        ls1, 0x4, "strt",     Ra, xx, Ma,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*strt()*/
    {OP_sub_imm,     dpi, 0x4, "sub_imm",  Ra, xx, Ra,  I12, xx,  0x0, 0x0,  x, END_LIST}, /*sub_imm()*/
    {OP_sub_reg,     dpe, 0x4, "sub_reg",  Ra, xx, Ra,  Ra,  I5,  0x0, 0x0,  x, END_LIST}, /*sub_reg()*/
    {OP_sub_rsr,     dpe, 0x4, "sub_rsr",  Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*sub_rsr()*/
    {OP_sub_sp_imm,  dpi, 0x4, "sub_sp_imm",Ra, xx, I12, xx,  xx, 0x0, 0x0,  x, END_LIST}, /*sub_sp_imm()*/
    {OP_sub_sp_reg,  dpe, 0x4, "sub_sp_reg",Ra, xx, Ra,  I5,  xx, 0x0, 0x0,  x, END_LIST}, /*sub_sp_reg()*/
    {OP_subs,        0x0, 0x0, "subs",     xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*subs()*/
    {OP_svc,         acs, 0x10,"svc",      xx, xx, I24, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*svc()*/
    {OP_swp,         dpe, 0x10,"swp",      Ma, xx, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*swp()*/
    {OP_swpb,        dpe, 0x10,"swpb",     Ma, xx, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*swpb()*/
    {OP_sxtab,       ls2, 0xa, "sxtab",    Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*sxtab()*/
    {OP_sxtab16,     ls2, 0x8, "sxtab16",  Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*sxtab16()*/
    {OP_sxtah,       ls2, 0xb, "sxtah",    Ra, xx, Ra,  xx,  xx,  0x7, 0x0,  x, END_LIST}, /*sxth()*/
    {OP_tbb,         0x0, 0x0, "tbb",      xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*tbb()*/
    {OP_tbh,         0x0, 0x0, "tbh",      xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*tbh()*/
    {OP_teq_imm,     dpi, 0x13,"teq_imm",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*teq_imm()*/
    {OP_teq_reg,     dpe, 0x13,"teq_reg",  Ra, xx, Ra,  I5,  xx,  0x0, 0x0,  x, END_LIST}, /*teq_reg()*/
    {OP_teq_rsr,     dpe, 0x13,"teq_rsr",  Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*teq_rsr()*/
    {OP_tst_imm,     dpi, 0x11,"tst_imm",  Ra, xx, I12, xx,  xx,  0x0, 0x0,  x, END_LIST}, /*tst_imm()*/
    {OP_tst_reg,     dpe, 0x11,"tst_reg",  Ra, xx, Ra,  I5,  xx,  0x0, 0x0,  x, END_LIST}, /*tst_reg()*/
    {OP_tst_rsr,     dpe, 0x11,"tst_rsr",  Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*tst_rsr()*/
    {OP_uadd16,      ls2, 0x7, "uadd16",   Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*uadd16()*/
    {OP_uadd8,       ls2, 0x7, "uadd8",    Ra, xx, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*uadd8()*/
    {OP_uasx,        ls2, 0x7, "uasx",     Ra, xx, Ra,  Ra,  xx,  0x3, 0x0,  x, END_LIST}, /*uasx()*/
    {OP_ubfx,        ls2, 0x1e,"ubfx",     Ra, xx, Ra,  I4,  I4,  0x5, 0x0,  x, END_LIST}, /*ubfx()*/
    {OP_udiv,        0x0, 0x0, "udiv",     xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*udiv()*/
    {OP_uhadd16,     ls2, 0x7, "uhadd16",  Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*uhadd16()*/
    {OP_uhadd8,      ls2, 0x7, "uhadd8",   Ra, xx, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*uhadd8()*/
    {OP_uhsax,       ls2, 0x7, "uhsax",    Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*uhsax()*/
    {OP_uhsub16,     ls2, 0x7, "uhsub16",  Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*uhsub16()*/
    {OP_uhsub8,      ls2, 0x7, "uhsub8",   Ra, xx, Ra,  Ra,  xx,  0xf, 0x0,  x, END_LIST}, /*uhsub8()*/
    {OP_umaal,       dpe, 0x4, "umaal",    Rh, Rl, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*umaal()*/
    {OP_umlal,       dpe, 0xa, "umlal",    Rh, Rl, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*umlal()*/
    {OP_umull,       dpe, 0x8, "umull",    Rh, Rl, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*umull()*/
    {OP_uqadd16,     ls2, 0x6, "uqadd16",  Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*uqadd16()*/
    {OP_uqadd8,      ls2, 0x6, "uqadd8",   Ra, xx, Ra,  Ra,  xx,  0x9, 0x0,  x, END_LIST}, /*uqadd8()*/
    {OP_uqasx,       ls2, 0x6, "uqasx",    Ra, xx, Ra,  Ra,  xx,  0x0, 0x0,  x, END_LIST}, /*uqasx()*/
    {OP_uqsax,       ls2, 0x6, "uqsax",    Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*uqsax()*/
    {OP_usub16,      ls2, 0x6, "usub16",   Ra, xx, Ra,  Ra,  xx,  0x0, 0x0,  x, END_LIST}, /*usub16()*/
    {OP_usub8,       ls2, 0x6, "usub8",    Ra, xx, Ra,  Ra,  xx,  0x0, 0x0,  x, END_LIST}, /*usub8()*/
    {OP_usad8,       ls2, 0x18,"usad8",    Ra, xx, Ra,  Ra,  xx,  0x1, 0x0,  x, END_LIST}, /*usad8()*/
    {OP_usada8,      ls2, 0x18,"usada8",   Ra, xx, Ra,  Ra,  Ra,  0x1, 0x0,  x, END_LIST}, /*usada8()*/
    {OP_usat,        ls2, 0xe, "usat",     Ra, xx, Ra,  I5,  I5,  0x1, 0x0,  x, END_LIST}, /*usat()*/
    {OP_usat16,      ls2, 0xe, "usat16",   Ra, xx, Ra,  I5,  xx,  0x3, 0x0,  x, END_LIST}, /*usat16()*/
    {OP_usax,        ls2, 0x5, "usax",     Ra, xx, Ra,  Ra,  xx,  0x5, 0x0,  x, END_LIST}, /*usax()*/
    {OP_uxtab,       ls2, 0xe, "uxtab",    Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*uxtab()*/
    {OP_uxtab16,     ls2, 0xc, "uxtab16",  Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*uxtab16()*/
    {OP_uxtah,       ls2, 0xf, "uxtah",    Ra, xx, Ra,  Ra,  xx,  0x7, 0x0,  x, END_LIST}, /*uxtah()*/
    {OP_uxtb,        ls2, 0xe, "uxtb",     Ra, xx, Ra,  xx,  xx,  0x7, 0x0,  x, END_LIST}, /*uxtb()*/
    {OP_uxtb16,      ls2, 0xc, "uxtb16",   Ra, xx, Ra,  xx,  xx,  0x7, 0x0,  x, END_LIST}, /*uxtb16()*/
    {OP_uxth,        ls2, 0xf, "uxth",     Ra, xx, Ra,  xx,  xx,  0x7, 0x0,  x, END_LIST}, /*uxth()*/
    {OP_vaba,        dpi, 0x8, "vaba",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vaba()*/
    {OP_vabal_int,   dpi, 0x0, "vabal_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vabal_int()*/
    {OP_vabd_int,    dpi, 0x0, "vabd_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vabd_int()*/
    {OP_vabd_flt,    dpi, 0x12,"vabd_flt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vabd_flt()*/
    {OP_vabs,        dpi, 0x1b,"vabs",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vabs()*/
    {OP_vacge,       dpi, 0x10,"vacge",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vacge()*/
    {OP_vacgt,       dpi, 0x10,"vacgt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vacgt()*/
    {OP_vacle,       dpi, 0x10,"vacle",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vacle()*/
    {OP_vaclt,       dpi, 0x10,"vaclt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vaclt()*/
    {OP_vadd_int,    dpi, 0x0, "vadd_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vadd_int()*/
    {OP_vadd_flt,    dpi, 0x0, "vadd_flt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vadd_flt()*/
    {OP_vaddhn,      dpi, 0x8, "vaddhn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vaddhn()*/
    {OP_vaddl,       dpi, 0x8, "vaddl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vaddl()*/
    {OP_vaddw,       dpi, 0x8, "vaddw",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vaddw()*/
    {OP_vand_imm,    0x0, 0x0, "vand_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vand_imm()*/
    {OP_vand_reg,    dpi, 0x0, "vand_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vand_reg()*/
    {OP_vbic_imm,    dpi, 0x8, "vbic_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vbic_imm()*/
    {OP_vbic_reg,    dpi, 0x1, "vbic_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vbic_reg()*/
    {OP_vbif,        dpi, 0x10,"vbif",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vbif()*/
    {OP_vbsl,        dpi, 0x10,"vbsl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vbsl()*/
    {OP_vceq_reg,    dpi, 0x10,"vceq_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vceq_reg()*/
    {OP_vceq_imm,    dpi, 0x1b,"vceq_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vceq_imm()*/
    {OP_vcge_reg,    dpi, 0x0, "vcge_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcge_reg()*/
    {OP_vcge_imm,    dpi, 0x1b,"vcge_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcge_imm()*/
    {OP_vcgt_reg,    dpi, 0x0, "vcgt_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcgt_reg()*/
    {OP_vcgt_imm,    dpi, 0x1b,"vcgt_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcgt_imm()*/
    {OP_vcle_reg,    0x0, 0x0, "vcle_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcle_reg()*/
    {OP_vcle_imm,    dpi, 0x1b,"vcle_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcle_imm()*/
    {OP_vcls,        dpi, 0x1b,"vcls",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcls()*/
    {OP_vclt_reg,    0x0, 0x0, "vclt_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vclt_reg()*/
    {OP_vclt_imm,    dpi, 0x1b,"vclt_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vclt_imm()*/
    {OP_vclz,        dpi, 0x1b,"vclz",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vclz()*/
    {OP_vcmp,        acs, 0xb, "vcmp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcmp()*/
    {OP_vcmpe,       acs, 0xb, "vcmpe",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcmpe()*/
    {OP_vcnt,        dpi, 0x1b,"vcnt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcnt()*/
    {OP_vcvt_flt_int_simd,  dpi, 0x1b, "vcvt_flt_int_simd",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcvt_flt_int_simd()*/
    {OP_vcvt_flt_int_vfp,  acs, 0xb, "vcvt_flt_int_vfp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcvt_flt_int_vfp()*/
    {OP_vcvtr_flt_int_vfp,  acs, 0xb, "vcvtr_flt_int_vfp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcvtr_flt_int_vfp()*/
    {OP_vcvt_flt_fip_simd,  dpi, 0x8, "vcvt_flt_fip_simd",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcvt_flt_fip_simd()*/
    {OP_vcvt_dp_sp,  acs, 0xb, "vcvt_dp_sp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcvt_dp_sp()*/
    {OP_vcvt_hp_sp_simd,  0x0, 0x0, "vcvt_hp_sp_simd",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcvt_hp_sp_simd()*/
    {OP_vcvtb_hp_sp_vfp,  0x0, 0x0, "vcvtb_hp_sp_vfp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcvtb_hp_sp_vfp()*/
    {OP_vcvtt_hp_sp_vfp,  0x0, 0x0, "vcvtt_hp_sp_vfp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vcvtt_hp_sp_vfp()*/
    {OP_vdiv,      acs, 0x8, "vdiv",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vdiv()*/
    {OP_vdup_scl,  dpi, 0x1b,"vdup_scl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vdup_scl()*/
    {OP_vdup_reg,  acs, 0x8, "vdup_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vdup_reg()*/
    {OP_veor,      dpi, 0x10,"veor",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*veor()*/
    {OP_vext,      dpi, 0xb, "vext",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vext()*/
    {OP_vhadd,     dpi, 0x0, "vhadd",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vhadd()*/
    {OP_vhsub,     dpi, 0x0, "vhsub",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vhsub()*/
    {OP_vld1_mse,  ls1, 0x2, "vld1_mse",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld1_mse()*/
    {OP_vld1_se1,  ls1, 0xa, "vld1_se1",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld1_se1()*/
    {OP_vld1_sea,  ls1, 0xa, "vld1_sea",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld1_sea()*/
    {OP_vld2_m2es,  ls1, 0x2, "vld2_m2es",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld2_m2es()*/
    {OP_vld2_s2e1,  ls1, 0xa, "vld2_s2e1",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld2_s2e1()*/
    {OP_vld2_s2ea,  ls1, 0xa, "vld2_s2ea",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld2_s2ea()*/
    {OP_vld3_m3s,   ls1, 0x2, "vld3_m3s",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld3_m3s()*/
    {OP_vld3_se1,   ls1, 0xa, "vld3_se1",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld3_se1()*/
    {OP_vld3_sea,   ls1, 0xa, "vld3_sea",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld3_sea()*/
    {OP_vld4_m4es,  ls1, 0x2, "vld4_m4es",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld4_m4es()*/
    {OP_vld4_se1,   ls1, 0xa, "vld4_se1",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld4_se1()*/
    {OP_vld4_s4ea,  ls1, 0xa, "vld4_s4ea",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vld4_s4ea()*/
    {OP_vldm,       cdm, 0x1, "vldm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vldm()*/
    {OP_vldr,       cdm, 0x11,"vldr",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vldr()*/
    {OP_vmax_int,   dpi, 0x0, "vmax_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmax_int()*/
    {OP_vmin_int,   dpi, 0x0, "vmin_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmin_int()*/
    {OP_vmax_flt,   dpi, 0x0, "vmax_flt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmax_flt()*/
    {OP_vmin_flt,   dpi, 0x0, "vmin_flt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmin_flt()*/
    {OP_vmla_int,   dpi, 0x8, "vmla_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmla_int()*/
    {OP_vmlal_int,  dpi, 0x8, "vmlal_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmlal_int()*/
    {OP_vmls_int,   dpi, 0x8, "vmls_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmls_int()*/
    {OP_vmlsl_int,  dpi, 0x8, "vmlsl_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmlsl_int()*/
    {OP_vmla_flt,   dpi, 0x0, "vmla_flt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmla_flt()*/
    {OP_vmls_flt,   dpi, 0x0, "vmls_flt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmls_flt()*/
    {OP_vmla_scl,   dpi, 0x8, "vmla_scl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmla_scl()*/
    {OP_vmlal_scl,  dpi, 0x8, "vmlal_scl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmlal_scl()*/
    {OP_vmls_scl,   dpi, 0x8, "vmls_scl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmls_scl()*/
    {OP_vmlsl_scl,  dpi, 0x8, "vmlsl_scl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmlsl_scl()*/
    {OP_vmov_imm,   dpi, 0x8, "vmov_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmov_imm()*/
    {OP_vmov_reg,   dpi, 0x2, "vmov_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmov_reg()*/
    {OP_vmov_reg_scl,  acs, 0x0, "vmov_reg_scl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmov_reg_scl()*/
    {OP_vmov_scl_reg,  acs, 0x1, "vmov_scl_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmov_scl_reg()*/
    {OP_vmov_reg_sp,   acs, 0x0, "vmov_reg_sp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmov_reg_sp()*/
    {OP_vmov_2reg_2sp,  cdm, 0x4, "vmov_2reg_2sp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmov_2reg_2sp()*/
    {OP_vmov_2reg_2dp,  cdm, 0x4, "vmov_2reg_2dp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmov_2reg_2dp()*/
    {OP_vmovl,          dpi, 0x8, "vmovl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmovl()*/
    {OP_vmovn,          dpi, 0x1b,"vmovn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmovn()*/
    {OP_vmrs,           acs, 0xf, "vmrs",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmrs()*/
    {OP_vmsr,           acs, 0xe, "vmsr",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmsr()*/
    {OP_vmul_int,       dpi, 0x8, "vmul_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmul_int()*/
    {OP_vmull_int,      dpi, 0x8, "vmull_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmull_int()*/
    {OP_vmul_flp,       dpi, 0x10,"vmul_flp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmul_flp()*/
    {OP_vmul_scl,       dpi, 0x8, "vmul_scl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmul_scl()*/
    {OP_vmull_scl,      dpi, 0x8, "vmull_scl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmull_scl()*/
    {OP_vmvn_imm,       dpi, 0x8, "vmvn_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmvn_imm()*/
    {OP_vmvn_reg,       dpi, 0x1b,"vmvn_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vmvn_reg()*/
    {OP_vneg,           dpi, 0x1b,"vneg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vneg()*/
    {OP_vnmla,          acs, 0x1, "vnmla",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vnmla()*/
    {OP_vnmls,          acs, 0x1, "vnmls",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vnmls()*/
    {OP_vnmul,          acs, 0x1, "vnmul",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vnmul()*/
    {OP_vorn_imm,       0x0, 0x0, "vorn_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vorn_imm()*/
    {OP_vorn_reg,       dpi, 0x3, "vorn_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vorn_reg()*/
    {OP_vorr_imm,       dpi, 0x8, "vorr_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vorr_imm()*/
    {OP_vorr_reg,       dpi, 0x2, "vorr_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vorr_reg()*/
    {OP_vpadal,         dpi, 0x1b,"vpadal",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpadal()*/
    {OP_vpadd_int,      dpi, 0x0, "vpadd_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpadd_int()*/
    {OP_vpadd_flp,      dpi, 0x10,"vpadd_flp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpadd_flp()*/
    {OP_vpaddl,         dpi, 0x1b,"vpaddl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpaddl()*/
    {OP_vpmax_int,      dpi, 0x0, "vpmax_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpmax_int()*/
    {OP_vpmin_int,      dpi, 0x0, "vpmin_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpmin_int()*/
    {OP_vpmax_flp,      dpi, 0x10,"vpmax_flp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpmax_flp()*/
    {OP_vpmin_flp,      dpi, 0x10,"vpmin_flp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpmin_flp()*/
    {OP_vpop,           cdm, 0xb, "vpop",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpop()*/
    {OP_vpush,          cdm, 0x13,"vpush",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vpush()*/
    {OP_vqabs,          dpi, 0x1b,"vqabs",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqabs()*/
    {OP_vqadd,          dpi, 0x0, "vqadd",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqadd()*/
    {OP_vqdmlal,        dpi, 0x8, "vqdmlal",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqdmlal()*/
    {OP_vqdmlsl,        dpi, 0x8, "vqdmlsl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqdmlsl()*/
    {OP_vqdmulh,        dpi, 0x0, "vqdmulh",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqdmulh()*/
    {OP_vqdmull,        dpi, 0x8, "vqdmull",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqdmull()*/
    {OP_vqdmovn,        dpi, 0x1b,"vqdmovn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqdmovn()*/
    {OP_vqdmovun,       dpi, 0x1b,"vqdmovun",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqdmovun()*/
    {OP_vqneq,          dpi, 0x1b,"vqneq",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqneq()*/
    {OP_vqrdmulh,       dpi, 0x10,"vqrdmulh",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqrdmulh()*/
    {OP_vqrshl,         dpi, 0x0, "vqrshl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqrshl()*/
    {OP_vqrshrn,        dpi, 0x8, "vqrshrn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqrshrn()*/
    {OP_vqrshrun,       dpi, 0x8, "vqrshrun",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqrshrun()*/
    {OP_vqshl_reg,      dpi, 0x0, "vqshl_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqshl_reg()*/
    {OP_vqshl_imm,      dpi, 0x8, "vqshl_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqshl_imm()*/
    {OP_vqshlu_imm,     dpi, 0x8, "vqshlu_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqshlu_imm()*/
    {OP_vqshrn,         dpi, 0x8, "vqshrn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqshrn()*/
    {OP_vqshrun,        dpi, 0x8, "vqshrun",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqshrun()*/
    {OP_vqsub,          dpi, 0x0, "vqsub",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqsub()*/
    {OP_vqraddhn,       dpi, 0x18,"vqraddhn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqraddhn()*/
    {OP_vqrecpe,        dpi, 0x1b,"vqrecpe",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqrecpe()*/
    {OP_vqrecps,        dpi, 0x0, "vqrecps",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vqrecps()*/
    {OP_vrev16,         dpi, 0x1b,"vrev16",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrev16()*/
    {OP_vrev32,         dpi, 0x1b,"vrev32",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrev32()*/
    {OP_vrev64,         dpi, 0x1b,"vrev64",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrev64()*/
    {OP_vrhadd,         dpi, 0x0, "vrhadd",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrhadd()*/
    {OP_vrshl,          dpi, 0x0, "vrshl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrshl()*/
    {OP_vrshr,          dpi, 0x8, "vrshr",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrshr()*/
    {OP_vrshrn,         dpi, 0x8, "vrshrn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrshrn()*/
    {OP_vrsqrte,        dpi, 0x1b,"vrsqrte",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrsqrte()*/
    {OP_vrsqrts,        dpi, 0x2, "vrsqrts",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrsqrts()*/
    {OP_vrsra,          dpi, 0x8, "vrsra",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrsra()*/
    {OP_vrsubhn,        dpi, 0x18,"vrsubhn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vrsubhn()*/
    {OP_vshl_imm,       dpi, 0x8, "vshl_imm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vshl_imm()*/
    {OP_vshl_reg,       dpi, 0x0, "vshl_reg",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vshl_reg()*/
    {OP_vshll,          dpi, 0x8, "vshll",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vshll()*/
    {OP_vshr,           dpi, 0x8, "vshr",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vshr()*/
    {OP_vshrn,          dpi, 0x8, "vshrn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vshrn()*/
    {OP_vsli,           dpi, 0x18,"vsli",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vsli()*/
    {OP_vsqrt,          acs, 0xb, "vsqrt",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vsqrt()*/
    {OP_vsra,           dpi, 0x8, "vsra",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vsra()*/
    {OP_vsri,           dpi, 0x18,"vsri",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vsri()*/
    {OP_vst1_mse,       ls1, 0x0, "vst1_mse",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vst1_mse()*/
    {OP_vst1_se1,       ls1, 0x8, "vst1_se1",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vst1_se1()*/
    {OP_vst2_m2e,       ls1, 0x0, "vst2_m2e",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vst2_m2e()*/
    {OP_vst2_s2e1,      ls1, 0x8, "vst2_s2e1",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vst2_s2e1()*/
    {OP_vst3_m3es,      ls1, 0x0, "vst3_m3es",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vst3_m3es()*/
    {OP_vst3_s3e1,      ls1, 0x8, "vst3_s3e1",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vst3_s3e1()*/
    {OP_vst4_m4es,      ls1, 0x0, "vst4_m4es",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vst4_m4es()*/
    {OP_vst4_s4e1,      ls1, 0x8, "vst4_s4e1",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vst4_s4e1()*/
    {OP_vstm,           cdm, 0x0, "vstm",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vstm()*/
    {OP_vstr,           cdm, 0x10,"vstr",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vstr()*/
    {OP_vsub_int,       dpi, 0x10,"vsub_int",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vsub_int()*/
    {OP_vsub_flp,       dpi, 0x2, "vsub_flp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vsub_flp()*/
    {OP_vsubhn,         dpi, 0x8, "vsubhn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vsubhn()*/
    {OP_vsubl,          dpi, 0x8, "vsubl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vsubl()*/
    {OP_vsubw,          dpi, 0x8, "vsubw",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vsubw()*/
    {OP_vswp,           dpi, 0x1b,"vswp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vswp()*/
    {OP_vtbl,           dpi, 0x1b,"vtbl",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vtbl()*/
    {OP_vtbx,           dpi, 0x1b, "vtbx",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vtbx()*/
    {OP_vtrn,           dpi, 0x1b,"vtrn",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vtrn()*/
    {OP_vtst,           dpi, 0x0, "vtst",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vtst()*/
    {OP_vuzp,           dpi, 0x1b,"vuzp",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vuzp()*/
    {OP_vzip,           dpi, 0x1b,"vzip",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*vzip()*/
    {OP_wfe,            dpi, 0x12,"wfe",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*wfe()*/
    {OP_wfi,            dpi, 0x12,"wfi",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*wfi()*/
    {OP_yield,          dpi, 0x12,"yield",  xx, xx, xx,  xx,  xx,  0x0, 0x0,  x, END_LIST}, /*yield()*/
};

/* SJF TODO 
const instr_info_t thumb_instrs[] = {
    {OP_and,  0x000000, "add",  Ra, xx, Ra, Ra, xx, mrm, x, END_LIST},
};
*/


/****************************************************************************
 * Added ARMv7-A instructions from technical manual.
 * Use a different opcode for each instruction variation.
 ****************************************************************************
 */

const instr_info_t * const op_instr[] =
{
    /* OP_INVALID */   NULL,
    /* OP_UNDECODED */ NULL,
    /* OP_CONTD   */   NULL,
    /* OP_LABEL   */   NULL,
    /* OP_adc_imm */    &armv7a_instrs[0],
    /* OP_adc_reg */    &armv7a_instrs[1],
    /* OP_adc_rsr */    &armv7a_instrs[2],
    /* OP_add_imm */    &armv7a_instrs[3],
    /* OP_add_reg */    &armv7a_instrs[4],
    /* OP_add_rsr */    &armv7a_instrs[5],
    /* OP_add_sp_imm */    &armv7a_instrs[6],
    /* OP_add_sp_reg */    &armv7a_instrs[7],
    /* OP_adr */    &armv7a_instrs[8],
    /* OP_and_imm */    &armv7a_instrs[9],
    /* OP_and_reg */    &armv7a_instrs[10],
    /* OP_and_rsr */    &armv7a_instrs[11],
    /* OP_asr_imm */    &armv7a_instrs[12],
    /* OP_asr_reg */    &armv7a_instrs[13],
    /* OP_b */    &armv7a_instrs[14],
    /* OP_bfc */    &armv7a_instrs[15],
    /* OP_bfi */    &armv7a_instrs[16],
    /* OP_bic_imm */    &armv7a_instrs[17],
    /* OP_bic_reg */    &armv7a_instrs[18],
    /* OP_bic_rsr */    &armv7a_instrs[19],
    /* OP_bkpt */    &armv7a_instrs[20],
    /* OP_bl */    &armv7a_instrs[21],
    /* OP_blx_imm */    &armv7a_instrs[22],
    /* OP_blx_reg */    &armv7a_instrs[23],
    /* OP_bx */    &armv7a_instrs[24],
    /* OP_bxj */    &armv7a_instrs[25],
    /* OP_cbnz */    &armv7a_instrs[26],
    /* op_cbz */    &armv7a_instrs[27],
    /* OP_cdp */    &armv7a_instrs[28],
    /* OP_cdp2 */    &armv7a_instrs[29],
    /* OP_clrex */    &armv7a_instrs[30],
    /* OP_clz */    &armv7a_instrs[31],
    /* OP_cmn_imm */    &armv7a_instrs[32],
    /* OP_cmn_reg */    &armv7a_instrs[33],
    /* OP_cmn_rsr */    &armv7a_instrs[34],
    /* OP_cmp_imm */    &armv7a_instrs[35],
    /* OP_cmp_reg */    &armv7a_instrs[36],
    /* OP_cmp_rsr */    &armv7a_instrs[37],
    /* OP_cps */    &armv7a_instrs[38],
    /* OP_dbg */    &armv7a_instrs[39],
    /* OP_dmb */    &armv7a_instrs[40],
    /* OP_dsb */    &armv7a_instrs[41],
    /* OP_eor_imm */    &armv7a_instrs[42],
    /* OP_eor_reg */    &armv7a_instrs[43],
    /* OP_eor_rsr */    &armv7a_instrs[44],
    /* OP_isb */    &armv7a_instrs[45],
    /* OP_it */    &armv7a_instrs[46],
    /* OP_ldc_imm */    &armv7a_instrs[47],
    /* OP_ldc2_imm */    &armv7a_instrs[48],
    /* OP_ldc_lit */    &armv7a_instrs[49],
    /* OP_ldc2_lit */    &armv7a_instrs[50],
    /* OP_ldm */    &armv7a_instrs[51],
    /* OP_ldmia */    &armv7a_instrs[52],
    /* OP_ldmfd */    &armv7a_instrs[53],
    /* OP_ldmda */    &armv7a_instrs[54],
    /* OP_ldmfa */    &armv7a_instrs[55],
    /* OP_ldmdb */    &armv7a_instrs[56],
    /* OP_ldmea */    &armv7a_instrs[57],
    /* OP_ldmib */    &armv7a_instrs[58],
    /* OP_ldmed */    &armv7a_instrs[59],
    /* OP_ldr_imm */    &armv7a_instrs[60],
    /* OP_ldr_lit */    &armv7a_instrs[61],
    /* OP_ldr_reg */    &armv7a_instrs[62],
    /* OP_ldrb_imm */    &armv7a_instrs[63],
    /* OP_ldrb_lit */    &armv7a_instrs[64],
    /* OP_ldrb_reg */    &armv7a_instrs[65],
    /* OP_ldrbt */    &armv7a_instrs[66],
    /* OP_ldrd_imm */    &armv7a_instrs[67],
    /* OP_ldrd_lit */    &armv7a_instrs[68],
    /* OP_ldrd_reg */    &armv7a_instrs[69],
    /* OP_ldrex */    &armv7a_instrs[70],
    /* OP_ldrexb */    &armv7a_instrs[71],
    /* OP_ldrexd */    &armv7a_instrs[72],
    /* OP_ldrexh */    &armv7a_instrs[73],
    /* OP_ldrh_imm */    &armv7a_instrs[74],
    /* OP_ldrh_lit */    &armv7a_instrs[75],
    /* OP_ldrh_reg */    &armv7a_instrs[76],
    /* OP_ldrht */    &armv7a_instrs[77],
    /* OP_ldrsb_imm */    &armv7a_instrs[78],
    /* OP_ldrsb_lit */    &armv7a_instrs[79],
    /* OP_ldrsb_reg */    &armv7a_instrs[80],
    /* OP_ldrsbt */    &armv7a_instrs[81],
    /* OP_ldrsh_imm */    &armv7a_instrs[82],
    /* OP_ldrsh_lit */    &armv7a_instrs[83],
    /* OP_ldrsh_reg */    &armv7a_instrs[84],
    /* OP_ldrsht */    &armv7a_instrs[85],
    /* OP_ldrt */    &armv7a_instrs[86],
    /* OP_lsl_imm */    &armv7a_instrs[87],
    /* OP_lsl_reg */    &armv7a_instrs[88],
    /* OP_lsr_imm */    &armv7a_instrs[89],
    /* OP_lsr_reg */    &armv7a_instrs[90],
    /* OP_mcr */    &armv7a_instrs[91],
    /* OP_mcr2 */    &armv7a_instrs[92],
    /* OP_mcrr */    &armv7a_instrs[93],
    /* OP_mcrr2 */    &armv7a_instrs[94],
    /* OP_mla */    &armv7a_instrs[95],
    /* OP_mls */    &armv7a_instrs[96],
    /* OP_mov_imm */    &armv7a_instrs[97],
    /* OP_mov_reg */    &armv7a_instrs[98],
    /* OP_movt */    &armv7a_instrs[99],
    /* OP_mrc */    &armv7a_instrs[100],
    /* OP_mrc2 */    &armv7a_instrs[101],
    /* OP_mrrc */    &armv7a_instrs[102],
    /* OP_mrrc2 */    &armv7a_instrs[103],
    /* OP_mrs */    &armv7a_instrs[104],
    /* OP_msr_imm */    &armv7a_instrs[105],
    /* OP_msr_reg */    &armv7a_instrs[106],
    /* OP_mul */    &armv7a_instrs[107],
    /* OP_mvn_imm */    &armv7a_instrs[108],
    /* OP_mvn_reg */    &armv7a_instrs[109],
    /* OP_mvn_rsr */    &armv7a_instrs[110],
    /* OP_nop */    &armv7a_instrs[111],
    /* OP_orn_imm */    &armv7a_instrs[112],
    /* OP_orn_reg */    &armv7a_instrs[113],
    /* OP_orr_imm */    &armv7a_instrs[114],
    /* OP_orr_reg */    &armv7a_instrs[115],
    /* OP_orr_rsr */    &armv7a_instrs[116],
    /* OP_pkh */    &armv7a_instrs[117],
    /* OP_pld_imm */    &armv7a_instrs[118],
    /* OP_pldw_imm */    &armv7a_instrs[119],
    /* OP_pld_lit */    &armv7a_instrs[120],
    /* OP_pldw_lit */    &armv7a_instrs[121],
    /* OP_pld_reg */    &armv7a_instrs[122],
    /* OP_pldw_reg */    &armv7a_instrs[123],
    /* OP_pli_imm */    &armv7a_instrs[124],
    /* OP_pli_lit */    &armv7a_instrs[125],
    /* OP_pli_reg */    &armv7a_instrs[126],
    /* OP_pop */    &armv7a_instrs[127],
    /* OP_push */    &armv7a_instrs[128],
    /* OP_qadd */    &armv7a_instrs[129],
    /* OP_qadd16 */    &armv7a_instrs[130],
    /* OP_qadd8 */    &armv7a_instrs[131],
    /* OP_qasx */    &armv7a_instrs[132],
    /* OP_qdadd */    &armv7a_instrs[133],
    /* OP_qdsub */    &armv7a_instrs[134],
    /* OP_qsax */    &armv7a_instrs[135],
    /* OP_qsub */    &armv7a_instrs[136],
    /* OP_qsub16 */    &armv7a_instrs[137],
    /* OP_qsub8 */    &armv7a_instrs[138],
    /* OP_rbit */    &armv7a_instrs[139],
    /* OP_rev */    &armv7a_instrs[140],
    /* OP_rev16 */    &armv7a_instrs[141],
    /* OP_revsh */    &armv7a_instrs[142],
    /* OP_rfe */    &armv7a_instrs[143],
    /* OP_ror_imm */    &armv7a_instrs[144],
    /* OP_ror_reg */    &armv7a_instrs[145],
    /* OP_rrx */    &armv7a_instrs[146],
    /* OP_rsb_imm */    &armv7a_instrs[147],
    /* OP_rsb_reg */    &armv7a_instrs[148],
    /* OP_rsb_rsr */    &armv7a_instrs[149],
    /* OP_rsc_imm */    &armv7a_instrs[150],
    /* OP_rsc_reg */    &armv7a_instrs[151],
    /* OP_rsc_rsr */    &armv7a_instrs[152],
    /* OP_sadd16 */    &armv7a_instrs[153],
    /* OP_sadd8 */    &armv7a_instrs[154],
    /* OP_sasx */    &armv7a_instrs[155],
    /* OP_sbc_imm */    &armv7a_instrs[156],
    /* OP_sbc_reg */    &armv7a_instrs[157],
    /* OP_sbc_rsr */    &armv7a_instrs[158],
    /* OP_sbfx */    &armv7a_instrs[159],
    /* OP_sdiv */    &armv7a_instrs[160],
    /* OP_sel */    &armv7a_instrs[161],
    /* OP_setend */    &armv7a_instrs[162],
    /* OP_sev */    &armv7a_instrs[163],
    /* OP_shadd16 */    &armv7a_instrs[164],
    /* OP_shadd8 */    &armv7a_instrs[165],
    /* OP_shsax */    &armv7a_instrs[166],
    /* OP_shsub16 */    &armv7a_instrs[167],
    /* OP_shsub8 */    &armv7a_instrs[168],
    /* OP_smlabb */    &armv7a_instrs[169],
    /* OP_smlabt */    &armv7a_instrs[170],
    /* OP_smlatb */    &armv7a_instrs[171],
    /* OP_smlatt */    &armv7a_instrs[172],
    /* OP_smlad */    &armv7a_instrs[173],
    /* OP_smlal */    &armv7a_instrs[174],
    /* OP_smlalbb */    &armv7a_instrs[175],
    /* OP_smlalbt */    &armv7a_instrs[176],
    /* OP_smlaltb */    &armv7a_instrs[177],
    /* OP_smlaltt */    &armv7a_instrs[178],
    /* OP_smlald */    &armv7a_instrs[179],
    /* OP_smlawb */    &armv7a_instrs[180],
    /* OP_smlawt */    &armv7a_instrs[181],
    /* OP_smlsd */    &armv7a_instrs[182],
    /* OP_smlsld */    &armv7a_instrs[183],
    /* OP_smmla */    &armv7a_instrs[184],
    /* OP_smmls */    &armv7a_instrs[185],
    /* OP_smmul */    &armv7a_instrs[186],
    /* OP_smuad */    &armv7a_instrs[187],
    /* OP_smulbb */    &armv7a_instrs[188],
    /* OP_smulbt */    &armv7a_instrs[189],
    /* OP_smultb */    &armv7a_instrs[190],
    /* OP_smultt */    &armv7a_instrs[191],
    /* OP_smull */    &armv7a_instrs[192],
    /* OP_smulwb */    &armv7a_instrs[193],
    /* OP_smulwt */    &armv7a_instrs[194],
    /* OP_smusd */    &armv7a_instrs[195],
    /* OP_srs */    &armv7a_instrs[196],
    /* OP_ssat */    &armv7a_instrs[197],
    /* OP_ssat16 */    &armv7a_instrs[198],
    /* OP_ssax */    &armv7a_instrs[199],
    /* OP_ssub16 */    &armv7a_instrs[200],
    /* OP_ssub8 */    &armv7a_instrs[201],
    /* OP_stc */    &armv7a_instrs[202],
    /* OP_stc2 */    &armv7a_instrs[203],
    /* OP_stm */    &armv7a_instrs[204],
    /* OP_stmia */    &armv7a_instrs[205],
    /* OP_stmea */    &armv7a_instrs[206],
    /* OP_stmda */    &armv7a_instrs[207],
    /* OP_stmed */    &armv7a_instrs[208],
    /* OP_stmdb */    &armv7a_instrs[209],
    /* OP_stmfd */    &armv7a_instrs[210],
    /* OP_stmib */    &armv7a_instrs[211],
    /* OP_stmfa */    &armv7a_instrs[212],
    /* OP_str_imm */    &armv7a_instrs[213],
    /* OP_str_reg */    &armv7a_instrs[214],
    /* OP_strb_imm */    &armv7a_instrs[215],
    /* OP_strb_reg */    &armv7a_instrs[216],
    /* OP_strbt */    &armv7a_instrs[217],
    /* OP_strd_imm */    &armv7a_instrs[218],
    /* OP_strd_reg */    &armv7a_instrs[219],
    /* OP_strex */    &armv7a_instrs[220],
    /* OP_strexb */    &armv7a_instrs[221],
    /* OP_strexd */    &armv7a_instrs[222],
    /* OP_strexh */    &armv7a_instrs[223],
    /* OP_strh_imm */    &armv7a_instrs[224],
    /* OP_strh_reg */    &armv7a_instrs[225],
    /* OP_strht */    &armv7a_instrs[226],
    /* OP_strt */    &armv7a_instrs[227],
    /* OP_sub_imm */    &armv7a_instrs[228],
    /* OP_sub_reg */    &armv7a_instrs[229],
    /* OP_sub_rsr */    &armv7a_instrs[230],
    /* OP_sub_sp_imm */    &armv7a_instrs[231],
    /* OP_sub_sp_reg */    &armv7a_instrs[232],
    /* OP_subs */    &armv7a_instrs[233],
    /* OP_svc */    &armv7a_instrs[234],
    /* OP_swp */    &armv7a_instrs[235],
    /* OP_swpb */    &armv7a_instrs[236],
    /* OP_sxtab */    &armv7a_instrs[237],
    /* OP_sxtab16 */    &armv7a_instrs[238],
    /* OP_sxtah */   &armv7a_instrs[239],
    /* OP_tbb */    &armv7a_instrs[240],
    /* OP_tbh */    &armv7a_instrs[241],
    /* OP_teq_imm */    &armv7a_instrs[242],
    /* OP_teq_reg */    &armv7a_instrs[243],
    /* OP_teq_rsr */    &armv7a_instrs[244],
    /* OP_tst_imm */    &armv7a_instrs[245],
    /* OP_tst_reg */    &armv7a_instrs[246],
    /* OP_tst_rsr */    &armv7a_instrs[247],
    /* OP_uadd16 */    &armv7a_instrs[248],
    /* OP_uadd8 */    &armv7a_instrs[249],
    /* OP_uasx */    &armv7a_instrs[250],
    /* OP_ubfx */    &armv7a_instrs[251],
    /* OP_udiv */    &armv7a_instrs[252],
    /* OP_uhadd16 */    &armv7a_instrs[253],
    /* OP_uhadd8 */    &armv7a_instrs[254],
    /* OP_uhsax */    &armv7a_instrs[255],
    /* OP_uhsub16 */    &armv7a_instrs[256],
    /* OP_uhsub8 */    &armv7a_instrs[257],
    /* OP_umaal */    &armv7a_instrs[258],
    /* OP_umlal */    &armv7a_instrs[259],
    /* OP_umull */    &armv7a_instrs[260],
    /* OP_uqadd16 */    &armv7a_instrs[261],
    /* OP_uqadd8 */    &armv7a_instrs[262],
    /* OP_uqasx */    &armv7a_instrs[263],
    /* OP_uqsax */    &armv7a_instrs[264],
    /* OP_usub16 */    &armv7a_instrs[265],
    /* OP_usub8 */    &armv7a_instrs[266],
    /* OP_usad8 */    &armv7a_instrs[267],
    /* OP_usada8 */    &armv7a_instrs[268],
    /* OP_usat */    &armv7a_instrs[269],
    /* OP_usat16 */    &armv7a_instrs[270],
    /* OP_usax */    &armv7a_instrs[271],
    /* OP_uxtab */    &armv7a_instrs[272],
    /* OP_uxtab16 */    &armv7a_instrs[273],
    /* OP_uxtah */    &armv7a_instrs[274],
    /* OP_uxtb */    &armv7a_instrs[275],
    /* OP_uxtb16 */    &armv7a_instrs[276],
    /* OP_uxth */    &armv7a_instrs[277],
    /* OP_vaba */    &armv7a_instrs[278],
    /* OP_vabal_int */    &armv7a_instrs[279],
    /* OP_vabd_int */    &armv7a_instrs[280],
    /* OP_vabd_flt */    &armv7a_instrs[281],
    /* OP_vabs */    &armv7a_instrs[282],
    /* OP_vacge */    &armv7a_instrs[283],
    /* OP_vacgt */    &armv7a_instrs[284],
    /* OP_vacle */    &armv7a_instrs[285],
    /* OP_vaclt */    &armv7a_instrs[286],
    /* OP_vadd_int */    &armv7a_instrs[287],
    /* OP_vadd_flt */    &armv7a_instrs[288],
    /* OP_vaddhn */    &armv7a_instrs[289],
    /* OP_vaddl */    &armv7a_instrs[290],
    /* OP_vaddw */    &armv7a_instrs[291],
    /* OP_vand_imm */    &armv7a_instrs[292],
    /* OP_vand_reg */    &armv7a_instrs[293],
    /* OP_vbic_imm */    &armv7a_instrs[294],
    /* OP_vbic_reg */    &armv7a_instrs[295],
    /* OP_vbif */    &armv7a_instrs[296],
    /* OP_vbsl */    &armv7a_instrs[297],
    /* OP_vceq_reg */    &armv7a_instrs[298],
    /* OP_vceq_imm */    &armv7a_instrs[299],
    /* OP_vcge_reg */    &armv7a_instrs[300],
    /* OP_vcge_imm */    &armv7a_instrs[301],
    /* OP_vcgt_reg */    &armv7a_instrs[302],
    /* OP_vcgt_imm */    &armv7a_instrs[303],
    /* OP_vcle_reg */    &armv7a_instrs[304],
    /* OP_vcle_imm */    &armv7a_instrs[305],
    /* OP_vcls */    &armv7a_instrs[306],
    /* OP_vclt_reg */    &armv7a_instrs[307],
    /* OP_vclt_imm */    &armv7a_instrs[308],
    /* OP_vclz */    &armv7a_instrs[309],
    /* OP_vcmp */    &armv7a_instrs[310],
    /* OP_vcmpe */    &armv7a_instrs[311],
    /* OP_vcnt */    &armv7a_instrs[312],
    /* OP_vcvt_flt_int_simd */    &armv7a_instrs[313],
    /* OP_vcvt_flt_int_vfp */    &armv7a_instrs[314],
    /* OP_vcvtr_flt_int_vfp */    &armv7a_instrs[315],
    /* OP_vcvt_flt_fip_simd */    &armv7a_instrs[316],
    /* OP_vcvt_dp_sp */    &armv7a_instrs[317],
    /* OP_vcvt_hp_sp_simd */    &armv7a_instrs[318],
    /* OP_vcvtb_hp_sp_vfp */    &armv7a_instrs[319],
    /* OP_vcvtt_hp_sp_vfp */    &armv7a_instrs[320],
    /* OP_vdiv */    &armv7a_instrs[321],
    /* OP_vdup_scl */    &armv7a_instrs[322],
    /* OP_vdup_reg */    &armv7a_instrs[323],
    /* OP_veor */    &armv7a_instrs[324],
    /* OP_vext */    &armv7a_instrs[325],
    /* OP_vhadd */    &armv7a_instrs[326],
    /* OP_vhsub */    &armv7a_instrs[327],
    /* OP_vld1_mse */    &armv7a_instrs[328],
    /* OP_vld1_se1 */    &armv7a_instrs[329],
    /* OP_vld1_sea */    &armv7a_instrs[330],
    /* OP_vld2_m2es */    &armv7a_instrs[331],
    /* OP_vld2_s2e1 */    &armv7a_instrs[332],
    /* OP_vld2_s2ea */    &armv7a_instrs[333],
    /* OP_vld3_m3s */    &armv7a_instrs[334],
    /* OP_vld3_se1 */    &armv7a_instrs[335],
    /* OP_vld3_sea */    &armv7a_instrs[336],
    /* OP_vld4_m4es */    &armv7a_instrs[337],
    /* OP_vld4_se1 */    &armv7a_instrs[338],
    /* OP_vld4_s4ea */    &armv7a_instrs[339],
    /* OP_vldm */    &armv7a_instrs[340],
    /* OP_vldr */    &armv7a_instrs[341],
    /* OP_vmax_int */    &armv7a_instrs[342],
    /* OP_vmin_int */    &armv7a_instrs[343],
    /* OP_vmax_flt */    &armv7a_instrs[344],
    /* OP_vmin_flt */    &armv7a_instrs[345],
    /* OP_vmla_int */    &armv7a_instrs[346],
    /* OP_vmlal_int */    &armv7a_instrs[347],
    /* OP_vmls_int */    &armv7a_instrs[348],
    /* OP_vmlsl_int */    &armv7a_instrs[349],
    /* OP_vmla_flt */    &armv7a_instrs[350],
    /* OP_vmls_flt */    &armv7a_instrs[351],
    /* OP_vmla_scl */    &armv7a_instrs[352],
    /* OP_vmlal_scl */    &armv7a_instrs[353],
    /* OP_vmls_scl */    &armv7a_instrs[354],
    /* OP_vmlsl_scl */    &armv7a_instrs[355],
    /* OP_vmov_imm */    &armv7a_instrs[356],
    /* OP_vmov_reg */    &armv7a_instrs[357],
    /* OP_vmov_reg_scl */    &armv7a_instrs[358],
    /* OP_vmov_scl_reg */    &armv7a_instrs[359],
    /* OP_vmov_reg_sp */    &armv7a_instrs[360],
    /* OP_vmov_2reg_2sp */    &armv7a_instrs[361],
    /* OP_vmov_2reg_2dp */    &armv7a_instrs[362],
    /* OP_vmovl */    &armv7a_instrs[363],
    /* OP_vmovn */    &armv7a_instrs[364],
    /* OP_vmrs */    &armv7a_instrs[365],
    /* OP_vmsr */    &armv7a_instrs[366],
    /* OP_vmul_int */    &armv7a_instrs[367],
    /* OP_vmull_int */    &armv7a_instrs[368],
    /* OP_vmul_flp */    &armv7a_instrs[369],
    /* OP_vmul_scl */    &armv7a_instrs[370],
    /* OP_vmull_scl */    &armv7a_instrs[371],
    /* OP_vmvn_imm */    &armv7a_instrs[372],
    /* OP_vmvn_reg */    &armv7a_instrs[373],
    /* OP_vneg */    &armv7a_instrs[374],
    /* OP_vnmla */    &armv7a_instrs[375],
    /* OP_vnmls */    &armv7a_instrs[376],
    /* OP_vnmul */    &armv7a_instrs[377],
    /* OP_vorn_imm */    &armv7a_instrs[378],
    /* OP_vorn_reg */    &armv7a_instrs[379],
    /* OP_vorr_imm */    &armv7a_instrs[380],
    /* OP_vorr_reg */    &armv7a_instrs[381],
    /* OP_vpadal */    &armv7a_instrs[382],
    /* OP_vpadd_int */    &armv7a_instrs[383],
    /* OP_vpadd_flp */    &armv7a_instrs[384],
    /* OP_vpaddl */    &armv7a_instrs[385],
    /* OP_vpmax_int */    &armv7a_instrs[386],
    /* OP_vpmin_int */    &armv7a_instrs[387],
    /* OP_vpmax_flp */    &armv7a_instrs[388],
    /* OP_vpmin_flp */    &armv7a_instrs[389],
    /* OP_vpop */    &armv7a_instrs[390],
    /* OP_vpush */    &armv7a_instrs[391],
    /* OP_vqabs */    &armv7a_instrs[392],
    /* OP_vqadd */    &armv7a_instrs[393],
    /* OP_vqdmlal */    &armv7a_instrs[394],
    /* OP_vqdmlsl */    &armv7a_instrs[395],
    /* OP_vqdmulh */    &armv7a_instrs[396],
    /* OP_vqdmull */    &armv7a_instrs[397],
    /* OP_vqdmovn */    &armv7a_instrs[398],
    /* OP_vqdmovun */    &armv7a_instrs[399],
    /* OP_vqneq */    &armv7a_instrs[400],
    /* OP_vqrdmulh */    &armv7a_instrs[401],
    /* OP_vqrshl */    &armv7a_instrs[402],
    /* OP_vqrshrn */    &armv7a_instrs[403],
    /* OP_vqrshrun */    &armv7a_instrs[404],
    /* OP_vqshl_reg */    &armv7a_instrs[405],
    /* OP_vqshl_imm */    &armv7a_instrs[406],
    /* OP_vqshlu_imm */    &armv7a_instrs[407],
    /* OP_vqshrn */    &armv7a_instrs[408],
    /* OP_vqshrun */    &armv7a_instrs[409],
    /* OP_vqsub */    &armv7a_instrs[410],
    /* OP_vqraddhn */    &armv7a_instrs[411],
    /* OP_vqrecpe */    &armv7a_instrs[412],
    /* OP_vqrecps */    &armv7a_instrs[413],
    /* OP_vrev16 */    &armv7a_instrs[414],
    /* OP_vrev32 */    &armv7a_instrs[415],
    /* OP_vrev64 */    &armv7a_instrs[416],
    /* OP_vrhadd */    &armv7a_instrs[417],
    /* OP_vrshl */    &armv7a_instrs[418],
    /* OP_vrshr */    &armv7a_instrs[419],
    /* OP_vrshrn */    &armv7a_instrs[420],
    /* OP_vrsqrte */    &armv7a_instrs[421],
    /* OP_vrsqrts */    &armv7a_instrs[422],
    /* OP_vrsra */    &armv7a_instrs[423],
    /* OP_vrsubhn */    &armv7a_instrs[424],
    /* OP_vshl_imm */    &armv7a_instrs[425],
    /* OP_vshl_reg */    &armv7a_instrs[426],
    /* OP_vshll */    &armv7a_instrs[427],
    /* OP_vshr */    &armv7a_instrs[428],
    /* OP_vshrn */    &armv7a_instrs[429],
    /* OP_vsli */    &armv7a_instrs[430],
    /* OP_vsqrt */    &armv7a_instrs[431],
    /* OP_vsra */    &armv7a_instrs[432],
    /* OP_vsri */    &armv7a_instrs[433],
    /* OP_vst1_mse */    &armv7a_instrs[434],
    /* OP_vst1_se1 */    &armv7a_instrs[435],
    /* OP_vst2_m2e */    &armv7a_instrs[436],
    /* OP_vst2_s2e1 */    &armv7a_instrs[437],
    /* OP_vst3_m3es */    &armv7a_instrs[438],
    /* OP_vst3_s3e1 */    &armv7a_instrs[439],
    /* OP_vst4_m4es */    &armv7a_instrs[440],
    /* OP_vst4_s4e1 */    &armv7a_instrs[441],
    /* OP_vstm */    &armv7a_instrs[442],
    /* OP_vstr */    &armv7a_instrs[443],
    /* OP_vsub_int */    &armv7a_instrs[444],
    /* OP_vsub_flp */    &armv7a_instrs[445],
    /* OP_vsubhn */    &armv7a_instrs[446],
    /* OP_vsubl */    &armv7a_instrs[447],
    /* OP_vsubw */    &armv7a_instrs[448],
    /* OP_vswp */    &armv7a_instrs[449],
    /* OP_vtbl */    &armv7a_instrs[450],
    /* OP_vtbx */    &armv7a_instrs[451],
    /* OP_vtrn */    &armv7a_instrs[452],
    /* OP_vtst */    &armv7a_instrs[453],
    /* OP_vuzp */    &armv7a_instrs[454],
    /* OP_vzip */    &armv7a_instrs[455],
    /* OP_wfe */    &armv7a_instrs[456],
    /* OP_wfi */    &armv7a_instrs[457],
    /* OP_yield */    &armv7a_instrs[458],

    /* Thumb + Thumb 32 bit instructions */

    /* OP_T_add_reg */    &thumb_instrs[464],
    /* OP_T_adc_reg */    &thumb_instrs[465],
    /* OP_T_add_low_reg */    &thumb_instrs[466],
    /* OP_T_add_high_reg */    &thumb_instrs[467],
    /* OP_T_add_sp_imm */    &thumb_instrs[468],
    /* OP_T_add_imm_3 */    &thumb_instrs[469],
    /* OP_T_add_imm_8 */    &thumb_instrs[470],
    /* OP_T_and_reg */    &thumb_instrs[471],
    /* OP_T_asr_imm */    &thumb_instrs[472],
    /* OP_T_asr_reg */    &thumb_instrs[473],
    /* OP_T_b */    &thumb_instrs[474],
    /* OP_T_bic_reg */    &thumb_instrs[475],
    /* OP_T_bkpt */    &thumb_instrs[476],
    /* OP_T_blx_ref */    &thumb_instrs[477],
    /* OP_T_bx */    &thumb_instrs[478],
    /* OP_T_cbnz */    &thumb_instrs[479],
    /* OP_T_cbnz_2 */    &thumb_instrs[480],
    /* OP_T_cbz */    &thumb_instrs[481],
    /* OP_T_cbz_2 */    &thumb_instrs[482],
    /* OP_T_cmn_reg */    &thumb_instrs[483],
    /* OP_T_cmp_high_reg */    &thumb_instrs[484],
    /* OP_T_cmp_imm */    &thumb_instrs[485],
    /* OP_T_cmp_reg */    &thumb_instrs[486],
    /* OP_T_cps */    &thumb_instrs[487],
    /* OP_T_eor_reg */    &thumb_instrs[488],
    /* OP_T_it */    &thumb_instrs[489],
    /* OP_T_ldrb_imm */    &thumb_instrs[490],
    /* OP_T_ldrb_reg */    &thumb_instrs[491],
    /* OP_T_ldrh_imm */    &thumb_instrs[492],
    /* OP_T_ldrh_reg */    &thumb_instrs[493],
    /* OP_T_ldrsb_reg */    &thumb_instrs[494],
    /* OP_T_ldrsh_reg */    &thumb_instrs[495],
    /* OP_T_ldr_imm */    &thumb_instrs[496],
    /* OP_T_ldr_reg */    &thumb_instrs[497],
    /* OP_T_lsl_imm */    &thumb_instrs[498],
    /* OP_T_lsl_reg */    &thumb_instrs[499],
    /* OP_T_lsr_imm */    &thumb_instrs[500],
    /* OP_T_lsr_reg */    &thumb_instrs[501],
    /* OP_T_mov_imm */    &thumb_instrs[502],
    /* OP_T_mov_high_reg */    &thumb_instrs[503],
    /* OP_T_mov_low_reg */    &thumb_instrs[504],
    /* OP_T_mvn_reg */    &thumb_instrs[505],
    /* OP_T_mul */    &thumb_instrs[506],
    /* OP_T_nop */    &thumb_instrs[507],
    /* OP_T_orr_reg */    &thumb_instrs[508],
    /* OP_T_pop */    &thumb_instrs[509],
    /* OP_T_push */    &thumb_instrs[510],
    /* OP_T_rev */    &thumb_instrs[511],
    /* OP_T_rev16 */    &thumb_instrs[512],
    /* OP_T_revsh */    &thumb_instrs[513],
    /* OP_T_ror_reg */    &thumb_instrs[514],
    /* OP_T_rsb_imm */    &thumb_instrs[515],
    /* OP_T_sbc_reg */    &thumb_instrs[516],
    /* OP_T_setend */    &thumb_instrs[517],
    /* OP_T_sev */    &thumb_instrs[518],
    /* OP_T_str_imm */    &thumb_instrs[519],
    /* OP_T_str_reg */    &thumb_instrs[520],
    /* OP_T_str_sp */    &thumb_instrs[521],
    /* OP_T_strb_imm */    &thumb_instrs[522],
    /* OP_T_strb_reg */    &thumb_instrs[523],
    /* OP_T_strh_imm */    &thumb_instrs[524],
    /* OP_T_strh_reg */    &thumb_instrs[525],
    /* OP_T_sub_sp_imm */    &thumb_instrs[526],
    /* OP_T_sub_imm_8 */    &thumb_instrs[527],
    /* OP_T_sub_reg */    &thumb_instrs[528],
    /* OP_T_sub_imm_3 */    &thumb_instrs[529],
    /* OP_T_svc */    &thumb_instrs[530],
    /* OP_T_sxth */    &thumb_instrs[531],
    /* OP_T_sxtb */    &thumb_instrs[532],
    /* OP_T_tst_reg */    &thumb_instrs[533],
    /* OP_T_uxtb */    &thumb_instrs[534],
    /* OP_T_uxth */    &thumb_instrs[535],
    /* OP_T_wfe */    &thumb_instrs[536],
    /* OP_T_wfi */    &thumb_instrs[537],
    /* OP_T_yield */    &thumb_instrs[538],
    /* OP_T_32_and_imm */    &thumb_instrs[539],
    /* OP_T_32_tst_imm */    &thumb_instrs[540],
    /* OP_T_32_bic_imm */    &thumb_instrs[541],
    /* OP_T_32_orr_imm */    &thumb_instrs[542],
    /* OP_T_32_mov_imm */    &thumb_instrs[543],
    /* OP_T_32_orn_imm */    &thumb_instrs[544],
    /* OP_T_32_mvn_imm */    &thumb_instrs[545],
    /* OP_T_32_eor_imm */    &thumb_instrs[546],
    /* OP_T_32_teq_imm */    &thumb_instrs[547],
    /* OP_T_32_add_imm */    &thumb_instrs[548],
    /* OP_T_32_cmn_imm */    &thumb_instrs[549],
    /* OP_T_32_adc_imm */    &thumb_instrs[550],
    /* OP_T_32_sbc_imm */    &thumb_instrs[551],
    /* OP_T_32_sub_imm */    &thumb_instrs[552],
    /* OP_T_32_cmp_imm */    &thumb_instrs[553],
    /* OP_T_32_rsb_imm */    &thumb_instrs[554],
    /* OP_T_32_add_wide */    &thumb_instrs[555],
    /* OP_T_32_adr */    &thumb_instrs[556],
    /* OP_T_32_mov_wide */    &thumb_instrs[557],
    /* OP_T_32_adr_2 */    &thumb_instrs[558],
    /* OP_T_32_movt_top */    &thumb_instrs[559],
    /* OP_T_32_ssat */    &thumb_instrs[560],
    /* OP_T_32_ssat16 */    &thumb_instrs[561],
    /* OP_T_32_sbfx */    &thumb_instrs[562],
    /* OP_T_32_bfi */    &thumb_instrs[563],
    /* OP_T_32_bfc */    &thumb_instrs[564],
    /* OP_T_32_usat16 */    &thumb_instrs[565],
    /* OP_T_32_ubfx */    &thumb_instrs[566],
    /* OP_T_32_b */    &thumb_instrs[567],
    /* OP_T_32_msr_reg_app */    &thumb_instrs[568],
    /* OP_T_32_msr_reg_sys */    &thumb_instrs[569],
    /* OP_T_32_bxj */    &thumb_instrs[570],
    /* OP_T_32_subs */    &thumb_instrs[571],
    /* OP_T_32_mrs */    &thumb_instrs[572],
    /* OP_T_32_smc */    &thumb_instrs[573],
    /* OP_T_32_b_2 */    &thumb_instrs[574],
    /* OP_T_32_blx_imm */    &thumb_instrs[575],
    /* OP_T_32_bl */    &thumb_instrs[576],
    /* OP_T_32_cps */    &thumb_instrs[577],
    /* OP_T_32_nop */    &thumb_instrs[578],
    /* OP_T_32_yield */    &thumb_instrs[579],
    /* OP_T_32_wfe */    &thumb_instrs[580],
    /* OP_T_32_wfi */    &thumb_instrs[581],
    /* OP_T_32_sev */    &thumb_instrs[582],
    /* OP_T_32_dbg */    &thumb_instrs[583],
    /* OP_T_32_enterx */    &thumb_instrs[584],
    /* OP_T_32_leavex */    &thumb_instrs[585],
    /* OP_T_32_clrex */    &thumb_instrs[586],
    /* OP_T_32_dsb */    &thumb_instrs[587],
    /* OP_T_32_dmb */    &thumb_instrs[588],
    /* OP_T_32_isb */    &thumb_instrs[589],
    /* OP_T_32_srs */    &thumb_instrs[590],
    /* OP_T_32_rfe */    &thumb_instrs[591],
    /* OP_T_32_stm */    &thumb_instrs[592],
    /* OP_T_32_stmia */    &thumb_instrs[593],
    /* OP_T_32_stmea */    &thumb_instrs[594],
    /* OP_T_32_ldm */    &thumb_instrs[595],
    /* OP_T_32_ldmia */    &thumb_instrs[596],
    /* OP_T_32_ldmfd */    &thumb_instrs[597],
    /* OP_T_32_pop */    &thumb_instrs[598],
    /* OP_T_32_stmdb */    &thumb_instrs[599],
    /* OP_T_32_stmfd */    &thumb_instrs[600],
    /* OP_T_32_push */    &thumb_instrs[601],
    /* OP_T_32_ldmdb */    &thumb_instrs[602],
    /* OP_T_32_ldmea */    &thumb_instrs[603],
    /* OP_T_32_strex */    &thumb_instrs[604],
    /* OP_T_32_ldrex */    &thumb_instrs[605],
    /* OP_T_32_strd_imm */    &thumb_instrs[606],
    /* OP_T_32_ldrd_imm */    &thumb_instrs[607],
    /* OP_T_32_ldrd_lit */    &thumb_instrs[608],
    /* OP_T_32_strexb */    &thumb_instrs[609],
    /* OP_T_32_strexh */    &thumb_instrs[610],
    /* OP_T_32_strexd */    &thumb_instrs[611],
    /* OP_T_32_tbb */    &thumb_instrs[612],
    /* OP_T_32_tbh */    &thumb_instrs[613],
    /* OP_T_32_ldrexb */    &thumb_instrs[614],
    /* OP_T_32_ldrexh */    &thumb_instrs[615],
    /* OP_T_32_ldrexd */    &thumb_instrs[616],
    /* OP_T_32_ldr_imm */    &thumb_instrs[617],
    /* OP_T_32_ldrt */    &thumb_instrs[618],
    /* OP_T_32_ldr_reg */    &thumb_instrs[619],
    /* OP_T_32_ldr_lit */    &thumb_instrs[620],
    /* OP_T_32_ldrh_lit */    &thumb_instrs[621],
    /* OP_T_32_ldrh_imm */    &thumb_instrs[622],
    /* OP_T_32_ldrht */    &thumb_instrs[623],
    /* OP_T_32_ldrh_reg */    &thumb_instrs[624],
    /* OP_T_32_ldrsh_imm */    &thumb_instrs[625],
    /* OP_T_32_ldrsht */    &thumb_instrs[626],
    /* OP_T_32_ldrsh_reg */    &thumb_instrs[627],
    /* OP_T_32_ldrb_lit */    &thumb_instrs[628],
    /* OP_T_32_ldrb_imm */    &thumb_instrs[629],
    /* OP_T_32_ldrbt */    &thumb_instrs[630],
    /* OP_T_32_ldrb_reg */    &thumb_instrs[631],
    /* OP_T_32_ldrsb_lit */    &thumb_instrs[632],
    /* OP_T_32_ldrsb_imm */    &thumb_instrs[633],
    /* OP_T_32_ldrsbt */    &thumb_instrs[634],
    /* OP_T_32_ldrsb */    &thumb_instrs[635],
    /* OP_T_32_pld_imm */    &thumb_instrs[636],
    /* OP_T_32_pld_lit */    &thumb_instrs[637],
    /* OP_T_32_pld_reg */    &thumb_instrs[638],
    /* OP_T_32_pli_imm */    &thumb_instrs[639],
    /* OP_T_32_pli_lit */    &thumb_instrs[640],
    /* OP_T_32_pli_reg */    &thumb_instrs[641],
    /* OP_T_32_strb_imm */    &thumb_instrs[642],
    /* OP_T_32_strbt */    &thumb_instrs[643],
    /* OP_T_32_strb_reg */    &thumb_instrs[644],
    /* OP_T_32_strh_imm */    &thumb_instrs[645],
    /* OP_T_32_strht */    &thumb_instrs[646],
    /* OP_T_32_strh_reg */    &thumb_instrs[647],
    /* OP_T_32_str_imm */    &thumb_instrs[648],
    /* OP_T_32_strt */    &thumb_instrs[649],
    /* OP_T_32_str_reg */    &thumb_instrs[650],
    /* OP_T_32_and_reg */    &thumb_instrs[651],
    /* OP_T_32_tst_reg */    &thumb_instrs[652],
    /* OP_T_32_bic_reg */    &thumb_instrs[653],
    /* OP_T_32_orr_reg */    &thumb_instrs[654],
    /* OP_T_32_mov_reg */    &thumb_instrs[655],
    /* OP_T_32_orn_reg */    &thumb_instrs[656],
    /* OP_T_32_mvn_reg */    &thumb_instrs[657],
    /* OP_T_32_eor_reg */    &thumb_instrs[658],
    /* OP_T_32_teq_reg */    &thumb_instrs[659],
    /* OP_T_32_pkh */    &thumb_instrs[660],
    /* OP_T_32_add_reg */    &thumb_instrs[661],
    /* OP_T_32_cmn_reg */    &thumb_instrs[662],
    /* OP_T_32_adc_reg */    &thumb_instrs[663],
    /* OP_T_32_sbc_reg */    &thumb_instrs[664],
    /* OP_T_32_sub_reg */    &thumb_instrs[665],
    /* OP_T_32_cmp_reg */    &thumb_instrs[666],
    /* OP_T_32_rsb_reg */    &thumb_instrs[667],
    /* OP_T_32_lsl_reg */    &thumb_instrs[668],
    /* OP_T_32_lsr_reg */    &thumb_instrs[669],
    /* OP_T_32_asr_reg */    &thumb_instrs[670],
    /* OP_T_32_ror_reg */    &thumb_instrs[671],
    /* OP_T_32_sxtah */    &thumb_instrs[672],
    /* OP_T_32_sxth */    &thumb_instrs[673],
    /* OP_T_32_uxtah */    &thumb_instrs[674],
    /* OP_T_32_uxth */    &thumb_instrs[675],
    /* OP_T_32_sxtab16 */    &thumb_instrs[676],
    /* OP_T_32_sxtb16 */    &thumb_instrs[677],
    /* OP_T_32_uxtab16 */    &thumb_instrs[678],
    /* OP_T_32_uxtb16 */    &thumb_instrs[679],
    /* OP_T_32_sxtab */    &thumb_instrs[680],
    /* OP_T_32_sxtb */    &thumb_instrs[681],
    /* OP_T_32_uxtab */    &thumb_instrs[682],
    /* OP_T_32_uxtb */    &thumb_instrs[683],
    /* OP_T_32_sadd16 */    &thumb_instrs[684],
    /* OP_T_32_sasx */    &thumb_instrs[685],
    /* OP_T_32_ssax */    &thumb_instrs[686],
    /* OP_T_32_ssub16 */    &thumb_instrs[687],
    /* OP_T_32_sadd8 */    &thumb_instrs[688],
    /* OP_T_32_ssub8 */    &thumb_instrs[689],
    /* OP_T_32_qadd16 */    &thumb_instrs[690],
    /* OP_T_32_qasx */    &thumb_instrs[691],
    /* OP_T_32_qsax */    &thumb_instrs[692],
    /* OP_T_32_qsub16 */    &thumb_instrs[693],
    /* OP_T_32_qadd8 */    &thumb_instrs[694],
    /* OP_T_32_qsub8 */    &thumb_instrs[695],
    /* OP_T_32_shadd16 */    &thumb_instrs[696],
    /* OP_T_32_shasx */    &thumb_instrs[697],
    /* OP_T_32_shsax */    &thumb_instrs[698],
    /* OP_T_32_shsub16 */    &thumb_instrs[699],
    /* OP_T_32_shadd8 */    &thumb_instrs[700],
    /* OP_T_32_shsub8 */    &thumb_instrs[701],
    /* OP_T_32_uadd16 */    &thumb_instrs[702],
    /* OP_T_32_uasx */    &thumb_instrs[703],
    /* OP_T_32_usax */    &thumb_instrs[704],
    /* OP_T_32_usub16 */    &thumb_instrs[705],
    /* OP_T_32_uadd8 */    &thumb_instrs[706],
    /* OP_T_32_usub8 */    &thumb_instrs[707],
    /* OP_T_32_uqadd16 */    &thumb_instrs[708],
    /* OP_T_32_uqasx */    &thumb_instrs[709],
    /* OP_T_32_uqsax */    &thumb_instrs[710],
    /* OP_T_32_uqsub16 */    &thumb_instrs[711],
    /* OP_T_32_uqadd8 */    &thumb_instrs[712],
    /* OP_T_32_uqsub8 */    &thumb_instrs[713],
    /* OP_T_32_uhadd16 */    &thumb_instrs[714],
    /* OP_T_32_uhasx */    &thumb_instrs[715],
    /* OP_T_32_uhsax */    &thumb_instrs[716],
    /* OP_T_32_uhsub16 */    &thumb_instrs[717],
    /* OP_T_32_uhadd8 */    &thumb_instrs[718],
    /* OP_T_32_uhsub8 */    &thumb_instrs[719],
    /* OP_T_32_qadd */    &thumb_instrs[720],
    /* OP_T_32_qdadd */    &thumb_instrs[721],
    /* OP_T_32_qsub */    &thumb_instrs[722],
    /* OP_T_32_qdsub */    &thumb_instrs[723],
    /* OP_T_32_rev */    &thumb_instrs[724],
    /* OP_T_32_rev16 */    &thumb_instrs[725],
    /* OP_T_32_rbit */    &thumb_instrs[726],
    /* OP_T_32_revsh */    &thumb_instrs[727],
    /* OP_T_32_sel */    &thumb_instrs[728],
    /* OP_T_32_clz */    &thumb_instrs[729],
    /* OP_T_32_mla */    &thumb_instrs[730],
    /* OP_T_32_mul */    &thumb_instrs[731],
    /* OP_T_32_mls */    &thumb_instrs[732],
    /* OP_T_32_smlabb */    &thumb_instrs[733],
    /* OP_T_32_smlabt */    &thumb_instrs[734],
    /* OP_T_32_smlatb */    &thumb_instrs[735],
    /* OP_T_32_smlatt */    &thumb_instrs[736],
    /* OP_T_32_smulbb */    &thumb_instrs[737],
    /* OP_T_32_smulbt */    &thumb_instrs[738],
    /* OP_T_32_smultb */    &thumb_instrs[739],
    /* OP_T_32_smultt */    &thumb_instrs[740],
    /* OP_T_32_smlad */    &thumb_instrs[741],
    /* OP_T_32_smuad */    &thumb_instrs[742],
    /* OP_T_32_smlawb */    &thumb_instrs[743],
    /* OP_T_32_smlawt */    &thumb_instrs[744],
    /* OP_T_32_smulwb */    &thumb_instrs[745],
    /* OP_T_32_smulwt */    &thumb_instrs[746],
    /* OP_T_32_smlsd */    &thumb_instrs[747],
    /* OP_T_32_smusd */    &thumb_instrs[748],
    /* OP_T_32_smmla */    &thumb_instrs[749],
    /* OP_T_32_smmul */    &thumb_instrs[750],
    /* OP_T_32_smmls */    &thumb_instrs[751],
    /* OP_T_32_usad8 */    &thumb_instrs[752],
    /* OP_T_32_usada8 */    &thumb_instrs[753],
    /* OP_T_32_smull */    &thumb_instrs[754],
    /* OP_T_32_sdiv */    &thumb_instrs[755],
    /* OP_T_32_umull */    &thumb_instrs[756],
    /* OP_T_32_udiv */    &thumb_instrs[757],
    /* OP_T_32_smlal */    &thumb_instrs[758],
    /* OP_T_32_smlalbb */    &thumb_instrs[759],
    /* OP_T_32_smlalbt */    &thumb_instrs[760],
    /* OP_T_32_smlaltb */    &thumb_instrs[761],
    /* OP_T_32_smlaltt */    &thumb_instrs[762],
    /* OP_T_32_smlald */    &thumb_instrs[763],
    /* OP_T_32_smlsld */    &thumb_instrs[764],
    /* OP_T_32_umlal */    &thumb_instrs[765],
    /* OP_T_32_umaal */    &thumb_instrs[766],
    /* OP_T_32_stc */    &thumb_instrs[767],
    /* OP_T_32_stc2 */    &thumb_instrs[768],
    /* OP_T_32_ldc_imm */    &thumb_instrs[769],
    /* OP_T_32_ldc_lit */    &thumb_instrs[770],
    /* OP_T_32_ldc2_imm */    &thumb_instrs[771],
    /* OP_T_32_ldc2_lit */    &thumb_instrs[772],
    /* OP_T_32_mcrr */    &thumb_instrs[773],
    /* OP_T_32_mcrr2 */    &thumb_instrs[774],
    /* OP_T_32_mrrc */    &thumb_instrs[775],
    /* OP_T_32_mrrc2 */    &thumb_instrs[776],
    /* OP_T_32_cdp */    &thumb_instrs[777],
    /* OP_T_32_cdp2 */    &thumb_instrs[778],
    /* OP_T_32_mcr */    &thumb_instrs[779],
    /* OP_T_32_mcr2 */    &thumb_instrs[780],
    /* OP_T_32_mrc */    &thumb_instrs[781],
    /* OP_T_32_mrc2 */    &thumb_instrs[782],


};
