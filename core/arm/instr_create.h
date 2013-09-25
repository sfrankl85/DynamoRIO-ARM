/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
 * Copyright (c) 2002-2010 VMware, Inc.  All rights reserved.
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
/* Copyright (c) 2002-2003 Massachusetts Institute of Technology */

#ifndef _INSTR_CREATE_H_
#define _INSTR_CREATE_H_ 1

/* DR_API EXPORT TOFILE dr_ir_macros.h */
/* DR_API EXPORT BEGIN */
/**
 * @file dr_ir_macros.h
 * @brief Instruction creation convenience macros.
 *
 * All macros assume default data and address sizes.  For the most part these
 * macros do not support building non-default address or data size
 * versions; for that, simply duplicate the macro's body, replacing the
 * SIZE and/or hardcoded registers with smaller versions (the IR does
 * not support cs segments with non-default sizes where the default
 * size requires instruction prefixes).  For shrinking data sizes, see
 * the instr_shrink_to_16_bits() routine.
 */

#include <math.h> /* for floating-point math constants */

#ifdef AVOID_API_EXPORT
# include "decode.h"
/* (deliberately not indenting the #includes in API_EXPORT_ONLY for generated file) */
#endif
#ifdef API_EXPORT_ONLY
#include "dr_ir_opnd.h"
#include "dr_ir_utils.h"
#endif

/* instruction modification convenience routines */
/**
 * Add the lock prefix to an instruction. For example:
 * instr_t *lock_inc_instr = LOCK(INSTR_CREATE_inc(....));
 */
#define LOCK(instr_ptr) instr_set_prefix_flag((instr_ptr), PREFIX_LOCK)
/**
 * Set the translation field for an instruction. For example:
 * instr_t *pushf_instr = INSTR_XL8(INSTR_CREATE_pushf(drcontext), addr);
 */
#define INSTR_XL8(instr_ptr, app_addr) instr_set_translation((instr_ptr), (app_addr))

/* operand convenience routines for common cases */
/** Create a base+disp 8-byte operand. */
#define OPND_CREATE_MEM64(base_reg, disp) \
  opnd_create_base_disp(base_reg, DR_REG_NULL, 0, disp, OPSZ_8)
/** Create a base+disp 4-byte operand. */
#define OPND_CREATE_MEM32(base_reg, disp) \
  opnd_create_base_disp(base_reg, DR_REG_NULL, 0, disp, OPSZ_4)
/** Create a base+disp 2-byte operand. */
#define OPND_CREATE_MEM16(base_reg, disp) \
  opnd_create_base_disp(base_reg, DR_REG_NULL, 0, disp, OPSZ_2)
/** Create a base+disp 1-byte operand. */
#define OPND_CREATE_MEM8(base_reg, disp) \
  opnd_create_base_disp(base_reg, DR_REG_NULL, 0, disp, OPSZ_1)
#ifdef X64
/** Create a base+disp pointer-sized operand. */
# define OPND_CREATE_MEMPTR OPND_CREATE_MEM64
/**
 * Create an absolute address operand encoded as pc-relative.
 * Encoding will fail if addr is out of 32-bit-signed-displacement reach.
 */
# define OPND_CREATE_ABSMEM(addr, size) \
  opnd_create_rel_addr(addr, size)
#else
/** Create a base+disp pointer-sized operand. */
# define OPND_CREATE_MEMPTR OPND_CREATE_MEM32
/** Create an absolute address operand. */
# define OPND_CREATE_ABSMEM(addr, size) \
  opnd_create_abs_addr(addr, size)
#endif 

#ifdef X64
/** Create an 8-byte immediate integer operand. */
#define OPND_CREATE_INT64(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_8)
/** Create a pointer-sized immediate integer operand. */
# define OPND_CREATE_INTPTR OPND_CREATE_INT64
#else
/** Create a pointer-sized immediate integer operand. */
# define OPND_CREATE_INTPTR OPND_CREATE_INT32
#endif
#define OPND_CREATE_IMM3(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_4_3)
#define OPND_CREATE_IMM5(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_4_5)
#define OPND_CREATE_IMM6(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_4_6)
#define OPND_CREATE_IMM8(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_4_8)
#define OPND_CREATE_IMM10(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_4_10)
#define OPND_CREATE_IMM12(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_4_12)
#define OPND_CREATE_IMM24(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_4_24)


/** Create a 4-byte immediate integer operand. */
#define OPND_CREATE_INT32(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_4)
/** Create a 2-byte immediate integer operand. */
#define OPND_CREATE_INT16(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_2)
/** Create a 1-byte immediate integer operand. */
#define OPND_CREATE_INT8(val) opnd_create_immed_int((ptr_int_t)(val), OPSZ_1)
/**
 * Create a 1-byte immediate interger operand if val will fit, else create a 4-byte
 * immediate integer operand.
 */
#define OPND_CREATE_INT_32OR8(val) ((val) <= INT8_MAX && (ptr_int_t)(val) >= INT8_MIN ? \
    OPND_CREATE_INT8(val) : OPND_CREATE_INT32(val))
/**
 * Create a 1-byte immediate interger operand if val will fit, else create a 2-byte
 * immediate integer operand.
 */
#define OPND_CREATE_INT_16OR8(val) ((val) <= INT8_MAX && (ptr_int_t)(val) >= INT8_MIN ? \
    OPND_CREATE_INT8(val) : OPND_CREATE_INT16(val))


/* operand convenience routines for specific opcodes with odd sizes */
/** Create a memory reference operand appropriately sized for OP_lea. */
#define OPND_CREATE_MEM_lea(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_lea)
/** Create a memory reference operand appropriately sized for OP_invlpg. */
#define OPND_CREATE_MEM_invlpg(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_invlpg)
/** Create a memory reference operand appropriately sized for OP_clflush. */
#define OPND_CREATE_MEM_clflush(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_clflush)
/** Create a memory reference operand appropriately sized for OP_prefetch*. */
#define OPND_CREATE_MEM_prefetch(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_prefetch)
/** Create a memory reference operand appropriately sized for OP_lgdt. */
#define OPND_CREATE_MEM_lgdt(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_lgdt)
/** Create a memory reference operand appropriately sized for OP_sgdt. */
#define OPND_CREATE_MEM_sgdt(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_sgdt)
/** Create a memory reference operand appropriately sized for OP_lidt. */
#define OPND_CREATE_MEM_lidt(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_lidt)
/** Create a memory reference operand appropriately sized for OP_sidt. */
#define OPND_CREATE_MEM_sidt(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_sidt)
/** Create a memory reference operand appropriately sized for OP_bound. */
#define OPND_CREATE_MEM_bound(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_bound)
/** Create a memory reference operand appropriately sized for OP_fldenv. */
#define OPND_CREATE_MEM_fldenv(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_fldenv)
/** Create a memory reference operand appropriately sized for OP_fnstenv. */
#define OPND_CREATE_MEM_fnstenv(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_fnstenv)
/** Create a memory reference operand appropriately sized for OP_fnsave. */
#define OPND_CREATE_MEM_fnsave(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_fnsave)
/** Create a memory reference operand appropriately sized for OP_frstor. */
#define OPND_CREATE_MEM_frstor(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_frstor)
/** Create a memory reference operand appropriately sized for OP_fxsave. */
#define OPND_CREATE_MEM_fxsave(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_fxsave)
/** Create a memory reference operand appropriately sized for OP_fxrstor. */
#define OPND_CREATE_MEM_fxrstor(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_fxrstor)
/**
 * Create a memory reference operand appropriately sized for OP_xsave,
 * OP_xsaveopt, or OP_xrstor.
 */
#define OPND_CREATE_MEM_xsave(base, index, scale, disp) \
    opnd_create_base_disp(base, index, scale, disp, OPSZ_xsave)

/* Macros for building instructions, one for each opcode.
 * Each INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * The macro parameter types, encoded by name, are:
 *   dc = DR Context*
 *   op = uint = opcode
 *   s  = opnd_t = source operand
 *   i  = opnd_t = source operand that is an immediate
 *   ri = opnd_t = source operand that can be a register or an immediate
 *   t  = opnd_t = source operand that is a jump target
 *   m  = opnd_t = source operand that can only reference memory
 *   f  = opnd_t = floating point register operand
 *   d  = opnd_t = destination operand
 */


/* SJF TODO New ARM Instr definitions */
/* no destination, 1 source */
/**
 * Creates an instr_t for a short conditional branch instruction with the given
 * opcode and target operand.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param op The OP_xxx opcode for the conditional branch, which should be
 * in the range [OP_b].
 * \param t The opnd_t target operand for the instruction, which can be either
 * a pc (opnd_create_pc()) or an instr_t (opnd_create_instr()).  Be sure to
 * ensure that the limited reach of this short branch will reach the target
 * (a pc operand is not suitable for most uses unless you know precisely where
 * this instruction will be encoded).
 */
/* TODO SJF Check + fix */
#define INSTR_CREATE_branch_short(dc, op, t, c) \
  instr_create_0dst_1src((dc), (op), (t), (c))
/**
 * Creates an instr_t for a conditional branch instruction with the given opcode
 * and target operand.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param t The opnd_t target operand for the instruction, which can be either
 * a pc (opnd_create_pc()) or an instr_t (opnd_create_instr()).
 */
#define INSTR_CREATE_branch(dc, t, c) \
  instr_create_0dst_1src((dc), OP_b, (t), (c))

/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_push(dc, s, c) \
  instr_create_0dst_1src((dc), OP_push, (s), c)

#define INSTR_CREATE_pop(dc, s, c) \
  instr_create_0dst_1src((dc), OP_pop, (s), c)




/* SJF Neew instr create macros */
/* TODO Fill in with the correct calls as needed */
#define INSTR_CREATE_adc_imm(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_adc_imm, (d), (s), (i), (c))
#define INSTR_CREATE_adc_reg(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_adc_reg, (d), (s), (i), (c))
#define INSTR_CREATE_adc_rsr(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_adc_rsr, (d), (s), (i), (c))
#define INSTR_CREATE_add_imm(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_add_imm, (d), (s), (i), (c))
#define INSTR_CREATE_add_reg(dc, d, s, i1, i2, c) \
    instr_create_1dst_3src((dc), OP_add_reg, (d), (s), (i1), (i2), (c))
#define INSTR_CREATE_add_rsr(dc, d, s, i1, i2, c) \
    instr_create_1dst_3src((dc), OP_add_rsr, (d), (s), (i1), (i2), (c))
#define INSTR_CREATE_add_sp_imm(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_add_sp_imm, (d), (s), (c))
#define INSTR_CREATE_add_sp_reg(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_add_sp_reg, (d), (s), (c))
#define INSTR_CREATE_adr(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_adr, (d), (s), (c))
#define INSTR_CREATE_and_imm(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_and_imm, (d), (s), (i), (c))
#define INSTR_CREATE_and_reg(dc, d, s, i1, i2, c) \
    instr_create_1dst_3src((dc), OP_and_reg, (d), (s), (i1), (i2), (c))
#define INSTR_CREATE_and_rsr(dc, d, s, i1, i2, c) \
    instr_create_1dst_3src((dc), OP_and_rsr, d, s, i1, i2, c)
#define INSTR_CREATE_asr_imm(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_asr_imm, (d), (s), (i), (c))
#define INSTR_CREATE_asr_reg(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_asr_reg, (d), (s), (i), (c))
#define INSTR_CREATE_b(dc, s) \
    instr_create_0dst_1src((dc), OP_b, (s))
#define INSTR_CREATE_bfc(dc) \
    instr_create_0dst_0src((dc), OP_bfc)
#define INSTR_CREATE_bfi(dc) \
    instr_create_0dst_0src((dc), OP_bfi)
#define INSTR_CREATE_bic_imm(dc) \
    instr_create_0dst_0src((dc), OP_bic_imm)
#define INSTR_CREATE_bic_reg(dc) \
    instr_create_0dst_0src((dc), OP_bic_reg)
#define INSTR_CREATE_bic_rsr(dc) \
    instr_create_0dst_0src((dc), OP_bic_rsr)
#define INSTR_CREATE_bkpt(dc) \
    instr_create_0dst_0src((dc), OP_bkpt)
#define INSTR_CREATE_bl(dc, d, c) \
    instr_create_0dst_1src((dc), OP_bl, (d), (c))
#define INSTR_CREATE_blx_imm(dc) \
    instr_create_0dst_0src((dc), OP_blx_imm)
#define INSTR_CREATE_blx_reg(dc, s, c) \
    instr_create_0dst_1src((dc), OP_blx_reg, (s), (c))
#define INSTR_CREATE_bx(dc) \
    instr_create_0dst_0src((dc), OP_bx)
#define INSTR_CREATE_bxj(dc) \
    instr_create_0dst_0src((dc), OP_bxj)
#define INSTR_CREATE_cbnz(dc) \
    instr_create_0dst_0src((dc), OP_cbnz)
#define INSTR_CREATE_cbz(dc) \
    instr_create_0dst_0src((dc), OP_cbz)
#define INSTR_CREATE_cdp(dc) \
    instr_create_0dst_0src((dc), OP_cdp)
#define INSTR_CREATE_cdp2(dc) \
    instr_create_0dst_0src((dc), OP_cdp2)
#define INSTR_CREATE_clrex(dc) \
    instr_create_0dst_0src((dc), OP_clrex)
#define INSTR_CREATE_clz(dc) \
    instr_create_0dst_0src((dc), OP_clz)
#define INSTR_CREATE_cmn_imm(dc) \
    instr_create_0dst_0src((dc), OP_cmn_imm)
#define INSTR_CREATE_cmn_reg(dc) \
    instr_create_0dst_0src((dc), OP_cmn_reg)
#define INSTR_CREATE_cmn_rsr(dc) \
    instr_create_0dst_0src((dc), OP_cmn_rsr)
#define INSTR_CREATE_cmp_imm(dc) \
    instr_create_0dst_0src((dc), OP_cmp_imm)
#define INSTR_CREATE_cmp_reg(dc) \
    instr_create_0dst_0src((dc), OP_cmp_reg)
#define INSTR_CREATE_cmp_rsr(dc) \
    instr_create_0dst_0src((dc), OP_cmp_rsr)
#define INSTR_CREATE_cps(dc) \
    instr_create_0dst_0src((dc), OP_cps)
#define INSTR_CREATE_dbg(dc) \
    instr_create_0dst_0src((dc), OP_dbg)
#define INSTR_CREATE_dmb(dc) \
    instr_create_0dst_0src((dc), OP_dmb)
#define INSTR_CREATE_dsb(dc) \
    instr_create_0dst_0src((dc), OP_dsb)
#define INSTR_CREATE_eor_imm(dc) \
    instr_create_0dst_0src((dc), OP_eor_imm)
#define INSTR_CREATE_eor_reg(dc) \
    instr_create_0dst_0src((dc), OP_eor_reg)
#define INSTR_CREATE_eor_rsr(dc) \
    instr_create_0dst_0src((dc), OP_eor_rsr)
#define INSTR_CREATE_isb(dc) \
    instr_create_0dst_0src((dc), OP_isb)
#define INSTR_CREATE_it(dc) \
    instr_create_0dst_0src((dc), OP_it)
#define INSTR_CREATE_ldc_imm(dc) \
    instr_create_0dst_0src((dc), OP_ldc_imm)
#define INSTR_CREATE_ldc2_imm(dc) \
    instr_create_0dst_0src((dc), OP_ldc2_imm)
#define INSTR_CREATE_ldc_lit(dc) \
    instr_create_0dst_0src((dc), OP_ldc_lit)
#define INSTR_CREATE_ldc2_lit(dc) \
    instr_create_0dst_0src((dc), OP_ldc2_lit)
#define INSTR_CREATE_ldm(dc) \
    instr_create_0dst_0src((dc), OP_ldm)
#define INSTR_CREATE_ldmia(dc) \
    instr_create_0dst_0src((dc), OP_ldmia)
#define INSTR_CREATE_ldmfd(dc) \
    instr_create_0dst_0src((dc), OP_ldmfd)
#define INSTR_CREATE_ldmda(dc) \
    instr_create_0dst_0src((dc), OP_ldmda)
#define INSTR_CREATE_ldmfa(dc) \
    instr_create_0dst_0src((dc), OP_ldmfa)
#define INSTR_CREATE_ldmdb(dc) \
    instr_create_0dst_0src((dc), OP_ldmdb)
#define INSTR_CREATE_ldmea(dc) \
    instr_create_0dst_0src((dc), OP_ldmea)
#define INSTR_CREATE_ldmib(dc) \
    instr_create_0dst_0src((dc), OP_ldmib)
#define INSTR_CREATE_ldmed(dc) \
    instr_create_0dst_0src((dc), OP_ldmed)
#define INSTR_CREATE_ldr_imm(dc, d, s1, s2, c) \
    instr_create_1dst_2src((dc), OP_ldr_imm, (d), (s1), (s2), (c))
#define INSTR_CREATE_ldr_lit(dc, d, i, c) \
    instr_create_1dst_1src((dc), OP_ldr_lit, (d), (i), (c))
#define INSTR_CREATE_ldr_reg(dc, d, s1, s2, i, c) \
    instr_create_1dst_3src((dc), OP_ldr_reg, (d), (s1), (s2), (i), (c))
#define INSTR_CREATE_ldrb_imm(dc) \
    instr_create_0dst_0src((dc), OP_ldrb_imm)
#define INSTR_CREATE_ldrb_lit(dc) \
    instr_create_0dst_0src((dc), OP_ldrb_lit)
#define INSTR_CREATE_ldrb_reg(dc) \
    instr_create_0dst_0src((dc), OP_ldrb_reg)
#define INSTR_CREATE_ldrbt(dc) \
    instr_create_0dst_0src((dc), OP_ldrbt)
#define INSTR_CREATE_ldrd_imm(dc) \
    instr_create_0dst_0src((dc), OP_ldrd_imm)
#define INSTR_CREATE_ldrd_lit(dc) \
    instr_create_0dst_0src((dc), OP_ldrd_lit)
#define INSTR_CREATE_ldrd_reg(dc) \
    instr_create_0dst_0src((dc), OP_ldrd_reg)
#define INSTR_CREATE_ldrex(dc) \
    instr_create_0dst_0src((dc), OP_ldrex)
#define INSTR_CREATE_ldrexb(dc) \
    instr_create_0dst_0src((dc), OP_ldrexb)
#define INSTR_CREATE_ldrexd(dc) \
    instr_create_0dst_0src((dc), OP_ldrexd)
#define INSTR_CREATE_ldrexh(dc) \
    instr_create_0dst_0src((dc), OP_ldrexh)
#define INSTR_CREATE_ldrh_imm(dc) \
    instr_create_0dst_0src((dc), OP_ldrh_imm)
#define INSTR_CREATE_ldrh_lit(dc) \
    instr_create_0dst_0src((dc), OP_ldrh_lit)
#define INSTR_CREATE_ldrh_reg(dc) \
    instr_create_0dst_0src((dc), OP_ldrh_reg)
#define INSTR_CREATE_ldrht(dc) \
    instr_create_0dst_0src((dc), OP_ldrht)
#define INSTR_CREATE_ldrsb_imm(dc) \
    instr_create_0dst_0src((dc), OP_ldrsb_imm)
#define INSTR_CREATE_ldrsb_lit(dc) \
    instr_create_0dst_0src((dc), OP_ldrsb_lit)
#define INSTR_CREATE_ldrsb_reg(dc) \
    instr_create_0dst_0src((dc), OP_ldrsb_reg)
#define INSTR_CREATE_ldrsbt(dc) \
    instr_create_0dst_0src((dc), OP_ldrsbt)
#define INSTR_CREATE_ldrsh_imm(dc) \
    instr_create_0dst_0src((dc), OP_ldrsh_imm)
#define INSTR_CREATE_ldrsh_lit(dc) \
    instr_create_0dst_0src((dc), OP_ldrsh_lit)
#define INSTR_CREATE_ldrsh_reg(dc) \
    instr_create_0dst_0src((dc), OP_ldrsh_reg)
#define INSTR_CREATE_ldrsht(dc) \
    instr_create_0dst_0src((dc), OP_ldrsht)
#define INSTR_CREATE_ldrt(dc) \
    instr_create_0dst_0src((dc), OP_ldrt)
#define INSTR_CREATE_lsl_imm(dc) \
    instr_create_0dst_0src((dc), OP_lsl_imm)
#define INSTR_CREATE_lsl_reg(dc) \
    instr_create_0dst_0src((dc), OP_lsl_reg)
#define INSTR_CREATE_lsr_imm(dc) \
    instr_create_0dst_0src((dc), OP_lsr_imm)
#define INSTR_CREATE_lsr_reg(dc) \
    instr_create_0dst_0src((dc), OP_lsr_reg)
#define INSTR_CREATE_mcr(dc) \
    instr_create_0dst_0src((dc), OP_mcr)
#define INSTR_CREATE_mcr2(dc) \
    instr_create_0dst_0src((dc), OP_mcr2)
#define INSTR_CREATE_mcrr(dc) \
    instr_create_0dst_0src((dc), OP_mcrr)
#define INSTR_CREATE_mcrr2(dc) \
    instr_create_0dst_0src((dc), OP_mcrr2)
#define INSTR_CREATE_mla(dc) \
    instr_create_0dst_0src((dc), OP_mla)
#define INSTR_CREATE_mls(dc) \
    instr_create_0dst_0src((dc), OP_mls)
#define INSTR_CREATE_mov_imm(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_mov_imm, (d), (s), (c))
#define INSTR_CREATE_mov_reg(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_mov_reg, (d), (s), (c))
#define INSTR_CREATE_movt(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_movt, (d), (s), (c))
#define INSTR_CREATE_mrc(dc) \
    instr_create_0dst_0src((dc), OP_mrc)
#define INSTR_CREATE_mrc2(dc) \
    instr_create_0dst_0src((dc), OP_mrc2)
#define INSTR_CREATE_mrrc(dc) \
    instr_create_0dst_0src((dc), OP_mrrc)
#define INSTR_CREATE_mrrc2(dc) \
    instr_create_0dst_0src((dc), OP_mrrc2)
#define INSTR_CREATE_mrs(dc, s, c) \
    instr_create_0dst_1src((dc), OP_mrs, (s), (c))
#define INSTR_CREATE_msr_imm(dc, s1, s2, c) \
    instr_create_0dst_2src((dc), OP_msr_imm, (s1), (s2), (c))
#define INSTR_CREATE_msr_reg(dc, s1, s2, c) \
    instr_create_0dst_2src((dc), OP_msr_reg, (s1), (s2), (c))
#define INSTR_CREATE_mul(dc) \
    instr_create_0dst_0src((dc), OP_mul)
#define INSTR_CREATE_mvn_imm(dc) \
    instr_create_0dst_0src((dc), OP_mvn_imm)
#define INSTR_CREATE_mvn_reg(dc) \
    instr_create_0dst_0src((dc), OP_mvn_reg)
#define INSTR_CREATE_mvn_rsr(dc) \
    instr_create_0dst_0src((dc), OP_mvn_rsr)
#define INSTR_CREATE_orn_imm(dc) \
    instr_create_0dst_0src((dc), OP_orn_imm)
#define INSTR_CREATE_orn_reg(dc) \
    instr_create_0dst_0src((dc), OP_orn_reg)
#define INSTR_CREATE_orr_imm(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_orr_imm, (d), (s), (i), (c))
#define INSTR_CREATE_orr_reg(dc, d, s1, s2, i, c) \
    instr_create_1dst_3src((dc), OP_orr_reg, (d), (s1), (s2), (i), (c))
#define INSTR_CREATE_orr_rsr(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_orr_rsr, (d), (s), (i), (c))
#define INSTR_CREATE_pkh(dc) \
    instr_create_0dst_0src((dc), OP_pkh)
#define INSTR_CREATE_pld_imm(dc) \
    instr_create_0dst_0src((dc), OP_pld_imm)
#define INSTR_CREATE_pldw_imm(dc) \
    instr_create_0dst_0src((dc), OP_pldw_imm)
#define INSTR_CREATE_pld_lit(dc) \
    instr_create_0dst_0src((dc), OP_pld_lit)
#define INSTR_CREATE_pldw_lit(dc) \
    instr_create_0dst_0src((dc), OP_pldw_lit)
#define INSTR_CREATE_pld_reg(dc) \
    instr_create_0dst_0src((dc), OP_pld_reg)
#define INSTR_CREATE_pldw_reg(dc) \
    instr_create_0dst_0src((dc), OP_pldw_reg)
#define INSTR_CREATE_pli_imm(dc) \
    instr_create_0dst_0src((dc), OP_pli_imm)
#define INSTR_CREATE_pli_lit(dc) \
    instr_create_0dst_0src((dc), OP_pli_lit)
#define INSTR_CREATE_pli_reg(dc) \
    instr_create_0dst_0src((dc), OP_pli_reg)
#define INSTR_CREATE_qadd(dc) \
    instr_create_0dst_0src((dc), OP_qadd)
#define INSTR_CREATE_qadd16(dc) \
    instr_create_0dst_0src((dc), OP_qadd16)
#define INSTR_CREATE_qadd8(dc) \
    instr_create_0dst_0src((dc), OP_qadd8)
#define INSTR_CREATE_qasx(dc) \
    instr_create_0dst_0src((dc), OP_qasx)
#define INSTR_CREATE_qdadd(dc) \
    instr_create_0dst_0src((dc), OP_qdadd)
#define INSTR_CREATE_qdsub(dc) \
    instr_create_0dst_0src((dc), OP_qdsub)
#define INSTR_CREATE_qsax(dc) \
    instr_create_0dst_0src((dc), OP_qsax)
#define INSTR_CREATE_qsub(dc) \
    instr_create_0dst_0src((dc), OP_qsub)
#define INSTR_CREATE_qsub16(dc) \
    instr_create_0dst_0src((dc), OP_qsub16)
#define INSTR_CREATE_qsub8(dc) \
    instr_create_0dst_0src((dc), OP_qsub8)
#define INSTR_CREATE_rbit(dc) \
    instr_create_0dst_0src((dc), OP_rbit)
#define INSTR_CREATE_rev(dc) \
    instr_create_0dst_0src((dc), OP_rev)
#define INSTR_CREATE_rev16(dc) \
    instr_create_0dst_0src((dc), OP_rev16)
#define INSTR_CREATE_revsh(dc) \
    instr_create_0dst_0src((dc), OP_revsh)
#define INSTR_CREATE_rfe(dc) \
    instr_create_0dst_0src((dc), OP_rfe)
#define INSTR_CREATE_ror_imm(dc) \
    instr_create_0dst_0src((dc), OP_ror_imm)
#define INSTR_CREATE_ror_reg(dc) \
    instr_create_0dst_0src((dc), OP_ror_reg)
#define INSTR_CREATE_rrx(dc) \
    instr_create_0dst_0src((dc), OP_rrx)
#define INSTR_CREATE_rsb_imm(dc) \
    instr_create_0dst_0src((dc), OP_rsb_imm)
#define INSTR_CREATE_rsb_reg(dc) \
    instr_create_0dst_0src((dc), OP_rsb_reg)
#define INSTR_CREATE_rsb_rsr(dc) \
    instr_create_0dst_0src((dc), OP_rsb_rsr)
#define INSTR_CREATE_rsc_imm(dc) \
    instr_create_0dst_0src((dc), OP_rsc_imm)
#define INSTR_CREATE_rsc_reg(dc) \
    instr_create_0dst_0src((dc), OP_rsc_reg)
#define INSTR_CREATE_rsc_rsr(dc) \
    instr_create_0dst_0src((dc), OP_rsc_rsr)
#define INSTR_CREATE_sadd16(dc) \
    instr_create_0dst_0src((dc), OP_sadd16)
#define INSTR_CREATE_sadd8(dc) \
    instr_create_0dst_0src((dc), OP_sadd8)
#define INSTR_CREATE_sasx(dc) \
    instr_create_0dst_0src((dc), OP_sasx)
#define INSTR_CREATE_sbc_imm(dc) \
    instr_create_0dst_0src((dc), OP_sbc_imm)
#define INSTR_CREATE_sbc_reg(dc) \
    instr_create_0dst_0src((dc), OP_sbc_reg)
#define INSTR_CREATE_sbc_rsr(dc) \
    instr_create_0dst_0src((dc), OP_sbc_rsr)
#define INSTR_CREATE_sbfx(dc) \
    instr_create_0dst_0src((dc), OP_sbfx)
#define INSTR_CREATE_sdiv(dc) \
    instr_create_0dst_0src((dc), OP_sdiv)
#define INSTR_CREATE_sel(dc) \
    instr_create_0dst_0src((dc), OP_sel)
#define INSTR_CREATE_setend(dc) \
    instr_create_0dst_0src((dc), OP_setend)
#define INSTR_CREATE_sev(dc) \
    instr_create_0dst_0src((dc), OP_sev)
#define INSTR_CREATE_shadd16(dc) \
    instr_create_0dst_0src((dc), OP_shadd16)
#define INSTR_CREATE_shadd8(dc) \
    instr_create_0dst_0src((dc), OP_shadd8)
#define INSTR_CREATE_shsax(dc) \
    instr_create_0dst_0src((dc), OP_shsax)
#define INSTR_CREATE_shsub16(dc) \
    instr_create_0dst_0src((dc), OP_shsub16)
#define INSTR_CREATE_shsub8(dc) \
    instr_create_0dst_0src((dc), OP_shsub8)
#define INSTR_CREATE_smlabb(dc) \
    instr_create_0dst_0src((dc), OP_smlabb)
#define INSTR_CREATE_smlabt(dc) \
    instr_create_0dst_0src((dc), OP_smlabt)
#define INSTR_CREATE_smlatb(dc) \
    instr_create_0dst_0src((dc), OP_smlatb)
#define INSTR_CREATE_smlatt(dc) \
    instr_create_0dst_0src((dc), OP_smlatt)
#define INSTR_CREATE_smlad(dc) \
    instr_create_0dst_0src((dc), OP_smlad)
#define INSTR_CREATE_smlal(dc) \
    instr_create_0dst_0src((dc), OP_smlal)
#define INSTR_CREATE_smlalbb(dc) \
    instr_create_0dst_0src((dc), OP_smlalbb)
#define INSTR_CREATE_smlalbt(dc) \
    instr_create_0dst_0src((dc), OP_smlalbt)
#define INSTR_CREATE_smlaltb(dc) \
    instr_create_0dst_0src((dc), OP_smlaltb)
#define INSTR_CREATE_smlaltt(dc) \
    instr_create_0dst_0src((dc), OP_smlaltt)
#define INSTR_CREATE_smlald(dc) \
    instr_create_0dst_0src((dc), OP_smlald)
#define INSTR_CREATE_smlawb(dc) \
    instr_create_0dst_0src((dc), OP_smlawb)
#define INSTR_CREATE_smlawt(dc) \
    instr_create_0dst_0src((dc), OP_smlawt)
#define INSTR_CREATE_smlsd(dc) \
    instr_create_0dst_0src((dc), OP_smlsd)
#define INSTR_CREATE_smlsld(dc) \
    instr_create_0dst_0src((dc), OP_smlsld)
#define INSTR_CREATE_smmla(dc) \
    instr_create_0dst_0src((dc), OP_smmla)
#define INSTR_CREATE_smmls(dc) \
    instr_create_0dst_0src((dc), OP_smmls)
#define INSTR_CREATE_smmul(dc) \
    instr_create_0dst_0src((dc), OP_smmul)
#define INSTR_CREATE_smuad(dc) \
    instr_create_0dst_0src((dc), OP_smuad)
#define INSTR_CREATE_smulbb(dc) \
    instr_create_0dst_0src((dc), OP_smulbb)
#define INSTR_CREATE_smulbt(dc) \
    instr_create_0dst_0src((dc), OP_smulbt)
#define INSTR_CREATE_smultb(dc) \
    instr_create_0dst_0src((dc), OP_smultb)
#define INSTR_CREATE_smultt(dc) \
    instr_create_0dst_0src((dc), OP_smultt)
#define INSTR_CREATE_smull(dc) \
    instr_create_0dst_0src((dc), OP_smull)
#define INSTR_CREATE_smulwb(dc) \
    instr_create_0dst_0src((dc), OP_smulwb)
#define INSTR_CREATE_smulwt(dc) \
    instr_create_0dst_0src((dc), OP_smulwt)
#define INSTR_CREATE_smusd(dc) \
    instr_create_0dst_0src((dc), OP_smusd)
#define INSTR_CREATE_srs(dc) \
    instr_create_0dst_0src((dc), OP_srs)
#define INSTR_CREATE_ssat(dc) \
    instr_create_0dst_0src((dc), OP_ssat)
#define INSTR_CREATE_ssat16(dc) \
    instr_create_0dst_0src((dc), OP_ssat16)
#define INSTR_CREATE_ssax(dc) \
    instr_create_0dst_0src((dc), OP_ssax)
#define INSTR_CREATE_ssub16(dc) \
    instr_create_0dst_0src((dc), OP_ssub16)
#define INSTR_CREATE_ssub8(dc) \
    instr_create_0dst_0src((dc), OP_ssub8)
#define INSTR_CREATE_stc(dc) \
    instr_create_0dst_0src((dc), OP_stc)
#define INSTR_CREATE_stc2(dc) \
    instr_create_0dst_0src((dc), OP_stc2)
#define INSTR_CREATE_stm(dc) \
    instr_create_0dst_0src((dc), OP_stm)
#define INSTR_CREATE_stmia(dc) \
    instr_create_0dst_0src((dc), OP_stmia)
#define INSTR_CREATE_stmea(dc) \
    instr_create_0dst_0src((dc), OP_stmea)
#define INSTR_CREATE_stmda(dc) \
    instr_create_0dst_0src((dc), OP_stmda)
#define INSTR_CREATE_stmed(dc) \
    instr_create_0dst_0src((dc), OP_stmed)
#define INSTR_CREATE_stmdb(dc) \
    instr_create_0dst_0src((dc), OP_stmdb)
#define INSTR_CREATE_stmfd(dc) \
    instr_create_0dst_0src((dc), OP_stmfd)
#define INSTR_CREATE_stmib(dc) \
    instr_create_0dst_0src((dc), OP_stmib)
#define INSTR_CREATE_stmfa(dc) \
    instr_create_0dst_0src((dc), OP_stmfa)
#define INSTR_CREATE_str_imm(dc, d, s1, s2, c) \
    instr_create_1dst_2src((dc), OP_str_imm, (d), (s1), (s2), (c))
#define INSTR_CREATE_str_reg(dc, d, s1, s2, i, c) \
    instr_create_1dst_3src((dc), OP_str_reg, (d), (s1), (s2), (i), (c))
#define INSTR_CREATE_strb_imm(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_strb_imm, (d), (s), (i), (c))
#define INSTR_CREATE_strb_reg(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_strb_reg, (d), (s), (i), (c))
#define INSTR_CREATE_strbt(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_strbt, (d), (s), (i), (c))
#define INSTR_CREATE_strd_imm(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_strd_imm, (d), (s), (i), (c))
#define INSTR_CREATE_strd_reg(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_strd_reg, d, s, i, c)
#define INSTR_CREATE_strex(dc) \
    instr_create_0dst_0src((dc), OP_strex)
#define INSTR_CREATE_strexb(dc) \
    instr_create_0dst_0src((dc), OP_strexb)
#define INSTR_CREATE_strexd(dc) \
    instr_create_0dst_0src((dc), OP_strexd)
#define INSTR_CREATE_strexh(dc) \
    instr_create_0dst_0src((dc), OP_strexh)
#define INSTR_CREATE_strh_imm(dc) \
    instr_create_0dst_0src((dc), OP_strh_imm)
#define INSTR_CREATE_strh_reg(dc) \
    instr_create_0dst_0src((dc), OP_strh_reg)
#define INSTR_CREATE_strht(dc) \
    instr_create_0dst_0src((dc), OP_strht)
#define INSTR_CREATE_strt(dc) \
    instr_create_0dst_0src((dc), OP_strt)
#define INSTR_CREATE_sub_imm(dc, d, s1, s2, c) \
    instr_create_1dst_2src((dc), OP_sub_imm, (d), (s1), (s2), (c))
#define INSTR_CREATE_sub_reg(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_sub_regi, (d), (s), (c))
#define INSTR_CREATE_sub_rsr(dc, d, s, i, c) \
    instr_create_1dst_2src((dc), OP_sub_rsr, (d), (s), (i), (c))
#define INSTR_CREATE_sub_sp_imm(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_sub_sp_imm, (d), (s), (c))
#define INSTR_CREATE_sub_sp_reg(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_sub_sp_reg, (d), (s), (c))
#define INSTR_CREATE_subs(dc) \
    instr_create_0dst_0src((dc), OP_subs)
#define INSTR_CREATE_svc(dc) \
    instr_create_0dst_0src((dc), OP_svc)
#define INSTR_CREATE_swp(dc, d, s, c) \
    instr_create_1dst_1src((dc), OP_swp, (d), (s), (c))
#define INSTR_CREATE_swpb(dc) \
    instr_create_0dst_0src((dc), OP_swpb)
#define INSTR_CREATE_sxtab(dc) \
    instr_create_0dst_0src((dc), OP_sxtab)
#define INSTR_CREATE_sxtab16(dc) \
    instr_create_0dst_0src((dc), OP_sxtab16)
#define INSTR_CREATE_sxtah(dc) \
    instr_create_0dst_0src((dc), OP_sxtah)
#define INSTR_CREATE_tbb(dc) \
    instr_create_0dst_0src((dc), OP_tbb)
#define INSTR_CREATE_tbh(dc) \
    instr_create_0dst_0src((dc), OP_tbh)
#define INSTR_CREATE_teq_imm(dc) \
    instr_create_0dst_0src((dc), OP_teq_imm)
#define INSTR_CREATE_teq_reg(dc) \
    instr_create_0dst_0src((dc), OP_teq_reg)
#define INSTR_CREATE_teq_rsr(dc) \
    instr_create_0dst_0src((dc), OP_teq_rsr)
#define INSTR_CREATE_tst_imm(dc) \
    instr_create_0dst_0src((dc), OP_tst_imm)
#define INSTR_CREATE_tst_reg(dc) \
    instr_create_0dst_0src((dc), OP_tst_reg)
#define INSTR_CREATE_tst_rsr(dc) \
    instr_create_0dst_0src((dc), OP_tst_rsr)
#define INSTR_CREATE_uadd16(dc) \
    instr_create_0dst_0src((dc), OP_uadd16)
#define INSTR_CREATE_uadd8(dc) \
    instr_create_0dst_0src((dc), OP_uadd8)
#define INSTR_CREATE_uasx(dc) \
    instr_create_0dst_0src((dc), OP_uasx)
#define INSTR_CREATE_ubfx(dc) \
    instr_create_0dst_0src((dc), OP_ubfx)
#define INSTR_CREATE_udiv(dc) \
    instr_create_0dst_0src((dc), OP_udiv)
#define INSTR_CREATE_uhadd16(dc) \
    instr_create_0dst_0src((dc), OP_uhadd16)
#define INSTR_CREATE_uhadd8(dc) \
    instr_create_0dst_0src((dc), OP_uhadd8)
#define INSTR_CREATE_uhsax(dc) \
    instr_create_0dst_0src((dc), OP_uhsax)
#define INSTR_CREATE_uhsub16(dc) \
    instr_create_0dst_0src((dc), OP_uhsub16)
#define INSTR_CREATE_uhsub8(dc) \
    instr_create_0dst_0src((dc), OP_uhsub8)
#define INSTR_CREATE_umaal(dc) \
    instr_create_0dst_0src((dc), OP_umaal)
#define INSTR_CREATE_umlal(dc) \
    instr_create_0dst_0src((dc), OP_umlal)
#define INSTR_CREATE_umull(dc) \
    instr_create_0dst_0src((dc), OP_umull)
#define INSTR_CREATE_uqadd16(dc) \
    instr_create_0dst_0src((dc), OP_uqadd16)
#define INSTR_CREATE_uqadd8(dc) \
    instr_create_0dst_0src((dc), OP_uqadd8)
#define INSTR_CREATE_uqasx(dc) \
    instr_create_0dst_0src((dc), OP_uqasx)
#define INSTR_CREATE_uqsax(dc) \
    instr_create_0dst_0src((dc), OP_uqsax)
#define INSTR_CREATE_usub16(dc) \
    instr_create_0dst_0src((dc), OP_usub16)
#define INSTR_CREATE_usub8(dc) \
    instr_create_0dst_0src((dc), OP_usub8)
#define INSTR_CREATE_usad8(dc) \
    instr_create_0dst_0src((dc), OP_usad8)
#define INSTR_CREATE_usada8(dc) \
    instr_create_0dst_0src((dc), OP_usada8)
#define INSTR_CREATE_usat(dc) \
    instr_create_0dst_0src((dc), OP_usat)
#define INSTR_CREATE_usat16(dc) \
    instr_create_0dst_0src((dc), OP_usat16)
#define INSTR_CREATE_usax(dc) \
    instr_create_0dst_0src((dc), OP_usax)
#define INSTR_CREATE_uxtab(dc) \
    instr_create_0dst_0src((dc), OP_uxtab)
#define INSTR_CREATE_uxtab16(dc) \
    instr_create_0dst_0src((dc), OP_uxtab16)
#define INSTR_CREATE_uxtah(dc) \
    instr_create_0dst_0src((dc), OP_uxtah)
#define INSTR_CREATE_uxtb(dc) \
    instr_create_0dst_0src((dc), OP_uxtb)
#define INSTR_CREATE_uxtb16(dc) \
    instr_create_0dst_0src((dc), OP_uxtb16)
#define INSTR_CREATE_uxth(dc) \
    instr_create_0dst_0src((dc), OP_uxth)
#define INSTR_CREATE_vaba(dc) \
    instr_create_0dst_0src((dc), OP_vaba)
#define INSTR_CREATE_vabal_int(dc) \
    instr_create_0dst_0src((dc), OP_vabal_int)
#define INSTR_CREATE_vabd_int(dc) \
    instr_create_0dst_0src((dc), OP_vabd_int)
#define INSTR_CREATE_vabd_flt(dc) \
    instr_create_0dst_0src((dc), OP_vabd_flt)
#define INSTR_CREATE_vabs(dc) \
    instr_create_0dst_0src((dc), OP_vabs)
#define INSTR_CREATE_vacge(dc) \
    instr_create_0dst_0src((dc), OP_vacge)
#define INSTR_CREATE_vacgt(dc) \
    instr_create_0dst_0src((dc), OP_vacgt)
#define INSTR_CREATE_vacle(dc) \
    instr_create_0dst_0src((dc), OP_vacle)
#define INSTR_CREATE_vaclt(dc) \
    instr_create_0dst_0src((dc), OP_vaclt)
#define INSTR_CREATE_vadd_int(dc) \
    instr_create_0dst_0src((dc), OP_vadd_int)
#define INSTR_CREATE_vadd_flt(dc) \
    instr_create_0dst_0src((dc), OP_vadd_flt)
#define INSTR_CREATE_vaddhn(dc) \
    instr_create_0dst_0src((dc), OP_vaddhn)
#define INSTR_CREATE_vaddl(dc) \
    instr_create_0dst_0src((dc), OP_vaddl)
#define INSTR_CREATE_vaddw(dc) \
    instr_create_0dst_0src((dc), OP_vaddw)
#define INSTR_CREATE_vand_imm(dc) \
    instr_create_0dst_0src((dc), OP_vand_imm)
#define INSTR_CREATE_vand_reg(dc) \
    instr_create_0dst_0src((dc), OP_vand_reg)
#define INSTR_CREATE_vbic_imm(dc) \
    instr_create_0dst_0src((dc), OP_vbic_imm)
#define INSTR_CREATE_vbic_reg(dc) \
    instr_create_0dst_0src((dc), OP_vbic_reg)
#define INSTR_CREATE_vbif(dc) \
    instr_create_0dst_0src((dc), OP_vbif)
#define INSTR_CREATE_vbsl(dc) \
    instr_create_0dst_0src((dc), OP_vbsl)
#define INSTR_CREATE_vceq_reg(dc) \
    instr_create_0dst_0src((dc), OP_vceq_reg)
#define INSTR_CREATE_vceq_imm(dc) \
    instr_create_0dst_0src((dc), OP_vceq_imm)
#define INSTR_CREATE_vcge_reg(dc) \
    instr_create_0dst_0src((dc), OP_vcge_reg)
#define INSTR_CREATE_vcge_imm(dc) \
    instr_create_0dst_0src((dc), OP_vcge_imm)
#define INSTR_CREATE_vcgt_reg(dc) \
    instr_create_0dst_0src((dc), OP_vcgt_reg)
#define INSTR_CREATE_vcgt_imm(dc) \
    instr_create_0dst_0src((dc), OP_vcgt_imm)
#define INSTR_CREATE_vcle_reg(dc) \
    instr_create_0dst_0src((dc), OP_vcle_reg)
#define INSTR_CREATE_vcle_imm(dc) \
    instr_create_0dst_0src((dc), OP_vcle_imm)
#define INSTR_CREATE_vcls(dc) \
    instr_create_0dst_0src((dc), OP_vcls)
#define INSTR_CREATE_vclt_reg(dc) \
    instr_create_0dst_0src((dc), OP_vclt_reg)
#define INSTR_CREATE_vclt_imm(dc) \
    instr_create_0dst_0src((dc), OP_vclt_imm)
#define INSTR_CREATE_vclz(dc) \
    instr_create_0dst_0src((dc), OP_vclz)
#define INSTR_CREATE_vcmp(dc) \
    instr_create_0dst_0src((dc), OP_vcmp)
#define INSTR_CREATE_vcmpe(dc) \
    instr_create_0dst_0src((dc), OP_vcmpe)
#define INSTR_CREATE_vcnt(dc) \
    instr_create_0dst_0src((dc), OP_vcnt)
#define INSTR_CREATE_vcvt_flt_int_simd(dc) \
    instr_create_0dst_0src((dc), OP_vcvt_flt_int_simd)
#define INSTR_CREATE_vcvt_flt_int_vfp(dc) \
    instr_create_0dst_0src((dc), OP_vcvt_flt_int_vfp)
#define INSTR_CREATE_vcvtr_flt_int_vfp(dc) \
    instr_create_0dst_0src((dc), OP_vcvtr_flt_int_vfp)
#define INSTR_CREATE_vcvt_flt_fip_simd(dc) \
    instr_create_0dst_0src((dc), OP_vcvt_flt_fip_simd)
#define INSTR_CREATE_vcvt_dp_sp(dc) \
    instr_create_0dst_0src((dc), OP_vcvt_dp_sp)
#define INSTR_CREATE_vcvt_hp_sp_simd(dc) \
    instr_create_0dst_0src((dc), OP_vcvt_hp_sp_simd)
#define INSTR_CREATE_vcvtb_hp_sp_vfp(dc) \
    instr_create_0dst_0src((dc), OP_vcvtb_hp_sp_vfp)
#define INSTR_CREATE_vcvtt_hp_sp_vfp(dc) \
    instr_create_0dst_0src((dc), OP_vcvtt_hp_sp_vfp)
#define INSTR_CREATE_vdiv(dc) \
    instr_create_0dst_0src((dc), OP_vdiv)
#define INSTR_CREATE_vdup_scl(dc) \
    instr_create_0dst_0src((dc), OP_vdup_scl)
#define INSTR_CREATE_vdup_reg(dc) \
    instr_create_0dst_0src((dc), OP_vdup_reg)
#define INSTR_CREATE_veor(dc) \
    instr_create_0dst_0src((dc), OP_veor)
#define INSTR_CREATE_vext(dc) \
    instr_create_0dst_0src((dc), OP_vext)
#define INSTR_CREATE_vhadd(dc) \
    instr_create_0dst_0src((dc), OP_vhadd)
#define INSTR_CREATE_vhsub(dc) \
    instr_create_0dst_0src((dc), OP_vhsub)
#define INSTR_CREATE_vld1_mse(dc) \
    instr_create_0dst_0src((dc), OP_vld1_mse)
#define INSTR_CREATE_vld1_se1(dc) \
    instr_create_0dst_0src((dc), OP_vld1_se1)
#define INSTR_CREATE_vld1_sea(dc) \
    instr_create_0dst_0src((dc), OP_vld1_sea)
#define INSTR_CREATE_vld2_m2es(dc) \
    instr_create_0dst_0src((dc), OP_vld2_m2es)
#define INSTR_CREATE_vld2_s2e1(dc) \
    instr_create_0dst_0src((dc), OP_vld2_s2e1)
#define INSTR_CREATE_vld2_s2ea(dc) \
    instr_create_0dst_0src((dc), OP_vld2_s2ea)
#define INSTR_CREATE_vld3_m3s(dc) \
    instr_create_0dst_0src((dc), OP_vld3_m3s)
#define INSTR_CREATE_vld3_se1(dc) \
    instr_create_0dst_0src((dc), OP_vld3_se1)
#define INSTR_CREATE_vld3_sea(dc) \
    instr_create_0dst_0src((dc), OP_vld3_sea)
#define INSTR_CREATE_vld4_m4es(dc) \
    instr_create_0dst_0src((dc), OP_vld4_m4es)
#define INSTR_CREATE_vld4_se1(dc) \
    instr_create_0dst_0src((dc), OP_vld4_se1)
#define INSTR_CREATE_vld4_s4ea(dc) \
    instr_create_0dst_0src((dc), OP_vld4_s4ea)
#define INSTR_CREATE_vldm(dc) \
    instr_create_0dst_0src((dc), OP_vldm)
#define INSTR_CREATE_vldr(dc) \
    instr_create_0dst_0src((dc), OP_vldr)
#define INSTR_CREATE_vmax_int(dc) \
    instr_create_0dst_0src((dc), OP_vmax_int)
#define INSTR_CREATE_vmin_int(dc) \
    instr_create_0dst_0src((dc), OP_vmin_int)
#define INSTR_CREATE_vmax_flt(dc) \
    instr_create_0dst_0src((dc), OP_vmax_flt)
#define INSTR_CREATE_vmin_flt(dc) \
    instr_create_0dst_0src((dc), OP_vmin_flt)
#define INSTR_CREATE_vmla_int(dc) \
    instr_create_0dst_0src((dc), OP_vmla_int)
#define INSTR_CREATE_vmlal_int(dc) \
    instr_create_0dst_0src((dc), OP_vmlal_int)
#define INSTR_CREATE_vmls_int(dc) \
    instr_create_0dst_0src((dc), OP_vmls_int)
#define INSTR_CREATE_vmlsl_int(dc) \
    instr_create_0dst_0src((dc), OP_vmlsl_int)
#define INSTR_CREATE_vmla_flt(dc) \
    instr_create_0dst_0src((dc), OP_vmla_flt)
#define INSTR_CREATE_vmls_flt(dc) \
    instr_create_0dst_0src((dc), OP_vmls_flt)
#define INSTR_CREATE_vmla_scl(dc) \
    instr_create_0dst_0src((dc), OP_vmla_scl)
#define INSTR_CREATE_vmlal_scl(dc) \
    instr_create_0dst_0src((dc), OP_vmlal_scl)
#define INSTR_CREATE_vmls_scl(dc) \
    instr_create_0dst_0src((dc), OP_vmls_scl)
#define INSTR_CREATE_vmlsl_scl(dc) \
    instr_create_0dst_0src((dc), OP_vmlsl_scl)
#define INSTR_CREATE_vmov_imm(dc) \
    instr_create_0dst_0src((dc), OP_vmov_imm)
#define INSTR_CREATE_vmov_reg(dc) \
    instr_create_0dst_0src((dc), OP_vmov_reg)
#define INSTR_CREATE_vmov_reg_scl(dc) \
    instr_create_0dst_0src((dc), OP_vmov_reg_scl)
#define INSTR_CREATE_vmov_scl_reg(dc) \
    instr_create_0dst_0src((dc), OP_vmov_scl_reg)
#define INSTR_CREATE_vmov_reg_sp(dc) \
    instr_create_0dst_0src((dc), OP_vmov_reg_sp)
#define INSTR_CREATE_vmov_2reg_2sp(dc) \
    instr_create_0dst_0src((dc), OP_vmov_2reg_2sp)
#define INSTR_CREATE_vmov_2reg_2dp(dc) \
    instr_create_0dst_0src((dc), OP_vmov_2reg_2dp)
#define INSTR_CREATE_vmovl(dc) \
    instr_create_0dst_0src((dc), OP_vmovl)
#define INSTR_CREATE_vmovn(dc) \
    instr_create_0dst_0src((dc), OP_vmovn)
#define INSTR_CREATE_vmrs(dc) \
    instr_create_0dst_0src((dc), OP_vmrs)
#define INSTR_CREATE_vmsr(dc) \
    instr_create_0dst_0src((dc), OP_vmsr)
#define INSTR_CREATE_vmul_int(dc) \
    instr_create_0dst_0src((dc), OP_vmul_int)
#define INSTR_CREATE_vmull_int(dc) \
    instr_create_0dst_0src((dc), OP_vmull_int)
#define INSTR_CREATE_vmul_flp(dc) \
    instr_create_0dst_0src((dc), OP_vmul_flp)
#define INSTR_CREATE_vmul_scl(dc) \
    instr_create_0dst_0src((dc), OP_vmul_scl)
#define INSTR_CREATE_vmull_scl(dc) \
    instr_create_0dst_0src((dc), OP_vmull_scl)
#define INSTR_CREATE_vmvn_imm(dc) \
    instr_create_0dst_0src((dc), OP_vmvn_imm)
#define INSTR_CREATE_vmvn_reg(dc) \
    instr_create_0dst_0src((dc), OP_vmvn_reg)
#define INSTR_CREATE_vneg(dc) \
    instr_create_0dst_0src((dc), OP_vneg)
#define INSTR_CREATE_vnmla(dc) \
    instr_create_0dst_0src((dc), OP_vnmla)
#define INSTR_CREATE_vnmls(dc) \
    instr_create_0dst_0src((dc), OP_vnmls)
#define INSTR_CREATE_vnmul(dc) \
    instr_create_0dst_0src((dc), OP_vnmul)
#define INSTR_CREATE_vorn_imm(dc) \
    instr_create_0dst_0src((dc), OP_vorn_imm)
#define INSTR_CREATE_vorn_reg(dc) \
    instr_create_0dst_0src((dc), OP_vorn_reg)
#define INSTR_CREATE_vorr_imm(dc) \
    instr_create_0dst_0src((dc), OP_vorr_imm)
#define INSTR_CREATE_vorr_reg(dc) \
    instr_create_0dst_0src((dc), OP_vorr_reg)
#define INSTR_CREATE_vpadal(dc) \
    instr_create_0dst_0src((dc), OP_vpadal)
#define INSTR_CREATE_vpadd_int(dc) \
    instr_create_0dst_0src((dc), OP_vpadd_int)
#define INSTR_CREATE_vpadd_flp(dc) \
    instr_create_0dst_0src((dc), OP_vpadd_flp)
#define INSTR_CREATE_vpaddl(dc) \
    instr_create_0dst_0src((dc), OP_vpaddl)
#define INSTR_CREATE_vpmax_int(dc) \
    instr_create_0dst_0src((dc), OP_vpmax_int)
#define INSTR_CREATE_vpmin_int(dc) \
    instr_create_0dst_0src((dc), OP_vpmin_int)
#define INSTR_CREATE_vpmax_flp(dc) \
    instr_create_0dst_0src((dc), OP_vpmax_flp)
#define INSTR_CREATE_vpmin_flp(dc) \
    instr_create_0dst_0src((dc), OP_vpmin_flp)
#define INSTR_CREATE_vpop(dc) \
    instr_create_0dst_0src((dc), OP_vpop)
#define INSTR_CREATE_vpush(dc) \
    instr_create_0dst_0src((dc), OP_vpush)
#define INSTR_CREATE_vqabs(dc) \
    instr_create_0dst_0src((dc), OP_vqabs)
#define INSTR_CREATE_vqadd(dc) \
    instr_create_0dst_0src((dc), OP_vqadd)
#define INSTR_CREATE_vqdmlal(dc) \
    instr_create_0dst_0src((dc), OP_vqdmlal)
#define INSTR_CREATE_vqdmlsl(dc) \
    instr_create_0dst_0src((dc), OP_vqdmlsl)
#define INSTR_CREATE_vqdmulh(dc) \
    instr_create_0dst_0src((dc), OP_vqdmulh)
#define INSTR_CREATE_vqdmull(dc) \
    instr_create_0dst_0src((dc), OP_vqdmull)
#define INSTR_CREATE_vqdmovn(dc) \
    instr_create_0dst_0src((dc), OP_vqdmovn)
#define INSTR_CREATE_vqdmovun(dc) \
    instr_create_0dst_0src((dc), OP_vqdmovun)
#define INSTR_CREATE_vqneq(dc) \
    instr_create_0dst_0src((dc), OP_vqneq)
#define INSTR_CREATE_vqrdmulh(dc) \
    instr_create_0dst_0src((dc), OP_vqrdmulh)
#define INSTR_CREATE_vqrshl(dc) \
    instr_create_0dst_0src((dc), OP_vqrshl)
#define INSTR_CREATE_vqrshrn(dc) \
    instr_create_0dst_0src((dc), OP_vqrshrn)
#define INSTR_CREATE_vqrshrun(dc) \
    instr_create_0dst_0src((dc), OP_vqrshrun)
#define INSTR_CREATE_vqshl_reg(dc) \
    instr_create_0dst_0src((dc), OP_vqshl_reg)
#define INSTR_CREATE_vqshl_imm(dc) \
    instr_create_0dst_0src((dc), OP_vqshl_imm)
#define INSTR_CREATE_vqshlu_imm(dc) \
    instr_create_0dst_0src((dc), OP_vqshlu_imm)
#define INSTR_CREATE_vqshrn(dc) \
    instr_create_0dst_0src((dc), OP_vqshrn)
#define INSTR_CREATE_vqshrun(dc) \
    instr_create_0dst_0src((dc), OP_vqshrun)
#define INSTR_CREATE_vqsub(dc) \
    instr_create_0dst_0src((dc), OP_vqsub)
#define INSTR_CREATE_vqraddhn(dc) \
    instr_create_0dst_0src((dc), OP_vqraddhn)
#define INSTR_CREATE_vqrecpe(dc) \
    instr_create_0dst_0src((dc), OP_vqrecpe)
#define INSTR_CREATE_vqrecps(dc) \
    instr_create_0dst_0src((dc), OP_vqrecps)
#define INSTR_CREATE_vrev16(dc) \
    instr_create_0dst_0src((dc), OP_vrev16)
#define INSTR_CREATE_vrev32(dc) \
    instr_create_0dst_0src((dc), OP_vrev32)
#define INSTR_CREATE_vrev64(dc) \
    instr_create_0dst_0src((dc), OP_vrev64)
#define INSTR_CREATE_vrhadd(dc) \
    instr_create_0dst_0src((dc), OP_vrhadd)
#define INSTR_CREATE_vrshl(dc) \
    instr_create_0dst_0src((dc), OP_vrshl)
#define INSTR_CREATE_vrshr(dc) \
    instr_create_0dst_0src((dc), OP_vrshr)
#define INSTR_CREATE_vrshrn(dc) \
    instr_create_0dst_0src((dc), OP_vrshrn)
#define INSTR_CREATE_vrsqrte(dc) \
    instr_create_0dst_0src((dc), OP_vrsqrte)
#define INSTR_CREATE_vrsqrts(dc) \
    instr_create_0dst_0src((dc), OP_vrsqrts)
#define INSTR_CREATE_vrsra(dc) \
    instr_create_0dst_0src((dc), OP_vrsra)
#define INSTR_CREATE_vrsubhn(dc) \
    instr_create_0dst_0src((dc), OP_vrsubhn)
#define INSTR_CREATE_vshl_imm(dc) \
    instr_create_0dst_0src((dc), OP_vshl_imm)
#define INSTR_CREATE_vshl_reg(dc) \
    instr_create_0dst_0src((dc), OP_vshl_reg)
#define INSTR_CREATE_vshll(dc) \
    instr_create_0dst_0src((dc), OP_vshll)
#define INSTR_CREATE_vshr(dc) \
    instr_create_0dst_0src((dc), OP_vshr)
#define INSTR_CREATE_vshrn(dc) \
    instr_create_0dst_0src((dc), OP_vshrn)
#define INSTR_CREATE_vsli(dc) \
    instr_create_0dst_0src((dc), OP_vsli)
#define INSTR_CREATE_vsqrt(dc) \
    instr_create_0dst_0src((dc), OP_vsqrt)
#define INSTR_CREATE_vsra(dc) \
    instr_create_0dst_0src((dc), OP_vsra)
#define INSTR_CREATE_vsri(dc) \
    instr_create_0dst_0src((dc), OP_vsri)
#define INSTR_CREATE_vst1_mse(dc) \
    instr_create_0dst_0src((dc), OP_vst1_mse)
#define INSTR_CREATE_vst1_se1(dc) \
    instr_create_0dst_0src((dc), OP_vst1_se1)
#define INSTR_CREATE_vst2_m2e(dc) \
    instr_create_0dst_0src((dc), OP_vst2_m2e)
#define INSTR_CREATE_vst2_s2e1(dc) \
    instr_create_0dst_0src((dc), OP_vst2_s2e1)
#define INSTR_CREATE_vst3_m3es(dc) \
    instr_create_0dst_0src((dc), OP_vst3_m3es)
#define INSTR_CREATE_vst3_s3e1(dc) \
    instr_create_0dst_0src((dc), OP_vst3_s3e1)
#define INSTR_CREATE_vst4_m4es(dc) \
    instr_create_0dst_0src((dc), OP_vst4_m4es)
#define INSTR_CREATE_vst4_s4e1(dc) \
    instr_create_0dst_0src((dc), OP_vst4_s4e1)
#define INSTR_CREATE_vstm(dc) \
    instr_create_0dst_0src((dc), OP_vstm)
#define INSTR_CREATE_vstr(dc) \
    instr_create_0dst_0src((dc), OP_vstr)
#define INSTR_CREATE_vsub_int(dc) \
    instr_create_0dst_0src((dc), OP_vsub_int)
#define INSTR_CREATE_vsub_flp(dc) \
    instr_create_0dst_0src((dc), OP_vsub_flp)
#define INSTR_CREATE_vsubhn(dc) \
    instr_create_0dst_0src((dc), OP_vsubhn)
#define INSTR_CREATE_vsubl(dc) \
    instr_create_0dst_0src((dc), OP_vsubl)
#define INSTR_CREATE_vsubw(dc) \
    instr_create_0dst_0src((dc), OP_vsubw)
#define INSTR_CREATE_vswp(dc) \
    instr_create_0dst_0src((dc), OP_vswp)
#define INSTR_CREATE_vtbl(dc) \
    instr_create_0dst_0src((dc), OP_vtbl)
#define INSTR_CREATE_vtbx(dc) \
    instr_create_0dst_0src((dc), OP_vtbx)
#define INSTR_CREATE_vtrn(dc) \
    instr_create_0dst_0src((dc), OP_vtrn)
#define INSTR_CREATE_vtst(dc) \
    instr_create_0dst_0src((dc), OP_vtst)
#define INSTR_CREATE_vuzp(dc) \
    instr_create_0dst_0src((dc), OP_vuzp)
#define INSTR_CREATE_vzip(dc) \
    instr_create_0dst_0src((dc), OP_vzip)
#define INSTR_CREATE_wfe(dc) \
    instr_create_0dst_0src((dc), OP_wfe)
#define INSTR_CREATE_wfi(dc) \
    instr_create_0dst_0src((dc), OP_wfi)
#define INSTR_CREATE_yield(dc) \
    instr_create_0dst_0src((dc), OP_yield)


//SJF Thumb instr creation macros

#define INSTR_CREATE_T_add_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_add_reg)
#define INSTR_CREATE_T_adc_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_adc_reg)
#define INSTR_CREATE_T_add_low_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_add_low_reg)
#define INSTR_CREATE_T_add_high_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_add_high_reg)
#define INSTR_CREATE_T_add_sp_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_add_sp_imm)
#define INSTR_CREATE_T_add_imm_3(dc) \
    instr_create_0dst_0src((dc), OP_T_add_imm_3)
#define INSTR_CREATE_T_add_imm_8(dc) \
    instr_create_0dst_0src((dc), OP_T_add_imm_8)
#define INSTR_CREATE_T_and_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_and_reg)
#define INSTR_CREATE_T_asr_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_asr_imm)
#define INSTR_CREATE_T_asr_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_asr_reg)
#define INSTR_CREATE_T_b(dc) \
    instr_create_0dst_0src((dc), OP_T_b)
#define INSTR_CREATE_T_bic_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_bic_reg)
#define INSTR_CREATE_T_bkpt(dc) \
    instr_create_0dst_0src((dc), OP_T_bkpt)
#define INSTR_CREATE_T_blx_ref(dc) \
    instr_create_0dst_0src((dc), OP_T_blx_ref)
#define INSTR_CREATE_T_bx(dc) \
    instr_create_0dst_0src((dc), OP_T_bx)
#define INSTR_CREATE_T_cbnz(dc) \
    instr_create_0dst_0src((dc), OP_T_cbnz)
#define INSTR_CREATE_T_cbnz_2(dc) \
    instr_create_0dst_0src((dc), OP_T_cbnz_2)
#define INSTR_CREATE_T_cbz(dc) \
    instr_create_0dst_0src((dc), OP_T_cbz)
#define INSTR_CREATE_T_cbz_2(dc) \
    instr_create_0dst_0src((dc), OP_T_cbz_2)
#define INSTR_CREATE_T_cmn_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_cmn_reg)
#define INSTR_CREATE_T_cmp_high_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_cmp_high_reg)
#define INSTR_CREATE_T_cmp_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_cmp_imm)
#define INSTR_CREATE_T_cmp_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_cmp_reg)
#define INSTR_CREATE_T_cps(dc) \
    instr_create_0dst_0src((dc), OP_T_cps)
#define INSTR_CREATE_T_eor_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_eor_reg)
#define INSTR_CREATE_T_it(dc) \
    instr_create_0dst_0src((dc), OP_T_it)
#define INSTR_CREATE_T_ldrb_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_ldrb_imm)
#define INSTR_CREATE_T_ldrb_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_ldrb_reg)
#define INSTR_CREATE_T_ldrh_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_ldrh_imm)
#define INSTR_CREATE_T_ldrh_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_ldrh_reg)
#define INSTR_CREATE_T_ldrsb_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_ldrsb_reg)
#define INSTR_CREATE_T_ldrsh_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_ldrsh_reg)
#define INSTR_CREATE_T_ldr_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_ldr_imm)
#define INSTR_CREATE_T_ldr_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_ldr_reg)
#define INSTR_CREATE_T_lsl_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_lsl_imm)
#define INSTR_CREATE_T_lsl_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_lsl_reg)
#define INSTR_CREATE_T_lsr_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_lsr_imm)
#define INSTR_CREATE_T_lsr_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_lsr_reg)
#define INSTR_CREATE_T_mov_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_mov_imm)
#define INSTR_CREATE_T_mov_high_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_mov_high_reg)
#define INSTR_CREATE_T_mov_low_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_mov_low_reg)
#define INSTR_CREATE_T_mvn_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_mvn_reg)
#define INSTR_CREATE_T_mul(dc) \
    instr_create_0dst_0src((dc), OP_T_mul)
#define INSTR_CREATE_T_nop(dc) \
    instr_create_0dst_0src((dc), OP_T_nop)
#define INSTR_CREATE_T_orr_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_orr_reg)
#define INSTR_CREATE_T_pop(dc) \
    instr_create_0dst_0src((dc), OP_T_pop)
#define INSTR_CREATE_T_push(dc) \
    instr_create_0dst_0src((dc), OP_T_push)
#define INSTR_CREATE_T_rev(dc) \
    instr_create_0dst_0src((dc), OP_T_rev)
#define INSTR_CREATE_T_rev16(dc) \
    instr_create_0dst_0src((dc), OP_T_rev16)
#define INSTR_CREATE_T_revsh(dc) \
    instr_create_0dst_0src((dc), OP_T_revsh)
#define INSTR_CREATE_T_ror_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_ror_reg)
#define INSTR_CREATE_T_rsb_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_rsb_imm)
#define INSTR_CREATE_T_sbc_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_sbc_reg)
#define INSTR_CREATE_T_setend(dc) \
    instr_create_0dst_0src((dc), OP_T_setend)
#define INSTR_CREATE_T_sev(dc) \
    instr_create_0dst_0src((dc), OP_T_sev)
#define INSTR_CREATE_T_str_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_str_imm)
#define INSTR_CREATE_T_str_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_str_reg)
#define INSTR_CREATE_T_str_sp(dc) \
    instr_create_0dst_0src((dc), OP_T_str_sp)
#define INSTR_CREATE_T_strb_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_strb_imm)
#define INSTR_CREATE_T_strb_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_strb_reg)
#define INSTR_CREATE_T_strh_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_strh_imm)
#define INSTR_CREATE_T_strh_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_strh_reg)
#define INSTR_CREATE_T_sub_sp_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_sub_sp_imm)
#define INSTR_CREATE_T_sub_imm_8(dc) \
    instr_create_0dst_0src((dc), OP_T_sub_imm_8)
#define INSTR_CREATE_T_sub_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_sub_reg)
#define INSTR_CREATE_T_sub_imm_3(dc) \
    instr_create_0dst_0src((dc), OP_T_sub_imm_3)
#define INSTR_CREATE_T_svc(dc) \
    instr_create_0dst_0src((dc), OP_T_svc)
#define INSTR_CREATE_T_sxth(dc) \
    instr_create_0dst_0src((dc), OP_T_sxth)
#define INSTR_CREATE_T_sxtb(dc) \
    instr_create_0dst_0src((dc), OP_T_sxtb)
#define INSTR_CREATE_T_tst_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_tst_reg)
#define INSTR_CREATE_T_uxtb(dc) \
    instr_create_0dst_0src((dc), OP_T_uxtb)
#define INSTR_CREATE_T_uxth(dc) \
    instr_create_0dst_0src((dc), OP_T_uxth)
#define INSTR_CREATE_T_wfe(dc) \
    instr_create_0dst_0src((dc), OP_T_wfe)
#define INSTR_CREATE_T_wfi(dc) \
    instr_create_0dst_0src((dc), OP_T_wfi)
#define INSTR_CREATE_T_yield(dc) \
    instr_create_0dst_0src((dc), OP_T_yield)
#define INSTR_CREATE_T_32_and_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_and_imm)
#define INSTR_CREATE_T_32_tst_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_tst_imm)
#define INSTR_CREATE_T_32_bic_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_bic_imm)
#define INSTR_CREATE_T_32_orr_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_orr_imm)
#define INSTR_CREATE_T_32_mov_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mov_imm)
#define INSTR_CREATE_T_32_orn_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_orn_imm)
#define INSTR_CREATE_T_32_mvn_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mvn_imm)
#define INSTR_CREATE_T_32_eor_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_eor_imm)
#define INSTR_CREATE_T_32_teq_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_teq_imm)
#define INSTR_CREATE_T_32_add_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_add_imm)
#define INSTR_CREATE_T_32_cmn_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_cmn_imm)
#define INSTR_CREATE_T_32_adc_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_adc_imm)
#define INSTR_CREATE_T_32_sbc_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sbc_imm)
#define INSTR_CREATE_T_32_sub_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sub_imm)
#define INSTR_CREATE_T_32_cmp_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_cmp_imm)
#define INSTR_CREATE_T_32_rsb_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_rsb_imm)
#define INSTR_CREATE_T_32_add_wide(dc) \
    instr_create_0dst_0src((dc), OP_T_32_add_wide)
#define INSTR_CREATE_T_32_adr(dc) \
    instr_create_0dst_0src((dc), OP_T_32_adr)
#define INSTR_CREATE_T_32_mov_wide(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mov_wide)
#define INSTR_CREATE_T_32_adr_2(dc) \
    instr_create_0dst_0src((dc), OP_T_32_adr_2)
#define INSTR_CREATE_T_32_movt_top(dc) \
    instr_create_0dst_0src((dc), OP_T_32_movt_top)
#define INSTR_CREATE_T_32_ssat(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ssat)
#define INSTR_CREATE_T_32_ssat16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ssat16)
#define INSTR_CREATE_T_32_sbfx(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sbfx)
#define INSTR_CREATE_T_32_bfi(dc) \
    instr_create_0dst_0src((dc), OP_T_32_bfi)
#define INSTR_CREATE_T_32_bfc(dc) \
    instr_create_0dst_0src((dc), OP_T_32_bfc)
#define INSTR_CREATE_T_32_usat16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_usat16)
#define INSTR_CREATE_T_32_ubfx(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ubfx)
#define INSTR_CREATE_T_32_b(dc) \
    instr_create_0dst_0src((dc), OP_T_32_b)
#define INSTR_CREATE_T_32_msr_reg_app(dc) \
    instr_create_0dst_0src((dc), OP_T_32_msr_reg_app)
#define INSTR_CREATE_T_32_msr_reg_sys(dc) \
    instr_create_0dst_0src((dc), OP_T_32_msr_reg_sys)
#define INSTR_CREATE_T_32_bxj(dc) \
    instr_create_0dst_0src((dc), OP_T_32_bxj)
#define INSTR_CREATE_T_32_subs(dc) \
    instr_create_0dst_0src((dc), OP_T_32_subs)
#define INSTR_CREATE_T_32_mrs(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mrs)
#define INSTR_CREATE_T_32_smc(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smc)
#define INSTR_CREATE_T_32_b_2(dc) \
    instr_create_0dst_0src((dc), OP_T_32_b_2)
#define INSTR_CREATE_T_32_blx_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_blx_imm)
#define INSTR_CREATE_T_32_bl(dc) \
    instr_create_0dst_0src((dc), OP_T_32_bl)
#define INSTR_CREATE_T_32_cps(dc) \
    instr_create_0dst_0src((dc), OP_T_32_cps)
#define INSTR_CREATE_T_32_nop(dc) \
    instr_create_0dst_0src((dc), OP_T_32_nop)
#define INSTR_CREATE_T_32_yield(dc) \
    instr_create_0dst_0src((dc), OP_T_32_yield)
#define INSTR_CREATE_T_32_wfe(dc) \
    instr_create_0dst_0src((dc), OP_T_32_wfe)
#define INSTR_CREATE_T_32_wfi(dc) \
    instr_create_0dst_0src((dc), OP_T_32_wfi)
#define INSTR_CREATE_T_32_sev(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sev)
#define INSTR_CREATE_T_32_dbg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_dbg)
#define INSTR_CREATE_T_32_enterx(dc) \
    instr_create_0dst_0src((dc), OP_T_32_enterx)
#define INSTR_CREATE_T_32_leavex(dc) \
    instr_create_0dst_0src((dc), OP_T_32_leavex)
#define INSTR_CREATE_T_32_clrex(dc) \
    instr_create_0dst_0src((dc), OP_T_32_clrex)
#define INSTR_CREATE_T_32_dsb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_dsb)
#define INSTR_CREATE_T_32_dmb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_dmb)
#define INSTR_CREATE_T_32_isb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_isb)
#define INSTR_CREATE_T_32_srs(dc) \
    instr_create_0dst_0src((dc), OP_T_32_srs)
#define INSTR_CREATE_T_32_rfe(dc) \
    instr_create_0dst_0src((dc), OP_T_32_rfe)
#define INSTR_CREATE_T_32_stm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_stm)
#define INSTR_CREATE_T_32_stmia(dc) \
    instr_create_0dst_0src((dc), OP_T_32_stmia)
#define INSTR_CREATE_T_32_stmea(dc) \
    instr_create_0dst_0src((dc), OP_T_32_stmea)
#define INSTR_CREATE_T_32_ldm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldm)
#define INSTR_CREATE_T_32_ldmia(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldmia)
#define INSTR_CREATE_T_32_ldmfd(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldmfd)
#define INSTR_CREATE_T_32_pop(dc) \
    instr_create_0dst_0src((dc), OP_T_32_pop)
#define INSTR_CREATE_T_32_stmdb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_stmdb)
#define INSTR_CREATE_T_32_stmfd(dc) \
    instr_create_0dst_0src((dc), OP_T_32_stmfd)
#define INSTR_CREATE_T_32_push(dc) \
    instr_create_0dst_0src((dc), OP_T_32_push)
#define INSTR_CREATE_T_32_ldmdb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldmdb)
#define INSTR_CREATE_T_32_ldmea(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldmea)
#define INSTR_CREATE_T_32_strex(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strex)
#define INSTR_CREATE_T_32_ldrex(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrex)
#define INSTR_CREATE_T_32_strd_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strd_imm)
#define INSTR_CREATE_T_32_ldrd_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrd_imm)
#define INSTR_CREATE_T_32_ldrd_lit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrd_lit)
#define INSTR_CREATE_T_32_strexb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strexb)
#define INSTR_CREATE_T_32_strexh(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strexh)
#define INSTR_CREATE_T_32_strexd(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strexd)
#define INSTR_CREATE_T_32_tbb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_tbb)
#define INSTR_CREATE_T_32_tbh(dc) \
    instr_create_0dst_0src((dc), OP_T_32_tbh)
#define INSTR_CREATE_T_32_ldrexb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrexb)
#define INSTR_CREATE_T_32_ldrexh(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrexh)
#define INSTR_CREATE_T_32_ldrexd(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrexd)
#define INSTR_CREATE_T_32_ldr_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldr_imm)
#define INSTR_CREATE_T_32_ldrt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrt)
#define INSTR_CREATE_T_32_ldr_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldr_reg)
#define INSTR_CREATE_T_32_ldr_lit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldr_lit)
#define INSTR_CREATE_T_32_ldrh_lit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrh_lit)
#define INSTR_CREATE_T_32_ldrh_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrh_imm)
#define INSTR_CREATE_T_32_ldrht(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrht)
#define INSTR_CREATE_T_32_ldrh_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrh_reg)
#define INSTR_CREATE_T_32_ldrsh_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrsh_imm)
#define INSTR_CREATE_T_32_ldrsht(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrsht)
#define INSTR_CREATE_T_32_ldrsh_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrsh_reg)
#define INSTR_CREATE_T_32_ldrb_lit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrb_lit)
#define INSTR_CREATE_T_32_ldrb_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrb_imm)
#define INSTR_CREATE_T_32_ldrbt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrbt)
#define INSTR_CREATE_T_32_ldrb_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrb_reg)
#define INSTR_CREATE_T_32_ldrsb_lit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrsb_lit)
#define INSTR_CREATE_T_32_ldrsb_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrsb_imm)
#define INSTR_CREATE_T_32_ldrsbt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrsbt)
#define INSTR_CREATE_T_32_ldrsb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldrsb)
#define INSTR_CREATE_T_32_pld_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_pld_imm)
#define INSTR_CREATE_T_32_pld_lit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_pld_lit)
#define INSTR_CREATE_T_32_pld_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_pld_reg)
#define INSTR_CREATE_T_32_pli_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_pli_imm)
#define INSTR_CREATE_T_32_pli_lit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_pli_lit)
#define INSTR_CREATE_T_32_pli_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_pli_reg)
#define INSTR_CREATE_T_32_strb_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strb_imm)
#define INSTR_CREATE_T_32_strbt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strbt)
#define INSTR_CREATE_T_32_strb_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strb_reg)
#define INSTR_CREATE_T_32_strh_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strh_imm)
#define INSTR_CREATE_T_32_strht(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strht)
#define INSTR_CREATE_T_32_strh_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strh_reg)
#define INSTR_CREATE_T_32_str_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_str_imm)
#define INSTR_CREATE_T_32_strt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_strt)
#define INSTR_CREATE_T_32_str_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_str_reg)
#define INSTR_CREATE_T_32_and_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_and_reg)
#define INSTR_CREATE_T_32_tst_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_tst_reg)
#define INSTR_CREATE_T_32_bic_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_bic_reg)
#define INSTR_CREATE_T_32_orr_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_orr_reg)
#define INSTR_CREATE_T_32_mov_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mov_reg)
#define INSTR_CREATE_T_32_orn_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_orn_reg)
#define INSTR_CREATE_T_32_mvn_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mvn_reg)
#define INSTR_CREATE_T_32_eor_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_eor_reg)
#define INSTR_CREATE_T_32_teq_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_teq_reg)
#define INSTR_CREATE_T_32_pkh(dc) \
    instr_create_0dst_0src((dc), OP_T_32_pkh)
#define INSTR_CREATE_T_32_add_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_add_reg)
#define INSTR_CREATE_T_32_cmn_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_cmn_reg)
#define INSTR_CREATE_T_32_adc_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_adc_reg)
#define INSTR_CREATE_T_32_sbc_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sbc_reg)
#define INSTR_CREATE_T_32_sub_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sub_reg)
#define INSTR_CREATE_T_32_cmp_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_cmp_reg)
#define INSTR_CREATE_T_32_rsb_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_rsb_reg)
#define INSTR_CREATE_T_32_lsl_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_lsl_reg)
#define INSTR_CREATE_T_32_lsr_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_lsr_reg)
#define INSTR_CREATE_T_32_asr_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_asr_reg)
#define INSTR_CREATE_T_32_ror_reg(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ror_reg)
#define INSTR_CREATE_T_32_sxtah(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sxtah)
#define INSTR_CREATE_T_32_sxth(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sxth)
#define INSTR_CREATE_T_32_uxtah(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uxtah)
#define INSTR_CREATE_T_32_uxth(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uxth)
#define INSTR_CREATE_T_32_sxtab16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sxtab16)
#define INSTR_CREATE_T_32_sxtb16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sxtb16)
#define INSTR_CREATE_T_32_uxtab16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uxtab16)
#define INSTR_CREATE_T_32_uxtb16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uxtb16)
#define INSTR_CREATE_T_32_sxtab(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sxtab)
#define INSTR_CREATE_T_32_sxtb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sxtb)
#define INSTR_CREATE_T_32_uxtab(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uxtab)
#define INSTR_CREATE_T_32_uxtb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uxtb)
#define INSTR_CREATE_T_32_sadd16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sadd16)
#define INSTR_CREATE_T_32_sasx(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sasx)
#define INSTR_CREATE_T_32_ssax(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ssax)
#define INSTR_CREATE_T_32_ssub16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ssub16)
#define INSTR_CREATE_T_32_sadd8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sadd8)
#define INSTR_CREATE_T_32_ssub8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ssub8)
#define INSTR_CREATE_T_32_qadd16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qadd16)
#define INSTR_CREATE_T_32_qasx(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qasx)
#define INSTR_CREATE_T_32_qsax(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qsax)
#define INSTR_CREATE_T_32_qsub16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qsub16)
#define INSTR_CREATE_T_32_qadd8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qadd8)
#define INSTR_CREATE_T_32_qsub8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qsub8)
#define INSTR_CREATE_T_32_shadd16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_shadd16)
#define INSTR_CREATE_T_32_shasx(dc) \
    instr_create_0dst_0src((dc), OP_T_32_shasx)
#define INSTR_CREATE_T_32_shsax(dc) \
    instr_create_0dst_0src((dc), OP_T_32_shsax)
#define INSTR_CREATE_T_32_shsub16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_shsub16)
#define INSTR_CREATE_T_32_shadd8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_shadd8)
#define INSTR_CREATE_T_32_shsub8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_shsub8)
#define INSTR_CREATE_T_32_uadd16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uadd16)
#define INSTR_CREATE_T_32_uasx(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uasx)
#define INSTR_CREATE_T_32_usax(dc) \
    instr_create_0dst_0src((dc), OP_T_32_usax)
#define INSTR_CREATE_T_32_usub16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_usub16)
#define INSTR_CREATE_T_32_uadd8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uadd8)
#define INSTR_CREATE_T_32_usub8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_usub8)
#define INSTR_CREATE_T_32_uqadd16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uqadd16)
#define INSTR_CREATE_T_32_uqasx(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uqasx)
#define INSTR_CREATE_T_32_uqsax(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uqsax)
#define INSTR_CREATE_T_32_uqsub16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uqsub16)
#define INSTR_CREATE_T_32_uqadd8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uqadd8)
#define INSTR_CREATE_T_32_uqsub8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uqsub8)
#define INSTR_CREATE_T_32_uhadd16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uhadd16)
#define INSTR_CREATE_T_32_uhasx(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uhasx)
#define INSTR_CREATE_T_32_uhsax(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uhsax)
#define INSTR_CREATE_T_32_uhsub16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uhsub16)
#define INSTR_CREATE_T_32_uhadd8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uhadd8)
#define INSTR_CREATE_T_32_uhsub8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_uhsub8)
#define INSTR_CREATE_T_32_qadd(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qadd)
#define INSTR_CREATE_T_32_qdadd(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qdadd)
#define INSTR_CREATE_T_32_qsub(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qsub)
#define INSTR_CREATE_T_32_qdsub(dc) \
    instr_create_0dst_0src((dc), OP_T_32_qdsub)
#define INSTR_CREATE_T_32_rev(dc) \
    instr_create_0dst_0src((dc), OP_T_32_rev)
#define INSTR_CREATE_T_32_rev16(dc) \
    instr_create_0dst_0src((dc), OP_T_32_rev16)
#define INSTR_CREATE_T_32_rbit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_rbit)
#define INSTR_CREATE_T_32_revsh(dc) \
    instr_create_0dst_0src((dc), OP_T_32_revsh)
#define INSTR_CREATE_T_32_sel(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sel)
#define INSTR_CREATE_T_32_clz(dc) \
    instr_create_0dst_0src((dc), OP_T_32_clz)
#define INSTR_CREATE_T_32_mla(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mla)
#define INSTR_CREATE_T_32_mul(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mul)
#define INSTR_CREATE_T_32_mls(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mls)
#define INSTR_CREATE_T_32_smlabb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlabb)
#define INSTR_CREATE_T_32_smlabt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlabt)
#define INSTR_CREATE_T_32_smlatb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlatb)
#define INSTR_CREATE_T_32_smlatt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlatt)
#define INSTR_CREATE_T_32_smulbb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smulbb)
#define INSTR_CREATE_T_32_smulbt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smulbt)
#define INSTR_CREATE_T_32_smultb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smultb)
#define INSTR_CREATE_T_32_smultt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smultt)
#define INSTR_CREATE_T_32_smlad(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlad)
#define INSTR_CREATE_T_32_smuad(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smuad)
#define INSTR_CREATE_T_32_smlawb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlawb)
#define INSTR_CREATE_T_32_smlawt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlawt)
#define INSTR_CREATE_T_32_smulwb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smulwb)
#define INSTR_CREATE_T_32_smulwt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smulwt)
#define INSTR_CREATE_T_32_smlsd(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlsd)
#define INSTR_CREATE_T_32_smusd(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smusd)
#define INSTR_CREATE_T_32_smmla(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smmla)
#define INSTR_CREATE_T_32_smmul(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smmul)
#define INSTR_CREATE_T_32_smmls(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smmls)
#define INSTR_CREATE_T_32_usad8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_usad8)
#define INSTR_CREATE_T_32_usada8(dc) \
    instr_create_0dst_0src((dc), OP_T_32_usada8)
#define INSTR_CREATE_T_32_smull(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smull)
#define INSTR_CREATE_T_32_sdiv(dc) \
    instr_create_0dst_0src((dc), OP_T_32_sdiv)
#define INSTR_CREATE_T_32_umull(dc) \
    instr_create_0dst_0src((dc), OP_T_32_umull)
#define INSTR_CREATE_T_32_udiv(dc) \
    instr_create_0dst_0src((dc), OP_T_32_udiv)
#define INSTR_CREATE_T_32_smlal(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlal)
#define INSTR_CREATE_T_32_smlalbb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlalbb)
#define INSTR_CREATE_T_32_smlalbt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlalbt)
#define INSTR_CREATE_T_32_smlaltb(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlaltb)
#define INSTR_CREATE_T_32_smlaltt(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlaltt)
#define INSTR_CREATE_T_32_smlald(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlald)
#define INSTR_CREATE_T_32_smlsld(dc) \
    instr_create_0dst_0src((dc), OP_T_32_smlsld)
#define INSTR_CREATE_T_32_umlal(dc) \
    instr_create_0dst_0src((dc), OP_T_32_umlal)
#define INSTR_CREATE_T_32_umaal(dc) \
    instr_create_0dst_0src((dc), OP_T_32_umaal)
#define INSTR_CREATE_T_32_stc(dc) \
    instr_create_0dst_0src((dc), OP_T_32_stc)
#define INSTR_CREATE_T_32_stc2(dc) \
    instr_create_0dst_0src((dc), OP_T_32_stc2)
#define INSTR_CREATE_T_32_ldc_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldc_imm)
#define INSTR_CREATE_T_32_ldc_lit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldc_lit)
#define INSTR_CREATE_T_32_ldc2_imm(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldc2_imm)
#define INSTR_CREATE_T_32_ldc2_lit(dc) \
    instr_create_0dst_0src((dc), OP_T_32_ldc2_lit)
#define INSTR_CREATE_T_32_mcrr(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mcrr)
#define INSTR_CREATE_T_32_mcrr2(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mcrr2)
#define INSTR_CREATE_T_32_mrrc(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mrrc)
#define INSTR_CREATE_T_32_mrrc2(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mrrc2)
#define INSTR_CREATE_T_32_cdp(dc) \
    instr_create_0dst_0src((dc), OP_T_32_cdp)
#define INSTR_CREATE_T_32_cdp2(dc) \
    instr_create_0dst_0src((dc), OP_T_32_cdp2)
#define INSTR_CREATE_T_32_mcr(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mcr)
#define INSTR_CREATE_T_32_mcr2(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mcr2)
#define INSTR_CREATE_T_32_mrc(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mrc)
#define INSTR_CREATE_T_32_mrc2(dc) \
    instr_create_0dst_0src((dc), OP_T_32_mrc2)



/**
 * Creates an instr_t with opcode OP_LABEL.  An OP_LABEL instruction can be used as a
 * jump or call instr_t target, and when emitted it will take no space in the
 * resulting machine code.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_label(dc)    instr_create_0dst_0src((dc), OP_LABEL, COND_ALWAYS)

#define INSTR_CREATE_movntps(dc, d, s) \
  instr_create_1dst_1src((dc), OP_mov, (d), (s))

#define INSTR_CREATE_RAW_nop2byte(dc) INSTR_CREATE_nop2byte_reg(dc, DR_REG_R7)
#define INSTR_CREATE_RAW_nop3byte(dc) INSTR_CREATE_nop3byte_reg(dc, DR_REG_R7)

#define INSTR_CREATE_RAW_nop1byte(dc, c) instr_create_0dst_0src((dc), OP_nop, (c))
#define INSTR_CREATE_nop(dc, c) instr_create_0dst_0src((dc), OP_nop, (c))

static inline instr_t *
INSTR_CREATE_nop2byte_reg(dcontext_t *dcontext, reg_id_t reg)
{
   /* SJF ?? What is going on here */
   return INSTR_CREATE_mov_imm(dcontext, opnd_create_reg(reg), opnd_create_reg(reg), COND_ALWAYS);
}

static inline instr_t *
INSTR_CREATE_nop3byte_reg(dcontext_t *dcontext, reg_id_t reg)
{
   /* SJF ?? What is going on here */
   return INSTR_CREATE_mov_imm(dcontext, opnd_create_reg(reg), opnd_create_reg(reg), COND_ALWAYS);
}

static inline instr_t *
INSTR_CREATE_branch_ind(dcontext_t *dcontext, opnd_t opnd)
{
   /* Move the value held in the reg passed into pc. This performs an
      indirect branch in combination with the address being put into reg */
   return INSTR_CREATE_mov_reg(dcontext, opnd_create_reg(DR_REG_R15), opnd, COND_ALWAYS);
}

static inline instr_t *
INSTR_CREATE_bl_ind(dcontext_t *dcontext, opnd_t opnd)
{       
   /* Move the value held in the reg passed into pc. This performs an
      indirect branch in combination with the address being put into reg */
   return INSTR_CREATE_blx_reg(dcontext, opnd, COND_ALWAYS);
} 


static inline instr_t* 
INSTR_CREATE_msr_cpsr(dcontext_t *dcontext, reg_id_t reg)
{
   return INSTR_CREATE_msr_reg(dcontext, opnd_create_reg(reg), opnd_create_mask(MASK_WRITE_ALL), COND_ALWAYS);
}

static inline instr_t* 
INSTR_CREATE_mrs_cpsr(dcontext_t *dcontext, reg_id_t reg)
{
   return INSTR_CREATE_mrs(dcontext, opnd_create_reg(reg), COND_ALWAYS);
}

/* SJF Add inline function to 'return' from a function. 
       'mov pc, lr'
 */
static inline instr_t*
INSTR_CREATE_ret(dcontext_t *dcontext)
{
   return INSTR_CREATE_mov_reg(dcontext, opnd_create_reg(DR_REG_R15), 
                               opnd_create_reg(DR_REG_R14), COND_ALWAYS);
}


/* @} */ /* end doxygen group */
#ifndef UNSUPPORTED_API
/* DR_API EXPORT END */
#endif

#ifdef UNSUPPORTED_API
/* DR_API EXPORT END */
#endif

#endif /* _INSTR_CREATE_H_ */

