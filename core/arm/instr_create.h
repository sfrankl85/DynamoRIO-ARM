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

/* no-operand instructions */
/** @name No-operand instructions */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
/* TODO SJF Add opcodes here */
#define INSTR_CREATE_nop(dc)      instr_create_0dst_0src((dc), OP_nop)
/* @} */ /* end doxygen group */
/**
 * Creates an instr_t with opcode OP_LABEL.  An OP_LABEL instruction can be used as a
 * jump or call instr_t target, and when emitted it will take no space in the
 * resulting machine code.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_label(dc)    instr_create_0dst_0src((dc), OP_LABEL)

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
#define INSTR_CREATE_b_short(dc, op, t) \
  instr_create_0dst_1src((dc), (op), (t))
/**
 * Creates an instr_t for a conditional branch instruction with the given opcode
 * and target operand.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param t The opnd_t target operand for the instruction, which can be either
 * a pc (opnd_create_pc()) or an instr_t (opnd_create_instr()).
 */
#define INSTR_CREATE_b(dc, t) \
  instr_create_0dst_1src((dc), OP_b, (t))
/** @name One explicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#ifdef NO
/* TODO SJF */

#define INSTR_CREATE_lldt(dc, s) \
  instr_create_0dst_1src((dc), OP_lldt, (s))
#define INSTR_CREATE_ltr(dc, s) \
  instr_create_0dst_1src((dc), OP_ltr, (s))
#define INSTR_CREATE_verr(dc, s) \
  instr_create_0dst_1src((dc), OP_verr, (s))
#define INSTR_CREATE_verw(dc, s) \
  instr_create_0dst_1src((dc), OP_verw, (s))
#define INSTR_CREATE_vmptrld(dc, s) \
  instr_create_0dst_1src((dc), OP_vmptrld, (s))
#define INSTR_CREATE_vmxon(dc, s) \
  instr_create_0dst_1src((dc), OP_vmxon, (s))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction, which can be
 * created with OPND_CREATE_MEM_lgdt() to get the appropriate operand size.
 */
#define INSTR_CREATE_lgdt(dc, s) \
  instr_create_0dst_1src((dc), OP_lgdt, (s))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction, which can be
 * created with OPND_CREATE_MEM_lidt() to get the appropriate operand size.
 */
#define INSTR_CREATE_lidt(dc, s) \
  instr_create_0dst_1src((dc), OP_lidt, (s))
#define INSTR_CREATE_lmsw(dc, s) \
  instr_create_0dst_1src((dc), OP_lmsw, (s))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction, which can be
 * created with OPND_CREATE_MEM_invlpg() to get the appropriate operand size.
 */
#define INSTR_CREATE_invlpg(dc, s) \
  instr_create_0dst_1src((dc), OP_invlpg, (s))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction, which can be
 * created with OPND_CREATE_MEM_fxrstor() to get the appropriate operand size.
 */
#define INSTR_CREATE_fxrstor(dc, s) \
  instr_create_0dst_1src((dc), OP_fxrstor, (s))
#define INSTR_CREATE_ldmxcsr(dc, s) \
  instr_create_0dst_1src((dc), OP_ldmxcsr, (s))
#define INSTR_CREATE_vldmxcsr(dc, s) \
  instr_create_0dst_1src((dc), OP_vldmxcsr, (s))
#define INSTR_CREATE_nop_modrm(dc, s) \
  instr_create_0dst_1src((dc), OP_nop_modrm, (s))
/* @} */ /* end doxygen group */
/** @name Prefetch */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction, which can be
 * created with OPND_CREATE_MEM_prefetch() to get the appropriate operand size.
 */
#define INSTR_CREATE_prefetchnta(dc, s) \
  instr_create_0dst_1src((dc), OP_prefetchnta, (s))
#define INSTR_CREATE_prefetcht0(dc, s) \
  instr_create_0dst_1src((dc), OP_prefetcht0, (s))
#define INSTR_CREATE_prefetcht1(dc, s) \
  instr_create_0dst_1src((dc), OP_prefetcht1, (s))
#define INSTR_CREATE_prefetcht2(dc, s) \
  instr_create_0dst_1src((dc), OP_prefetcht2, (s))
#define INSTR_CREATE_prefetch(dc, s) \
  instr_create_0dst_1src((dc), OP_prefetch, (s))
#define INSTR_CREATE_prefetchw(dc, s) \
  instr_create_0dst_1src((dc), OP_prefetchw, (s))
/* @} */ /* end doxygen group */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction, which can be
 * created with OPND_CREATE_MEM_clflush() to get the appropriate operand size.
 */
#define INSTR_CREATE_clflush(dc, s) \
  instr_create_0dst_1src((dc), OP_clflush, (s))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param i The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_int(dc, i) \
  instr_create_0dst_1src((dc), OP_int, (i))


#ifdef IA32_ON_IA64
/* DR_API EXPORT BEGIN */
#define INSTR_CREATE_jmpe(dc, t) \
  instr_create_0dst_1src((dc), OP_jmpe, (t))
#define INSTR_CREATE_jmpe_abs(dc, t) \
  instr_create_0dst_1src((dc), OP_jmpe_abs, (t))
#endif

/* floating-point */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param m The opnd_t explicit destination operand for the instruction, which can be
 * created with OPND_CREATE_MEM_fldenv() to get the appropriate operand size.
 */
#define INSTR_CREATE_fldenv(dc, m) \
  instr_create_0dst_1src((dc), OP_fldenv, (m))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param m The opnd_t explicit destination operand for the instruction, which must
 * be a memory reference (opnd_create_base_disp() or opnd_create_far_base_disp()).
 */
#define INSTR_CREATE_fldcw(dc, m) \
  instr_create_0dst_1src((dc), OP_fldcw, (m))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param m The opnd_t explicit destination operand for the instruction, which can be
 * created with OPND_CREATE_MEM_frstor() to get the appropriate operand size.
 */
#define INSTR_CREATE_frstor(dc, m) \
  instr_create_0dst_1src((dc), OP_frstor, (m))

/* no destination, 1 implicit source */
/** @name One implicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_fxam(dc) \
  instr_create_0dst_1src((dc), OP_fxam, opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_sahf(dc) \
  instr_create_0dst_1src((dc), OP_sahf, opnd_create_reg(DR_REG_AH))
#define INSTR_CREATE_vmrun(dc) \
  instr_create_0dst_1src((dc), OP_vmrun, opnd_create_reg(DR_REG_XAX))
#define INSTR_CREATE_vmload(dc) \
  instr_create_0dst_1src((dc), OP_vmload, opnd_create_reg(DR_REG_XAX))
#define INSTR_CREATE_vmsave(dc) \
  instr_create_0dst_1src((dc), OP_vmsave, opnd_create_reg(DR_REG_XAX))
#define INSTR_CREATE_skinit(dc) \
  instr_create_0dst_1src((dc), OP_skinit, opnd_create_reg(DR_REG_EAX))
/* @} */ /* end doxygen group */

#endif

/* no destination, 2 explicit sources */
/** @name No destination, 2 explicit sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s1 The opnd_t first source operand for the instruction.
 * \param s2 The opnd_t second source operand for the instruction.
 */
#define INSTR_CREATE_cmp(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_cmp, (s1), (s2))
#define INSTR_CREATE_test(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_test, (s1), (s2))
#define INSTR_CREATE_ptest(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_ptest, (s1), (s2))

#ifdef NO
/*TODO SJF */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s1 The opnd_t first source operand for the instruction.
 * \param s2 The opnd_t second source operand for the instruction, which can
 * be created with OPND_CREATE_MEM_bound() to get the appropriate operand size.
 */
#define INSTR_CREATE_bound(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_bound, (s1), (s2))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t first source operand for the instruction.
 * \param ri The opnd_t second source operand for the instruction, which can
 * be either a register or an immediate integer.
 */
#define INSTR_CREATE_bt(dc, s, ri) \
  instr_create_0dst_2src((dc), OP_bt, (s), (ri))
#define INSTR_CREATE_ucomiss(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_ucomiss, (s1), (s2))
#define INSTR_CREATE_ucomisd(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_ucomisd, (s1), (s2))
#define INSTR_CREATE_comiss(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_comiss, (s1), (s2))
#define INSTR_CREATE_comisd(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_comisd, (s1), (s2))
#define INSTR_CREATE_invept(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_invept, (s1), (s2))
#define INSTR_CREATE_invvpid(dc, s1, s2) \
  instr_create_0dst_2src((dc), OP_invvpid, (s1), (s2))
/* @} */ /* end doxygen group */

/* no destination, 2 sources: 1 implicit */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param t The opnd_t target operand for the instruction, which can be either
 * a pc (opnd_create_pc()) or an instr_t (opnd_create_instr()).
 */
#define INSTR_CREATE_jecxz(dc, t) \
  instr_create_0dst_2src((dc), OP_jecxz, (t), opnd_create_reg(DR_REG_XCX))
/**
 * Creates an instr_t for an OP_jecxz instruction that uses cx instead of ecx
 * (there is no separate OP_jcxz).
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param t The opnd_t target operand for the instruction, which can be either
 * a pc (opnd_create_pc()) or an instr_t (opnd_create_instr()).
 */
#define INSTR_CREATE_jcxz(dc, t) \
  instr_create_0dst_2src((dc), OP_jecxz, (t), opnd_create_reg(DR_REG_CX))

/* no destination, 2 sources */
/** @name No destination, 2 sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * Creates an instr_t for an OP_out instruction with a source of al
 * (INSTR_CREATE_out_1()) or eax (INSTR_CREATE_out_4()) and dx.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_out_1(dc) \
  instr_create_0dst_2src((dc), OP_out, opnd_create_reg(DR_REG_AL), \
    opnd_create_reg(DR_REG_DX))
#define INSTR_CREATE_out_4(dc) \
  instr_create_0dst_2src((dc), OP_out, opnd_create_reg(DR_REG_EAX), \
    opnd_create_reg(DR_REG_DX))
/* @} */ /* end doxygen group */
/** @name No destination, explicit immed source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * Creates an instr_t for an OP_out instruction with a source of al
 * (INSTR_CREATE_out_1_imm()) or eax (INSTR_CREATE_out_4_imm()) and an immediate.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param i The opnd_t explicit source operand for the instruction, which must be an
 * immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_out_1_imm(dc, i) \
  instr_create_0dst_2src((dc), OP_out, (i), opnd_create_reg(DR_REG_AL))
#define INSTR_CREATE_out_4_imm(dc, i) \
  instr_create_0dst_2src((dc), OP_out, (i), opnd_create_reg(DR_REG_EAX))
/* @} */ /* end doxygen group */

/** @name No destination, 2 implicit sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
/* no destination, 2 implicit sources */
#define INSTR_CREATE_mwait(dc) \
  instr_create_0dst_2src((dc), OP_mwait, opnd_create_reg(DR_REG_EAX), \
      opnd_create_reg(DR_REG_ECX))
#define INSTR_CREATE_invlpga(dc) \
  instr_create_0dst_2src((dc), OP_invlpga, opnd_create_reg(DR_REG_XAX), \
      opnd_create_reg(DR_REG_ECX))
/* no destination, 3 implicit sources */
#define INSTR_CREATE_wrmsr(dc) \
  instr_create_0dst_3src((dc), OP_wrmsr, opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_ECX))
#define INSTR_CREATE_monitor(dc) \
  instr_create_0dst_3src((dc), OP_monitor, opnd_create_reg(DR_REG_EAX), \
      opnd_create_reg(DR_REG_ECX), opnd_create_reg(DR_REG_EDX))
#define INSTR_CREATE_xsetbv(dc) \
  instr_create_0dst_3src((dc), OP_xsetbv, opnd_create_reg(DR_REG_ECX), \
    opnd_create_reg(DR_REG_EDX), opnd_create_reg(DR_REG_EAX))
/* @} */ /* end doxygen group */

/** @name No destination, 3 sources: 1 implicit */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction, which can be
 * created with OPND_CREATE_MEM_xsave() to get the appropriate operand size.
 */
#define INSTR_CREATE_xrstor(dc, s)                                          \
  instr_create_0dst_3src((dc), OP_xrstor, (s), opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX))
/* @} */ /* end doxygen group */

/* floating-point */
/** @name Floating-point with source of memory or fp register */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction, which must
 * be one of the following:
 * -# A floating point register (opnd_create_reg()).
 * -# A memory reference (opnd_create_base_disp() or opnd_create_far_base_disp()).
 * The other (implicit) source operand is #DR_REG_ST0.
 */
#define INSTR_CREATE_fcom(dc, s) \
  instr_create_0dst_2src((dc), OP_fcom, (s), opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fcomp(dc, s) \
  instr_create_0dst_2src((dc), OP_fcomp, (s), opnd_create_reg(DR_REG_ST0))
/* @} */ /* end doxygen group */
/** @name Floating-point with fp register source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param f The opnd_t explicit source operand for the instruction, which must
 * be a floating point register (opnd_create_reg()).
 * The other (implicit) source operand is #DR_REG_ST0.
 */
#define INSTR_CREATE_fcomi(dc, f) \
  instr_create_0dst_2src((dc), OP_fcomi, opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fcomip(dc, f) \
  instr_create_0dst_2src((dc), OP_fcomip, opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fucomi(dc, f) \
  instr_create_0dst_2src((dc), OP_fucomi, opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fucomip(dc, f) \
  instr_create_0dst_2src((dc), OP_fucomip, opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fucom(dc, f) \
  instr_create_0dst_2src((dc), OP_fucom, opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fucomp(dc, f) \
  instr_create_0dst_2src((dc), OP_fucomp, opnd_create_reg(DR_REG_ST0), (f))
/* @} */ /* end doxygen group */
/** @name Floating-point with no explicit sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx,
 * automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_fucompp(dc) \
  instr_create_0dst_2src((dc), OP_fucompp, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST1))
#define INSTR_CREATE_fcompp(dc) \
  instr_create_0dst_2src((dc), OP_fcompp, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST1))
/* @} */ /* end doxygen group */

/* 1 destination, no sources */
/**
 * Creats an instr_t for a conditional set instruction with the given opcode
 * and destination operand.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param op The OP_xxx opcode for the instruction, which should be in the range
 * [OP_seto, OP_setnle].
 * \param d The opnd_t destination operand for the instruction.
 */
#define INSTR_CREATE_setcc(dc, op, d) \
  instr_create_1dst_0src((dc), (op), (d))
/** @name 1 explicit destination, no sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 */
#define INSTR_CREATE_sldt(dc, d) \
  instr_create_1dst_0src((dc), OP_sldt, (d))
#define INSTR_CREATE_str(dc, d) \
  instr_create_1dst_0src((dc), OP_str, (d))
#define INSTR_CREATE_vmptrst(dc, d) \
  instr_create_1dst_0src((dc), OP_vmptrst, (d))
#define INSTR_CREATE_vmclear(dc, d) \
  instr_create_1dst_0src((dc), OP_vmclear, (d))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction, which can
 * be created with OPND_CREATE_MEM_sgdt() to get the appropriate operand size.
 */
#define INSTR_CREATE_sgdt(dc, d) \
  instr_create_1dst_0src((dc), OP_sgdt, (d))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction, which can
 * be created with OPND_CREATE_MEM_sidt() to get the appropriate operand size.
 */
#define INSTR_CREATE_sidt(dc, d) \
  instr_create_1dst_0src((dc), OP_sidt, (d))
#define INSTR_CREATE_smsw(dc, d) \
  instr_create_1dst_0src((dc), OP_smsw, (d))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction, which can
 * be created with OPND_CREATE_MEM_fxsave() to get the appropriate operand size.
 */
#define INSTR_CREATE_fxsave(dc, d) \
  instr_create_1dst_0src((dc), OP_fxsave, (d))
#define INSTR_CREATE_stmxcsr(dc, d) \
  instr_create_1dst_0src((dc), OP_stmxcsr, (d))
#define INSTR_CREATE_vstmxcsr(dc, d) \
  instr_create_1dst_0src((dc), OP_vstmxcsr, (d))
/* @} */ /* end doxygen group */

/* floating-point */
/** @name Floating-point with memory destination */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param m The opnd_t explicit destination operand for the instruction, which must
 * be a memory reference (opnd_create_base_disp() or opnd_create_far_base_disp()).
 */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param m The opnd_t explicit destination operand for the instruction, which can
 * be created with OPND_CREATE_MEM_fnstenv() to get the appropriate operand size.
 */
#define INSTR_CREATE_fnstenv(dc, m) \
  instr_create_1dst_0src((dc), OP_fnstenv, (m))
#define INSTR_CREATE_fnstcw(dc, m) \
  instr_create_1dst_0src((dc), OP_fnstcw, (m))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param m The opnd_t explicit destination operand for the instruction, which can
 * be created with OPND_CREATE_MEM_fnsave() to get the appropriate operand size.
 */
#define INSTR_CREATE_fnsave(dc, m) \
  instr_create_1dst_0src((dc), OP_fnsave, (m))
#define INSTR_CREATE_fnstsw(dc, m) \
  instr_create_1dst_0src((dc), OP_fnstsw, (m))
/* @} */ /* end doxygen group */

/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param f The opnd_t explicit destination operand for the instruction, which must
 * be a floating point register (opnd_create_reg()).
 */
#define INSTR_CREATE_ffree(dc, f) \
  instr_create_1dst_0src((dc), OP_ffree, (f))
#define INSTR_CREATE_ffreep(dc, f) \
  instr_create_1dst_0src((dc), OP_ffreep, (f))

/* 1 implicit destination, no sources */
/** @name 1 implicit destination, no sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_lahf(dc) \
  instr_create_1dst_0src((dc), OP_lahf, opnd_create_reg(DR_REG_AH))
#define INSTR_CREATE_sysenter(dc) \
  instr_create_1dst_0src((dc), OP_sysenter, opnd_create_reg(DR_REG_XSP))
#define INSTR_CREATE_sysexit(dc) \
  instr_create_1dst_0src((dc), OP_sysexit, opnd_create_reg(DR_REG_XSP))
#define INSTR_CREATE_syscall(dc) \
  instr_create_1dst_0src((dc), OP_syscall, opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_salc(dc) \
  instr_create_1dst_0src((dc), OP_salc, opnd_create_reg(DR_REG_AL))
/* @} */ /* end doxygen group */

/* 1 destination, 1 source */
/** @name 1 destination, 1 source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_arpl(dc, d, s) \
  instr_create_1dst_1src((dc), OP_arpl, (d), (s))

/* TODO SJF */
#endif

/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction, which can be
 * created with OPND_CREATE_MEM_lea() to get the appropriate operand size.
 */
/* TODO SJF Just added the ones I need for now here */
#define INSTR_CREATE_mov(dc, d, s) \
  instr_create_1dst_1src((dc), OP_mov, (d), (s))
#define INSTR_CREATE_lsl(dc, d, s) \
  instr_create_1dst_1src((dc), OP_lsl, (d), (s))
#define INSTR_CREATE_lsr(dc, d, s) \
  instr_create_1dst_1src((dc), OP_lsr, (d), (s))

/* @} */ /* end doxygen group */

#ifdef NO
/** @name In with no explicit sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * Creates an instr_t for an OP_in instruction with a source of al
 * (INSTR_CREATE_in_1()) or eax (INSTR_CREATE_in_4()) and dx.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_in_1(dc) \
  instr_create_1dst_1src((dc), OP_in, opnd_create_reg(DR_REG_AL), \
    opnd_create_reg(DR_REG_DX))
#define INSTR_CREATE_in_4(dc) \
  instr_create_1dst_1src((dc), OP_in, opnd_create_reg(DR_REG_EAX), \
    opnd_create_reg(DR_REG_DX))
/* @} */ /* end doxygen group */
/** @name In with explicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * Creates an instr_t for an OP_in instruction with a source of al
 * (INSTR_CREATE_in_1_imm()) or eax (INSTR_CREATE_in_4_imm()) and an immediate.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param i The opnd_t explicit source operand for the instruction, which must be an
 * immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_in_1_imm(dc, i) \
  instr_create_1dst_1src((dc), OP_in, opnd_create_reg(DR_REG_AL), (i))
#define INSTR_CREATE_in_4_imm(dc, i) \
  instr_create_1dst_1src((dc), OP_in, opnd_create_reg(DR_REG_EAX), (i))
/* @} */ /* end doxygen group */

/* floating-point */
/**
 * Creats an instr_t for a conditional move instruction with the given opcode
 * and destination operand.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param op The OP_xxx opcode for the instruction, which should be in the range
 * [OP_fcmovb, OP_fcmovnu], excluding OP_fucompp.
 * \param f The opnd_t explicit source operand for the instruction, which must
 * be a floating point register (opnd_create_reg()).
 */
#define INSTR_CREATE_fcmovcc(dc, op, f) \
  instr_create_1dst_1src((dc), (op), opnd_create_reg(DR_REG_ST0), (f))
/** @name Floating point with destination that is memory or fp register */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction, which must
 * be one of the following:
 * -# A floating point register (opnd_create_reg()).
 * -# A memory reference (opnd_create_base_disp() or opnd_create_far_base_disp()).
 */
#define INSTR_CREATE_fst(dc, d) \
  instr_create_1dst_1src((dc), OP_fst, (d), opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fstp(dc, d) \
  instr_create_1dst_1src((dc), OP_fstp, (d), opnd_create_reg(DR_REG_ST0))
/* @} */ /* end doxygen group */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction, which must
 * be one of the following:
 * -# A floating point register (opnd_create_reg()).
 * -# A memory reference (opnd_create_base_disp() or opnd_create_far_base_disp()).
 */
#define INSTR_CREATE_fld(dc, s) \
  instr_create_1dst_1src((dc), OP_fld, opnd_create_reg(DR_REG_ST0), (s))
/** @name Floating-point with memory destination and implicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx_mem macro creates an instr_t with opcode OP_xxx and
 * the given explicit memory operand, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param m The opnd_t explicit destination operand for the instruction, which must be
 * a memory reference (opnd_create_base_disp() or opnd_create_far_base_disp()).
 */
#define INSTR_CREATE_fist(dc, m) \
  instr_create_1dst_1src((dc), OP_fist, (m), opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fistp(dc, m) \
  instr_create_1dst_1src((dc), OP_fistp, (m), opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fisttp(dc, m) \
  instr_create_1dst_1src((dc), OP_fisttp, (m), opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fbstp(dc, m) \
  instr_create_1dst_1src((dc), OP_fbstp, (m), opnd_create_reg(DR_REG_ST0))
/* @} */ /* end doxygen group */
/** @name Floating-point with memory source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx_mem macro creates an instr_t with opcode OP_xxx and
 * the given explicit memory operand, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param m The opnd_t explicit source operand for the instruction, which must be
 * a memory reference (opnd_create_base_disp() or opnd_create_far_base_disp()).
 */
#define INSTR_CREATE_fild(dc, m) \
  instr_create_1dst_1src((dc), OP_fild, opnd_create_reg(DR_REG_ST0), (m))
#define INSTR_CREATE_fbld(dc, m) \
  instr_create_1dst_1src((dc), OP_fbld, opnd_create_reg(DR_REG_ST0), (m))
/* @} */ /* end doxygen group */
/** @name Floating-point implicit destination and implicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_fchs(dc) \
  instr_create_1dst_1src((dc), OP_fchs, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fabs(dc) \
  instr_create_1dst_1src((dc), OP_fabs, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_ftst(dc) \
  instr_create_1dst_1src((dc), OP_ftst, opnd_create_reg(DR_REG_ST0), \
    opnd_create_immed_float(0.0f))
#define INSTR_CREATE_fld1(dc) \
  instr_create_1dst_1src((dc), OP_fld1, opnd_create_reg(DR_REG_ST0), \
    opnd_create_immed_float(1.0f))
/* FIXME: do we really want these constants here? Should they be floats or doubles? */
#define INSTR_CREATE_fldl2t(dc) \
  instr_create_1dst_1src((dc), OP_fldl2t, opnd_create_reg(DR_REG_ST0), \
  opnd_create_immed_float((float)M_LN10/(float)M_LN2))
#define INSTR_CREATE_fldl2e(dc) \
  instr_create_1dst_1src((dc), OP_fldl2e, opnd_create_reg(DR_REG_ST0), \
  opnd_create_immed_float(1.0f/(float)M_LN2))
#define INSTR_CREATE_fldpi(dc) \
  instr_create_1dst_1src((dc), OP_fldpi, opnd_create_reg(DR_REG_ST0), \
  opnd_create_immed_float((float)M_PI))
#define INSTR_CREATE_fldlg2(dc) \
  instr_create_1dst_1src((dc), OP_fldlg2, opnd_create_reg(DR_REG_ST0), \
  opnd_create_immed_float((float)M_LN2/(float)M_LN10))
#define INSTR_CREATE_fldln2(dc) \
  instr_create_1dst_1src((dc), OP_fldln2, opnd_create_reg(DR_REG_ST0), \
  opnd_create_immed_float((float)M_LN2))
#define INSTR_CREATE_fldz(dc) \
  instr_create_1dst_1src((dc), OP_fldz, opnd_create_reg(DR_REG_ST0), \
    opnd_create_immed_float(0.0f))
#define INSTR_CREATE_f2xm1(dc) \
  instr_create_1dst_1src((dc), OP_f2xm1, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fptan(dc) \
  instr_create_1dst_1src((dc), OP_fptan, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fxtract(dc) \
  instr_create_1dst_1src((dc), OP_fxtract, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fsqrt(dc) \
  instr_create_1dst_1src((dc), OP_fsqrt, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fsincos(dc) \
  instr_create_1dst_1src((dc), OP_fsincos, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_frndint(dc) \
  instr_create_1dst_1src((dc), OP_frndint, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fsin(dc) \
  instr_create_1dst_1src((dc), OP_fsin, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fcos(dc) \
  instr_create_1dst_1src((dc), OP_fcos, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST0))

#define INSTR_CREATE_fscale(dc) \
  instr_create_1dst_2src((dc), OP_fscale, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST1), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fyl2x(dc) \
  instr_create_2dst_2src((dc), OP_fyl2x, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST1), \
    opnd_create_reg(DR_REG_ST0), opnd_create_reg(DR_REG_ST1))
#define INSTR_CREATE_fyl2xp1(dc) \
  instr_create_2dst_2src((dc), OP_fyl2xp1, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST1), \
    opnd_create_reg(DR_REG_ST0), opnd_create_reg(DR_REG_ST1))
#define INSTR_CREATE_fpatan(dc) \
  instr_create_2dst_2src((dc), OP_fpatan, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST1), \
    opnd_create_reg(DR_REG_ST0), opnd_create_reg(DR_REG_ST1))
#define INSTR_CREATE_fprem(dc) \
  instr_create_2dst_2src((dc), OP_fprem, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST1), \
    opnd_create_reg(DR_REG_ST0), opnd_create_reg(DR_REG_ST1))
#define INSTR_CREATE_fprem1(dc) \
  instr_create_2dst_2src((dc), OP_fprem1, opnd_create_reg(DR_REG_ST0), \
    opnd_create_reg(DR_REG_ST1), \
    opnd_create_reg(DR_REG_ST0), opnd_create_reg(DR_REG_ST1))
/* @} */ /* end doxygen group */

/* 1 destination, 2 sources */
/** @name 1 destination, 2 sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 * \param i The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_pshufw(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pshufw, (d), (s), (i))
#define INSTR_CREATE_pshufd(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pshufd, (d), (s), (i))
#define INSTR_CREATE_pshufhw(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pshufhw, (d), (s), (i))
#define INSTR_CREATE_pshuflw(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pshuflw, (d), (s), (i))
#define INSTR_CREATE_pinsrw(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pinsrw, (d), (s), (i))
#define INSTR_CREATE_pextrw(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pextrw, (d), (s), (i))
/* SSE4 */
#define INSTR_CREATE_pextrb(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pextrb, (d), (s), (i))
#define INSTR_CREATE_pextrd(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pextrd, (d), (s), (i))
#define INSTR_CREATE_extractps(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_extractps, (d), (s), (i))
#define INSTR_CREATE_roundps(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_roundps, (d), (s), (i))
#define INSTR_CREATE_roundpd(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_roundpd, (d), (s), (i))
#define INSTR_CREATE_roundss(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_roundss, (d), (s), (i))
#define INSTR_CREATE_roundsd(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_roundsd, (d), (s), (i))
#define INSTR_CREATE_pinsrb(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pinsrb, (d), (s), (i))
#define INSTR_CREATE_insertps(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_insertps, (d), (s), (i))
#define INSTR_CREATE_pinsrd(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_pinsrd, (d), (s), (i))
#define INSTR_CREATE_aeskeygenassist(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_aeskeygenassist, (d), (s), (i))
/* @} */ /* end doxygen group */

/** @name 1 destination, 2 non-immediate sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s1 The opnd_t explicit first source operand for the instruction.
 * \param s2 The opnd_t explicit second source operand for the instruction
 */
/* AVX: some of these have immeds, we don't bother to distinguish */
/* NDS means "Non-Destructive Source" */
#define INSTR_CREATE_vmovlps_NDS(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmovlps, (d), (s1), (s2))
#define INSTR_CREATE_vmovlpd_NDS(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmovlpd, (d), (s1), (s2))
#define INSTR_CREATE_vunpcklps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vunpcklps, (d), (s1), (s2))
#define INSTR_CREATE_vunpcklpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vunpcklpd, (d), (s1), (s2))
#define INSTR_CREATE_vunpckhps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vunpckhps, (d), (s1), (s2))
#define INSTR_CREATE_vunpckhpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vunpckhpd, (d), (s1), (s2))
#define INSTR_CREATE_vmovhps_NDS(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmovhps, (d), (s1), (s2))
#define INSTR_CREATE_vmovhpd_NDS(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmovhpd, (d), (s1), (s2))
#define INSTR_CREATE_vcvtsi2ss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vcvtsi2ss, (d), (s1), (s2))
#define INSTR_CREATE_vcvtsi2sd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vcvtsi2sd, (d), (s1), (s2))
#define INSTR_CREATE_vsqrtss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vsqrtss, (d), (s1), (s2))
#define INSTR_CREATE_vsqrtsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vsqrtsd, (d), (s1), (s2))
#define INSTR_CREATE_vrsqrtss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vrsqrtss, (d), (s1), (s2))
#define INSTR_CREATE_vrcpss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vrcpss, (d), (s1), (s2))
#define INSTR_CREATE_vandps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vandps, (d), (s1), (s2))
#define INSTR_CREATE_vandpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vandpd, (d), (s1), (s2))
#define INSTR_CREATE_vandnps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vandnps, (d), (s1), (s2))
#define INSTR_CREATE_vandnpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vandnpd, (d), (s1), (s2))
#define INSTR_CREATE_vorps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vorps, (d), (s1), (s2))
#define INSTR_CREATE_vorpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vorpd, (d), (s1), (s2))
#define INSTR_CREATE_vxorps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vxorps, (d), (s1), (s2))
#define INSTR_CREATE_vxorpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vxorpd, (d), (s1), (s2))
#define INSTR_CREATE_vaddps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaddps, (d), (s1), (s2))
#define INSTR_CREATE_vaddss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaddss, (d), (s1), (s2))
#define INSTR_CREATE_vaddpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaddpd, (d), (s1), (s2))
#define INSTR_CREATE_vaddsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaddsd, (d), (s1), (s2))
#define INSTR_CREATE_vmulps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmulps, (d), (s1), (s2))
#define INSTR_CREATE_vmulss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmulss, (d), (s1), (s2))
#define INSTR_CREATE_vmulpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmulpd, (d), (s1), (s2))
#define INSTR_CREATE_vmulsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmulsd, (d), (s1), (s2))
#define INSTR_CREATE_vcvtss2sd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vcvtss2sd, (d), (s1), (s2))
#define INSTR_CREATE_vcvtsd2ss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vcvtsd2ss, (d), (s1), (s2))
#define INSTR_CREATE_vsubps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vsubps, (d), (s1), (s2))
#define INSTR_CREATE_vsubss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vsubss, (d), (s1), (s2))
#define INSTR_CREATE_vsubpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vsubpd, (d), (s1), (s2))
#define INSTR_CREATE_vsubsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vsubsd, (d), (s1), (s2))
#define INSTR_CREATE_vminps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vminps, (d), (s1), (s2))
#define INSTR_CREATE_vminss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vminss, (d), (s1), (s2))
#define INSTR_CREATE_vminpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vminpd, (d), (s1), (s2))
#define INSTR_CREATE_vminsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vminsd, (d), (s1), (s2))
#define INSTR_CREATE_vdivps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vdivps, (d), (s1), (s2))
#define INSTR_CREATE_vdivss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vdivss, (d), (s1), (s2))
#define INSTR_CREATE_vdivpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vdivpd, (d), (s1), (s2))
#define INSTR_CREATE_vdivsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vdivsd, (d), (s1), (s2))
#define INSTR_CREATE_vmaxps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmaxps, (d), (s1), (s2))
#define INSTR_CREATE_vmaxss(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmaxss, (d), (s1), (s2))
#define INSTR_CREATE_vmaxpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmaxpd, (d), (s1), (s2))
#define INSTR_CREATE_vmaxsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmaxsd, (d), (s1), (s2))
#define INSTR_CREATE_vpunpcklbw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpunpcklbw, (d), (s1), (s2))
#define INSTR_CREATE_vpunpcklwd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpunpcklwd, (d), (s1), (s2))
#define INSTR_CREATE_vpunpckldq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpunpckldq, (d), (s1), (s2))
#define INSTR_CREATE_vpacksswb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpacksswb, (d), (s1), (s2))
#define INSTR_CREATE_vpcmpgtb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpcmpgtb, (d), (s1), (s2))
#define INSTR_CREATE_vpcmpgtw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpcmpgtw, (d), (s1), (s2))
#define INSTR_CREATE_vpcmpgtd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpcmpgtd, (d), (s1), (s2))
#define INSTR_CREATE_vpackuswb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpackuswb, (d), (s1), (s2))
#define INSTR_CREATE_vpunpckhbw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpunpckhbw, (d), (s1), (s2))
#define INSTR_CREATE_vpunpckhwd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpunpckhwd, (d), (s1), (s2))
#define INSTR_CREATE_vpunpckhdq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpunpckhdq, (d), (s1), (s2))
#define INSTR_CREATE_vpackssdw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpackssdw, (d), (s1), (s2))
#define INSTR_CREATE_vpunpcklqdq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpunpcklqdq, (d), (s1), (s2))
#define INSTR_CREATE_vpunpckhqdq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpunpckhqdq, (d), (s1), (s2))
#define INSTR_CREATE_vpshufhw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpshufhw, (d), (s1), (s2))
#define INSTR_CREATE_vpshufd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpshufd, (d), (s1), (s2))
#define INSTR_CREATE_vpshuflw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpshuflw, (d), (s1), (s2))
#define INSTR_CREATE_vpcmpeqb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpcmpeqb, (d), (s1), (s2))
#define INSTR_CREATE_vpcmpeqw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpcmpeqw, (d), (s1), (s2))
#define INSTR_CREATE_vpcmpeqd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpcmpeqd, (d), (s1), (s2))
#define INSTR_CREATE_vpextrw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpextrw, (d), (s1), (s2))
#define INSTR_CREATE_vpsrlw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsrlw, (d), (s1), (s2))
#define INSTR_CREATE_vpsrld(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsrld, (d), (s1), (s2))
#define INSTR_CREATE_vpsrlq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsrlq, (d), (s1), (s2))
#define INSTR_CREATE_vpaddq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpaddq, (d), (s1), (s2))
#define INSTR_CREATE_vpmullw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmullw, (d), (s1), (s2))
#define INSTR_CREATE_vpsubusb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsubusb, (d), (s1), (s2))
#define INSTR_CREATE_vpsubusw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsubusw, (d), (s1), (s2))
#define INSTR_CREATE_vpminub(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpminub, (d), (s1), (s2))
#define INSTR_CREATE_vpand(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpand, (d), (s1), (s2))
#define INSTR_CREATE_vpaddusb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpaddusb, (d), (s1), (s2))
#define INSTR_CREATE_vpaddusw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpaddusw, (d), (s1), (s2))
#define INSTR_CREATE_vpmaxub(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmaxub, (d), (s1), (s2))
#define INSTR_CREATE_vpandn(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpandn, (d), (s1), (s2))
#define INSTR_CREATE_vpavgb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpavgb, (d), (s1), (s2))
#define INSTR_CREATE_vpsraw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsraw, (d), (s1), (s2))
#define INSTR_CREATE_vpsrad(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsrad, (d), (s1), (s2))
#define INSTR_CREATE_vpavgw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpavgw, (d), (s1), (s2))
#define INSTR_CREATE_vpmulhuw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmulhuw, (d), (s1), (s2))
#define INSTR_CREATE_vpmulhw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmulhw, (d), (s1), (s2))
#define INSTR_CREATE_vpsubsb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsubsb, (d), (s1), (s2))
#define INSTR_CREATE_vpsubsw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsubsw, (d), (s1), (s2))
#define INSTR_CREATE_vpminsw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpminsw, (d), (s1), (s2))
#define INSTR_CREATE_vpor(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpor, (d), (s1), (s2))
#define INSTR_CREATE_vpaddsb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpaddsb, (d), (s1), (s2))
#define INSTR_CREATE_vpaddsw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpaddsw, (d), (s1), (s2))
#define INSTR_CREATE_vpmaxsw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmaxsw, (d), (s1), (s2))
#define INSTR_CREATE_vpxor(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpxor, (d), (s1), (s2))
#define INSTR_CREATE_vpsllw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsllw, (d), (s1), (s2))
#define INSTR_CREATE_vpslld(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpslld, (d), (s1), (s2))
#define INSTR_CREATE_vpsllq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsllq, (d), (s1), (s2))
#define INSTR_CREATE_vpmuludq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmuludq, (d), (s1), (s2))
#define INSTR_CREATE_vpmaddwd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmaddwd, (d), (s1), (s2))
#define INSTR_CREATE_vpsadbw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsadbw, (d), (s1), (s2))
#define INSTR_CREATE_vpsubb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsubb, (d), (s1), (s2))
#define INSTR_CREATE_vpsubw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsubw, (d), (s1), (s2))
#define INSTR_CREATE_vpsubd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsubd, (d), (s1), (s2))
#define INSTR_CREATE_vpsubq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsubq, (d), (s1), (s2))
#define INSTR_CREATE_vpaddb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpaddb, (d), (s1), (s2))
#define INSTR_CREATE_vpaddw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpaddw, (d), (s1), (s2))
#define INSTR_CREATE_vpaddd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpaddd, (d), (s1), (s2))
#define INSTR_CREATE_vpsrldq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsrldq, (d), (s1), (s2))
#define INSTR_CREATE_vpslldq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpslldq, (d), (s1), (s2))
#define INSTR_CREATE_vhaddpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vhaddpd, (d), (s1), (s2))
#define INSTR_CREATE_vhaddps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vhaddps, (d), (s1), (s2))
#define INSTR_CREATE_vhsubpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vhsubpd, (d), (s1), (s2))
#define INSTR_CREATE_vhsubps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vhsubps, (d), (s1), (s2))
#define INSTR_CREATE_vaddsubpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaddsubpd, (d), (s1), (s2))
#define INSTR_CREATE_vaddsubps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaddsubps, (d), (s1), (s2))
#define INSTR_CREATE_vphaddw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vphaddw, (d), (s1), (s2))
#define INSTR_CREATE_vphaddd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vphaddd, (d), (s1), (s2))
#define INSTR_CREATE_vphaddsw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vphaddsw, (d), (s1), (s2))
#define INSTR_CREATE_vpmaddubsw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmaddubsw, (d), (s1), (s2))
#define INSTR_CREATE_vphsubw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vphsubw, (d), (s1), (s2))
#define INSTR_CREATE_vphsubd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vphsubd, (d), (s1), (s2))
#define INSTR_CREATE_vphsubsw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vphsubsw, (d), (s1), (s2))
#define INSTR_CREATE_vpsignb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsignb, (d), (s1), (s2))
#define INSTR_CREATE_vpsignw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsignw, (d), (s1), (s2))
#define INSTR_CREATE_vpsignd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpsignd, (d), (s1), (s2))
#define INSTR_CREATE_vpmulhrsw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmulhrsw, (d), (s1), (s2))
#define INSTR_CREATE_vpabsb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpabsb, (d), (s1), (s2))
#define INSTR_CREATE_vpabsw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpabsw, (d), (s1), (s2))
#define INSTR_CREATE_vpabsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpabsd, (d), (s1), (s2))
#define INSTR_CREATE_vpmuldq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmuldq, (d), (s1), (s2))
#define INSTR_CREATE_vpcmpeqq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpcmpeqq, (d), (s1), (s2))
#define INSTR_CREATE_vpackusdw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpackusdw, (d), (s1), (s2))
#define INSTR_CREATE_vpcmpgtq(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpcmpgtq, (d), (s1), (s2))
#define INSTR_CREATE_vpminsb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpminsb, (d), (s1), (s2))
#define INSTR_CREATE_vpminsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpminsd, (d), (s1), (s2))
#define INSTR_CREATE_vpminuw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpminuw, (d), (s1), (s2))
#define INSTR_CREATE_vpminud(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpminud, (d), (s1), (s2))
#define INSTR_CREATE_vpmaxsb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmaxsb, (d), (s1), (s2))
#define INSTR_CREATE_vpmaxsd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmaxsd, (d), (s1), (s2))
#define INSTR_CREATE_vpmaxuw(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmaxuw, (d), (s1), (s2))
#define INSTR_CREATE_vpmaxud(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmaxud, (d), (s1), (s2))
#define INSTR_CREATE_vpmulld(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpmulld, (d), (s1), (s2))
#define INSTR_CREATE_vaesenc(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaesenc, (d), (s1), (s2))
#define INSTR_CREATE_vaesenclast(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaesenclast, (d), (s1), (s2))
#define INSTR_CREATE_vaesdec(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaesdec, (d), (s1), (s2))
#define INSTR_CREATE_vaesdeclast(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaesdeclast, (d), (s1), (s2))
#define INSTR_CREATE_vpextrb(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpextrb, (d), (s1), (s2))
#define INSTR_CREATE_vpextrd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpextrd, (d), (s1), (s2))
#define INSTR_CREATE_vextractps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vextractps, (d), (s1), (s2))
#define INSTR_CREATE_vroundps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vroundps, (d), (s1), (s2))
#define INSTR_CREATE_vroundpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vroundpd, (d), (s1), (s2))
#define INSTR_CREATE_vaeskeygenassist(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vaeskeygenassist, (d), (s1), (s2))
#define INSTR_CREATE_vmovss_NDS(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmovss, (d), (s1), (s2))
#define INSTR_CREATE_vmovsd_NDS(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmovsd, (d), (s1), (s2))
#define INSTR_CREATE_vcvtps2ph(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vcvtps2ph, (d), (s1), (s2))
#define INSTR_CREATE_vmaskmovps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmaskmovps, (d), (s1), (s2))
#define INSTR_CREATE_vmaskmovpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmaskmovpd, (d), (s1), (s2))
#define INSTR_CREATE_vpermilps(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpermilps, (d), (s1), (s2))
#define INSTR_CREATE_vpermilpd(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vpermilpd, (d), (s1), (s2))
#define INSTR_CREATE_vextractf128(dc, d, s1, s2) \
  instr_create_1dst_2src((dc), OP_vextractf128, (d), (s1), (s2))
/* @} */ /* end doxygen group */
#endif

/* 1 destination, 2 sources: 1 explicit, 1 implicit */
/** @name 1 destination, 2 sources: 1 explicit, 1 implicit */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_add(dc, d, s) \
  instr_create_1dst_2src((dc), OP_add, (d), (s), (d))
#define INSTR_CREATE_or(dc, d, s) \
  instr_create_1dst_2src((dc), OP_or,  (d), (s), (d))
#define INSTR_CREATE_adc(dc, d, s) \
  instr_create_1dst_2src((dc), OP_adc, (d), (s), (d))
#define INSTR_CREATE_and(dc, d, s) \
  instr_create_1dst_2src((dc), OP_and, (d), (s), (d))
#define INSTR_CREATE_sub(dc, d, s) \
  instr_create_1dst_2src((dc), OP_sub, (d), (s), (d))
#define INSTR_CREATE_xor(dc, d, s) \
  instr_create_1dst_2src((dc), OP_xor, (d), (s), (d))
/* @} */ /* end doxygen group */

#ifdef NO
/* TODO SJF */
/** @name 1 destination, 1 explicit register-or-immediate source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param ri The opnd_t explicit source operand for the instruction, which can
 * be a register (opnd_create_reg()) or an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_bts(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_bts, (d), (ri), (d))
#define INSTR_CREATE_btr(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_btr, (d), (ri), (d))
#define INSTR_CREATE_btc(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_btc, (d), (ri), (d))
/* @} */ /* end doxygen group */

/**
 * Creats an instr_t for a conditional move instruction with the given opcode
 * and destination operand.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param op The OP_xxx opcode for the instruction, which should be in the range
 * [OP_cmovo, OP_cmovnle].
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_cmovcc(dc, op, d, s) \
  instr_create_1dst_2src((dc), (op), (d), (s), (d))

/**
 * This INSTR_CREATE_xxx_imm macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands. The _imm
 * suffix distinguishes between alternative forms of the same opcode: this
 * form takes an explicit immediate.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 * \param i The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_imul_imm(dc, d, s, i) \
  instr_create_1dst_2src((dc), OP_imul, (d), (s), (i))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_imul(dc, d, s) \
  instr_create_1dst_2src((dc), OP_imul, (d), (s), (d))

#endif

/** @name 1 implicit destination, 1 explicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx, INSTR_CREATE_xxx_1, or INSTR_CREATE_xxx_4 macro creates an
 * instr_t with opcode OP_xxx and the given explicit operands, automatically
 * supplying any implicit operands.    The _1 or _4 suffixes distinguish between
 * alternative forms of the same opcode (1 and 4 identify the operand size).
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_mul_1(dc, s) \
  instr_create_1dst_2src((dc), OP_mul, opnd_create_reg(DR_REG_AX), (s), \
    opnd_create_reg(DR_REG_AL))
#define INSTR_CREATE_mul_4(dc, s) \
  instr_create_2dst_2src((dc), OP_mul, opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX), (s), opnd_create_reg(DR_REG_EAX))
#define INSTR_CREATE_div_1(dc, s) \
  instr_create_2dst_2src((dc), OP_div, opnd_create_reg(DR_REG_AH), \
    opnd_create_reg(DR_REG_AL), (s), opnd_create_reg(DR_REG_AX))
#define INSTR_CREATE_div_4(dc, s) \
  instr_create_2dst_3src((dc), OP_div, opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX), \
    (s), opnd_create_reg(DR_REG_EDX), opnd_create_reg(DR_REG_EAX))
/* @} */ /* end doxygen group */


#ifdef NO
/* TODO SJF */
/** @name 1 destination, 1 explicit source that is cl, an immediate, or a constant */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param ri The opnd_t explicit source operand for the instruction, which must
 * be one of the following:
 * -# The register cl (#opnd_create_reg(#DR_REG_CL));
 * -# An immediate integer (opnd_create_immed_int()) of size #OPSZ_1;
 * -# An immediate integer with value 1 and size #OPSZ_0
 * (#opnd_create_immed_int(1, #OPSZ_0)), which will become an implicit operand
 * (whereas #opnd_create_immed_int(1, #OPSZ_1) will be encoded explicitly).
 */
#define INSTR_CREATE_rol(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_rol, (d), (ri), (d))
#define INSTR_CREATE_ror(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_ror, (d), (ri), (d))
#define INSTR_CREATE_rcl(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_rcl, (d), (ri), (d))
#define INSTR_CREATE_rcr(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_rcr, (d), (ri), (d))
#define INSTR_CREATE_shl(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_shl, (d), (ri), (d))
#define INSTR_CREATE_shr(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_shr, (d), (ri), (d))
#define INSTR_CREATE_sar(dc, d, ri) \
  instr_create_1dst_2src((dc), OP_sar, (d), (ri), (d))
/* @} */ /* end doxygen group */

/** @name 1 implicit destination, 2 explicit sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s1 The opnd_t first source operand for the instruction.
 * \param s2 The opnd_t second source operand for the instruction.
 */
#define INSTR_CREATE_maskmovq(dc, s1, s2) \
  instr_create_1dst_2src((dc), OP_maskmovq, \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_maskmovq), \
   (s1), (s2))
#define INSTR_CREATE_maskmovdqu(dc, s1, s2) \
  instr_create_1dst_2src((dc), OP_maskmovdqu, \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_maskmovdqu), \
    (s1), (s2))
#define INSTR_CREATE_vmaskmovdqu(dc, s1, s2) \
  instr_create_1dst_2src((dc), OP_vmaskmovdqu, \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_maskmovdqu), \
    (s1), (s2))
/* @} */ /* end doxygen group */

/* floating-point */
/** @name Floating-point with explicit destination and explicit mem-or-fp-reg source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given operands, automatically supplying any further implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param f The opnd_t destination (and implicit source) operand for the
 * instruction, which must be a floating point register (opnd_create_reg()).
 * \param s The opnd_t source (and non-destination) operand for the
 * instruction, which must be one of the following:
 * -# A floating point register (opnd_create_reg()).
 * -# A memory reference (opnd_create_base_disp() or opnd_create_far_base_disp()),
 *    in which case the destination \p f must be #DR_REG_ST0.
 */
#define INSTR_CREATE_fadd(dc, f, s) \
  instr_create_1dst_2src((dc), OP_fadd, (f), (s), (f))
#define INSTR_CREATE_fmul(dc, f, s) \
  instr_create_1dst_2src((dc), OP_fmul, (f), (s), (f))
#define INSTR_CREATE_fdiv(dc, f, s) \
  instr_create_1dst_2src((dc), OP_fdiv, (f), (s), (f))
#define INSTR_CREATE_fdivr(dc, f, s) \
  instr_create_1dst_2src((dc), OP_fdivr, (f), (s), (f))
#define INSTR_CREATE_fsub(dc, f, s) \
  instr_create_1dst_2src((dc), OP_fsub, (f), (s), (f))
#define INSTR_CREATE_fsubr(dc, f, s) \
  instr_create_1dst_2src((dc), OP_fsubr, (f), (s), (f))
/* @} */ /* end doxygen group */
/** @name Floating-point with explicit destination and implicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with
 * opcode OP_xxx and the given explicit register operand, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param f The opnd_t explicit destination + source operand for the instruction, which 
 * must be a floating point register (opnd_create_reg()).
 */
#define INSTR_CREATE_faddp(dc, f) \
  instr_create_1dst_2src((dc), OP_faddp, (f), opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fmulp(dc, f) \
  instr_create_1dst_2src((dc), OP_fmulp, (f), opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fdivp(dc, f) \
  instr_create_1dst_2src((dc), OP_fdivp, (f), opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fdivrp(dc, f) \
  instr_create_1dst_2src((dc), OP_fdivrp, (f), opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fsubp(dc, f) \
  instr_create_1dst_2src((dc), OP_fsubp, (f), opnd_create_reg(DR_REG_ST0), (f))
#define INSTR_CREATE_fsubrp(dc, f) \
  instr_create_1dst_2src((dc), OP_fsubrp, (f), opnd_create_reg(DR_REG_ST0), (f))
/* @} */ /* end doxygen group */
/** @name Floating-point with implicit destination and explicit memory source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit memory operand, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param m The opnd_t explicit source operand for the instruction, which must be
 * a memory reference (opnd_create_base_disp() or opnd_create_far_base_disp()).
 */
#define INSTR_CREATE_fiadd(dc, m) \
  instr_create_1dst_2src((dc), OP_fiadd, opnd_create_reg(DR_REG_ST0), (m), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fimul(dc, m) \
  instr_create_1dst_2src((dc), OP_fimul, opnd_create_reg(DR_REG_ST0), (m), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fidiv(dc, m) \
  instr_create_1dst_2src((dc), OP_fidiv, opnd_create_reg(DR_REG_ST0), (m), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fidivr(dc, m) \
  instr_create_1dst_2src((dc), OP_fidivr, opnd_create_reg(DR_REG_ST0), (m), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fisub(dc, m) \
  instr_create_1dst_2src((dc), OP_fisub, opnd_create_reg(DR_REG_ST0), (m), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_fisubr(dc, m) \
  instr_create_1dst_2src((dc), OP_fisubr, opnd_create_reg(DR_REG_ST0), (m), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_ficom(dc, m) \
  instr_create_1dst_2src((dc), OP_ficom, opnd_create_reg(DR_REG_ST0), (m), \
    opnd_create_reg(DR_REG_ST0))
#define INSTR_CREATE_ficomp(dc, m) \
  instr_create_1dst_2src((dc), OP_ficomp, opnd_create_reg(DR_REG_ST0), (m), \
    opnd_create_reg(DR_REG_ST0))
/* @} */ /* end doxygen group */

/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param r The opnd_t explicit source operand for the instruction, which
 * must be an xmm register (opnd_create_reg()).
 */
#define INSTR_CREATE_extrq(dc, d, r) \
  instr_create_1dst_1src((dc), OP_extrq, (d), (r))
/**
 * This INSTR_CREATE_xxx_imm macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands. The _imm
 * suffix distinguishes between alternative forms of the same opcode: this
 * form takes explicit immediates.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param i1 The opnd_t explicit first source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 * \param i2 The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_extrq_imm(dc, d, i1, i2) \
  instr_create_1dst_2src((dc), OP_extrq, (d), (i1), (i2))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param r The opnd_t explicit source operand for the instruction, which
 * must be an xmm register (opnd_create_reg()).
 */
#define INSTR_CREATE_insertq(dc, d, r) \
  instr_create_1dst_1src((dc), OP_insertq, (d), (r))
/**
 * This INSTR_CREATE_xxx_imm macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands. The _imm
 * suffix distinguishes between alternative forms of the same opcode: this
 * form takes explicit immediates.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param r The opnd_t explicit first source operand for the instruction, which
 * must be an xmm register (opnd_create_reg()).
 * \param i1 The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 * \param i2 The opnd_t explicit third source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_insertq_imm(dc, d, r, i1, i2) \
  instr_create_1dst_3src((dc), OP_insertq, (d), (r), (i1), (i2))

/* 1 destination, 2 implicit sources */
/** @name 1 destination, 2 implicit sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction, which can be
 * created with OPND_CREATE_MEM_xsave() to get the appropriate operand size.
 */
#define INSTR_CREATE_xsave(dc, d) \
  instr_create_1dst_2src((dc), OP_xsave, (d), opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX))
#define INSTR_CREATE_xsaveopt(dc, d) \
  instr_create_1dst_2src((dc), OP_xsaveopt, (d), opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX))
/* @} */ /* end doxygen group */

/* 1 implicit destination, 2 sources: 1 explicit, 1 implicit */
/** @name 1 implicit destination, 2 sources: 1 explicit, 1 implicit */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param i The opnd_t explicit source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_aam(dc, i) \
  instr_create_1dst_2src((dc), OP_aam, opnd_create_reg(DR_REG_AX), (i), \
    opnd_create_reg(DR_REG_AX))
#define INSTR_CREATE_aad(dc, i) \
  instr_create_1dst_2src((dc), OP_aad, opnd_create_reg(DR_REG_AX), (i), \
    opnd_create_reg(DR_REG_AX))
/* @} */ /* end doxygen group */
/** @name Loop instructions */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param t The opnd_t target operand for the instruction, which can be either
 * a pc (opnd_create_pc()) or an instr_t (opnd_create_instr()).
 */
#define INSTR_CREATE_loopne(dc, t) \
  instr_create_1dst_2src((dc), OP_loopne, opnd_create_reg(DR_REG_XCX), (t), \
    opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_loope(dc, t) \
  instr_create_1dst_2src((dc), OP_loope, opnd_create_reg(DR_REG_XCX), (t), \
    opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_loop(dc, t) \
  instr_create_1dst_2src((dc), OP_loop, opnd_create_reg(DR_REG_XCX), (t), \
    opnd_create_reg(DR_REG_XCX))
/* @} */ /* end doxygen group */

/* 1 implicit destination, 2 implicit sources */
/** @name 1 implicit destination, 2 implicit sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_popf(dc) \
  instr_create_1dst_2src((dc), OP_popf, opnd_create_reg(DR_REG_XSP), \
    opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, 0, OPSZ_STACK))
#define INSTR_CREATE_ret(dc) \
  instr_create_1dst_2src((dc), OP_ret, opnd_create_reg(DR_REG_XSP), \
    opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, 0, OPSZ_ret))
/* XXX: blindly asking for rex.w (b/c 32-bit is default for x64) but don't
 * know x64 mode! */
#define INSTR_CREATE_ret_far(dc) \
  instr_create_1dst_2src((dc), OP_ret_far, opnd_create_reg(DR_REG_XSP), \
    opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, 0, IF_X64_ELSE(OPSZ_16, OPSZ_8)))
/* XXX: blindly asking for rex.w (b/c 32-bit is default for x64) but don't
 * know x64 mode! */
#define INSTR_CREATE_iret(dc) \
  instr_create_1dst_2src((dc), OP_iret, opnd_create_reg(DR_REG_XSP), \
    opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, 0, IF_X64_ELSE(OPSZ_40, OPSZ_12)))
/* @} */ /* end doxygen group */

/* 1 destination, 3 sources */
/** @name 1 destination, 3 non-immediate sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s1 The opnd_t explicit first source operand for the instruction.
 * \param s2 The opnd_t explicit second source operand for the instruction
 * \param s3 The opnd_t explicit third source operand for the instruction
 */
/* AVX */
#define INSTR_CREATE_vpblendvb(dc, d, s1, s2, s3) \
  instr_create_1dst_3src((dc), OP_vpblendvb, (d), (s1), (s2), (s3))
#define INSTR_CREATE_vblendvps(dc, d, s1, s2, s3) \
  instr_create_1dst_3src((dc), OP_vblendvps, (d), (s1), (s2), (s3))
#define INSTR_CREATE_vblendvpd(dc, d, s1, s2, s3) \
  instr_create_1dst_3src((dc), OP_vblendvpd, (d), (s1), (s2), (s3))
/* @} */ /* end doxygen group */

/** @name 1 destination, 3 sources including one immediate */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s1 The opnd_t explicit first source operand for the instruction.
 * \param s2 The opnd_t explicit second source operand for the instruction
 * \param i  The opnd_t explicit third source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
/* AVX */
#define INSTR_CREATE_vcmpps(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vcmpps, (d), (s1), (s2), (i))
#define INSTR_CREATE_vcmpss(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vcmpss, (d), (s1), (s2), (i))
#define INSTR_CREATE_vcmppd(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vcmppd, (d), (s1), (s2), (i))
#define INSTR_CREATE_vcmpsd(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vcmpsd, (d), (s1), (s2), (i))
#define INSTR_CREATE_vpinsrw(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vpinsrw, (d), (s1), (s2), (i))
#define INSTR_CREATE_vshufps(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vshufps, (d), (s1), (s2), (i))
#define INSTR_CREATE_vshufpd(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vshufpd, (d), (s1), (s2), (i))
#define INSTR_CREATE_vpalignr(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vpalignr, (d), (s1), (s2), (i))
#define INSTR_CREATE_vblendps(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vblendps, (d), (s1), (s2), (i))
#define INSTR_CREATE_vblendpd(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vblendpd, (d), (s1), (s2), (i))
#define INSTR_CREATE_vpblendw(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vpblendw, (d), (s1), (s2), (i))
#define INSTR_CREATE_vpinsrb(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vpinsrb, (d), (s1), (s2), (i))
#define INSTR_CREATE_vinsertps(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vinsertps, (d), (s1), (s2), (i))
#define INSTR_CREATE_vpinsrd(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vpinsrd, (d), (s1), (s2), (i))
#define INSTR_CREATE_vdpps(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vdpps, (d), (s1), (s2), (i))
#define INSTR_CREATE_vdppd(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vdppd, (d), (s1), (s2), (i))
#define INSTR_CREATE_vmpsadbw(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vmpsadbw, (d), (s1), (s2), (i))
#define INSTR_CREATE_vpclmulqdq(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vpclmulqdq, (d), (s1), (s2), (i))
#define INSTR_CREATE_vroundss(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vroundss, (d), (s1), (s2), (i))
#define INSTR_CREATE_vroundsd(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vroundsd, (d), (s1), (s2), (i))
#define INSTR_CREATE_vperm2f128(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vperm2f128, (d), (s1), (s2), (i))
#define INSTR_CREATE_vinsertf128(dc, d, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vinsertf128, (d), (s1), (s2), (i))
/* @} */ /* end doxygen group */

/* 1 destination, 3 sources: 1 implicit */
/** @name 1 destination, 3 sources: 1 implicit */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 * \param ri The opnd_t explicit source operand for the instruction, which must
 * be one of the following:
 * -# The register cl (#opnd_create_reg(#DR_REG_CL));
 * -# An immediate integer (opnd_create_immed_int()) of size #OPSZ_1;
 */
#define INSTR_CREATE_shld(dc, d, s, ri) \
  instr_create_1dst_3src((dc), OP_shld, (d), (s), (ri), (d))
#define INSTR_CREATE_shrd(dc, d, s, ri) \
  instr_create_1dst_3src((dc), OP_shrd, (d), (s), (ri), (d))
/* @} */ /* end doxygen group */
/** @name 1 destination, 3 sources: 1 implicit, 1 immed */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 * \param i The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_pclmulqdq(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_pclmulqdq, (d), (s), (i), (d))
#define INSTR_CREATE_blendps(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_blendps, (d), (s), (i), (d))
#define INSTR_CREATE_blendpd(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_blendpd, (d), (s), (i), (d))
#define INSTR_CREATE_pblendw(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_pblendw, (d), (s), (i), (d))
/* @} */ /* end doxygen group */
/** @name 1 explicit destination, 2 explicit sources, 1 implicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 * \param i The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_shufps(dc, d, s, i ) \
  instr_create_1dst_3src((dc), OP_shufps, (d), (s), (i), (d))
#define INSTR_CREATE_shufpd(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_shufpd, (d), (s), (i), (d))
#define INSTR_CREATE_cmpps(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_cmpps, (d), (s), (i), (d))
#define INSTR_CREATE_cmpss(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_cmpss, (d), (s), (i), (d))
#define INSTR_CREATE_cmppd(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_cmppd, (d), (s), (i), (d))
#define INSTR_CREATE_cmpsd(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_cmpsd, (d), (s), (i), (d))
#define INSTR_CREATE_palignr(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_palignr, (d), (s), (i), (d))
#define INSTR_CREATE_dpps(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_dpps, (d), (s), (i), (d))
#define INSTR_CREATE_dppd(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_dppd, (d), (s), (i), (d))
#define INSTR_CREATE_mpsadbw(dc, d, s, i) \
  instr_create_1dst_3src((dc), OP_mpsadbw, (d), (s), (i), (d))
/* @} */ /* end doxygen group */

/** @name 1 explicit destination, 2 explicit sources, dest is implicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s1 The opnd_t explicit first source operand for the instruction.
 * \param s2 The opnd_t explicit second source operand for the instruction.
 */
/* FMA */
#define INSTR_CREATE_vfmadd132ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd132ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd132pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd132pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd213ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd213ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd213pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd213pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd231ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd231ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd231pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd231pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd132ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd132ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd132sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd132sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd213ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd213ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd213sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd213sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd231ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd231ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmadd231sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmadd231sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmaddsub132ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmaddsub132ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmaddsub132pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmaddsub132pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmaddsub213ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmaddsub213ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmaddsub213pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmaddsub213pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmaddsub231ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmaddsub231ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmaddsub231pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmaddsub231pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsubadd132ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsubadd132ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsubadd132pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsubadd132pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsubadd213ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsubadd213ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsubadd213pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsubadd213pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsubadd231ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsubadd231ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsubadd231pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsubadd231pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub132ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub132ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub132pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub132pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub213ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub213ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub213pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub213pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub231ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub231ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub231pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub231pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub132ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub132ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub132sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub132sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub213ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub213ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub213sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub213sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub231ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub231ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfmsub231sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfmsub231sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd132ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd132ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd132pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd132pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd213ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd213ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd213pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd213pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd231ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd231ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd231pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd231pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd132ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd132ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd132sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd132sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd213ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd213ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd213sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd213sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd231ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd231ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmadd231sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmadd231sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub132ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub132ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub132pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub132pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub213ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub213ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub213pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub213pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub231ps(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub231ps, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub231pd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub231pd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub132ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub132ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub132sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub132sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub213ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub213ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub213sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub213sd, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub231ss(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub231ss, (d), (s1), (s2), (d))
#define INSTR_CREATE_vfnmsub231sd(dc, d, s1, s2) \
  instr_create_1dst_3src((dc), OP_vfnmsub231sd, (d), (s1), (s2), (d))
/* @} */ /* end doxygen group */

/** @name 1 destination, 3 sources where 2 are implicit */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s  The opnd_t explicit source operand for the instruction.
 */
/* SSE4 */
#define INSTR_CREATE_pblendvb(dc, d, s) \
  instr_create_1dst_3src((dc), OP_pblendvb, (d), (s), opnd_create_reg(DR_REG_XMM0), (d))
#define INSTR_CREATE_blendvps(dc, d, s) \
  instr_create_1dst_3src((dc), OP_blendvps, (d), (s), opnd_create_reg(DR_REG_XMM0), (d))
#define INSTR_CREATE_blendvpd(dc, d, s) \
  instr_create_1dst_3src((dc), OP_blendvpd, (d), (s), opnd_create_reg(DR_REG_XMM0), (d))
/* @} */ /* end doxygen group */

/* 1 implicit destination, 3 sources */
/** @name 1 implicit destination, 3 sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s1 The opnd_t explicit first source operand for the instruction.
 * \param s2 The opnd_t explicit second source operand for the instruction.
 * \param i The opnd_t explicit third source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_pcmpistrm(dc, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_pcmpistrm, opnd_create_reg(DR_REG_XMM0), (s1), (s2), (i))
#define INSTR_CREATE_pcmpistri(dc, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_pcmpistri, opnd_create_reg(DR_REG_ECX), (s1), (s2), (i))
#define INSTR_CREATE_vpcmpistrm(dc, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vpcmpistrm, opnd_create_reg(DR_REG_XMM0), \
    (s1), (s2), (i))
#define INSTR_CREATE_vpcmpistri(dc, s1, s2, i) \
  instr_create_1dst_3src((dc), OP_vpcmpistri, opnd_create_reg(DR_REG_ECX), \
    (s1), (s2), (i))
/* @} */ /* end doxygen group */


/* 1 implicit destination, 3 sources: 2 implicit */
/** @name 1 implicit destination, 3 sources: 2 implicit */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx_imm macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands. The _imm
 * suffix distinguishes between alternative forms of the same opcode: these
 * forms take an explicit immediate.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param i The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_ret_imm(dc, i) \
  instr_create_1dst_3src((dc), OP_ret, opnd_create_reg(DR_REG_XSP), (i), \
    opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, 0, OPSZ_ret))
/* XXX: blindly asking for rex.w (b/c 32-bit is default for x64) but don't
 * know x64 mode! */
#define INSTR_CREATE_ret_far_imm(dc, i) \
  instr_create_1dst_3src((dc), OP_ret_far, opnd_create_reg(DR_REG_XSP), (i), \
    opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, 0, IF_X64_ELSE(OPSZ_16,OPSZ_8)))
/* @} */ /* end doxygen group */

/* 1 implicit destination, 5 sources: 2 implicit */
/** @name 1 implicit destination, 5 sources: 2 implicit */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s1 The opnd_t explicit first source operand for the instruction.
 * \param s2 The opnd_t explicit second source operand for the instruction.
 * \param i The opnd_t explicit third source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_pcmpestrm(dc, s1, s2, i) \
  instr_create_1dst_5src((dc), OP_pcmpestrm, opnd_create_reg(DR_REG_XMM0), \
    (s1), (s2), (i), opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_EDX))
#define INSTR_CREATE_pcmpestri(dc, s1, s2, i) \
  instr_create_1dst_5src((dc), OP_pcmpestri, opnd_create_reg(DR_REG_ECX), \
    (s1), (s2), (i), opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_EDX))
/* AVX */
#define INSTR_CREATE_vpcmpestrm(dc, s1, s2, i) \
  instr_create_1dst_5src((dc), OP_vpcmpestrm, opnd_create_reg(DR_REG_XMM0), \
    (s1), (s2), (i), opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_EDX))
#define INSTR_CREATE_vpcmpestri(dc, s1, s2, i) \
  instr_create_1dst_5src((dc), OP_vpcmpestri, opnd_create_reg(DR_REG_ECX), \
    (s1), (s2), (i), opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_EDX))
/* @} */ /* end doxygen group */

/* 2 implicit destinations, no sources */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_rdtsc(dc) \
  instr_create_2dst_0src((dc), OP_rdtsc, opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX))

/* 2 destinations: 1 implicit, 1 source */
/** @name 2 destinations: 1 implicit, 1 source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_lds(dc, d, s) \
  instr_create_2dst_1src((dc), OP_lds, (d), opnd_create_reg(DR_SEG_DS), (s))
#define INSTR_CREATE_lss(dc, d, s) \
  instr_create_2dst_1src((dc), OP_lss, (d), opnd_create_reg(DR_SEG_SS), (s))
#define INSTR_CREATE_les(dc, d, s) \
  instr_create_2dst_1src((dc), OP_les, (d), opnd_create_reg(DR_SEG_ES), (s))
#define INSTR_CREATE_lfs(dc, d, s) \
  instr_create_2dst_1src((dc), OP_lfs, (d), opnd_create_reg(DR_SEG_FS), (s))
#define INSTR_CREATE_lgs(dc, d, s) \
  instr_create_2dst_1src((dc), OP_lgs, (d), opnd_create_reg(DR_SEG_GS), (s))
/* @} */ /* end doxygen group */

/* 2 implicit destinations, 1 implicit source */
/** @name 2 implicit destinations, 1 implicit source */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_pushf(dc) \
  instr_create_2dst_1src((dc), OP_pushf, opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, IF_X64_ELSE(-8,-4), OPSZ_STACK), \
    opnd_create_reg(DR_REG_XSP))
#define INSTR_CREATE_rdmsr(dc) \
  instr_create_2dst_1src((dc), OP_rdmsr, opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_ECX))
#define INSTR_CREATE_rdpmc(dc) \
  instr_create_2dst_1src((dc), OP_rdpmc, opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_ECX))
#define INSTR_CREATE_xgetbv(dc) \
  instr_create_2dst_1src((dc), OP_xgetbv, opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_ECX))
/* @} */ /* end doxygen group */

/* 2 destinations: 1 implicit, 2 sources */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 */
#define INSTR_CREATE_pop(dc, d) \
  instr_create_2dst_2src((dc), OP_pop, (d), opnd_create_reg(DR_REG_XSP), \
    opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, 0, OPSZ_VARSTACK))

/* 2 destinations: 1 implicit, 2 sources: 1 implicit */
/** @name 2 destinations: 1 implicit, 2 sources: 1 implicit */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_xchg(dc, d, s) \
  instr_create_2dst_2src((dc), OP_xchg, (d), (s), (d), (s))
#define INSTR_CREATE_xadd(dc, d, s) \
  instr_create_2dst_2src((dc), OP_xadd, (d), (s), (d), (s))
/* @} */ /* end doxygen group */

/* string instructions */
/** @name String instructions */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx_1 or INSTR_CREATE_xxx_4 macro creates an instr_t with opcode
 * OP_xxx, automatically supplying any implicit operands.  The _1 or _4 suffixes
 * distinguish between alternative forms of the same opcode (1 and 4 identify the
 * operand size).
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_ins_1(dc) \
  instr_create_2dst_2src((dc), OP_ins, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_DX), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_ins_4(dc) \
  instr_create_2dst_2src((dc), OP_ins, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_DX), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_stos_1(dc) \
  instr_create_2dst_2src((dc), OP_stos, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_AL), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_stos_4(dc) \
  instr_create_2dst_2src((dc), OP_stos, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XAX), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_lods_1(dc) \
  instr_create_2dst_2src((dc), OP_lods, opnd_create_reg(DR_REG_AL), \
    opnd_create_reg(DR_REG_XSI), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XSI))
#define INSTR_CREATE_lods_4(dc) \
  instr_create_2dst_2src((dc), OP_lods, opnd_create_reg(DR_REG_XAX), \
    opnd_create_reg(DR_REG_XSI), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XSI)) 
#define INSTR_CREATE_movs_1(dc) \
  instr_create_3dst_3src((dc), OP_movs, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_movs_4(dc) \
  instr_create_3dst_3src((dc), OP_movs, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_rep_ins_1(dc) \
  instr_create_3dst_3src((dc), OP_rep_ins, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX), \
    opnd_create_reg(DR_REG_DX), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_ins_4(dc) \
  instr_create_3dst_3src((dc), OP_rep_ins, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX), \
    opnd_create_reg(DR_REG_DX), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_stos_1(dc) \
  instr_create_3dst_3src((dc), OP_rep_stos, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX), \
    opnd_create_reg(DR_REG_AL), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_stos_4(dc) \
  instr_create_3dst_3src((dc), OP_rep_stos, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX), \
    opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_lods_1(dc) \
  instr_create_3dst_3src((dc), OP_rep_lods, opnd_create_reg(DR_REG_AL), \
    opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_lods_4(dc) \
  instr_create_3dst_3src((dc), OP_rep_lods, opnd_create_reg(DR_REG_EAX), \
    opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_movs_1(dc) \
  instr_create_4dst_4src((dc), OP_rep_movs, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_movs_4(dc) \
  instr_create_4dst_4src((dc), OP_rep_movs, \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_outs_1(dc) \
  instr_create_1dst_3src((dc), OP_outs, opnd_create_reg(DR_REG_XSI), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_DX), opnd_create_reg(DR_REG_XSI))
#define INSTR_CREATE_outs_4(dc) \
  instr_create_1dst_3src((dc), OP_outs, opnd_create_reg(DR_REG_XSI), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_DX), opnd_create_reg(DR_REG_XSI))
#define INSTR_CREATE_cmps_1(dc) \
  instr_create_2dst_4src((dc), OP_cmps, opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XDI), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_cmps_4(dc) \
  instr_create_2dst_4src((dc), OP_cmps, opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XDI), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_scas_1(dc) \
  instr_create_1dst_3src((dc), OP_scas, opnd_create_reg(DR_REG_XDI), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_AL), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_scas_4(dc) \
  instr_create_1dst_3src((dc), OP_scas, opnd_create_reg(DR_REG_XDI), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_XDI))
#define INSTR_CREATE_rep_outs_1(dc) \
  instr_create_2dst_4src((dc), OP_rep_outs, opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_DX), opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_outs_4(dc) \
  instr_create_2dst_4src((dc), OP_rep_outs, opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_DX), opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_cmps_1(dc) \
  instr_create_3dst_5src((dc), OP_rep_cmps, opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_cmps_4(dc) \
  instr_create_3dst_5src((dc), OP_rep_cmps, opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_repne_cmps_1(dc) \
  instr_create_3dst_5src((dc), OP_repne_cmps, opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_repne_cmps_4(dc) \
  instr_create_3dst_5src((dc), OP_repne_cmps, opnd_create_reg(DR_REG_XSI), \
    opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_DS, DR_REG_XSI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_XSI), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_scas_1(dc) \
  instr_create_2dst_4src((dc), OP_rep_scas, opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_AL), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_rep_scas_4(dc) \
  instr_create_2dst_4src((dc), OP_rep_scas, opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_repne_scas_1(dc) \
  instr_create_2dst_4src((dc), OP_repne_scas, opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, OPSZ_1), \
    opnd_create_reg(DR_REG_AL), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
#define INSTR_CREATE_repne_scas_4(dc) \
  instr_create_2dst_4src((dc), OP_repne_scas, opnd_create_reg(DR_REG_XDI), \
    opnd_create_reg(DR_REG_XCX), \
    opnd_create_far_base_disp(DR_SEG_ES, DR_REG_XDI, DR_REG_NULL, 0, 0, \
      OPSZ_4_rex8_short2), \
    opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_XDI), opnd_create_reg(DR_REG_XCX))
/* @} */ /* end doxygen group */

/* floating point */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit register operand, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param f The opnd_t explicit source operand for the instruction, which must
 * be a floating point register (opnd_create_reg()).
 */
#define INSTR_CREATE_fxch(dc, f) \
  instr_create_2dst_2src((dc), OP_fxch, opnd_create_reg(DR_REG_ST0), (f), \
    opnd_create_reg(DR_REG_ST0), (f))

/* 2 destinations, 2 sources: 1 implicit */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param t The opnd_t target operand for the instruction, which can be either
 * a pc (opnd_create_pc()) or an instr_t (opnd_create_instr()).
 */
#define INSTR_CREATE_call(dc, t) \
  instr_create_2dst_2src((dc), OP_call, opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, IF_X64_ELSE(-8,-4), OPSZ_STACK), \
    (t), opnd_create_reg(DR_REG_XSP))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param t The opnd_t target operand for the instruction, which should be
 * a memory reference created with opnd_create_base_disp().
 */
#define INSTR_CREATE_call_ind(dc, t) \
  instr_create_2dst_2src((dc), OP_call_ind, opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, IF_X64_ELSE(-8,-4), OPSZ_STACK), \
    (t), opnd_create_reg(DR_REG_XSP))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param t The opnd_t target operand for the instruction, which should be
 * a far pc operand created with opnd_create_far_pc().
 */
/* note: unlike iret/ret_far, 32-bit is typical desired size even for 64-bit mode */
#define INSTR_CREATE_call_far(dc, t) \
  instr_create_2dst_2src((dc), OP_call_far, opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, -8, OPSZ_8), \
    (t), opnd_create_reg(DR_REG_XSP))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param t The opnd_t target operand for the instruction, which should be
 * a far memory reference created with opnd_create_far_base_disp().
 */
/* note: unlike iret/ret_far, 32-bit is typical desired size even for 64-bit mode */
#define INSTR_CREATE_call_far_ind(dc, t) \
  instr_create_2dst_2src((dc), OP_call_far_ind, opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, -8, OPSZ_8), \
    (t), opnd_create_reg(DR_REG_XSP))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and
 * the given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_push(dc, s) \
  instr_create_2dst_2src((dc), OP_push, opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, IF_X64_ELSE(-8,-4), OPSZ_VARSTACK), \
    (s), opnd_create_reg(DR_REG_XSP))
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the
 * given explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param i The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()).
 */
#define INSTR_CREATE_push_imm(dc, i) \
  instr_create_2dst_2src((dc), OP_push_imm, opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, IF_X64_ELSE(-8,-4), OPSZ_VARSTACK), \
    (i), opnd_create_reg(DR_REG_XSP))

/* 2 destinations: 1 implicit, 3 sources: 1 implicit */
/** @name 2 destinations: 1 implicit, 3 sources: 1 implicit */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx_1 or INSTR_CREATE_xxx_4 macro creates an
 * instr_t with opcode OP_xxx and the given explicit operands, automatically
 * supplying any implicit operands.    The _1 or _4 suffixes distinguish between
 * alternative forms of the same opcode (1 and 4 identify the operand size).
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 * \param s The opnd_t explicit source operand for the instruction.
 */
#define INSTR_CREATE_cmpxchg_1(dc, d, s) \
  instr_create_2dst_3src((dc), OP_cmpxchg, (d), opnd_create_reg(DR_REG_AL), (s), (d), \
    opnd_create_reg(DR_REG_AL))
#define INSTR_CREATE_cmpxchg_4(dc, d, s) \
  instr_create_2dst_3src((dc), OP_cmpxchg, (d), opnd_create_reg(DR_REG_EAX), (s), (d), \
    opnd_create_reg(DR_REG_EAX))
/* @} */ /* end doxygen group */

/* 2 implicit destinations, 3 implicit sources */
#define INSTR_CREATE_leave(dc) \
  instr_create_2dst_3src((dc), OP_leave, opnd_create_reg(DR_REG_XSP), \
    opnd_create_reg(DR_REG_XBP), opnd_create_reg(DR_REG_XBP), \
    opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XBP, DR_REG_NULL, 0, 0, OPSZ_STACK))

/** @name No destination, many implicit sources */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
/* 2 implicit destinations, 8 implicit sources */
#define INSTR_CREATE_pusha(dc)  instr_create_pusha((dc))

/* 3 implicit destinations, no sources */
#define INSTR_CREATE_rdtscp(dc) \
  instr_create_3dst_0src((dc), OP_rdtscp, opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_EAX), opnd_create_reg(DR_REG_ECX))

/* 3 implicit destinations, 1 source */
#define INSTR_CREATE_cpuid(dc) \
  instr_create_4dst_1src((dc), OP_cpuid, opnd_create_reg(DR_REG_EAX), \
    opnd_create_reg(DR_REG_EBX), opnd_create_reg(DR_REG_ECX), \
    opnd_create_reg(DR_REG_EDX), opnd_create_reg(DR_REG_EAX))
/* @} */ /* end doxygen group */

/* 3 destinations: 2 implicit, 5 implicit sources */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param d The opnd_t explicit destination operand for the instruction.
 */
#define INSTR_CREATE_cmpxchg8b(dc, d) \
  instr_create_3dst_5src((dc), OP_cmpxchg8b, (d), opnd_create_reg(DR_REG_EAX), \
    opnd_create_reg(DR_REG_EDX), (d), opnd_create_reg(DR_REG_EAX), \
    opnd_create_reg(DR_REG_EDX), \
    opnd_create_reg(DR_REG_ECX), opnd_create_reg(DR_REG_EBX))

/* 3 implicit destinations, 4 sources: 2 implicit */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx and the given
 * explicit operands, automatically supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param i16 The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()) of OPSZ_2.
 * \param i8 The opnd_t explicit second source operand for the instruction, which
 * must be an immediate integer (opnd_create_immed_int()) of OPSZ_1.
 */
/* XXX: IR ignores non-zero immed for size+disp */
#define INSTR_CREATE_enter(dc, i16, i8) \
  instr_create_3dst_4src((dc), OP_enter, opnd_create_reg(DR_REG_XSP), \
    opnd_create_base_disp(DR_REG_XSP, DR_REG_NULL, 0, IF_X64_ELSE(-8,-4), OPSZ_STACK), \
    opnd_create_reg(DR_REG_XBP), \
    (i16), (i8), opnd_create_reg(DR_REG_XSP), opnd_create_reg(DR_REG_XBP))

/* 8 implicit destinations, 2 implicit sources */
/**
 * This INSTR_CREATE_xxx macro creates an instr_t with opcode OP_xxx, automatically
 * supplying any implicit operands.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_popa(dc)   instr_create_popa((dc))

#endif //NO

/****************************************************************************/

/** @name Nops */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */
/**
 * Convenience routine for nop of certain size.  We choose edi as working register
 * for multibyte nops (seems least likely to impact performance: Microsoft uses it
 * and DR used to steal it).
 * Note that Intel now recommends a different set of multi-byte nops,
 * but we stick with these as our tools (mainly windbg) don't understand
 * the OP_nop_modrm encoding (though should work on PPro+).
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 */
#define INSTR_CREATE_nop1byte(dc) INSTR_CREATE_nop(dc)
#define INSTR_CREATE_nop2byte(dc) INSTR_CREATE_nop2byte_reg(dc, DR_REG_R7)
#define INSTR_CREATE_nop3byte(dc) INSTR_CREATE_nop3byte_reg(dc, DR_REG_R7)
/* @} */ /* end doxygen group */
/** @name 2-byte reg nops */
/* @{ */ /* doxygen start group; w/ DISTRIBUTE_GROUP_DOC=YES, one comment suffices. */

/**
 * Convenience routine for nop of certain size.
 * Note that Intel now recommends a different set of multi-byte nops,
 * but we stick with these as our tools (mainly windbg) don't understand
 * the OP_nop_modrm encoding (though should work on PPro+).
 * AMD recommends 0x66 0x66 ... 0x90 for older processors.
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param reg A reg_id_t (NOT opnd_t) to use as source and destination.
 * For 64-bit mode, use a 64-bit register, but NOT rbp or rsp for the 3-byte form.
 */
static inline instr_t *
INSTR_CREATE_nop2byte_reg(dcontext_t *dcontext, reg_id_t reg)
{
#ifdef X64
    if (!get_x86_mode(dcontext)) {
        /* 32-bit register target zeroes out the top bits, so we use the Intel
         * and AMD recommended 0x66 0x90 */
        instr_t *in = instr_build_bits(dcontext, OP_nop, 2);
# ifdef WINDOWS
        /* avoid warning C4100: 'reg' : unreferenced formal parameter */
        UNREFERENCED_PARAMETER(reg);
# endif
        instr_set_raw_byte(in, 0, 0x66);
        instr_set_raw_byte(in, 1, 0x90);
        instr_set_operands_valid(in, true);
        return in;
    } else {
#endif
        // TODO SJF Fixme
        //return INSTR_CREATE_mov_st(dcontext, opnd_create_reg(reg), opnd_create_reg(reg));
        return NULL;
#ifdef X64
        /* XXX: could have INSTR_CREATE_nop{1,2,3}byte() pick DR_REG_EDI for x86
         * mode, or could call instr_shrink_to_32_bits() here, but we aren't planning
         * to change any of the other regular macros in this file: only those that
         * have completely different forms in the two modes, and we expect caller to
         * shrink to 32 for all INSTR_CREATE_* functions/macros.
         */
    }
#endif
}
/* lea's target is 32-bit but address register is 64: so we eliminate the
 * displacement and put in rex.w 
 */
#ifdef NO
static inline instr_t *
INSTR_CREATE_nop3byte_reg(dcontext_t *dcontext, reg_id_t reg)
{
#ifdef X64
    if (!get_x86_mode(dcontext)) {
        return INSTR_CREATE_lea(dcontext, opnd_create_reg(reg),
                              OPND_CREATE_MEM_lea(reg, DR_REG_NULL, 0, 0));
    } else {
#endif
        return INSTR_CREATE_lea(dcontext, opnd_create_reg(reg),
                                opnd_create_base_disp_ex(reg, DR_REG_NULL, 0, 0, OPSZ_lea,
                                                         true/*encode 0*/, false, false));
#ifdef X64
        /* see note above for whether to auto-shrink */
    }
#endif
}
#endif

/* @} */ /* end doxygen group */
#ifndef UNSUPPORTED_API
/* DR_API EXPORT END */
#endif

/**
 * Convenience routine for nop of certain size.
 * Note that Intel now recommends a different set of multi-byte nops,
 * but we stick with these as our tools (mainly windbg) don't understand
 * the OP_nop_modrm encoding (though should work on PPro+).
 * \param dc The void * dcontext used to allocate memory for the instr_t.
 * \param n  The number of bytes in the encoding of the nop.
 */
#define INSTR_CREATE_nopNbyte(dc, n) instr_create_nbyte_nop(dc, n, false)

/* convenience routines for when you only need raw bits */
#define INSTR_CREATE_RAW_pushf(dc) instr_create_raw_1byte(dc, 0x9c)
#define INSTR_CREATE_RAW_popf(dc)  instr_create_raw_1byte(dc, 0x9d)
#define INSTR_CREATE_RAW_pusha(dc) instr_create_raw_1byte(dc, 0x60)
#define INSTR_CREATE_RAW_popa(dc)  instr_create_raw_1byte(dc, 0x61)
#define INSTR_CREATE_RAW_nop(dc)   instr_create_raw_1byte(dc, 0x90)
#define INSTR_CREATE_RAW_nop1byte(dc) INSTR_CREATE_RAW_nop(dc)
#ifdef X64
# define INSTR_CREATE_RAW_nop2byte(dc) instr_create_raw_2bytes(dc, 0x66, 0x90)
# define INSTR_CREATE_RAW_nop3byte(dc) instr_create_raw_3bytes(dc, 0x48, 0x8d, 0x3f)
#else
# define INSTR_CREATE_RAW_nop2byte(dc) instr_create_raw_2bytes(dc, 0x8b, 0xff)
# define INSTR_CREATE_RAW_nop3byte(dc) instr_create_raw_3bytes(dc, 0x8d, 0x7f, 0x00)
#endif
#define INSTR_CREATE_RAW_nopNbyte(dc, n) instr_create_nbyte_nop(dc, n, true)
#ifdef UNSUPPORTED_API
/* DR_API EXPORT END */
#endif

#endif /* _INSTR_CREATE_H_ */

