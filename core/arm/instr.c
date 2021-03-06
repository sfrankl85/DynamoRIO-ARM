/* **********************************************************
 * Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
 * Copyright (c) 2000-2010 VMware, Inc.  All rights reserved.
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
/* Copyright (c) 2000-2001 Hewlett-Packard Company */

/* file "instr.c" -- x86-specific IR utilities
 */

/* We need to provide at least one out-of-line definition for our inline
 * functions in instr_inline.h in case they are all inlined away within DR.
 *
 * For gcc, we use -std=gnu99, which uses the C99 inlining model.  Using "extern
 * inline" will provide a definition, but we can only do this in one C file.
 * Elsewhere we use plain "inline", which will not emit an out of line
 * definition if inlining fails.
 *
 * MSVC always emits link_once definitions for dllexported inline functions, so
 * this macro magic is unnecessary.
 * http://msdn.microsoft.com/en-us/library/xa0d9ste.aspx
 */
#define INSTR_INLINE extern inline

#include "../globals.h"
#include "instr.h"
#include "arch.h"
#include "../link.h"
#include "decode.h"
#include "decode_fast.h"
#include "instr_create.h"

#include <string.h> /* for memcpy */

#ifdef DEBUG
# include "disassemble.h"
#endif

#ifdef VMX86_SERVER
# include "vmkuw.h" /* VMKUW_SYSCALL_GATEWAY */
#endif

#if defined(DEBUG) && !defined(STANDALONE_DECODER)
/* case 10450: give messages to clients */
/* we can't undef ASSERT b/c of DYNAMO_OPTION */
# undef ASSERT_TRUNCATE
# undef ASSERT_BITFIELD_TRUNCATE
# undef ASSERT_NOT_REACHED
# define ASSERT_TRUNCATE DO_NOT_USE_ASSERT_USE_CLIENT_ASSERT_INSTEAD
# define ASSERT_BITFIELD_TRUNCATE DO_NOT_USE_ASSERT_USE_CLIENT_ASSERT_INSTEAD
# define ASSERT_NOT_REACHED DO_NOT_USE_ASSERT_USE_CLIENT_ASSERT_INSTEAD
#endif


/*************************
 ***       opnd_t        ***
 *************************/

#undef opnd_is_null
#undef opnd_is_immed_int
#undef opnd_is_immed_float
#undef opnd_is_near_pc
#undef opnd_is_near_instr
#undef opnd_is_reg
#undef opnd_is_base_disp
#undef opnd_is_far_pc
#undef opnd_is_far_instr
#undef opnd_is_mem_instr
#undef opnd_is_valid
bool opnd_is_null       (opnd_t op) { return OPND_IS_NULL(op); }
bool opnd_is_immed_int  (opnd_t op) { return OPND_IS_IMMED_INT(op); }
bool opnd_is_immed_float(opnd_t op) { return OPND_IS_IMMED_FLOAT(op); }
bool opnd_is_near_pc    (opnd_t op) { return OPND_IS_NEAR_PC(op); }
bool opnd_is_near_instr (opnd_t op) { return OPND_IS_NEAR_INSTR(op); }
bool opnd_is_reg        (opnd_t op) { return OPND_IS_REG(op); }
bool opnd_is_reglist    (opnd_t op) { return OPND_IS_REGLIST(op); }
bool opnd_is_mem_reg    (opnd_t op) { return OPND_IS_MEM_REG(op); }
bool opnd_is_mask       (opnd_t op) { return OPND_IS_MASK(op); }
bool opnd_is_base_disp  (opnd_t op) { return OPND_IS_BASE_DISP(op); }
bool opnd_is_far_pc     (opnd_t op) { return OPND_IS_FAR_PC(op); }
bool opnd_is_far_instr  (opnd_t op) { return OPND_IS_FAR_INSTR(op); }
bool opnd_is_mem_instr  (opnd_t op) { return OPND_IS_MEM_INSTR(op); }
bool opnd_is_valid      (opnd_t op) { return OPND_IS_VALID(op); }
#define opnd_is_null            OPND_IS_NULL
#define opnd_is_immed_int       OPND_IS_IMMED_INT
#define opnd_is_immed_float     OPND_IS_IMMED_FLOAT
#define opnd_is_near_pc         OPND_IS_NEAR_PC
#define opnd_is_near_instr      OPND_IS_NEAR_INSTR
#define opnd_is_reg             OPND_IS_REG
#define opnd_is_base_disp       OPND_IS_BASE_DISP
#define opnd_is_far_pc          OPND_IS_FAR_PC
#define opnd_is_far_instr       OPND_IS_FAR_INSTR
#define opnd_is_mem_instr       OPND_IS_MEM_INSTR
#define opnd_is_valid           OPND_IS_VALID
#define opnd_is_mask            OPND_IS_MASK

#ifdef X64
# undef opnd_is_rel_addr
bool opnd_is_rel_addr(opnd_t op) { return OPND_IS_REL_ADDR(op); }
# define opnd_is_rel_addr OPND_IS_REL_ADDR
#endif


/* We allow overlap between ABS_ADDR_kind and BASE_DISP_kind w/ no base or index */
static bool
opnd_is_abs_base_disp(opnd_t opnd) {
    return (opnd_is_base_disp(opnd) && opnd_get_base(opnd) == REG_NULL &&
            opnd_get_index(opnd) == REG_NULL);
}
bool opnd_is_abs_addr(opnd_t opnd) {
    return IF_X64(opnd.kind == ABS_ADDR_kind ||) opnd_is_abs_base_disp(opnd);
}
bool opnd_is_near_abs_addr(opnd_t opnd) {
    return opnd_is_abs_addr(opnd) && opnd.seg.segment == REG_NULL; 
}
bool opnd_is_far_abs_addr(opnd_t opnd) {
    return opnd_is_abs_addr(opnd) && opnd.seg.segment != REG_NULL; 
}

bool
opnd_is_reg_32bit(opnd_t opnd)
{
    if (opnd_is_reg(opnd))
        return reg_is_32bit(opnd_get_reg(opnd));
    return false;
}

bool
reg_is_32bit(reg_id_t reg)
{
    return (reg >= REG_START_32 && reg <= REG_STOP_32);
}

bool
opnd_is_reg_64bit(opnd_t opnd)
{
    if (opnd_is_reg(opnd))
        return reg_is_64bit(opnd_get_reg(opnd));
    return false;
}

bool
reg_is_64bit(reg_id_t reg)
{
    return (reg >= REG_START_64 && reg <= REG_STOP_64);
}

bool
opnd_is_reg_pointer_sized(opnd_t opnd)
{
    if (opnd_is_reg(opnd))
        return reg_is_pointer_sized(opnd_get_reg(opnd));
    return false;
}

bool
reg_is_pointer_sized(reg_id_t reg)
{
#ifdef X64
    return (reg >= REG_START_64 && reg <= REG_STOP_64);
#else
    return (reg >= REG_START_32 && reg <= REG_STOP_32);
#endif
}

#undef opnd_get_reg
reg_id_t
opnd_get_reg(opnd_t opnd)
{
    return OPND_GET_REG(opnd);
}
#define opnd_get_reg OPND_GET_REG

opnd_size_t
opnd_get_size(opnd_t opnd)
{
    switch(opnd.kind) {
    case REG_kind: 
        return reg_get_size(opnd_get_reg(opnd));
    case MEM_REG_kind: 
        return OPSZ_4_4;
    case REG_LIST_kind: 
        return OPSZ_4_16;
    case IMMED_INTEGER_kind:
    case IMMED_FLOAT_kind:
    case BASE_DISP_kind:
    case MEM_INSTR_kind:
        return opnd.size;
    case INSTR_kind:
    case PC_kind:
        return OPSZ_PTR;
    case NULL_kind:
        return OPSZ_NA;
    case MASK_kind:
        return OPSZ_4_2;
    default:
        CLIENT_ASSERT(false, "opnd_get_size: unknown opnd type");
        return OPSZ_NA;
    }
}

int
opnd_get_mask_value(opnd_t opnd)
{
  if( opnd.kind == MASK_kind )
  {
    return opnd.value.mask;
  }
  else
    return INVALID_MASK;
  
}

void
opnd_set_size(opnd_t *opnd, opnd_size_t newsize)
{
    switch(opnd->kind) {
    case IMMED_INTEGER_kind:
    case BASE_DISP_kind:
#ifdef X64
    case REL_ADDR_kind: 
    case ABS_ADDR_kind: 
#endif
    case MEM_INSTR_kind:
        opnd->size = newsize;
        return;
    default:
        CLIENT_ASSERT(false, "opnd_set_size: unknown opnd type");
    }
}

/* immediate operands */

opnd_t
opnd_create_immed_int(ptr_int_t i, opnd_size_t size)
{
    opnd_t opnd;
    opnd.kind = IMMED_INTEGER_kind;
    CLIENT_ASSERT(size < OPSZ_LAST_ENUM, "opnd_create_immed_int: invalid size");
    opnd.size = size;
    opnd.value.immed_int = i;
    DOCHECK(1, {
        /* SJF Change to check bits here as ARM operands can be < 1 byte */
        uint sz = opnd_size_in_bits(size);
        if (sz == 8) {
            CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_sbyte(i),
                          "opnd_create_immed_int: value too large for 8-bit size");
        } else if (sz == 16) {
            CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_short(i),
                          "opnd_create_immed_int: value too large for 16-bit size");
        } else if (sz == 32) {
            CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_int(i),
                          "opnd_create_immed_int: value too large for 32-bit size");
        } else if (sz == 3){
            CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_3bit(i),
                          "opnd_create_immed_int: value too large for 3-bit size");
        } else if (sz == 5){
            CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_5bit(i),
                          "opnd_create_immed_int: value too large for 5-bit size");
        } else if (sz == 6){
            CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_6bit(i),
                          "opnd_create_immed_int: value too large for 6-bit size");
        } else if (sz == 10){
            CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_10bit(i),
                          "opnd_create_immed_int: value too large for 10-bit size");
        } else if (sz == 12){
            CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_32bit(i),// 32 bits allowed in 12 bits
                          "opnd_create_immed_int: value too large for 12-bit size(allows 32 bits using shift)");
        } else if (sz == 24){
            CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_24bit(i),
                          "opnd_create_immed_int: value too large for 24-bit size");
        }
    });
    return opnd;
}

/* NOTE: requires caller to be under PRESERVE_FLOATING_POINT_STATE */
opnd_t
opnd_create_immed_float(float i)
{
    opnd_t opnd;
    opnd.kind = IMMED_FLOAT_kind;
    /* note that manipulating floats is dangerous - see case 4360 
     * even this copy can end up using fp load/store instrs and could
     * trigger a pending fp exception (i#386)
     */
    opnd.value.immed_float = i;
    /* currently only used for implicit constants that have no size */
    opnd.size = OPSZ_0;
    return opnd;
}

opnd_t
opnd_create_immed_float_zero(void)
{
    opnd_t opnd;
    opnd.kind = IMMED_FLOAT_kind;
    /* avoid any fp instrs (xref i#386) */
    memset(&opnd.value.immed_float, 0, sizeof(opnd.value.immed_float));
    /* currently only used for implicit constants that have no size */
    opnd.size = OPSZ_0;
    return opnd;
}

ptr_int_t
opnd_get_immed_int(opnd_t opnd)
{
    CLIENT_ASSERT(opnd_is_immed_int(opnd), "opnd_get_immed_int called on non-immed-int");
    return opnd.value.immed_int;
}

/* NOTE: requires caller to be under PRESERVE_FLOATING_POINT_STATE */
float
opnd_get_immed_float(opnd_t opnd)
{
    CLIENT_ASSERT(opnd_is_immed_float(opnd),
                  "opnd_get_immed_float called on non-immed-float");
    /* note that manipulating floats is dangerous - see case 4360 
     * this return shouldn't require any fp state, though
     */
    return opnd.value.immed_float;
}


/* address operands */

/* N.B.: seg_selector is a segment selector, not a SEG_ constant */
opnd_t
opnd_create_far_pc(ushort seg_selector, app_pc pc)
{
    opnd_t opnd;
    opnd.kind = FAR_PC_kind;
    opnd.seg.far_pc_seg_selector = seg_selector;
    opnd.value.pc = pc;
    return opnd;
}

opnd_t
opnd_create_instr(instr_t *instr)
{
    opnd_t opnd;
    opnd.kind = INSTR_kind;
    opnd.value.instr = instr;
    return opnd;
}

opnd_t
opnd_create_far_instr(ushort seg_selector, instr_t *instr)
{
    opnd_t opnd;
    opnd.kind = FAR_INSTR_kind;
    opnd.seg.far_pc_seg_selector = seg_selector;
    opnd.value.instr = instr;
    return opnd;
}

DR_API
opnd_t
opnd_create_mem_instr(instr_t *instr, short disp, opnd_size_t data_size)
{
    opnd_t opnd;
    opnd.kind = MEM_INSTR_kind;
    opnd.size = data_size;
    opnd.seg.disp = disp;
    opnd.value.instr = instr;
    return opnd;
}

app_pc
opnd_get_pc(opnd_t opnd)
{
    if (opnd_is_pc(opnd))
        return opnd.value.pc;
    else {
        SYSLOG_INTERNAL_ERROR("opnd type is %d", opnd.kind);
        CLIENT_ASSERT(false, "opnd_get_pc called on non-pc");
        return NULL;
    }
}

ushort
opnd_get_segment_selector(opnd_t opnd)
{
    if (opnd_is_far_pc(opnd) || opnd_is_far_instr(opnd)) {
        /* FIXME: segment selectors are 16-bit values */
        return opnd.seg.far_pc_seg_selector;
    }
    CLIENT_ASSERT(false, "opnd_get_segment_selector called on invalid opnd type");
    return REG_INVALID;
}

instr_t *
opnd_get_instr(opnd_t opnd)
{
    CLIENT_ASSERT(opnd_is_instr(opnd) || opnd_is_mem_instr(opnd),
                  "opnd_get_instr called on non-instr");
    return opnd.value.instr;
}

short 
opnd_get_mem_instr_disp(opnd_t opnd)
{
    CLIENT_ASSERT(opnd_is_mem_instr(opnd),
                  "opnd_get_mem_instr_disp called on non-mem-instr");
    return opnd.seg.disp;
}

/* Base+displacement+scaled index operands */

opnd_t
opnd_create_base_disp_ex(reg_id_t base_reg, reg_id_t index_reg, int scale, int disp,
                         opnd_size_t size, bool encode_zero_disp, bool force_full_disp,
                         bool disp_short_addr)
{
    return opnd_create_far_base_disp_ex(REG_NULL, base_reg, index_reg, scale, disp, size,
                                        encode_zero_disp, force_full_disp,
                                        disp_short_addr);
}

opnd_t
opnd_create_base_disp(reg_id_t base_reg, reg_id_t index_reg, int scale, int disp,
                      opnd_size_t size)
{
    return opnd_create_far_base_disp_ex(REG_NULL, base_reg, index_reg, scale, disp, size,
                                        false, false, false);
}

opnd_t
opnd_create_mem_reg(reg_id_t reg)
{
    opnd_t opnd;
    opnd.kind = MEM_REG_kind;
    CLIENT_ASSERT(reg <= REG_LAST_ENUM, "opnd_create_mem_reg: invalid reg");
    opnd.value.reg = reg;
    return opnd;
}


opnd_t
opnd_create_far_base_disp_ex(reg_id_t seg, reg_id_t base_reg, reg_id_t index_reg,
                             int scale, int disp, opnd_size_t size,
                             bool encode_zero_disp, bool force_full_disp,
                             bool disp_short_addr)
{
    opnd_t opnd;
    opnd.kind = BASE_DISP_kind;
    CLIENT_ASSERT(size < OPSZ_LAST_ENUM, "opnd_create_*base_disp*: invalid size");
    opnd.size = size;
    CLIENT_ASSERT(scale <= 8, "opnd_create_*base_disp*: invalid scale");
    CLIENT_ASSERT(index_reg == REG_NULL || scale > 0,
                  "opnd_create_*base_disp*: index requires scale");
    CLIENT_ASSERT(seg == REG_NULL ||
                  (seg >= REG_START_SEGMENT && seg <= REG_STOP_SEGMENT),
                  "opnd_create_*base_disp*: invalid segment");
    CLIENT_ASSERT(base_reg <= REG_LAST_ENUM, "opnd_create_*base_disp*: invalid base");
    CLIENT_ASSERT(index_reg <= REG_LAST_ENUM, "opnd_create_*base_disp*: invalid index");
    CLIENT_ASSERT_BITFIELD_TRUNCATE(SCALE_SPECIFIER_BITS, scale,
                                    "opnd_create_*base_disp*: invalid scale");
    opnd.seg.segment = seg;
    opnd.value.base_disp.base_reg = base_reg;
    opnd.value.base_disp.index_reg = index_reg;
    opnd.value.base_disp.scale = (byte) scale;
    opnd.value.base_disp.disp = disp;
    opnd.value.base_disp.encode_zero_disp = (byte) encode_zero_disp;
    opnd.value.base_disp.force_full_disp = (byte) force_full_disp;
    opnd.value.base_disp.disp_short_addr = (byte) disp_short_addr;
    return opnd;
}

opnd_t
opnd_create_far_base_disp(reg_id_t seg, reg_id_t base_reg, reg_id_t index_reg, int scale,
                          int disp, opnd_size_t size)
{
    return opnd_create_far_base_disp_ex(seg, base_reg, index_reg, scale, disp, size,
                                        false, false, false);
}

#undef opnd_get_base
#undef opnd_get_disp
#undef opnd_get_index
#undef opnd_get_scale
#undef opnd_get_segment
reg_id_t opnd_get_base   (opnd_t opnd) { return OPND_GET_BASE(opnd); }
int      opnd_get_disp   (opnd_t opnd) { return OPND_GET_DISP(opnd); }
reg_id_t opnd_get_index  (opnd_t opnd) { return OPND_GET_INDEX(opnd); }
int      opnd_get_scale  (opnd_t opnd) { return OPND_GET_SCALE(opnd); }
reg_id_t opnd_get_segment(opnd_t opnd) { return OPND_GET_SEGMENT(opnd); }
#define opnd_get_base  OPND_GET_BASE
#define opnd_get_disp  OPND_GET_DISP
#define opnd_get_index OPND_GET_INDEX
#define opnd_get_scale OPND_GET_SCALE
#define opnd_get_segment OPND_GET_SEGMENT

bool
opnd_is_disp_encode_zero(opnd_t opnd)
{
    if (opnd_is_base_disp(opnd))
        return opnd.value.base_disp.encode_zero_disp;
    CLIENT_ASSERT(false, "opnd_is_disp_encode_zero called on invalid opnd type");
    return false;
}

bool
opnd_is_disp_force_full(opnd_t opnd)
{
    if (opnd_is_base_disp(opnd))
        return opnd.value.base_disp.force_full_disp;
    CLIENT_ASSERT(false, "opnd_is_disp_force_full called on invalid opnd type");
    return false;
}

bool
opnd_is_disp_short_addr(opnd_t opnd)
{
    if (opnd_is_base_disp(opnd))
        return opnd.value.base_disp.disp_short_addr;
    CLIENT_ASSERT(false, "opnd_is_disp_short_addr called on invalid opnd type");
    return false;
}

void
opnd_set_disp(opnd_t *opnd, int disp)
{
    if (opnd_is_base_disp(*opnd))
        opnd->value.base_disp.disp = disp;
    else
        CLIENT_ASSERT(false, "opnd_set_disp called on invalid opnd type");
}

void
opnd_set_disp_ex(opnd_t *opnd, int disp, bool encode_zero_disp, bool force_full_disp,
                 bool disp_short_addr)
{
    if (opnd_is_base_disp(*opnd)) {
        opnd->value.base_disp.encode_zero_disp = (byte) encode_zero_disp;
        opnd->value.base_disp.force_full_disp = (byte) force_full_disp;
        opnd->value.base_disp.disp_short_addr = (byte) disp_short_addr;
        opnd->value.base_disp.disp = disp;
    } else
        CLIENT_ASSERT(false, "opnd_set_disp_ex called on invalid opnd type"); 
}

opnd_t 
opnd_create_abs_addr(void *addr, opnd_size_t data_size)
{
    return opnd_create_far_abs_addr(REG_NULL, addr, data_size);
}

opnd_t 
opnd_create_far_abs_addr(reg_id_t seg, void *addr, opnd_size_t data_size)
{
    /* PR 253327: For x64, there's no way to create 0xa0-0xa3 w/ addr
     * prefix since we'll make a base-disp instead: but our IR is
     * supposed to be at a higher abstraction level anyway, though w/
     * the sib byte the base-disp ends up being one byte longer.
     */
    bool need_addr32 = false;
    CLIENT_ASSERT(CHECK_TRUNCATE_TYPE_uint((ptr_uint_t)addr),
                  "internal error: abs addr too large");
    return opnd_create_far_base_disp_ex(seg, REG_NULL, REG_NULL, 0,
                                        (int)(ptr_int_t)addr, data_size,
                                        false, false, need_addr32);
}


opnd_t
opnd_create_mask(uint mask)
{
    opnd_t opnd;
    opnd.kind = MASK_kind;
    opnd.value.mask = mask;
    return opnd;
}

void *
opnd_get_addr(opnd_t opnd)
{
    /* check base-disp first since opnd_is_abs_addr() says yes for it */
    if (opnd_is_abs_base_disp(opnd))
        return (void *)(ptr_uint_t) opnd_get_disp(opnd);
#ifdef X64
    if (opnd_is_rel_addr(opnd) || opnd_is_abs_addr(opnd))
        return opnd.value.addr;
#endif
    CLIENT_ASSERT(false, "opnd_get_addr called on invalid opnd type");
    return NULL;
}

bool
opnd_is_memory_reference(opnd_t opnd)
{
    return (opnd_is_base_disp(opnd)
            IF_X64(|| opnd_is_abs_addr(opnd) || opnd_is_rel_addr(opnd)) ||
            opnd_is_mem_instr(opnd));
}

bool
opnd_is_far_memory_reference(opnd_t opnd)
{
    return (opnd_is_far_base_disp(opnd)
            IF_X64(|| opnd_is_far_abs_addr(opnd) || opnd_is_far_rel_addr(opnd)));
}

bool
opnd_is_near_memory_reference(opnd_t opnd)
{
    return (opnd_is_near_base_disp(opnd)
            IF_X64(|| opnd_is_near_abs_addr(opnd) || opnd_is_near_rel_addr(opnd)) ||
            opnd_is_mem_instr(opnd));
}

int
opnd_num_regs_used(opnd_t opnd)
{
    switch (opnd.kind) {
    case NULL_kind:
    case IMMED_INTEGER_kind:
    case IMMED_FLOAT_kind:
    case PC_kind:
    case FAR_PC_kind:
    case INSTR_kind:
    case FAR_INSTR_kind:
    case MEM_INSTR_kind:
        return 0;

    case REG_kind: 
        return 1;

    case BASE_DISP_kind: 
        return (((opnd_get_base(opnd)==REG_NULL) ? 0 : 1) + 
                ((opnd_get_index(opnd)==REG_NULL) ? 0 : 1) +
                ((opnd_get_segment(opnd)==REG_NULL) ? 0 : 1));

#ifdef X64
    case REL_ADDR_kind: 
    case ABS_ADDR_kind: 
        return ((opnd_get_segment(opnd) == REG_NULL) ? 0 : 1);
#endif
    default: 
        CLIENT_ASSERT(false, "opnd_num_regs_used called on invalid opnd type"); 
        return 0;
    }    
}

reg_id_t
opnd_get_reg_used(opnd_t opnd, int index)
{
    switch (opnd.kind) {
    case NULL_kind:
    case IMMED_INTEGER_kind:
    case IMMED_FLOAT_kind:
    case PC_kind:
    case FAR_PC_kind:
    case MEM_INSTR_kind:
        CLIENT_ASSERT(false, "opnd_get_reg_used called on invalid opnd type");
        return REG_NULL;

    case REG_kind: 
        if (index == 0)
            return opnd_get_reg(opnd);
        else {
            CLIENT_ASSERT(false, "opnd_get_reg_used called on invalid opnd type");
            return REG_NULL;
        }

    case BASE_DISP_kind: 
        if (index == 0) {
            if (opnd_get_base(opnd) != REG_NULL)
                return opnd_get_base(opnd);
            else if (opnd_get_index(opnd) != REG_NULL)
                return opnd_get_index(opnd);
            else
                return opnd_get_segment(opnd);
        } else if (index == 1) {
            if (opnd_get_index(opnd) != REG_NULL)
                return opnd_get_index(opnd);
            else
                return opnd_get_segment(opnd);
        } else if (index == 2)
            return opnd_get_segment(opnd);
        else {
            CLIENT_ASSERT(false, "opnd_get_reg_used called on invalid opnd type"); 
            return REG_NULL;
        }

#ifdef X64
    case REL_ADDR_kind: 
    case ABS_ADDR_kind: 
        if (index == 0)
            return opnd_get_segment(opnd);
        else {
            /* We only assert if beyond the number possible: not if beyond the
             * number present.  Should we assert on the latter?
             */
            CLIENT_ASSERT(false, "opnd_get_reg_used called on invalid opnd type"); 
            return REG_NULL;
        }
#endif

    default: 
        CLIENT_ASSERT(false, "opnd_get_reg_used called on invalid opnd type"); 
        return REG_NULL;
    }    
}

/***************************************************************************/
/* utility routines */

const reg_id_t regparms[] = {
#ifdef X64
    REGPARM_0, REGPARM_1, REGPARM_2, REGPARM_3, 
# ifdef LINUX
    REGPARM_4, REGPARM_5,
# endif
#endif
    REG_INVALID
};

/* Maps sub-registers to their containing register. */
const reg_id_t dr_reg_fixer[]={
    REG_NULL,
    REG_RR0,         REG_RR1,     REG_RR2,     REG_RR3,
    REG_RR4,         REG_RR5,     REG_RR6,     REG_RR7,
    REG_RR8,         REG_RR9,     REG_RR10,    REG_RR11,
    REG_RR12,        REG_RR13,    REG_RR14,    REG_RR15,
    REG_Q0,          REG_Q1,      REG_Q2,      REG_Q3,
    REG_Q4,          REG_Q5,      REG_Q6,      REG_Q7,
    REG_Q8,          REG_Q9,      REG_Q10,     REG_Q11,
    REG_Q12,         REG_Q13,     REG_Q14,     REG_Q15,
    REG_D0,          REG_D1,      REG_D2,      REG_D3,
    REG_D4,          REG_D5,      REG_D6,      REG_D7,
    REG_D8,          REG_D9,      REG_D10,     REG_D11,
    REG_D12,         REG_D13,     REG_D14,     REG_D15,
    REG_D16,         REG_D17,     REG_D18,     REG_D19,
    REG_D20,         REG_D21,     REG_D22,     REG_D23,
    REG_D24,         REG_D25,     REG_D26,     REG_D27,
    REG_D28,         REG_D29,     REG_D30,     REG_D31,
    REG_S0,          REG_S1,      REG_S2,      REG_S3,
    REG_S4,          REG_S5,      REG_S6,      REG_S7,
    REG_S8,          REG_S9,      REG_S10,     REG_S11,
    REG_S12,         REG_S13,     REG_S14,     REG_S15,
    REG_S16,         REG_S17,     REG_S18,     REG_S19,
    REG_S20,         REG_S21,     REG_S22,     REG_S23,
    REG_S24,         REG_S25,     REG_S26,     REG_S27,
    REG_S28,         REG_S29,     REG_S30,     REG_S31,
    SEG_ES,   SEG_CS,   SEG_SS,   SEG_DS,   SEG_FS,   SEG_GS,
    REG_DEBUG1,  REG_DEBUG2,
    REG_CONTROL1,  REG_CONTROL2,
    REG_INVALID,
};

#ifdef DEBUG
void
reg_check_reg_fixer(void)
{
    /* ignore REG_INVALID, so should equal REG_LAST_ENUM */
    CLIENT_ASSERT(sizeof(dr_reg_fixer)/sizeof(dr_reg_fixer[0]) == REG_LAST_ENUM,
                  "internal register enum error");
}
#endif

/* 
   opnd_uses_reg is now changed so that it does consider 8/16 bit
   register overlaps.  i think this change is OK and correct, but not
   sure.  as far as I'm aware, only my optimization stuff and the
   register stealing code (which is now not used, right?) relies on
   this code ==> but we now export it via CI API */

bool 
opnd_uses_reg(opnd_t opnd, reg_id_t reg)
{
    if (reg == REG_NULL)
        return false;
    switch (opnd.kind) {
    case NULL_kind:
    case IMMED_INTEGER_kind:
    case IMMED_FLOAT_kind:
    case PC_kind:
    case FAR_PC_kind:
    case INSTR_kind:
    case FAR_INSTR_kind:
    case MEM_INSTR_kind:
        return false;

    case REG_kind: 
        return (dr_reg_fixer[reg] == dr_reg_fixer[opnd_get_reg(opnd)]);

    case BASE_DISP_kind: 
        return (dr_reg_fixer[reg] == dr_reg_fixer[opnd_get_base(opnd)] || 
                dr_reg_fixer[reg] == dr_reg_fixer[opnd_get_index(opnd)] ||
                dr_reg_fixer[reg] == dr_reg_fixer[opnd_get_segment(opnd)]);

#ifdef X64
    case REL_ADDR_kind:
    case ABS_ADDR_kind:
        return (dr_reg_fixer[reg] == dr_reg_fixer[opnd_get_segment(opnd)]);
#endif

    default: 
        CLIENT_ASSERT(false, "opnd_uses_reg: unknown opnd type"); 
        return false;
    }    
}

bool 
opnd_replace_reg(opnd_t *opnd, reg_id_t old_reg, reg_id_t new_reg)
{
    switch (opnd->kind) {
    case NULL_kind:
    case IMMED_INTEGER_kind:
    case IMMED_FLOAT_kind:
    case PC_kind:
    case FAR_PC_kind:
    case INSTR_kind:
    case FAR_INSTR_kind:
    case MEM_INSTR_kind:
        return false;

    case REG_kind: 
        if (old_reg == opnd_get_reg(*opnd)) {
            *opnd = opnd_create_reg(new_reg);
            return true;
        }
        return false;
                
    case BASE_DISP_kind:
        {
            reg_id_t ob = opnd_get_base(*opnd);
            reg_id_t oi = opnd_get_index(*opnd);
            reg_id_t os = opnd_get_segment(*opnd);
            opnd_size_t size = opnd_get_size(*opnd);
            if (old_reg == ob || old_reg == oi || old_reg == os) {
                reg_id_t b = (old_reg == ob) ? new_reg : ob;
                reg_id_t i = (old_reg == oi) ? new_reg : oi;
                reg_id_t s = (old_reg == os) ? new_reg : os;
                int sc = opnd_get_scale(*opnd);
                int d = opnd_get_disp(*opnd);
                *opnd = opnd_create_far_base_disp_ex(s, b, i, sc, d, size,
                                                     opnd_is_disp_encode_zero(*opnd),
                                                     opnd_is_disp_force_full(*opnd),
                                                     opnd_is_disp_short_addr(*opnd));
                return true;
            }
        }
        return false;

#ifdef X64
    case REL_ADDR_kind:
        if (old_reg == opnd_get_segment(*opnd)) {
            *opnd = opnd_create_far_rel_addr(new_reg, opnd_get_addr(*opnd),
                                             opnd_get_size(*opnd));
            return true;
        }
        return false;

    case ABS_ADDR_kind:
        if (old_reg == opnd_get_segment(*opnd)) {
            *opnd = opnd_create_far_abs_addr(new_reg, opnd_get_addr(*opnd),
                                             opnd_get_size(*opnd));
            return true;
        }
        return false;
#endif
                
    default: 
        CLIENT_ASSERT(false, "opnd_replace_reg: invalid opnd type"); 
        return false;
    }    
}

/* this is not conservative -- only considers two memory references to
 * be the same if their constituent components (registers, displacement)
 * are the same.
 * different from opnd_same b/c this routine ignores data size!
 */
bool opnd_same_address(opnd_t op1, opnd_t op2)
{
    if (op1.kind != op2.kind)
        return false;
    if (!opnd_is_memory_reference(op1) || !opnd_is_memory_reference(op2))
    if (opnd_get_segment(op1) != opnd_get_segment(op2))
        return false;
    if (opnd_is_base_disp(op1)) {
        if (!opnd_is_base_disp(op2))
            return false;
        if (opnd_get_base(op1) != opnd_get_base(op2))
            return false;
        if (opnd_get_index(op1) != opnd_get_index(op2))
            return false;
        if (opnd_get_scale(op1) != opnd_get_scale(op2))
            return false;
        if (opnd_get_disp(op1) != opnd_get_disp(op2))
            return false;
    } else {
#ifdef X64        
        CLIENT_ASSERT(opnd_is_abs_addr(op1) || opnd_is_rel_addr(op1),
                      "internal type error in opnd_same_address");
        if (opnd_get_addr(op1) != opnd_get_addr(op2))
            return false;
#else
        CLIENT_ASSERT(false, "internal type error in opnd_same_address");
#endif
    }

    /* we ignore size */

    return true;
}

static bool
opnd_same_sizes_ok(opnd_size_t s1, opnd_size_t s2, bool is_reg)
{
    opnd_size_t s1_default, s2_default;
    decode_info_t di;
    if (s1 == s2)
        return true;
    /* This routine is used for variable sizes in INSTR_CREATE macros so we
     * check whether the default size matches.  If we need to do more
     * then we'll have to hook into encode's size resolution to resolve all
     * operands with each other's constraints at the instr level before coming here.
     */
    s1_default = resolve_variable_size(&di, s1, is_reg);
    s2_default = resolve_variable_size(&di, s2, is_reg);
    return (s1_default == s2_default);
}

bool opnd_same(opnd_t op1, opnd_t op2)
{
    if (op1.kind!=op2.kind)
        return false;
    else if (!opnd_same_sizes_ok(op1.size, op2.size, opnd_is_reg(op1)) &&
             (opnd_is_immed_int(op1) ||
              opnd_is_memory_reference(op1)))
        return false;
    /* If we could rely on unused bits being 0 could avoid dispatch on type.
     * Presumably not on critical path, though, so not bothering to try and
     * asssert that those bits are 0.
     */
    switch (op1.kind) {
    case NULL_kind:
        return true;
    case IMMED_INTEGER_kind:
        return op1.value.immed_int == op2.value.immed_int;
    case IMMED_FLOAT_kind:
        /* HACK to avoid generating floating point instrs:
         * we assume a float is 32 bit just like an int
         */
        return op1.value.immed_int == op2.value.immed_int;
    case PC_kind:
        return op1.value.pc == op2.value.pc;
    case FAR_PC_kind:
        return (op1.seg.far_pc_seg_selector == op2.seg.far_pc_seg_selector && 
                op1.value.pc == op2.value.pc);
    case INSTR_kind:
    case FAR_INSTR_kind:
        return op1.value.instr == op2.value.instr;
    case REG_kind: 
        return op1.value.reg == op2.value.reg;
    case BASE_DISP_kind:
        return (op1.seg.segment == op2.seg.segment && 
                op1.value.base_disp.base_reg == op2.value.base_disp.base_reg &&
                op1.value.base_disp.index_reg == op2.value.base_disp.index_reg &&
                op1.value.base_disp.scale == op2.value.base_disp.scale &&
                op1.value.base_disp.disp == op2.value.base_disp.disp &&
                op1.value.base_disp.encode_zero_disp ==
                op2.value.base_disp.encode_zero_disp &&
                op1.value.base_disp.force_full_disp ==
                op2.value.base_disp.force_full_disp &&
                /* disp_short_addr only matters if no registers are set */
                (((op1.value.base_disp.base_reg != REG_NULL ||
                   op1.value.base_disp.index_reg != REG_NULL) &&
                  (op2.value.base_disp.base_reg != REG_NULL ||
                   op2.value.base_disp.index_reg != REG_NULL)) ||
                 op1.value.base_disp.disp_short_addr ==
                 op2.value.base_disp.disp_short_addr));
#ifdef X64
    case REL_ADDR_kind:
    case ABS_ADDR_kind:
        return (op1.seg.segment == op2.seg.segment && 
                op1.value.addr == op2.value.addr);
#endif
    case MEM_INSTR_kind:
        return (op1.value.instr == op2.value.instr &&
                op1.seg.disp == op2.seg.disp);
    default: 
        CLIENT_ASSERT(false, "opnd_same: invalid opnd type"); 
        return false;
    }    
}

bool opnd_share_reg(opnd_t op1, opnd_t op2)
{
    switch (op1.kind) {
    case NULL_kind:
    case IMMED_INTEGER_kind:
    case IMMED_FLOAT_kind:
    case PC_kind:
    case FAR_PC_kind:
    case INSTR_kind:
    case FAR_INSTR_kind:
    case MEM_INSTR_kind:
        return false;
    case REG_kind: 
        return opnd_uses_reg(op2, opnd_get_reg(op1));
    case BASE_DISP_kind:
        return (opnd_uses_reg(op2, opnd_get_base(op1)) ||
                opnd_uses_reg(op2, opnd_get_index(op1)) ||
                opnd_uses_reg(op2, opnd_get_segment(op1)));
#ifdef X64
    case REL_ADDR_kind:
    case ABS_ADDR_kind:
        return (opnd_uses_reg(op2, opnd_get_segment(op1)));
#endif
    default: 
        CLIENT_ASSERT(false, "opnd_share_reg: invalid opnd type"); 
        return false;
    }    
}

static bool
range_overlap(ptr_uint_t a1, ptr_uint_t a2, size_t s1, size_t s2)
{
    ptr_uint_t min, max;
    size_t min_plus;
    if (a1 < a2) {
        min = a1;
        min_plus = s1;
        max = a2;
    } else {
        min = a2;
        min_plus = s2;
        max = a1;
    }
    return (min + min_plus > max); /* open-ended */
}

/* Returns true if def, considered as a write, affects use.
 * Is conservative, so if both def and use are memory references,
 * will return true unless it can disambiguate them.
 */
bool opnd_defines_use(opnd_t def, opnd_t use)
{
    switch (def.kind) {
    case NULL_kind:
    case IMMED_INTEGER_kind:
    case IMMED_FLOAT_kind:
    case PC_kind:
    case FAR_PC_kind:
    case INSTR_kind:
    case FAR_INSTR_kind:
        return false;
    case REG_kind: 
        return opnd_uses_reg(use, opnd_get_reg(def));
    case BASE_DISP_kind:
        if (!opnd_is_memory_reference(use))
            return false;
#ifdef X64
        if (!opnd_is_base_disp(use))
            return true;
#endif
        /* try to disambiguate the two memory references 
         * for now, only consider identical regs and different disp
         */
        if (opnd_get_base(def) != opnd_get_base(use))
            return true;
        if (opnd_get_index(def) != opnd_get_index(use))
            return true;
        if (opnd_get_scale(def) != opnd_get_scale(use))
            return true;
        if (opnd_get_segment(def) != opnd_get_segment(use))
            return true;
        /* everything is identical, now make sure disps don't overlap */
        return range_overlap(opnd_get_disp(def), opnd_get_disp(use),
                             opnd_size_in_bytes(opnd_get_size(def)),
                             opnd_size_in_bytes(opnd_get_size(use)));
#ifdef X64
    case REL_ADDR_kind:
    case ABS_ADDR_kind:
        if (!opnd_is_memory_reference(use))
            return false;
        if (opnd_is_base_disp(use))
            return true;
        if (opnd_get_segment(def) != opnd_get_segment(use))
            return true;
        return range_overlap((ptr_uint_t)opnd_get_addr(def),
                             (ptr_uint_t)opnd_get_addr(use),
                             opnd_size_in_bytes(opnd_get_size(def)),
                             opnd_size_in_bytes(opnd_get_size(use)));
#endif
    case MEM_INSTR_kind:
        if (!opnd_is_memory_reference(use))
            return false;
        /* we don't know our address so we have to assume true */
        return true;
    default: 
        CLIENT_ASSERT(false, "opnd_defines_use: invalid opnd type"); 
        return false;
    }    
}

uint
opnd_size_in_bytes(opnd_size_t size)
{
    /* allow some REG_ constants, convert them to OPSZ_ constants */
    if (size < OPSZ_FIRST)
        size = reg_get_size(size);
    switch (size) {
    case OPSZ_0:
        return 0;
    case OPSZ_1:
        return 1;
    case OPSZ_2:
        return 2;
    case OPSZ_4:
        return 4;
    case OPSZ_16:
        return 16;
    case OPSZ_10:
        return 10;
    case OPSZ_14:
        return 14;
    case OPSZ_28:
        return 28;
    case OPSZ_32:
        return 32;
    case OPSZ_40:
        return 40;
    case OPSZ_94:
        return 94;
    case OPSZ_108:
        return 108;
    case OPSZ_512:
        return 512;
    case OPSZ_4_2:
    case OPSZ_4_3:
    case OPSZ_4_4:
    case OPSZ_4_5:
    case OPSZ_4_6:
    case OPSZ_4_8:
        return 1;
    case OPSZ_4_10:
    case OPSZ_4_12:
    case OPSZ_4_16:
        return 2;
    case OPSZ_4_24:
        return 3;
    default:
        CLIENT_ASSERT(false, "opnd_size_in_bytes: invalid opnd type");
        return 0;
    }
}

uint
opnd_size_in_bits(opnd_size_t size)
{
    /* allow some REG_ constants, convert them to OPSZ_ constants */
    if (size < OPSZ_FIRST)
        size = reg_get_size(size);
    switch (size) {
    case OPSZ_0:
        return 0;
    case OPSZ_1:
        return 8;
    case OPSZ_2:
        return 16;
    case OPSZ_4:
        return 32;
    case OPSZ_16:
        return 128;
    case OPSZ_10:
        return 80;
    case OPSZ_14:
        return 112;
    case OPSZ_28:
        return 224;
    case OPSZ_32:
        return 256;
    case OPSZ_40:
        return 320;
    case OPSZ_94:
        return 752;
    case OPSZ_108:
        return 864;
    case OPSZ_512:
        return 4096;
    case OPSZ_4_3:
        return 3;
    case OPSZ_4_4:
        return 4;
    case OPSZ_4_5:
        return 5;
    case OPSZ_4_6:
        return 6;
    case OPSZ_4_8:
        return 8;
    case OPSZ_4_10:
        return 10;
    case OPSZ_4_12:
        return 12;
    case OPSZ_4_16:
        return 16;
    case OPSZ_4_24:
        return 24;

    default:
        CLIENT_ASSERT(false, "opnd_size_in_bits: invalid opnd type");
        return 0;
    }
}

DR_API
opnd_size_t
opnd_size_from_bytes(uint bytes)
{
    switch (bytes) {
    case 0: return OPSZ_0;
    case 1: return OPSZ_1;
    case 2: return OPSZ_2;
    case 4: return OPSZ_4;
    case 10: return OPSZ_10;
    case 16: return OPSZ_16;
    case 14: return OPSZ_14;
    case 28: return OPSZ_28;
    case 94: return OPSZ_94;
    case 108: return OPSZ_108;
    case 512: return OPSZ_512;
    default: return OPSZ_NA;
    }
}

/* shrinks all 32-bit registers in opnd to 16 bits.  also shrinks the size of
 * immed ints and mem refs from OPSZ_4 to OPSZ_2.
 */
opnd_t
opnd_shrink_to_16_bits(opnd_t opnd)
{
    int i;
    for (i=0; i<opnd_num_regs_used(opnd); i++) {
        reg_id_t reg = opnd_get_reg_used(opnd, i);
        if (reg >= REG_START_32 && reg <= REG_STOP_32) {
            opnd_replace_reg(&opnd, reg, reg_32_to_16(reg));
        }
    }
    if ((opnd_is_immed_int(opnd) || opnd_is_memory_reference(opnd)) &&
        opnd_get_size(opnd) == OPSZ_4) /* OPSZ_*_short2 will shrink at encode time */
        opnd_set_size(&opnd, OPSZ_2);
    return opnd;
}

#ifdef X64
/* shrinks all 64-bit registers in opnd to 32 bits.  also shrinks the size of
 * immed ints and mem refs from OPSZ_8 to OPSZ_4.
 */
opnd_t
opnd_shrink_to_32_bits(opnd_t opnd)
{
    int i;
    for (i=0; i<opnd_num_regs_used(opnd); i++) {
        reg_id_t reg = opnd_get_reg_used(opnd, i);
        if (reg >= REG_START_64 && reg <= REG_STOP_64) {
            opnd_replace_reg(&opnd, reg, reg_64_to_32(reg));
        }
    }
    if ((opnd_is_immed_int(opnd) || opnd_is_memory_reference(opnd)) &&
        opnd_get_size(opnd) == OPSZ_8)
        opnd_set_size(&opnd, OPSZ_4);
    return opnd;
}

#endif

static reg_t
reg_get_value_helper(reg_id_t reg, priv_mcontext_t *mc)
{
    CLIENT_ASSERT(reg_is_pointer_sized(reg),
                  "reg_get_value_helper(): internal error non-ptr sized reg");
    if (reg == REG_NULL)
        return 0;

    return *(reg_t *)((byte *)mc + opnd_get_reg_mcontext_offs(reg));
}

/* Returns the value of the register reg, selected from the passed-in
 * register values.
 */
reg_t
reg_get_value_priv(reg_id_t reg, priv_mcontext_t *mc)
{
    if (reg == REG_NULL)
        return 0;
#ifdef X64
    if (reg >= REG_START_64 && reg <= REG_STOP_64)
        return reg_get_value_helper(reg, mc);
    if (reg >= REG_START_32 && reg <= REG_STOP_32) {
        reg_t val = reg_get_value_helper(dr_reg_fixer[reg], mc);
        return (val & 0x00000000ffffffff);
    }
#else
    if (reg >= REG_START_32 && reg <= REG_STOP_32) {
        return reg_get_value_helper(reg, mc);
    }
#endif

#ifdef NO
/* TODO SJF Removed 8 bit regs */
    if (reg >= REG_START_8 && reg <= REG_STOP_8) {
        reg_t val = reg_get_value_helper(dr_reg_fixer[reg], mc);
        if (reg >= REG_AH && reg <= REG_BH)
            return ((val & 0x0000ff00) >> 8);
        else /* all others are the lower 8 bits */
            return (val & 0x000000ff);
    }
#endif

    if (reg >= REG_START_16 && reg <= REG_STOP_16) {
        reg_t val = reg_get_value_helper(dr_reg_fixer[reg], mc);
        return (val & 0x0000ffff);
    }
    /* mmx, xmm, and segment cannot be part of address 
     * if want to use this routine for more than just effective address
     * calculations, need to pass in mmx/xmm state, or need to grab it
     * here.  would then need to check dr_mcontext_t.size.
     */
    CLIENT_ASSERT(false, "reg_get_value: unsupported register");
    return 0;
}

DR_API
reg_t
reg_get_value(reg_id_t reg, dr_mcontext_t *mc)
{
    /* only supports GPRs so we ignore mc.size */
    return reg_get_value_priv(reg, dr_mcontext_as_priv_mcontext(mc));
}

/* Sets the register reg in the passed in mcontext to value.  Currently only works
 * with ptr sized registers. FIXME - handle other sized registers. */
void
reg_set_value_priv(reg_id_t reg, priv_mcontext_t *mc, reg_t value)
{
    CLIENT_ASSERT(reg_is_pointer_sized(reg),
                  "reg_get_value_helper(): internal error non-ptr sized reg");

    if (reg == REG_NULL)
        return;

    *(reg_t *)((byte *)mc + opnd_get_reg_mcontext_offs(reg)) = value;
}

DR_API
void
reg_set_value(reg_id_t reg, dr_mcontext_t *mc, reg_t value)
{
    /* only supports GPRs so we ignore mc.size */
    reg_set_value_priv(reg, dr_mcontext_as_priv_mcontext(mc), value);
}

/* Returns the effective address of opnd, computed using the passed-in
 * register values.  If opnd is a far address, ignores that aspect
 * except for TLS references on Windows (fs: for 32-bit, gs: for 64-bit)
 * or typical fs: or gs: references on Linux.  For far addresses the
 * calling thread's segment selector is used.
 */
app_pc
opnd_compute_address_priv(opnd_t opnd, priv_mcontext_t *mc)
{
    reg_id_t base, index;
    int scale, disp;
    ptr_uint_t seg_base = 0;
    ptr_uint_t addr = 0;
    CLIENT_ASSERT(opnd_is_memory_reference(opnd),
                  "opnd_compute_address: must pass memory reference");
    if (opnd_is_far_base_disp(opnd)) {
#ifdef X86
# ifdef STANDALONE_DECODER
        seg_base = 0; /* not supported */
# else
        seg_base = (ptr_uint_t) get_app_segment_base(opnd_get_segment(opnd));
        if (seg_base == POINTER_MAX) /* failure */
            seg_base = 0;
# endif
#endif
    }
#ifdef X64
    if (opnd_is_abs_addr(opnd) || opnd_is_rel_addr(opnd)) {
        return (app_pc) opnd_get_addr(opnd) + seg_base;
    }
#endif
    addr = seg_base;
    base = opnd_get_base(opnd);
    index = opnd_get_index(opnd);
    scale = opnd_get_scale(opnd);
    disp = opnd_get_disp(opnd);
    logopnd(get_thread_private_dcontext(), 4, opnd, "opnd_compute_address for");
    addr += reg_get_value_priv(base, mc);
    LOG(THREAD_GET, LOG_ALL, 4, "\tbase => "PFX"\n", addr);
    addr += scale * reg_get_value_priv(index, mc);
    LOG(THREAD_GET, LOG_ALL, 4, "\tindex,scale => "PFX"\n", addr);
    /* FIXME PR 332730: should disp with no base or index be unsigned
     * (only matters for x64 or seg_base != 0)?  Certainly not allowed
     * to subtract from non-zero seg_base but not clear whether it
     * wraps or what.
     */
    addr += disp;
    LOG(THREAD_GET, LOG_ALL, 4, "\tdisp => "PFX"\n", addr);
    return (app_pc) addr;
}

DR_API
app_pc
opnd_compute_address(opnd_t opnd, dr_mcontext_t *mc)
{
    /* only uses GPRs so we ignore mc.size */
    return opnd_compute_address_priv(opnd, dr_mcontext_as_priv_mcontext(mc));
}

/***************************************************************************
 ***      Register utility functions
 ***************************************************************************/

const char *
get_register_name(reg_id_t reg)
{
    return reg_names[reg];
}

reg_id_t
reg_to_pointer_sized(reg_id_t reg)
{
    return dr_reg_fixer[reg];
}

reg_id_t
reg_32_to_16(reg_id_t reg)
{
    CLIENT_ASSERT(reg >= REG_START_32 && reg <= REG_STOP_32,
                  "reg_32_to_16: passed non-32-bit reg");
    return (reg - REG_START_32) + REG_START_16;
}

/* No 8 bit registers any more TODO SJF */
#ifdef NO
reg_id_t
reg_32_to_8(reg_id_t reg)
{
    reg_id_t r8;
    CLIENT_ASSERT(reg >= REG_START_32 && reg <= REG_STOP_32,
                  "reg_32_to_16: passed non-32-bit reg");
    r8 = (reg - REG_START_32) + REG_START_8;
    if (r8 >= REG_START_x86_8 && r8 <= REG_STOP_x86_8) {
#ifdef X64
        r8 += (REG_START_x64_8 - REG_START_x86_8);
#else
        r8 = REG_NULL;
#endif
    }
    return r8;
}
#endif

#ifdef X64
reg_id_t
reg_32_to_64(reg_id_t reg)
{
    CLIENT_ASSERT(reg >= REG_START_32 && reg <= REG_STOP_32,
                  "reg_32_to_64: passed non-32-bit reg");
    return (reg - REG_START_32) + REG_START_64;
}

reg_id_t
reg_64_to_32(reg_id_t reg)
{
    CLIENT_ASSERT(reg >= REG_START_64 && reg <= REG_STOP_64,
                  "reg_64_to_32: passed non-64-bit reg");
    return (reg - REG_START_64) + REG_START_32;
}

bool
reg_is_extended(reg_id_t reg)
{
    /* Note that we do consider spl, bpl, sil, and dil to be "extended" */
    return ((reg >= REG_START_64+8  && reg <= REG_STOP_64) ||
            (reg >= REG_START_32+8  && reg <= REG_STOP_32) ||
            (reg >= REG_START_16+8  && reg <= REG_STOP_16) ||
            (reg >= REG_START_8+8   && reg <= REG_STOP_8) ||
            (reg >= REG_START_x64_8 && reg <= REG_STOP_x64_8) ||
            (reg >= REG_START_XMM+8 && reg <= REG_STOP_XMM) ||
            (reg >= REG_START_YMM+8 && reg <= REG_STOP_YMM) ||
            (reg >= REG_START_DR+8  && reg <= REG_STOP_DR) ||
            (reg >= REG_START_CR+8  && reg <= REG_STOP_CR));
}
#endif

reg_id_t
reg_32_to_opsz(reg_id_t reg, opnd_size_t sz)
{
    CLIENT_ASSERT(reg >= REG_START_32 && reg <= REG_STOP_32,
                  "reg_32_to_opsz: passed non-32-bit reg");
    if (sz == OPSZ_4)
        return reg;
    else if (sz == OPSZ_2)
        return reg_32_to_16(reg);
#ifdef NO
    else if (sz == OPSZ_1)
        return reg_32_to_8(reg);
#endif //NO
#ifdef X64
    else if (sz == OPSZ_8)
        return reg_32_to_64(reg);
#endif
    else
        CLIENT_ASSERT(false, "reg_32_to_opsz: invalid size parameter");
    return reg;
}

reg_id_t
reg_resize_to_opsz(reg_id_t reg, opnd_size_t sz)
{
    CLIENT_ASSERT(reg_is_gpr(reg), "reg_resize_to_opsz: passed non GPR reg");
    reg = reg_to_pointer_sized(reg);
    return reg_32_to_opsz(IF_X64_ELSE(reg_64_to_32(reg), reg), sz);
}

int
reg_parameter_num(reg_id_t reg)
{
    int r;
    for (r = 0; r < NUM_REGPARM; r++) {
        if (reg == regparms[r])
            return r;
    }
    return -1;
}

int
opnd_get_reg_dcontext_offs(reg_id_t reg)
{
    switch (reg) {

    case REG_RR0:  return  R0_OFFSET;
    case REG_RR1:  return  R1_OFFSET;
    case REG_RR2:  return  R2_OFFSET;
    case REG_RR3:  return  R3_OFFSET;
    case REG_RR4:  return  R4_OFFSET;
    case REG_RR5:  return  R5_OFFSET;
    case REG_RR6:  return  R6_OFFSET;
    case REG_RR7:  return  R7_OFFSET;
    case REG_RR8:  return  R8_OFFSET;
    case REG_RR9:  return  R9_OFFSET;
    case REG_RR10: return R10_OFFSET;
    case REG_RR11: return R11_OFFSET;
    case REG_RR12: return R12_OFFSET;
    case REG_RR13: return R13_OFFSET;
    case REG_RR14: return R14_OFFSET;
    case REG_RR15: return R15_OFFSET;
    default: CLIENT_ASSERT(false, "opnd_get_reg_dcontext_offs: invalid reg");
        return -1;
    }
}

int
opnd_get_reg_mcontext_offs(reg_id_t reg)
{
    return opnd_get_reg_dcontext_offs(reg) - MC_OFFS;
}

bool
reg_overlap(reg_id_t r1, reg_id_t r2)
{
    if (r1 == REG_NULL || r2 == REG_NULL)
        return false;
    
    //We shouldnt have any overlaps here as I removed all
    //short regs. Can address short versions of regs in
    //ARM but Ive not directly implemented it. They
    //will show as normal size regs

    return (dr_reg_fixer[r1] == dr_reg_fixer[r2]);
}

/* returns the register's representation as 3 bits in a modrm byte,
 * callers do not expect it to fail 
 */
enum {REG_INVALID_BITS = 0x0}; /* returns a valid register nevertheless */
byte
reg_get_bits(reg_id_t reg)
{
#ifdef X64
    if (reg >= REG_START_64 && reg <= REG_STOP_64)
        return (byte) ((reg - REG_START_64) % 8);
#endif
    if (reg >= REG_START_32 && reg <= REG_STOP_32)
        return (byte) ((reg - REG_START_32) % 8);
/* TODO SJF
    if (reg >= REG_START_8 && reg <= REG_RRR15L)
        return (byte) ((reg - REG_START_8) % 8);
*/
#ifdef X64
    if (reg >= REG_START_x64_8 && reg <= REG_STOP_x64_8) /* alternates to AH-BH */
        return (byte) ((reg - REG_START_x64_8 + 4) % 8);
#endif
    if (reg >= REG_START_16 && reg <= REG_STOP_16)
        return (byte) ((reg - REG_START_16) % 8);
    if (reg >= REG_START_QWR && reg <= REG_STOP_QWR)
        return (byte) ((reg - REG_START_QWR) % 8);
    if (reg >= REG_START_DWR && reg <= REG_STOP_DWR)
        return (byte) ((reg - REG_START_DWR) % 8);
    if (reg >= REG_START_SWR && reg <= REG_STOP_SWR)
        return (byte) ((reg - REG_START_SWR) % 8);
/* TODO SJF Do we have segments 
    if (reg >= REG_START_SEGMENT && reg <= REG_STOP_SEGMENT)
        return (byte) ((reg - REG_START_SEGMENT) % 8);
*/
    if (reg >= REG_START_DR && reg <= REG_STOP_DR)
        return (byte) ((reg - REG_START_DR) % 8);
    if (reg >= REG_START_CR && reg <= REG_STOP_CR)
        return (byte) ((reg - REG_START_CR) % 8);
    CLIENT_ASSERT(false, "reg_get_bits: invalid register");
    return REG_INVALID_BITS; /* callers don't expect a failure - return some value */
}

/* returns the OPSZ_ field appropriate for the register */
opnd_size_t
reg_get_size(reg_id_t reg)
{
    /* SJF Special case for CPSR. Just another 32 bit reg */
    if ( reg == DR_REG_CPSR )
        return OPSZ_4;
    if (reg >= REG_START_32 && reg <= REG_STOP_32)
        return OPSZ_4;
    if (reg >= REG_START_16 && reg <= REG_STOP_16)
        return OPSZ_2;
/* SJF Ignore QW/DW/SW regs for now 
    if (reg >= REG_START_QWR && reg <= REG_STOP_QWR)
        return OPSZ_16;
    if (reg >= REG_START_DWR && reg <= REG_STOP_DWR)
        return OPSZ_8;
    if (reg >= REG_START_SWR && reg <= REG_STOP_SWR)
        return OPSZ_4;
*/
    if (reg >= REG_START_SEGMENT && reg <= REG_STOP_SEGMENT)
        return OPSZ_4;
    if (reg >= REG_START_DR && reg <= REG_STOP_DR)
        return OPSZ_4;
    if (reg >= REG_START_CR && reg <= REG_STOP_CR)
        return OPSZ_4;
    /* i#176 add reg size handling for floating point registers */
/* TODO SJF Comment out 
    if (reg >= REG_START_FLOAT && reg <= REG_STOP_FLOAT)
        return OPSZ_10;
*/
    CLIENT_ASSERT(false, "reg_get_size: invalid register");
    return OPSZ_NA;
}

/*************************
 ***       instr_t       ***
 *************************/

/* returns an empty instr_t object */
instr_t*
instr_create(dcontext_t *dcontext)
{
    instr_t *instr = (instr_t*) heap_alloc(dcontext, sizeof(instr_t) HEAPACCT(ACCT_IR));
    /* everything initializes to 0, even flags, to indicate
     * an uninitialized instruction */
    memset((void *)instr, 0, sizeof(instr_t));
    IF_X64(instr_set_x86_mode(instr, !X64_CACHE_MODE_DC(dcontext)));
    return instr;
}

/* deletes the instr_t object with handle "inst" and frees its storage */
void
instr_destroy(dcontext_t *dcontext, instr_t *instr)
{
    instr_free(dcontext, instr);

    /* CAUTION: assumes that instr is not part of any instrlist */
    heap_free(dcontext, instr, sizeof(instr_t) HEAPACCT(ACCT_IR));
}

/* returns a clone of orig, but with next and prev fields set to NULL */
instr_t *
instr_clone(dcontext_t *dcontext, instr_t *orig)
{
    instr_t *instr = (instr_t*) heap_alloc(dcontext, sizeof(instr_t) HEAPACCT(ACCT_IR));
    memcpy((void *)instr, (void *)orig, sizeof(instr_t));
    instr->next = NULL;
    instr->prev = NULL;

    /* PR 214962: clients can see some of our mangling
     * (dr_insert_mbr_instrumentation(), traces), but don't let the flag
     * mark other client instrs, which could mess up state translation
     */
    instr_set_our_mangling(instr, false);

    if ((orig->flags & INSTR_RAW_BITS_ALLOCATED) != 0) {
        /* instr length already set from memcpy */
        instr->bytes = (byte *) heap_alloc(dcontext, instr->length
                                           HEAPACCT(ACCT_IR));
        memcpy((void *)instr->bytes, (void *)orig->bytes, instr->length);
    }
#ifdef CUSTOM_EXIT_STUBS
    if ((orig->flags & INSTR_HAS_CUSTOM_STUB) != 0) {
        /* HACK: dsts is used to store list */
        instrlist_t *existing = (instrlist_t *) orig->dsts;
        CLIENT_ASSERT(existing != NULL, "instr_clone: src has inconsistent custom stub");
        instr->dsts = (opnd_t *) instrlist_clone(dcontext, existing);
    } 
    else /* disable normal dst cloning */
#endif
    if (orig->num_dsts > 0) { /* checking num_dsts, not dsts, b/c of label data */
        instr->dsts = (opnd_t *) heap_alloc(dcontext, instr->num_dsts*sizeof(opnd_t)
                                          HEAPACCT(ACCT_IR));
        memcpy((void *)instr->dsts, (void *)orig->dsts,
               instr->num_dsts*sizeof(opnd_t));
    }
    if (orig->num_srcs > 1) { /* checking num_src, not srcs, b/c of label data */
        instr->srcs = (opnd_t *) heap_alloc(dcontext,
                                          (instr->num_srcs-1)*sizeof(opnd_t)
                                          HEAPACCT(ACCT_IR));
        memcpy((void *)instr->srcs, (void *)orig->srcs,
               (instr->num_srcs-1)*sizeof(opnd_t));
    }
    /* copy note (we make no guarantee, and have no way, to do a deep clone) */
    instr->note = orig->note;
    if (instr_is_label(orig))
        memcpy(&instr->label_data, &orig->label_data, sizeof(instr->label_data));
    return instr;
}

/* zeroes out the fields of instr */
void
instr_init(dcontext_t *dcontext, instr_t *instr)
{
    /* everything initializes to 0, even flags, to indicate
     * an uninitialized instruction */
    memset((void *)instr, 0, sizeof(instr_t));
    IF_X64(instr_set_x86_mode(instr, get_x86_mode(dcontext)));
}

/* Frees all dynamically allocated storage that was allocated by instr */
void 
instr_free(dcontext_t *dcontext, instr_t *instr)
{
    if ((instr->flags & INSTR_RAW_BITS_ALLOCATED) != 0) {
        heap_free(dcontext, instr->bytes, instr->length HEAPACCT(ACCT_IR));
        instr->bytes = NULL;
        instr->flags &= ~INSTR_RAW_BITS_ALLOCATED;
    }
#ifdef CUSTOM_EXIT_STUBS
    if ((instr->flags & INSTR_HAS_CUSTOM_STUB) != 0) {
        /* HACK: dsts is used to store list */
        instrlist_t *existing = (instrlist_t *) instr->dsts;
        CLIENT_ASSERT(existing != NULL, "instr_free: custom stubs inconsistent");
        instrlist_clear_and_destroy(dcontext, existing);
        instr->dsts = NULL;
    }
#endif
    if (instr->num_dsts > 0) { /* checking num_dsts, not dsts, b/c of label data */
        heap_free(dcontext, instr->dsts, instr->num_dsts*sizeof(opnd_t)
                  HEAPACCT(ACCT_IR));
        instr->dsts = NULL;
        instr->num_dsts = 0;
    }
    if (instr->num_srcs > 1) { /* checking num_src, not src, b/c of label data */
        /* remember one src is static, rest are dynamic */
        heap_free(dcontext, instr->srcs, (instr->num_srcs-1)*sizeof(opnd_t)
                  HEAPACCT(ACCT_IR));
        instr->srcs = NULL;
        instr->num_srcs = 0;
    }
}

/* Returns number of bytes of heap used by instr */
int
instr_mem_usage(instr_t *instr)
{
    int usage = 0;
    if ((instr->flags & INSTR_RAW_BITS_ALLOCATED) != 0) {
        usage += instr->length;
    }
#ifdef CUSTOM_EXIT_STUBS
    if ((instr->flags & INSTR_HAS_CUSTOM_STUB) != 0) {
        /* HACK: dsts is used to store list */
        instrlist_t *il = (instrlist_t *) instr->dsts;
        instr_t *in;
        CLIENT_ASSERT(il != NULL, "instr_mem_usage: custom stubs inconsistent");
        for (in = instrlist_first(il); in != NULL; in = instr_get_next(in))
            usage += instr_mem_usage(in);
    }
#endif
    if (instr->dsts != NULL) {
        usage += instr->num_dsts*sizeof(opnd_t);
    }
    if (instr->srcs != NULL) {
        /* remember one src is static, rest are dynamic */
        usage += (instr->num_srcs-1)*sizeof(opnd_t);
    }
    usage += sizeof(instr_t);
    return usage;
}


/* Frees all dynamically allocated storage that was allocated by instr
 * Also zeroes out instr's fields
 * This instr must have been initialized before!
 */
void 
instr_reset(dcontext_t *dcontext, instr_t *instr)
{
    instr_free(dcontext, instr);
    instr_init(dcontext, instr);
}

/* Frees all dynamically allocated storage that was allocated by instr,
 * except for allocated raw bits.
 * Also zeroes out instr's fields, except for raw bit fields and next and prev
 * fields, whether instr is ok to mangle, and instr's x86 mode.
 * Use this routine when you want to decode more information into the
 * same instr_t structure.
 * This instr must have been initialized before!
 */
void 
instr_reuse(dcontext_t *dcontext, instr_t *instr)
{
    byte *bits = NULL;
    uint len = 0;
    bool alloc = false;
    bool mangle = instr_ok_to_mangle(instr);
#ifdef X64
    bool x86_mode = instr_get_x86_mode(instr);
    uint rip_rel_pos = instr_rip_rel_valid(instr) ? instr->rip_rel_pos : 0;
#endif
    instr_t *next = instr->next;
    instr_t *prev = instr->prev;
    if (instr_raw_bits_valid(instr)) {
        if (instr_has_allocated_bits(instr)) {
            /* pretend has no allocated bits to prevent freeing of them */
            instr->flags &= ~INSTR_RAW_BITS_ALLOCATED;
            alloc = true;
        }
        bits = instr->bytes;
        len = instr->length;
    }
    instr_free(dcontext, instr);
    instr_init(dcontext, instr);
    /* now re-add them */
    instr->next = next;
    instr->prev = prev;
    if (bits != NULL) {
        instr->bytes = bits;
        instr->length = len;
        /* assume that the bits are now valid and the operands are not
         * (operand and eflags flags are already unset from init)
         */
        instr->flags |= INSTR_RAW_BITS_VALID;
        if (alloc)
            instr->flags |= INSTR_RAW_BITS_ALLOCATED;
    }
#ifdef X64
    /* preserve across the up-decode */
    instr_set_x86_mode(instr, x86_mode);
    if (rip_rel_pos > 0)
        instr_set_rip_rel_pos(instr, rip_rel_pos);
#endif
    if (!mangle)
        instr->flags |= INSTR_DO_NOT_MANGLE;
}

instr_t *
instr_build(dcontext_t *dcontext, int opcode, int instr_num_dsts, int instr_num_srcs)
{
    instr_t *instr = instr_create(dcontext);
    instr_set_opcode(instr, opcode);
    instr_set_num_opnds(dcontext, instr, instr_num_dsts, instr_num_srcs);
    return instr;
}

instr_t *
instr_build_bits(dcontext_t *dcontext, int opcode, uint num_bytes)
{
    instr_t *instr = instr_create(dcontext);
    instr_set_opcode(instr, opcode);
    instr_allocate_raw_bits(dcontext, instr, num_bytes);
    return instr;
}

/* encodes to buffer, then returns length.
 * needed for things we must have encoding for: length and eflags.
 * if !always_cache, only caches the encoding if instr_ok_to_mangle();
 * if always_cache, the caller should invalidate the cache when done.
 */
static int
private_instr_encode(dcontext_t *dcontext, instr_t *instr, bool always_cache)
{
#ifdef NO
    /* we cannot use a stack buffer for encoding since our stack on x64 linux
     * can be too far to reach from our heap
     */
    byte *buf = heap_alloc(dcontext, 32 /* max instr length is 17 bytes */
                           HEAPACCT(ACCT_IR));
    uint len;
    /* Do not cache instr opnds as they are pc-relative to final encoding location.
     * Rather than us walking all of the operands separately here, we have
     * instr_encode_check_reachability tell us while it does its normal walk.
     * Xref i#731.
     */
    bool has_instr_opnds;
    byte *nxt = instr_encode_check_reachability(dcontext, instr, buf, &has_instr_opnds);
    bool valid_to_cache = !has_instr_opnds;
    if (nxt == NULL) {
        nxt = instr_encode_ignore_reachability(dcontext, instr, buf);
        if (nxt == NULL) {
            SYSLOG_INTERNAL_WARNING("cannot encode %s\n", op_instr[instr->opcode]->name);
            heap_free(dcontext, buf, 32 HEAPACCT(ACCT_IR));
            return 0;
        }
        /* if unreachable, we can't cache, since re-relativization won't work */
        valid_to_cache = false;
    }
    len = (int) (nxt - buf);    
    CLIENT_ASSERT(len > 0 || instr_is_label(instr),
                  "encode instr for length/eflags error: zero length");
    CLIENT_ASSERT(len < 32, "encode instr for length/eflags error: instr too long");
    ASSERT_CURIOSITY(len >= 0 && len < 18);

    /* do not cache encoding if mangle is false, that way we can have
     * non-cti-instructions that are pc-relative.
     * we also cannot cache if a rip-relative operand is unreachable.
     * we can cache if a rip-relative operand is present b/c instr_encode()
     * sets instr_set_rip_rel_pos() for us.
     */
    if (len > 0 &&
        ((valid_to_cache && instr_ok_to_mangle(instr)) ||
         always_cache /*caller will use then invalidate*/)) {
        bool valid = instr_operands_valid(instr);
#ifdef X64
        /* we can't call instr_rip_rel_valid() b/c the raw bytes are not yet
         * set up: we rely on instr_encode() setting instr->rip_rel_pos and
         * the valid flag, even though raw bytes weren't there at the time.
         * we rely on the INSTR_RIP_REL_VALID flag being invalidated whenever
         * the raw bits are.
         */
        bool rip_rel_valid = TEST(INSTR_RIP_REL_VALID, instr->flags);
#endif
        byte *tmp;
        CLIENT_ASSERT(!instr_raw_bits_valid(instr),
                      "encode instr: bit validity error"); /* else shouldn't get here */
        instr_allocate_raw_bits(dcontext, instr, len);
        /* we use a hack in order to take advantage of
         * copy_and_re_relativize_raw_instr(), which copies from instr->bytes
         * using rip-rel-calculating routines that also use instr->bytes.
         */
        tmp = instr->bytes;
        instr->bytes = buf;
#ifdef X64
        instr_set_rip_rel_valid(instr, rip_rel_valid);
#endif
        copy_and_re_relativize_raw_instr(dcontext, instr, tmp, tmp);
        instr->bytes = tmp;
        instr_set_operands_valid(instr, valid);
    }
    heap_free(dcontext, buf, 32 HEAPACCT(ACCT_IR));
    return len;
#endif //NO
}

#define inlined_instr_get_instr_type(instr) \
    (IF_DEBUG_(CLIENT_ASSERT(sizeof(*instr) == sizeof(instr_t), "invalid type")) \
     (((instr)->instr_type == INSTR_TYPE_UNDECODED) ? \
      (instr_decode_with_current_dcontext(instr), (instr)->instr_type) : \
      (instr)->instr_type))

#define inlined_instr_get_opcode(instr) \
    (IF_DEBUG_(CLIENT_ASSERT(sizeof(*instr) == sizeof(instr_t), "invalid type")) \
     (((instr)->opcode == OP_UNDECODED) ? \
      (instr_decode_with_current_dcontext(instr), (instr)->opcode) : \
      (instr)->opcode))

int
instr_get_opcode(instr_t *instr)
{
    return inlined_instr_get_opcode(instr);
}

int
instr_get_instr_type(instr_t *instr)
{
    return inlined_instr_get_instr_type(instr);
}

int
instr_info_get_instr_type( instr_info_t * ii )
{
    return ii->instr_type;
}

int
instr_get_instr_type_value(uint it)
{
    int b = 0;

    switch( it )
    {
      case INSTR_TYPE_DATA_PROCESSING_AND_ELS:
        b = 0;
        break;
      case INSTR_TYPE_DATA_PROCESSING_IMM:
        b = 1;
        break;
      case INSTR_TYPE_LOAD_STORE1:
        b = 2;
        break;
      case INSTR_TYPE_LOAD_STORE2_AND_MEDIA:
        b = 3;
        break;
      case INSTR_TYPE_LOAD_STORE_MULTIPLE:
        b = 4;
        break;
      case INSTR_TYPE_BRANCH:
        b = 5;
        break;
      case INSTR_TYPE_COPROCESSOR_DATA_MOVEMENT:
        b = 6;
        break;
      case INSTR_TYPE_ADVANCED_COPROCESSOR_AND_SYSCALL:
        b = 7;
        break;

      default:
        CLIENT_ASSERT(false, "instr_encode error: invalid instr type" );
        break;

    }

    return b;
}

uint
instr_get_cpsr(instr_t *instr)
{   
    if ((instr->flags & INSTR_CPSR_VALID) == 0) {
        bool encoded = false;
        dcontext_t *dcontext = get_thread_private_dcontext();
        /* we assume we cannot trust the opcode independently of operands */
        if (instr_needs_encoding(instr)) {
            int len;
            encoded = true;
            len = private_instr_encode(dcontext, instr, true/*cache*/);
            if (len == 0) {
                if (!instr_is_label(instr))
                    CLIENT_ASSERT(false, "instr_get_eflags: invalid instr");
                return 0;
            }
        }
        decode_cpsr_usage(dcontext, instr_get_raw_bits(instr), &instr->cpsr);
        if (encoded) {
            /* if private_instr_encode passed us back whether it's valid
             * to cache (i.e., non-meta instr that can reach) we could skip
             * this invalidation for such cases */
            instr_free_raw_bits(dcontext, instr);
            CLIENT_ASSERT(!instr_raw_bits_valid(instr), "internal encoding buf error");
        }
        /* even if decode fails, set valid to true -- ok?  FIXME */
        instr_set_cpsr_valid(instr, true);
    }
    return instr->cpsr;
}


/* in rest of file, directly de-reference for performance (PR 622253) */
#define instr_get_opcode inlined_instr_get_opcode
#define instr_get_instr_type inlined_instr_get_instr_type_

static inline void
instr_being_modified(instr_t *instr, bool raw_bits_valid)
{
    if (!raw_bits_valid) {
        /* if we're modifying the instr, don't use original bits to encode! */
        instr_set_raw_bits_valid(instr, false);
    }
    /* PR 214962: if client changes our mangling, un-mark to avoid bad translation */
    instr_set_our_mangling(instr, false);
}

void
instr_set_cond(instr_t *instr, int cond)
{
    instr->cond = cond;

    /* if we're modifying opcode, don't use original bits to encode! */
    instr_being_modified(instr, false/*raw bits invalid*/);

    CLIENT_ASSERT((cond != COND_INVALID) ||
                  !instr_operands_valid(instr),
                  "instr_set_cond: cond validity mismatch");
}

void
instr_set_opcode(instr_t *instr, int opcode)
{
    instr->opcode = opcode;
    /* if we're modifying opcode, don't use original bits to encode! */
    instr_being_modified(instr, false/*raw bits invalid*/);
    /* do not assume operands are valid, they are separate from opcode,
     * but if opcode is invalid operands shouldn't be valid
     */
    CLIENT_ASSERT((opcode != OP_INVALID && opcode != OP_UNDECODED) ||
                  !instr_operands_valid(instr),
                  "instr_set_opcode: operand-opcode validity mismatch");
}


void
instr_set_instr_type(instr_t *instr, int instr_type)
{
    instr->instr_type = instr_type;
    /* if we're modifying opcode, don't use original bits to encode! */
    instr_being_modified(instr, false/*raw bits invalid*/);
    /* do not assume operands are valid, they are separate from opcode,
     * but if opcode is invalid operands shouldn't be valid
     */
    CLIENT_ASSERT((instr_type != OP_INVALID && instr_type != OP_UNDECODED) ||
                  !instr_operands_valid(instr),
                  "instr_set_instr_type: operand-instr_type validity mismatch");
}

/* Returns true iff instr's opcode is NOT OP_INVALID.
 * Not to be confused with an invalid opcode, which can be OP_INVALID or
 * OP_UNDECODED.  OP_INVALID means an instruction with no valid fields:
 * raw bits (may exist but do not correspond to a valid instr), opcode,
 * eflags, or operands.  It could be an uninitialized
 * instruction or the result of decoding an invalid sequence of bytes.
 */
bool 
instr_valid(instr_t *instr)
{
    return (instr->opcode != OP_INVALID);
}

DR_API
/* Get the original application PC of the instruction if it exists. */
app_pc
instr_get_app_pc(instr_t *instr)
{
    return instr_get_translation(instr);
}

bool 
instr_instr_type_valid(instr_t *instr)
{
    return (instr->instr_type != INSTR_TYPE_UNDECODED && instr->opcode != INSTR_TYPE_INVALID);
}


/* Returns true iff instr's opcode is valid.  If the opcode is not
 * OP_INVALID or OP_UNDECODED it is assumed to be valid.  However, calling
 * instr_get_opcode() will attempt to decode an OP_UNDECODED opcode, hence the
 * purpose of this routine.  
 */
DR_API
bool 
instr_opcode_valid(instr_t *instr)
{
    return (instr->opcode != OP_INVALID && instr->opcode != OP_UNDECODED);
}


const instr_info_t * 
instr_get_instr_info(instr_t *instr)
{
    return op_instr[instr_get_opcode(instr)];
}

const instr_info_t * 
get_instr_info(int opcode)
{
    return op_instr[opcode];
}

#undef instr_get_src
opnd_t
instr_get_src(instr_t *instr, uint pos)
{
    return INSTR_GET_SRC(instr, pos);
}
#define instr_get_src INSTR_GET_SRC

#undef instr_get_dst
opnd_t
instr_get_dst(instr_t *instr, uint pos)
{
    return INSTR_GET_DST(instr, pos);
}
#define instr_get_dst INSTR_GET_DST

/* allocates storage for instr_num_srcs src operands and instr_num_dsts dst operands
 * assumes that instr is currently all zeroed out!
 */
void
instr_set_num_opnds(dcontext_t *dcontext,
                    instr_t *instr, int instr_num_dsts, int instr_num_srcs)
{
    if (instr_num_dsts > 0) {
        CLIENT_ASSERT(instr->num_dsts == 0 && instr->dsts == NULL,
                      "instr_set_num_opnds: dsts are already set");
        CLIENT_ASSERT_TRUNCATE(instr->num_dsts, byte, instr_num_dsts,
                               "instr_set_num_opnds: too many dsts");
        instr->num_dsts = (byte) instr_num_dsts;
        instr->dsts = (opnd_t *) heap_alloc(dcontext, instr_num_dsts*sizeof(opnd_t)
                                          HEAPACCT(ACCT_IR));
    }
    if (instr_num_srcs > 0) {
        /* remember that src0 is static, rest are dynamic */
        if (instr_num_srcs > 1) {
            CLIENT_ASSERT(instr->num_srcs <= 1 && instr->srcs == NULL,
                          "instr_set_num_opnds: srcs are already set");
            instr->srcs = (opnd_t *) heap_alloc(dcontext, (instr_num_srcs-1)*sizeof(opnd_t)
                                              HEAPACCT(ACCT_IR));
        }
        CLIENT_ASSERT_TRUNCATE(instr->num_srcs, byte, instr_num_srcs,
                               "instr_set_num_opnds: too many srcs");
        instr->num_srcs = (byte) instr_num_srcs;
    }
    instr_being_modified(instr, false/*raw bits invalid*/);
    /* assume all operands are valid */
    instr_set_operands_valid(instr, true);
}

/* sets the src opnd at position pos in instr */
void
instr_set_src(instr_t *instr, uint pos, opnd_t opnd)
{
    CLIENT_ASSERT(pos >= 0 && pos < instr->num_srcs, "instr_set_src: ordinal invalid");
    /* remember that src0 is static, rest are dynamic */
    if (pos == 0)
        instr->src0 = opnd;
    else
        instr->srcs[pos-1] = opnd;
    /* if we're modifying operands, don't use original bits to encode! */
    instr_being_modified(instr, false/*raw bits invalid*/);
    /* assume all operands are valid */
    instr_set_operands_valid(instr, true);
}

/* sets the dst opnd at position pos in instr */
void
instr_set_dst(instr_t *instr, uint pos, opnd_t opnd)
{
    CLIENT_ASSERT(pos >= 0 && pos < instr->num_dsts, "instr_set_dst: ordinal invalid");
    instr->dsts[pos] = opnd;
    /* if we're modifying operands, don't use original bits to encode! */
    instr_being_modified(instr, false/*raw bits invalid*/);
    /* assume all operands are valid */
    instr_set_operands_valid(instr, true);
}

#undef instr_get_target
opnd_t
instr_get_target(instr_t *instr)
{
    return INSTR_GET_TARGET(instr);
}
#define instr_get_target INSTR_GET_TARGET

/* Assumes that if an instr has a jump target, it's stored in the 0th src
 * location.
 */
void
instr_set_target(instr_t *instr, opnd_t target)
{
    CLIENT_ASSERT(instr->num_srcs >= 1, "instr_set_target: instr has no sources");
    instr->src0 = target;
    /* if we're modifying operands, don't use original bits to encode,
     * except for jecxz/loop*
     */
    instr_being_modified(instr, true);
    /* assume all operands are valid */
    instr_set_operands_valid(instr, true);
}

#ifdef X64
/*
 * Each instruction stores whether it should be interpreted in 32-bit
 * (x86) or 64-bit (x64) mode.  This routine sets the mode for \p instr.
 */
void
instr_set_x86_mode(instr_t *instr, bool x86)
{
    if (x86)
        instr->flags |= INSTR_X86_MODE;
    else
        instr->flags &= ~INSTR_X86_MODE;
}

/*
 * Each instruction stores whether it should be interpreted in 32-bit
 * (x86) or 64-bit (x64) mode.  This routine returns the mode for \p instr.
 */
bool 
instr_get_x86_mode(instr_t *instr)
{
    return TEST(INSTR_X86_MODE, instr->flags);
}
#endif

#ifdef UNSUPPORTED_API
/* Returns true iff instr has been marked as targeting the prefix of its
 * target fragment.
 *
 * Some code manipulations need to store a target address in a
 * register and then jump there, but need the register to be restored
 * as well.  DR provides a single-instruction prefix that is
 * placed on all fragments (basic blocks as well as traces) that
 * restores ecx.  It is on traces for internal DR use.  To have
 * it added to basic blocks as well, call
 * dr_add_prefixes_to_basic_blocks() during initialization.
 */
bool
instr_branch_targets_prefix(instr_t *instr)
{
    return ((instr->flags & INSTR_BRANCH_TARGETS_PREFIX) != 0);
}

/* If val is true, indicates that instr's target fragment should be
 *   entered through its prefix, which restores ecx.
 * If val is false, indicates that instr should target the normal entry
 *   point and not the prefix.
 *
 * Some code manipulations need to store a target address in a
 * register and then jump there, but need the register to be restored
 * as well.  DR provides a single-instruction prefix that is
 * placed on all fragments (basic blocks as well as traces) that
 * restores ecx.  It is on traces for internal DR use.  To have
 * it added to basic blocks as well, call
 * dr_add_prefixes_to_basic_blocks() during initialization.
 */
void
instr_branch_set_prefix_target(instr_t *instr, bool val)
{
    if (val)
        instr->flags |= INSTR_BRANCH_TARGETS_PREFIX;
    else
        instr->flags &= ~INSTR_BRANCH_TARGETS_PREFIX;
}
#endif /* UNSUPPORTED_API */

/*Checks if the instr takes a reg or a mem reg as its first src.
         If it does then it checks if the first src is the pc and returns true if it is
         false otheriwse.
*/
DR_API
bool
instr_reads_pc( instr_t* instr )
{
   instr_info_t* ii;

   ASSERT( (instr != NULL) );

   ii = op_instr[instr->opcode];

   if( ii->src1_type == TYPE_REG ||
       ii->src1_type == TYPE_M )
   {
     if( instr->src0.kind == REG_kind ||
         instr->src0.kind == MEM_REG_kind )
       return ( instr->src0.value.reg == REG_RR15 );
     else
       return false;
   } 
   else
     return false;
}

instrlist_t*
instrlist_rewrite_relative_to_absolute( dcontext_t* dcontext, instrlist_t* ilist )
{
    instr_t* inst;
    opnd_t orig_opnd;

    for (inst = instrlist_first(ilist); inst; inst = instr_get_next(inst)) 
    {
        if( opcode_is_relative_load( inst->opcode ))
        {
          switch( inst->opcode )
          {
            case OP_ldr_lit:
            case OP_ldrb_lit:
            case OP_ldrd_lit:
            case OP_ldrh_lit:
            case OP_ldrsb_lit:
            case OP_ldrsh_lit:
              instrlist_meta_preinsert( ilist, inst, INSTR_CREATE_push(dcontext,
                                               opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                               COND_ALWAYS ));

              memcpy( &orig_opnd, &(inst->src0), sizeof( opnd_t ));

              //Move addr + offset into reg. SJF weird shit going on with offset so just add to addr
              instrlist_preinsert_move_32bits_to_reg( ilist, dcontext, REG_RR8, REG_RR9,
                                                      inst->bytes+8+orig_opnd.value.immed_int, inst, COND_ALWAYS ); //Before current inst 

              //Change ldr*_lit to ldr*_reg 
              inst->src0 = opnd_create_mem_reg( REG_RR8 );

              //Allocate space for new src opnd
              instr_set_num_opnds(dcontext, inst, 0, 2);

              //Set to 0 as added to the addr above
              orig_opnd.value.immed_int = 0;
              memcpy( &inst->srcs[0], &orig_opnd, sizeof( opnd_t ));

              //bit of a hack here relies on the imm version of the instr 
              // being before the lit one
              inst->opcode--;
              //Make sure it is computing base + offset 
              instr_set_u_flag( dcontext, inst, true );
              //Make sure it writes the modified instruction
              instr_set_raw_bits_valid( inst, false );

              //Hope it isnt R9 that is the dst of the ldr instr
              instrlist_meta_postinsert( ilist, inst, INSTR_CREATE_pop(dcontext,
                                                         opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                         COND_ALWAYS ));
              break;

            default:
              CLIENT_ASSERT( false, "unimplemented relative instr found" );
              break;
          }
        }
        else if( opcode_is_other_relative( inst->opcode ))
        //First src is r15. If any other instrs have a 2nd++ src of r15 it wont check it
        {
          //Only unrelativeise the first src opnd
          switch( inst->opcode )
          {
            case OP_adr:
              instrlist_meta_preinsert( ilist, inst, INSTR_CREATE_push(dcontext,
                                               opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                               COND_ALWAYS ));

              memcpy( &orig_opnd, &(inst->src0), sizeof( opnd_t ));

              //Move addr + offset into reg. SJF weird shit going on with offset so just add to addr
              instrlist_preinsert_move_32bits_to_reg( ilist, dcontext, REG_RR8, REG_RR9,
                                                      inst->bytes+8+orig_opnd.value.immed_int, inst, COND_ALWAYS ); //Before current inst

              //Change ldr*_lit to ldr*_reg
              inst->src0 = opnd_create_reg( REG_RR8 );

              //Allocate space for new src opnd
              instr_set_num_opnds(dcontext, inst, 0, 2);

              //Set to 0 as added to the addr above
              orig_opnd.value.immed_int = 0;
              memcpy( &inst->srcs[0], &orig_opnd, sizeof( opnd_t ));

              //Just change the adr to an add imm 
              inst->opcode = OP_add_imm;
              //Make sure it is computing base + offset
              instr_set_u_flag( dcontext, inst, true );
              //Make sure it writes the modified instruction
              instr_set_raw_bits_valid( inst, false );

              //Hope it isnt R9 that is the dst of the ldr instr
              instrlist_meta_postinsert( ilist, inst, INSTR_CREATE_pop(dcontext,
                                                         opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                         COND_ALWAYS ));
              break;
          }
        }
        else if( opcode_is_possible_pc_read( inst->opcode ) )
        //If the instr reads the PC then change to absolute
        {
          //Only unrelativeise the first src opnd
          if( instr_is_pc_read( inst ) )
          {
            switch( inst->opcode )
            {
              case OP_add_reg:
              case OP_add_imm:
              case OP_sub_reg:
              case OP_sub_imm:
                //TODO Check dest and poss other src of instr and use different
                //scratch registers if used
                instrlist_meta_preinsert( ilist, inst, INSTR_CREATE_push(dcontext,
                                                 opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                 COND_ALWAYS ));

                instrlist_preinsert_move_32bits_to_reg( ilist, dcontext, REG_RR8, REG_RR9,
                                                        inst->bytes+8, inst, COND_ALWAYS ); //Before current inst

                //Change reg r15 to reg r8
                inst->src0 = opnd_create_reg( REG_RR8 );

                //Make sure it writes the modified instruction
                instr_set_raw_bits_valid( inst, false );

                //Hope it isnt R9 that is the dst of the ldr instr
                instrlist_meta_postinsert( ilist, inst, INSTR_CREATE_pop(dcontext,
                                                           opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                           COND_ALWAYS ));
                break;
            }
          }
          //If not a pc read then copy straight from app. unless it is a cti
          /* Remove this for now. As cti will have been changed to write to R0
             then this will not know it is a cti and try to mark it as raw bits 
             valid. This will cause a slowdown as all possible pc read instrs
             will now be fully encoded.
          else if( !instr_is_cti( inst )) 
            instr_set_raw_bits_valid( inst, true );
           */
        }
    }
}


/* Returns true iff instr has been marked as a selfmod check failure exit
 */
bool
instr_branch_selfmod_exit(instr_t *instr)
{
    return ((instr->flags & INSTR_BRANCH_SELFMOD_EXIT) != 0);
}

/* If val is true, indicates that instr is a selfmod check failure exit
 * If val is false, indicates otherwise
 */
void
instr_branch_set_selfmod_exit(instr_t *instr, bool val)
{
    if (val)
        instr->flags |= INSTR_BRANCH_SELFMOD_EXIT;
    else
        instr->flags &= ~INSTR_BRANCH_SELFMOD_EXIT;
}

/* Returns the type of the original indirect branch of an exit
 */
int
instr_exit_branch_type(instr_t *instr)
{
    return instr->flags & EXIT_CTI_TYPES;
}

/* Set type of indirect branch exit
 */
void
instr_exit_branch_set_type(instr_t *instr, uint type)
{
    /* set only expected flags */
    type &= EXIT_CTI_TYPES;
    instr->flags &= ~EXIT_CTI_TYPES;
    instr->flags |= type;
}

void
instr_set_ok_to_mangle(instr_t *instr, bool val)
{
    if (val)
        instr->flags &= ~INSTR_DO_NOT_MANGLE;
    else
        instr->flags |= INSTR_DO_NOT_MANGLE;
}

bool
instr_is_meta_may_fault(instr_t *instr)
{
    /* no longer using a special flag (i#496) */
    return !instr_ok_to_mangle(instr) && instr_get_translation(instr) != NULL;
}

void
instr_set_meta_may_fault(instr_t *instr, bool val)
{
    /* no longer using a special flag (i#496) */
    instr_set_ok_to_mangle(instr, false);
    CLIENT_ASSERT(instr_get_translation(instr) != NULL,
                  "meta_may_fault instr must have translation");
}

/* convenience routine */
void
instr_set_meta_no_translation(instr_t *instr)
{
    instr_set_ok_to_mangle(instr, false);
    instr_set_translation(instr, NULL);
}

void
instr_set_ok_to_emit(instr_t *instr, bool val)
{
    CLIENT_ASSERT(instr != NULL, "instr_set_ok_to_emit: passed NULL");
    if (val)
        instr->flags &= ~INSTR_DO_NOT_EMIT;
    else
        instr->flags |= INSTR_DO_NOT_EMIT;
}

#ifdef CUSTOM_EXIT_STUBS
/* If instr is not an exit cti, does nothing.  
 * If instr is an exit cti, sets stub to be custom exit stub code
 * that will be inserted in the exit stub prior to the normal exit
 * stub code.  If instr already has custom exit stub code, that
 * existing instrlist_t is cleared and destroyed (using current thread's
 * context).  (If stub is NULL, any existing stub code is NOT destroyed.)
 * The creator of the instrlist_t containing instr is
 * responsible for destroying stub.  
 */
void
instr_set_exit_stub_code(instr_t *instr, instrlist_t *stub)
{
    /* HACK: dsts array is NULL, so we use the dsts pointer
     * FIXME: put checks in set_num_opnds, etc. that may overwrite this?
     * FIXME: make separate call to clear existing stubs?
     * having it not clear for stub==NULL a little hacky
     */
    CLIENT_ASSERT(instr_is_cbr(instr) || instr_is_ubr(instr),
                  "instr_set_exit_stub_code called on non-exit");
    CLIENT_ASSERT(instr->num_dsts == 0, "instr_set_exit_stub_code: instr invalid");
    if (stub != NULL && (instr->flags & INSTR_HAS_CUSTOM_STUB) != 0) {
        /* delete existing */
        instrlist_t *existing = (instrlist_t *) instr->dsts;
        instrlist_clear_and_destroy(get_thread_private_dcontext(), existing);
    }
    if (stub == NULL) {
        instr->flags &= ~INSTR_HAS_CUSTOM_STUB;
        instr->dsts = NULL;
    } else {
        instr->flags |= INSTR_HAS_CUSTOM_STUB;
        instr->dsts = (opnd_t *) stub;
    }
}

/* Returns the custom exit stub code instruction list that has been
 * set for this instruction.  If none exists, returns NULL.
 */
instrlist_t *
instr_exit_stub_code(instr_t *instr)
{
    if (!instr_is_cbr(instr) && !instr_is_ubr(instr))
        return NULL;
    if (opnd_is_far_pc(instr_get_target(instr)))
        return NULL;
    if ((instr->flags & INSTR_HAS_CUSTOM_STUB) == 0)
        return NULL;
    return (instrlist_t *) instr->dsts;
}
#endif

void        
instr_set_cpsr_valid(instr_t *instr, bool valid)
{           
    if (valid) {
        instr->flags |= INSTR_CPSR_VALID;
        instr->flags |= INSTR_CPSR_6_VALID;
    } else {
        /* assume that arith flags are also invalid */
        instr->flags &= ~INSTR_CPSR_VALID;
        instr->flags &= ~INSTR_CPSR_6_VALID;
    }
}

void
instr_set_operands_valid(instr_t *instr, bool valid)
{
    if (valid)
        instr->flags |= INSTR_OPERANDS_VALID;
    else
        instr->flags &= ~INSTR_OPERANDS_VALID;
}

/* N.B.: this routine sets the "raw bits are valid" flag */
void
instr_set_raw_bits(instr_t *instr, byte *addr, uint length)
{
    if ((instr->flags & INSTR_RAW_BITS_ALLOCATED) != 0) {
        /* this does happen, when up-decoding an instr using its
         * own raw bits, so let it happen, but make sure allocated
         * bits aren't being lost
         */
        CLIENT_ASSERT(addr == instr->bytes && length == instr->length,
                      "instr_set_raw_bits: bits already there, but different");
    }
    if (!instr_valid(instr))
        instr_set_opcode(instr, OP_UNDECODED);
    instr->flags |= INSTR_RAW_BITS_VALID;
    instr->bytes = addr;
    instr->length = length;
}

/* this is sort of a hack, used to allow dynamic reallocation of
 * the trace buffer, which requires shifting the addresses of all
 * the trace Instrs since they point into the old buffer
 */
void
instr_shift_raw_bits(instr_t *instr, ssize_t offs)
{
    if ((instr->flags & INSTR_RAW_BITS_VALID) != 0)
        instr->bytes += offs;
#ifdef X64
    instr_set_rip_rel_valid(instr, false); /* relies on original raw bits */
#endif
}

/* moves the instruction from USE_ORIGINAL_BITS state to a 
 * needs-full-encoding state
 */
void
instr_set_raw_bits_valid(instr_t *instr, bool valid)
{
    if (valid)
        instr->flags |= INSTR_RAW_BITS_VALID;
    else {
        instr->flags &= ~INSTR_RAW_BITS_VALID;
        /* DO NOT set bytes to NULL or length to 0, we still want to be
         * able to point at the original instruction for use in translating
         * addresses for exception/signal handlers
         * Also do not de-allocate allocated bits
         */
#ifdef X64
        instr_set_rip_rel_valid(instr, false);
#endif
    }
}

void
instr_free_raw_bits(dcontext_t *dcontext, instr_t *instr)
{
    if ((instr->flags & INSTR_RAW_BITS_ALLOCATED) == 0)
        return;
    heap_free(dcontext, instr->bytes, instr->length HEAPACCT(ACCT_IR));
    instr->flags &= ~INSTR_RAW_BITS_VALID;
    instr->flags &= ~INSTR_RAW_BITS_ALLOCATED;
}

/* creates array of bytes to store raw bytes of an instr into
 * (original bits are read-only)
 * initializes array to the original bits!
 */
void
instr_allocate_raw_bits(dcontext_t *dcontext, instr_t *instr, uint num_bytes)
{
    byte *original_bits = NULL;
    if ((instr->flags & INSTR_RAW_BITS_VALID) != 0)
        original_bits = instr->bytes;
    if ((instr->flags & INSTR_RAW_BITS_ALLOCATED) == 0 ||
        instr->length != num_bytes) {
        byte * new_bits = (byte *) heap_alloc(dcontext, num_bytes HEAPACCT(ACCT_IR));
        if (original_bits != NULL) {
            /* copy original bits into modified bits so can just modify
             * a few and still have all info in one place
             */
            memcpy(new_bits, original_bits,
                   (num_bytes < instr->length) ? num_bytes : instr->length);
        }
        if ((instr->flags & INSTR_RAW_BITS_ALLOCATED) != 0)
            instr_free_raw_bits(dcontext, instr);
        instr->bytes = new_bits;
        instr->length = num_bytes;
    }
    /* assume that the bits are now valid and the operands are not */
    instr->flags |= INSTR_RAW_BITS_VALID;
    instr->flags |= INSTR_RAW_BITS_ALLOCATED;
    instr->flags &= ~INSTR_OPERANDS_VALID;
    instr->flags &= ~INSTR_CPSR_VALID;
#ifdef X64
    instr_set_rip_rel_valid(instr, false); /* relies on original raw bits */
#endif
}

instr_t * 
instr_set_translation(instr_t *instr, app_pc addr)
{
#if defined(WINDOWS) && !defined(STANDALONE_DECODER)
    addr = get_app_pc_from_intercept_pc_if_necessary(addr);
#endif
    instr->translation = addr;
    return instr;
}

app_pc
instr_get_translation(instr_t *instr)
{
    return instr->translation;
}

/* This makes it safe to keep an instr around indefinitely when an instrs raw
 * bits point into the cache. It allocates memory local to the instr to hold
 * a copy of the raw bits. If this was not done the original raw bits could 
 * be deleted at some point.  This is necessary if you want to keep an instr
 * around for a long time (for clients, beyond returning from the call that 
 * gave you the instr)
 */
void
instr_make_persistent(dcontext_t *dcontext, instr_t *instr)
{
    if ((instr->flags & INSTR_RAW_BITS_VALID) != 0 &&
        (instr->flags & INSTR_RAW_BITS_ALLOCATED) == 0) {
        instr_allocate_raw_bits(dcontext, instr, instr->length);
    }
}

byte *
instr_get_raw_bits(instr_t *instr)
{
    return instr->bytes;
}

/* returns the pos-th instr byte */
byte
instr_get_raw_byte(instr_t *instr, uint pos)
{
    CLIENT_ASSERT(pos >= 0 && pos < instr->length && instr->bytes != NULL,
                  "instr_get_raw_byte: ordinal invalid, or no raw bits");
    return instr->bytes[pos];
}

/* returns the 4 bytes starting at position pos */
uint 
instr_get_raw_word(instr_t *instr, uint pos)
{
    CLIENT_ASSERT(pos >= 0 && pos+3 < instr->length && instr->bytes != NULL,
                  "instr_get_raw_word: ordinal invalid, or no raw bits");
    return *((uint *)(instr->bytes + pos));
}

/* Sets the pos-th instr byte by storing the unsigned
 * character value in the pos-th slot
 * Must call instr_allocate_raw_bits before calling this function
 * (original bits are read-only!)
 */
void
instr_set_raw_byte(instr_t *instr, uint pos, byte val)
{
    CLIENT_ASSERT((instr->flags & INSTR_RAW_BITS_ALLOCATED) != 0,
                  "instr_set_raw_byte: no raw bits");
    CLIENT_ASSERT(pos >= 0 && pos < instr->length && instr->bytes != NULL,
                  "instr_set_raw_byte: ordinal invalid, or no raw bits");
    instr->bytes[pos] = (byte) val;
#ifdef X64
    instr_set_rip_rel_valid(instr, false); /* relies on original raw bits */
#endif
}

/* Copies num_bytes bytes from start into the mangled bytes
 * array of instr.
 * Must call instr_allocate_raw_bits before calling this function.
 */
void 
instr_set_raw_bytes(instr_t *instr, byte *start, uint num_bytes)
{
    CLIENT_ASSERT((instr->flags & INSTR_RAW_BITS_ALLOCATED) != 0,
                  "instr_set_raw_bytes: no raw bits");
    CLIENT_ASSERT(num_bytes <= instr->length && instr->bytes != NULL,
                  "instr_set_raw_bytes: ordinal invalid, or no raw bits");
    memcpy(instr->bytes, start, num_bytes);
#ifdef X64
    instr_set_rip_rel_valid(instr, false); /* relies on original raw bits */
#endif
}

/* Stores 32-bit value word in positions pos through pos+3 in
 * modified_bits.
 * Must call instr_allocate_raw_bits before calling this function.
 */
void
instr_set_raw_word(instr_t *instr, uint pos, uint word)
{
    CLIENT_ASSERT((instr->flags & INSTR_RAW_BITS_ALLOCATED) != 0,
                  "instr_set_raw_word: no raw bits");
    CLIENT_ASSERT(pos >= 0 && pos+3 < instr->length && instr->bytes != NULL,
                  "instr_set_raw_word: ordinal invalid, or no raw bits");
    *((uint *)(instr->bytes+pos)) = word;
#ifdef X64
    instr_set_rip_rel_valid(instr, false); /* relies on original raw bits */
#endif
}

int
instr_length(dcontext_t *dcontext, instr_t *instr)
{
    if (!instr_needs_encoding(instr))
        return instr->length;

    /* SJF All 4 bytes */
    return 4;
}

/***********************************************************************/
/* decoding routines */

/* If instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands instr into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.
 * Returns the replacement of instr, if any expansion is performed
 * (in which case the old instr is destroyed); otherwise returns
 * instr unchanged.
 * If encounters an invalid instr, stops expanding at that instr, and keeps
 * instr in the ilist pointing to the invalid bits as an invalid instr.
 */
instr_t *
instr_expand(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr)
{
    /* Sometimes deleting instr but sometimes not (when return early)
     * is painful -- so we go to the trouble of re-using instr
     * for the first expanded instr
     */
    instr_t *newinstr, *firstinstr = NULL;
    int remaining_bytes, cur_inst_len;
    byte *curbytes, *newbytes;
    IF_X64(bool old_mode;)

    /* make it easy for iterators: handle NULL
     * assume that if opcode is valid, is at Level 2, so not a bundle
     * do not expand meta-instrs -- FIXME: is that the right thing to do?
     */
    if (instr == NULL || instr_opcode_valid(instr) || !instr_ok_to_mangle(instr) ||
        /* if an invalid instr (not just undecoded) do not try to expand */
        !instr_valid(instr))
        return instr;

    DOLOG(5, LOG_ALL, { loginst(dcontext, 4, instr, "instr_expand"); });

    /* decode routines use dcontext mode, but we want instr mode */
    IF_X64(old_mode = set_x86_mode(dcontext, instr_get_x86_mode(instr)));

    /* never have opnds but not opcode */
    CLIENT_ASSERT(!instr_operands_valid(instr), "instr_expand: opnds are already valid");
    CLIENT_ASSERT(instr_raw_bits_valid(instr), "instr_expand: raw bits are invalid");
    curbytes = instr->bytes;
    if ((uint)decode_sizeof(dcontext, curbytes, NULL _IF_X64(NULL)) == instr->length) {
        IF_X64(set_x86_mode(dcontext, old_mode));
        return instr; /* Level 1 */
    }
    
    remaining_bytes = instr->length;
    while (remaining_bytes > 0) {
        /* insert every separated instr into list */
        newinstr = instr_create(dcontext);
        newbytes = decode_raw(dcontext, curbytes, newinstr);
#ifndef NOT_DYNAMORIO_CORE_PROPER
        if (expand_should_set_translation(dcontext))
            instr_set_translation(newinstr, curbytes);
#endif
        if (newbytes == NULL) {
            /* invalid instr -- stop expanding, point instr at remaining bytes */
            instr_set_raw_bits(instr, curbytes, remaining_bytes);
            instr_set_opcode(instr, OP_INVALID);
            if (firstinstr == NULL)
                firstinstr = instr;
            instr_destroy(dcontext, newinstr);
            IF_X64(set_x86_mode(dcontext, old_mode));
            return firstinstr;
        }
        DOLOG(5, LOG_ALL, { loginst(dcontext, 4, newinstr, "\tjust expanded into"); });

        /* CAREFUL of what you call here -- don't call anything that
         * auto-upgrades instr to Level 2, it will fail on Level 0 bundles!
         */

        if (instr_has_allocated_bits(instr) ){
            /* make sure to have our own copy of any allocated bits
             * before we destroy the original instr
             */
            instr_allocate_raw_bits(dcontext, newinstr, (uint)(newbytes - curbytes));
        }
        
        /* special case: for cti_short, do not fully decode the
         * constituent instructions, leave as a bundle.
         * the instr will still have operands valid.
         */
        cur_inst_len = (int) (newbytes - curbytes);
        remaining_bytes -= cur_inst_len;
        curbytes = newbytes;
        
        instrlist_preinsert(ilist, instr, newinstr);
        if (firstinstr == NULL)
            firstinstr = newinstr;
    }
    
    /* delete original instr from list */
    instrlist_remove(ilist, instr);
    instr_destroy(dcontext, instr);
    
    CLIENT_ASSERT(firstinstr != NULL, "instr_expand failure");
    IF_X64(set_x86_mode(dcontext, old_mode));
    return firstinstr;
}

bool
instr_is_level_0(instr_t *instr) 
{
    dcontext_t *dcontext = get_thread_private_dcontext();
    IF_X64(bool old_mode;)
    /* assume that if opcode is valid, is at Level 2, so not a bundle
     * do not expand meta-instrs -- FIXME: is that the right to do? */
    if (instr == NULL || instr_opcode_valid(instr) || !instr_ok_to_mangle(instr) ||
        /* if an invalid instr (not just undecoded) do not try to expand */
        !instr_valid(instr))
        return false;

    /* never have opnds but not opcode */
    CLIENT_ASSERT(!instr_operands_valid(instr),
                  "instr_is_level_0: opnds are already valid");
    CLIENT_ASSERT(instr_raw_bits_valid(instr),
                  "instr_is_level_0: raw bits are invalid");
    IF_X64(old_mode = set_x86_mode(dcontext, instr_get_x86_mode(instr)));
    if ((uint)decode_sizeof(dcontext, instr->bytes, NULL _IF_X64(NULL)) ==
        instr->length) {
        IF_X64(set_x86_mode(dcontext, old_mode));
        return false; /* Level 1 */
    }
    IF_X64(set_x86_mode(dcontext, old_mode));
    return true;
}

/* If the next instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands it into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.  Then returns the new next instr.
 */
instr_t *
instr_get_next_expanded(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr)
{
    instr_expand(dcontext, ilist, instr_get_next(instr));
    return instr_get_next(instr);
}

/* If the prev instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands it into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.  Then returns the new prev instr.
 */
instr_t *
instr_get_prev_expanded(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr)
{
    instr_expand(dcontext, ilist, instr_get_prev(instr));
    return instr_get_prev(instr);
}

/* If the first instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands it into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.  Then returns the new first instr.
 */
instr_t *
instrlist_first_expanded(dcontext_t *dcontext, instrlist_t *ilist)
{
    instr_expand(dcontext, ilist, instrlist_first(ilist));
    return instrlist_first(ilist);
}


/* If the last instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands it into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.  Then returns the new last instr.
 */
instr_t *
instrlist_last_expanded(dcontext_t *dcontext, instrlist_t *ilist)
{
    instr_expand(dcontext, ilist, instrlist_last(ilist));
    return instrlist_last(ilist);
}

/* If instr is not already at the level of decode_cti, decodes enough
 * from the raw bits pointed to by instr to bring it to that level.
 * Assumes that instr is a single instr (i.e., NOT Level 0).
 *
 * decode_cti decodes only enough of instr to determine
 * its size, its effects on the 6 arithmetic eflags, and whether it is
 * a control-transfer instruction.  If it is, the operands fields of
 * instr are filled in.  If not, only the raw bits fields of instr are
 * filled in.  This corresponds to a Level 3 decoding for control
 * transfer instructions but a Level 1 decoding plus arithmetic eflags
 * information for all other instructions.
 */
void
instr_decode_cti(dcontext_t *dcontext, instr_t *instr)
{
    /* if arith flags are missing but otherwise decoded, who cares,
     * next get_arith_flags() will fill it in
     */
    if (!instr_opcode_valid(instr) ||
        (instr_is_cti(instr) && !instr_operands_valid(instr))) {
        byte *next_pc;
        /* decode_cti() will use the dcontext mode, but we want the instr mode */
        IF_X64(bool old_mode = set_x86_mode(dcontext, instr_get_x86_mode(instr));)
        DEBUG_EXT_DECLARE(int old_len = instr->length;)
        CLIENT_ASSERT(instr_raw_bits_valid(instr),
                      "instr_decode_cti: raw bits are invalid");
        instr_reuse(dcontext, instr);
        next_pc = decode_cti(dcontext, instr->bytes, instr);
        IF_X64(set_x86_mode(dcontext, old_mode));
        /* ok to be invalid, let caller deal with it */
        CLIENT_ASSERT(next_pc == NULL || (next_pc - instr->bytes == old_len),
                      "instr_decode_cti requires a Level 1 or higher instruction");
    }
}

/* If instr is not already at the level of decode_opcode, decodes enough
 * from the raw bits pointed to by instr to bring it to that level.
 * Assumes that instr is a single instr (i.e., NOT Level 0).
 *
 * decode_opcode decodes the opcode and eflags usage of the instruction.
 * This corresponds to a Level 2 decoding.
 */
void
instr_decode_opcode(dcontext_t *dcontext, instr_t *instr)
{
    if (!instr_opcode_valid(instr)) {
        byte *next_pc;

        DEBUG_EXT_DECLARE(int old_len = instr->length;)
        CLIENT_ASSERT(instr_raw_bits_valid(instr),
                      "instr_decode_opcode: raw bits are invalid");
        instr_reuse(dcontext, instr);
        next_pc = decode_opcode(dcontext, instr->bytes, instr);

        /* ok to be invalid, let caller deal with it */
        CLIENT_ASSERT(next_pc == NULL || (next_pc - instr->bytes == old_len),
                      "instr_decode_opcode requires a Level 1 or higher instruction");
    }
}

/* If instr is not already fully decoded, decodes enough
 * from the raw bits pointed to by instr to bring it Level 3.
 * Assumes that instr is a single instr (i.e., NOT Level 0).
 */
void
instr_decode(dcontext_t *dcontext, instr_t *instr)
{
    if (!instr_operands_valid(instr)) {
        byte *next_pc;
        DEBUG_EXT_DECLARE(int old_len = instr->length;)
        CLIENT_ASSERT(instr_raw_bits_valid(instr), "instr_decode: raw bits are invalid");
        instr_reuse(dcontext, instr);
        next_pc = decode(dcontext, instr_get_raw_bits(instr), instr);
#ifndef NOT_DYNAMORIO_CORE_PROPER
        if (expand_should_set_translation(dcontext))
            instr_set_translation(instr, instr_get_raw_bits(instr));
#endif
        /* ok to be invalid, let caller deal with it */
        CLIENT_ASSERT(next_pc == NULL || (next_pc - instr->bytes == old_len),
                      "instr_decode requires a Level 1 or higher instruction");
    }
}

/* Calls instr_decode() with the current dcontext.  Mostly useful as the slow
 * path for IR routines that get inlined.
 */
NOINLINE  /* rarely called */
instr_t *
instr_decode_with_current_dcontext(instr_t *instr)
{
    instr_decode(get_thread_private_dcontext(), instr);
    return instr;
}

/* Brings all instrs in ilist up to the decode_cti level, and
 * hooks up intra-ilist cti targets to use instr_t targets, by
 * matching pc targets to each instruction's raw bits.
 *
 * decode_cti decodes only enough of instr to determine
 * its size, its effects on the 6 arithmetic eflags, and whether it is
 * a control-transfer instruction.  If it is, the operands fields of
 * instr are filled in.  If not, only the raw bits fields of instr are
 * filled in.  This corresponds to a Level 3 decoding for control
 * transfer instructions but a Level 1 decoding plus arithmetic eflags
 * information for all other instructions.
 */
void 
instrlist_decode_cti(dcontext_t *dcontext, instrlist_t *ilist)
{
    instr_t *instr;

    LOG(THREAD, LOG_ALL, 3, "\ninstrlist_decode_cti\n");

    DOLOG(4, LOG_ALL, {
        LOG(THREAD, LOG_ALL, 4, "beforehand:\n");
        instrlist_disassemble(dcontext, 0, ilist, THREAD);
    });

    /* just use the expanding iterator to get to Level 1, then decode cti */
    for (instr = instrlist_first_expanded(dcontext, ilist);
         instr != NULL;
         instr = instr_get_next_expanded(dcontext, ilist, instr)) {
        /* if arith flags are missing but otherwise decoded, who cares,
         * next get_arith_flags() will fill it in
         */
        if (!instr_opcode_valid(instr) ||
            (instr_is_cti(instr) && !instr_operands_valid(instr))) {
            DOLOG(4, LOG_ALL, { 
                loginst(dcontext, 4, instr, "instrlist_decode_cti: about to decode");
            });
            instr_decode_cti(dcontext, instr);
            DOLOG(4, LOG_ALL, { loginst(dcontext, 4, instr, "\tjust decoded"); });
        }
    }

    /* must fix up intra-ilist cti's to have instr_t targets
     * assumption: all intra-ilist cti's have been marked as do-not-mangle,
     * plus all targets have their raw bits already set
     */
    for (instr = instrlist_first(ilist); instr != NULL;
         instr = instr_get_next(instr)) {
        /* N.B.: if we change exit cti's to have instr_t targets, we have to
         * change other modules like emit to handle that!
         * FIXME
         */
        if (!instr_is_exit_cti(instr) &&
            instr_opcode_valid(instr) && /* decode_cti only filled in cti opcodes */
            instr_is_cti(instr) &&
            instr_num_srcs(instr) > 0 && opnd_is_near_pc(instr_get_src(instr, 0))) {
            instr_t *tgt;
            DOLOG(4, LOG_ALL, {
                loginst(dcontext, 4, instr, "instrlist_decode_cti: found cti w/ pc target");
            });
            for (tgt = instrlist_first(ilist); tgt != NULL; tgt = instr_get_next(tgt)) {
                DOLOG(4, LOG_ALL, { loginst(dcontext, 4, tgt, "\tchecking"); });
                LOG(THREAD, LOG_INTERP|LOG_OPTS, 4, "\t\taddress is "PFX"\n",
                    instr_get_raw_bits(tgt));
                if (opnd_get_pc(instr_get_target(instr)) == instr_get_raw_bits(tgt)) {
                    /* cti targets this instr */
                    app_pc bits = 0;
                    int len = 0;
                    if (instr_raw_bits_valid(instr)) {
                        bits = instr_get_raw_bits(instr);
                        len = instr_length(dcontext, instr);
                    }
                    instr_set_target(instr, opnd_create_instr(tgt));
                    if (bits != 0)
                        instr_set_raw_bits(instr, bits, len);
                    DOLOG(4, LOG_ALL, { loginst(dcontext, 4, tgt, "\tcti targets this"); });
                    break;
                }
            }
        }
    }

    DOLOG(4, LOG_ALL, { 
        LOG(THREAD, LOG_ALL, 4, "afterward:\n");
        instrlist_disassemble(dcontext, 0, ilist, THREAD);
    });
    LOG(THREAD, LOG_ALL, 4, "done with instrlist_decode_cti\n");
}

/****************************************************************************/
/* utility routines */

/**************** SJF flags functions *******************/
/* Just checks to see if opcode is one that allows the bit to be set. */

DR_API
bool
instr_is_shift_type( instr_t* instr )
{
    int opc = instr_get_opcode(instr);

    if( opc == OP_and_rsr || opc == OP_and_reg ||
        opc == OP_add_sp_reg || opc == OP_add_rsr ||
        opc == OP_add_reg || opc == OP_adc_reg ||
        opc == OP_adc_rsr || opc == OP_bic_reg ||
        opc == OP_bic_rsr || opc == OP_cmn_reg ||
        opc == OP_cmn_rsr || opc == OP_cmp_reg || 
        opc == OP_cmp_rsr || opc == OP_eor_reg || 
        opc == OP_eor_rsr || opc == OP_ldr_reg ||
        opc == OP_ldrb_reg || opc == OP_ldrbt ||
        opc == OP_ldrt || opc == OP_mvn_reg ||
        opc == OP_mvn_rsr || opc == OP_orr_reg || 
        opc == OP_orr_rsr || opc == OP_pld_reg || 
        opc == OP_pli_reg || opc == OP_rsb_reg ||
        opc == OP_rsb_rsr || opc == OP_rsc_reg ||
        opc == OP_rsc_rsr || opc == OP_sbc_reg ||
        opc == OP_sbc_rsr || opc == OP_str_reg ||
        opc == OP_strb_reg|| opc == OP_strbt ||
        opc == OP_sub_reg || opc == OP_sub_rsr ||
        opc == OP_sub_sp_reg || opc == OP_teq_reg ||
        opc == OP_teq_rsr  || opc == OP_tst_reg || 
        opc == OP_tst_rsr  )
        return true;
    else
        return false;
}

DR_API
bool
instr_has_l_flag( instr_t* instr )
{
    //TODO SJF Do this
    return false;
}

DR_API
bool
instr_has_b_flag( instr_t* instr )
{
    //TODO SJF Do this
    return false;
}

DR_API
bool
instr_has_h_flag( instr_t* instr )
{
    //TODO SJF Do this
    return false;
}

DR_API
bool
instr_has_m_flag( instr_t* instr )
{
    //TODO SJF Do this
    return false;
}

DR_API
bool
instr_has_r_flag( instr_t* instr )
{
    //TODO SJF Do this
    return false;
}

/*** TODO Add all this information to instr_info_t and change all calls ***/

DR_API
bool
opcode_has_s_flag( int opc )
{
    if( opc == OP_adc_imm || opc == OP_adc_reg ||
        opc == OP_adc_rsr || opc == OP_add_reg ||
        opc == OP_add_rsr || opc == OP_add_imm ||
        opc == OP_add_sp_imm || opc == OP_and_imm ||
        opc == OP_and_reg || opc == OP_and_rsr ||
        opc == OP_asr_imm || opc == OP_asr_reg ||
        opc == OP_bic_imm || opc == OP_bic_reg ||
        opc == OP_bic_rsr || opc == OP_eor_imm ||
        opc == OP_eor_reg || opc == OP_eor_rsr ||
        opc == OP_lsl_imm || opc == OP_lsl_reg ||
        opc == OP_lsr_imm || opc == OP_lsr_reg ||
        opc == OP_mla     || opc == OP_mov_imm ||
        opc == OP_mov_reg || opc == OP_mul ||
        opc == OP_mvn_imm || opc == OP_mvn_reg ||
        opc == OP_mvn_rsr || opc == OP_orr_imm ||
        opc == OP_orr_reg || opc == OP_orr_rsr ||
        opc == OP_ror_imm || opc == OP_ror_reg ||
        opc == OP_rrx || opc == OP_rsb_imm ||
        opc == OP_rsb_reg || opc == OP_rsb_rsr ||
        opc == OP_rsc_imm || opc == OP_rsc_reg ||
        opc == OP_rsc_rsr || opc == OP_sbc_imm ||
        opc == OP_sbc_reg || opc == OP_sbc_rsr ||
        opc == OP_smlal   || opc == OP_smull ||
        opc == OP_sub_imm || opc == OP_sub_reg ||
        opc == OP_sub_rsr || opc == OP_sub_sp_imm ||
        opc == OP_sub_sp_reg || opc == OP_umlal ||
        opc == OP_umull )
      return true;
    else
      return false;
}

DR_API
bool
instr_has_s_flag( instr_t* instr )
{
    int opc = instr_get_opcode(instr);

    return opcode_has_s_flag( opc );
}

DR_API
bool
opcode_has_w_flag( int opc )
{
    if( opc == OP_ldc_imm || opc == OP_ldc2_imm || 
        opc == OP_ldm  || opc == OP_ldmia ||
        opc == OP_ldmfd || opc == OP_ldmda ||
        opc == OP_ldmfa || opc == OP_ldmdb ||
        opc == OP_ldmea || opc == OP_ldmib ||
        opc == OP_ldmed || opc == OP_ldr_imm ||
        opc == OP_ldr_reg || opc == OP_ldrb_imm ||
        opc == OP_ldrb_reg || opc == OP_ldrd_imm ||
        opc == OP_ldrd_reg || opc == OP_ldrh_imm ||
        opc == OP_ldrh_reg || opc == OP_ldrsb_imm ||
        opc == OP_ldrsb_reg || opc == OP_ldrsb_imm ||
        opc == OP_ldrsh_reg || opc == OP_stc ||
        opc == OP_stc2 || opc == OP_stm ||
        opc == OP_stmia || opc == OP_stmfd ||
        opc == OP_stmda || opc == OP_stmfa ||
        opc == OP_stmdb || opc == OP_stmea ||
        opc == OP_stmib || opc == OP_stmed ||
        opc == OP_str_imm || opc == OP_str_reg ||
        opc == OP_strb_imm || opc == OP_strb_reg ||
        opc == OP_strd_imm || opc == OP_strd_reg ||
        opc == OP_strh_imm || opc == OP_strh_reg )
      return true;
    else
      return false;
}

DR_API
bool
instr_has_w_flag( instr_t* instr )
{
    int opc = instr_get_opcode(instr);

    return opcode_has_w_flag( opc );
}

DR_API
bool
opcode_has_d_flag( int opc )
{
    if( opc == OP_ldc_imm || opc == OP_ldc2_imm ||
        opc == OP_ldc_lit || opc == OP_ldc2_lit ||
        opc == OP_stc || opc == OP_stc2 )
      return true;
    else
      return false;
}

DR_API
bool
instr_has_d_flag( instr_t* instr )
{
    int opc = instr_get_opcode(instr);

    return opcode_has_d_flag( opc );
}

DR_API
bool
opcode_has_u_flag( int opc )
{
    if( opc == OP_ldc_imm || opc == OP_ldc2_imm ||
        opc == OP_ldc_lit || opc == OP_ldc2_lit || 
        opc == OP_ldr_imm || opc == OP_ldr_lit ||
        opc == OP_ldr_reg || opc == OP_ldrb_reg ||
        opc == OP_ldrb_imm || opc == OP_ldrb_lit ||
        opc == OP_ldrbt || opc == OP_ldrd_imm ||
        opc == OP_ldrd_lit || opc == OP_ldrd_reg ||
        opc == OP_ldrh_imm || opc == OP_ldrh_lit ||
        opc == OP_ldrh_reg || opc == OP_ldrht ||
        opc == OP_ldrsb_imm || opc == OP_ldrsb_lit ||
        opc == OP_ldrsb_reg || opc == OP_ldrsbt ||
        opc == OP_ldrsh_imm || opc == OP_ldrsh_lit || 
        opc == OP_ldrsh_reg || opc == OP_ldrsht ||
        opc == OP_ldrt || opc == OP_pld_imm ||
        opc == OP_pld_lit || opc == OP_pld_reg ||
        opc == OP_pli_imm || opc == OP_pli_lit ||
        opc == OP_pli_reg || opc == OP_stc ||
        opc == OP_stc2 || opc == OP_str_imm || 
        opc == OP_str_reg || opc == OP_strb_imm ||
        opc == OP_strb_reg || opc == OP_strbt ||
        opc == OP_strd_imm || opc == OP_strd_reg ||
        opc == OP_strh_imm || opc == OP_strh_reg ||
        opc == OP_strht || opc == OP_strt )
      return true;
    else
      return false;
}

DR_API
bool
instr_has_u_flag( instr_t* instr )
{
    int opc = instr_get_opcode(instr);

    return opcode_has_u_flag( opc );
}

DR_API
bool
opcode_has_p_flag( int opc )
{
    if( opc == OP_ldc_imm || opc == OP_ldc2_imm ||
        opc == OP_ldr_imm || opc == OP_ldr_reg || 
        opc == OP_ldrb_imm || opc == OP_ldrb_reg ||
        opc == OP_ldrd_imm || opc == OP_ldrd_reg ||
        opc == OP_ldrh_imm || opc == OP_ldrh_reg ||
        opc == OP_ldrsb_imm || opc == OP_ldrsb_reg ||
        opc == OP_ldrsb_imm || opc == OP_ldrsh_reg ||
        opc == OP_stc || opc == OP_stc2 ||
        opc == OP_str_imm || opc == OP_str_reg ||
        opc == OP_strb_imm || opc == OP_strb_reg ||
        opc == OP_strd_imm || opc == OP_strd_reg ||
        opc == OP_strh_imm || opc == OP_strh_reg )
      return true;
    else
      return false;
}

DR_API
bool
instr_has_p_flag( instr_t* instr )
{
    int opc = instr_get_opcode(instr);

    return opcode_has_p_flag( opc );
}


/************ SJF: Functions to allow setting of flags against an instr type ***********/

DR_API
bool
instr_set_shift_type( dcontext_t* dcontext, instr_t* instr, int val )
{
  ASSERT( instr != NULL );

  instr->shift_type = val;
}

DR_API
bool
instr_set_p_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_p_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 3,
        "decode: attempt to set p flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->p_flag = val;
}

DR_API
bool
instr_set_u_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_u_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 3,
        "decode: attempt to set u flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->u_flag = val;
}

DR_API
bool
instr_set_s_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_s_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 1,
        "decode: attempt to set s flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->s_flag = val;
}

DR_API
bool
instr_set_w_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_w_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 1,
        "decode: attempt to set w flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->w_flag = val;
}

DR_API
bool
instr_set_l_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_l_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 1,
        "decode: attempt to set l flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->l_flag = val;
}

DR_API
bool
instr_set_b_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_b_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 1,
        "decode: attempt to set b flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->b_flag = val;
}

DR_API
bool
instr_set_d_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_d_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 1,
        "decode: attempt to set d flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->d_flag = val;
}

DR_API
bool
instr_set_h_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_h_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 1,
        "decode: attempt to set h flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->h_flag = val;
}

DR_API
bool
instr_set_m_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_m_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 1,
        "decode: attempt to set m flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->m_flag = val;
}

DR_API
bool
instr_set_r_flag( dcontext_t* dcontext, instr_t* instr, bool val )
{
  if( !instr_has_r_flag( instr ))
  {
    LOG(THREAD, LOG_INTERP, 1,
        "decode: attempt to set r flag for invalid instr '%d' \n",
        instr->opcode );
    /*SJF: Exit process here? Might be worthwhile as should not 
           try to set a value that shouldnt be set */
  }

  instr->r_flag = val;
}

void
instr_set_flags_from_di( instr_t* instr, decode_info_t* di )
{
    ASSERT(instr != NULL && di != NULL );

    instr->cond = di->cond;

    instr->p_flag = di->p_flag;
    instr->u_flag = di->u_flag;
    instr->s_flag = di->s_flag;
    instr->w_flag = di->w_flag;
    instr->l_flag = di->l_flag;
    instr->b_flag = di->b_flag;
    instr->d_flag = di->d_flag;
    instr->h_flag = di->h_flag;
    instr->m_flag = di->m_flag;
    instr->r_flag = di->r_flag;

    instr->shift_type = di->shift_type;
}

void 
loginst(dcontext_t *dcontext, uint level, instr_t *instr, const char *string)
{
    DOLOG(level, LOG_ALL, {
        LOG(THREAD, LOG_ALL, level, "%s: ", string);
        instr_disassemble(dcontext,instr,THREAD);
        LOG(THREAD, LOG_ALL, level,"\n");
    });
}

void 
logopnd(dcontext_t *dcontext, uint level, opnd_t opnd, const char *string) 
{
    DOLOG(level, LOG_ALL, {
        LOG(THREAD, LOG_ALL, level, "%s: ", string);
        opnd_disassemble(dcontext, opnd, THREAD);
        LOG(THREAD, LOG_ALL, level,"\n");
    });
}


void
logtrace(dcontext_t *dcontext, uint level, instrlist_t *trace, const char *string)
{
    DOLOG(level, LOG_ALL, {
        instr_t *inst;
        instr_t *next_inst;
        LOG(THREAD, LOG_ALL, level, "%s:\n", string);
        for (inst = instrlist_first(trace); inst != NULL; inst = next_inst) {
            next_inst = instr_get_next(inst);
            instr_disassemble(dcontext, inst, THREAD);
            LOG(THREAD, LOG_ALL, level, "\n");
        }
        LOG(THREAD, LOG_ALL, level, "\n");
    });
}

/* Shrinks all registers not used as addresses, and all immed int and
 * address sizes, to 16 bits
 */
void
instr_shrink_to_16_bits(instr_t *instr)
{
    int i;
    opnd_t opnd;
    const instr_info_t * info;
    byte optype;
    CLIENT_ASSERT(instr_operands_valid(instr), "instr_shrink_to_16_bits: invalid opnds");
    info = get_encoding_info(instr);
    for (i=0; i<instr_num_dsts(instr); i++) {
        opnd = instr_get_dst(instr, i);
        /* some non-memory references vary in size by addr16, not data16:
         * e.g., the edi/esi inc/dec of string instrs
         */
        optype = instr_info_opnd_type(info, false/*dst*/, i);
        if (!opnd_is_memory_reference(opnd) &&
            !optype_is_indir_reg(optype)) {
            instr_set_dst(instr, i, opnd_shrink_to_16_bits(opnd));
        }
    }
    for (i=0; i<instr_num_srcs(instr); i++) {
        opnd = instr_get_src(instr, i);
        optype = instr_info_opnd_type(info, true/*dst*/, i);
        if (!opnd_is_memory_reference(opnd) &&
            !optype_is_indir_reg(optype)) {
            instr_set_src(instr, i, opnd_shrink_to_16_bits(opnd));
        }
    }
}

bool
instr_uses_reg(instr_t *instr, reg_id_t reg)
{
    return (instr_reg_in_dst(instr,reg)||instr_reg_in_src(instr,reg));
}

bool instr_reg_in_dst(instr_t *instr, reg_id_t reg)
{
    int i;
    for (i=0; i<instr_num_dsts(instr); i++)
        if (opnd_uses_reg(instr_get_dst(instr, i), reg))
            return true;
    return false;
}

bool
instr_reg_in_src(instr_t *instr, reg_id_t reg)
{
    int i;
/* TODO SJF Removed 
    if (instr_get_opcode(instr) == OP_nop_modrm)
        return false;
*/
    for (i =0; i<instr_num_srcs(instr); i++)
        if (opnd_uses_reg(instr_get_src(instr, i), reg))
            return true;
    return false;
}

/* checks regs in dest base-disp but not dest reg */
bool
instr_reads_from_reg(instr_t *instr, reg_id_t reg)
{
    int i;
    opnd_t opnd;

    if (instr_reg_in_src(instr, reg))
        return true;

    for (i=0; i<instr_num_dsts(instr); i++) {
        opnd = instr_get_dst(instr, i);
        if (!opnd_is_reg(opnd) && opnd_uses_reg(opnd, reg))
            return true;
    }
    return false;
}

/* this checks sub-registers */
bool instr_writes_to_reg(instr_t *instr, reg_id_t reg)
{
    int i;
    opnd_t opnd;

    for (i=0; i<instr_num_dsts(instr); i++) {
        opnd=instr_get_dst(instr, i);
        if (opnd_is_reg(opnd)&&(dr_reg_fixer[opnd_get_reg(opnd)]==dr_reg_fixer[reg]))
            return true;
    }
    return false;
}

/* in this func, it must be the exact same register, not a sub reg. ie. eax!=ax */
bool instr_writes_to_exact_reg(instr_t *instr, reg_id_t reg)
{
    int i;
    opnd_t opnd;

    for (i=0; i<instr_num_dsts(instr); i++) {
        opnd=instr_get_dst(instr, i);
        if (opnd_is_reg(opnd)&&(opnd_get_reg(opnd)==reg))
            return true;
    }
    return false;
}

bool instr_replace_src_opnd(instr_t *instr, opnd_t old_opnd, opnd_t new_opnd)
{
    int srcs,a;
    
    srcs=instr_num_srcs(instr);
    
    for (a=0;a<srcs;a++) {
        if (opnd_same(instr_get_src(instr,a),old_opnd)||
            opnd_same_address(instr_get_src(instr,a),old_opnd)) {
            instr_set_src(instr,a,new_opnd);
            return true;
        }
    }
    return false;
}


bool instr_same(instr_t *inst1,instr_t *inst2)
{
    int dsts,srcs,a;

    if (instr_get_opcode(inst1)!=instr_get_opcode(inst2))
        return false;

    if ((srcs=instr_num_srcs(inst1))!=instr_num_srcs(inst2))
        return false;
    for (a=0;a<srcs;a++) {
        if (!opnd_same(instr_get_src(inst1,a),instr_get_src(inst2,a)))
            return false;
    }

    if ((dsts=instr_num_dsts(inst1))!=instr_num_dsts(inst2))
        return false;
    for (a=0;a<dsts;a++) {
        if (!opnd_same(instr_get_dst(inst1,a),instr_get_dst(inst2,a)))
            return false;
    }

    return true;
}

bool instr_reads_memory(instr_t *instr)
{
    int a;
    opnd_t curop;
    int opc = instr_get_opcode(instr);

    for (a=0; a<instr_num_srcs(instr); a++) {
        curop = instr_get_src(instr,a);
        if (opnd_is_memory_reference(curop)) {
            return true;
        }
    }
    return false;
}

bool instr_writes_memory(instr_t *instr)
{
    int a;
    opnd_t curop;
    for (a=0; a<instr_num_dsts(instr); a++) {
        curop = instr_get_dst(instr,a);
        if (opnd_is_memory_reference(curop)) {
            return true;
        }
    }
    return false;
}

bool
instr_is_our_mangling(instr_t *instr)
{
    return TEST(INSTR_OUR_MANGLING, instr->flags);
}

void
instr_set_our_mangling(instr_t *instr, bool ours)
{
    if (ours)
        instr->flags |= INSTR_OUR_MANGLING;
    else
        instr->flags &= ~INSTR_OUR_MANGLING;
}

/* Emulates instruction to find the address of the index-th memory operand.
 * Either or both OUT variables can be NULL.
 */
bool
instr_compute_address_ex_priv(instr_t *instr, priv_mcontext_t *mc, uint index,
                              OUT app_pc *addr, OUT bool *is_write,
                              OUT uint *pos)
{
    /* for string instr, even w/ rep prefix, assume want value at point of
     * register snapshot passed in
     */
    int i;
    opnd_t curop = {0};
    int memcount = -1;
    bool write = false;;
    for (i=0; i<instr_num_dsts(instr); i++) {
        curop = instr_get_dst(instr, i);
        if (opnd_is_memory_reference(curop)) {
            memcount++;
            if (memcount == (int)index) {
                write = true;
                break;
            }
        }
    }
#ifdef NO
    /* lea has a mem_ref source operand, but doesn't actually read */
    if (memcount != (int)index && instr_get_opcode(instr) != OP_lea) {
        for (i=0; i<instr_num_srcs(instr); i++) {
            curop = instr_get_src(instr, i);
            if (opnd_is_memory_reference(curop)) {
                memcount++;
                if (memcount == (int)index)
                    break;
            }
        }
    }
#endif
    if (memcount != (int)index)
        return false;
    if (addr != NULL)
        *addr = opnd_compute_address_priv(curop, mc);
    if (is_write != NULL)
        *is_write = write;
    if (pos != 0)
        *pos = i;
    return true;
}

DR_API
bool
instr_compute_address_ex(instr_t *instr, dr_mcontext_t *mc, uint index,
                         OUT app_pc *addr, OUT bool *is_write)
{
    /* only supports GPRs so we ignore mc.size */
    return instr_compute_address_ex_priv(instr, dr_mcontext_as_priv_mcontext(mc),
                                         index, addr, is_write, NULL);
}

/* i#682: add pos so that the caller knows which opnd is used. */
DR_API
bool
instr_compute_address_ex_pos(instr_t *instr, dr_mcontext_t *mc, uint index,
                             OUT app_pc *addr, OUT bool *is_write,
                             OUT uint *pos)
{
    /* only supports GPRs so we ignore mc.size */
    return instr_compute_address_ex_priv(instr, dr_mcontext_as_priv_mcontext(mc),
                                         index, addr, is_write, pos);
}

DR_API
/* Returns NULL if none of instr's operands is a memory reference.
 * Otherwise, returns the effective address of the first memory operand
 * when the operands are considered in this order: destinations and then
 * sources.  The address is computed using the passed-in registers.
 */
app_pc
instr_compute_address_priv(instr_t *instr, priv_mcontext_t *mc)
{
    app_pc addr;
    if (!instr_compute_address_ex_priv(instr, mc, 0, &addr, NULL, NULL))
        return NULL;
    return addr;
}

DR_API
app_pc
instr_compute_address(instr_t *instr, dr_mcontext_t *mc)
{
    /* only supports GPRs so we ignore mc.size */
    return instr_compute_address_priv(instr, dr_mcontext_as_priv_mcontext(mc));
}

/* Calculates the size, in bytes, of the memory read or write of instr
 * If instr does not reference memory, or is invalid, returns 0
 */
uint
instr_memory_reference_size(instr_t *instr)
{
    int i;
    if (!instr_valid(instr))
        return 0;
    for (i=0; i<instr_num_dsts(instr); i++) {
        if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
            return opnd_size_in_bytes(opnd_get_size(instr_get_dst(instr, i)));
        }
    }
    for (i=0; i<instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i))) {
            return opnd_size_in_bytes(opnd_get_size(instr_get_src(instr, i)));
        }
    }
    return 0;
}

/* Calculates the size, in bytes, of the memory read or write of
 * the instr at pc.
 * Returns the pc of the following instr.
 * If the instr at pc does not reference memory, or is invalid, 
 * returns NULL.
 */
app_pc
decode_memory_reference_size(dcontext_t *dcontext, app_pc pc, uint *size_in_bytes)
{
    app_pc next_pc;
    instr_t instr;
    instr_init(dcontext, &instr);
    next_pc = decode(dcontext, pc, &instr);
    if (!instr_valid(&instr))
        return NULL;
    CLIENT_ASSERT(size_in_bytes != NULL, "decode_memory_reference_size: passed NULL");
    *size_in_bytes = instr_memory_reference_size(&instr);
    instr_free(dcontext, &instr);
    return next_pc;
}

DR_API
dr_instr_label_data_t *
instr_get_label_data_area(instr_t *instr)
{
    CLIENT_ASSERT(instr != NULL, "invalid arg");
    if (instr_is_label(instr))
        return &instr->label_data;
    else
        return NULL;
}

/* return the branch type of the (branch) inst */
uint
instr_branch_type(instr_t *cti_instr)
{
    switch (instr_get_opcode(cti_instr)) {
    case OP_b:
    case OP_blx_imm:
        return LINK_DIRECT|LINK_JMP;   
    case OP_blx_reg:
    case OP_bx:
    case OP_bxj:
        return LINK_INDIRECT;
    case OP_bl:
        //Class bl's as a call as it saves the pc to lr
        return LINK_DIRECT|LINK_CALL; 
    case OP_mov_reg:
    case OP_mov_imm:
    case OP_ldr_reg:
    case OP_ldr_imm:
    case OP_ldr_lit:
    case OP_ldrb_imm:
    case OP_ldrb_lit:
    case OP_ldrb_reg:
    case OP_ldrbt:
    case OP_ldrd_imm:
    case OP_ldrd_lit:
    case OP_ldrd_reg:
    case OP_ldrex:
    case OP_ldrexb:
    case OP_ldrexd:
    case OP_ldrexh:
    case OP_ldrh_imm:
    case OP_ldrh_lit:
    case OP_ldrh_reg:
    case OP_ldrht:
    case OP_ldrsb_imm:
    case OP_ldrsb_lit:
    case OP_ldrsb_reg:
    case OP_ldrsbt:
    case OP_ldrsh_imm:
    case OP_ldrsh_lit:
    case OP_ldrsh_reg:
    case OP_ldrsht:
    case OP_ldrt:
        if( instr_is_return( cti_instr ))
          return LINK_INDIRECT|LINK_RETURN;
        //We know the opc is mov_reg/imm so can use this to just check the dest
        else if( instr_is_mbr( cti_instr ))
          return LINK_INDIRECT;
        //No break so falls through to error state if not mov cti

    default:
        LOG(THREAD_GET, LOG_ALL, 0, "branch_type: unknown opcode: %d\n",
            instr_get_opcode(cti_instr));
        CLIENT_ASSERT(false, "instr_branch_type: unknown opcode");
    }

    return LINK_INDIRECT;
}

DR_API
/* return the taken target pc of the (direct branch) inst */
app_pc
instr_get_branch_target_pc(instr_t *cti_instr)
{
    CLIENT_ASSERT(opnd_is_pc(instr_get_target(cti_instr)),
                  "instr_branch_target_pc: target not pc");
    return opnd_get_pc(instr_get_target(cti_instr));
}

DR_API
/* set the taken target pc of the (direct branch) inst */
void
instr_set_branch_target_pc(instr_t *cti_instr, app_pc pc)
{
    opnd_t op = opnd_create_pc(pc);
    instr_set_target(cti_instr, op);
}

DR_API
bool
instr_type_is_branch(int instr_type)
{
    return( instr_type == INSTR_TYPE_BRANCH );
}

int
opcode_get_encoding_type(int opc)
{
    switch( opc )
    {
      case OP_and_reg: case OP_adc_reg:
      case OP_add_reg: case OP_sub_reg:
      case OP_sbc_reg: case OP_rsc_reg:
      case OP_rsb_reg: case OP_orr_reg:
      case OP_eor_reg: case OP_bic_reg:
      case OP_ldrt:    case OP_ldr_reg:
      case OP_ldrb_reg: case OP_str_reg:
      case OP_strb_reg:
        return ENC_1DST_REG_2SRC_REG_1SRC_IMM;

      case OP_mvn_reg: case OP_add_sp_reg:
      case OP_sub_sp_reg: case OP_lsr_imm:
      case OP_ror_imm:
        return ENC_1DST_REG_1SRC_REG_1SRC_IMM_1;

      case OP_sub_imm: case OP_sbc_imm:
      case OP_rsc_imm: case OP_rsb_imm:
      case OP_orr_imm: case OP_bic_imm:
      case OP_eor_imm: case OP_and_imm:
      case OP_add_imm: case OP_adc_imm:
      case OP_str_imm: case OP_ldr_imm:
      case OP_ldrb_imm: case OP_strb_imm:
      case OP_strt:    case OP_strbt:
      case OP_ldrbt:
        return ENC_1DST_REG_1SRC_REG_1SRC_IMM_2;

      case OP_cmp_reg: case OP_cmn_reg:
      case OP_teq_reg: case OP_tst_reg:
        return ENC_1DST_REG_1SRC_REG_1SRC_IMM_3;

      case OP_strh_imm: case OP_ldrd_imm:
      case OP_ldrh_imm: case OP_ldrsb_imm:
      case OP_strd_imm: case OP_strht:
        return ENC_1DST_REG_1SRC_REG_1SRC_IMM_4;

      case OP_mov_reg: case OP_rrx:
        return ENC_1DST_REG_1SRC_REG_0SRC_IMM_1;

      case OP_ldrex: case OP_ldrexh:
      case OP_ldrexb:  case OP_ldrexd:
        return ENC_1DST_REG_1SRC_REG_0SRC_IMM_2;

      case OP_sel:
      case OP_rbit:    case OP_rev:
      case OP_rev16:   case OP_revsh:
        return ENC_1DST_REG_1SRC_REG_0SRC_IMM_1;

      case OP_add_sp_imm: case OP_adr:
      case OP_cmn_imm:    case OP_cmp_imm:
      case OP_teq_imm:    case OP_tst_imm:
        return ENC_1DST_REG_0SRC_REG_1SRC_IMM_1;

      case OP_sub_sp_imm: case OP_mvn_imm:
      case OP_mov_imm:    case OP_ldr_lit:
      case OP_ldrb_lit:
        return ENC_1DST_REG_0SRC_REG_1SRC_IMM_2;

      case OP_ldrd_lit:   case OP_ldrh_lit:
      case OP_ldrsb_lit:  case OP_ldrsh_lit:
        return ENC_1DST_REG_0SRC_REG_1SRC_IMM_3;

      case OP_lsl_reg:    case OP_lsr_reg:
      case OP_asr_reg:    case OP_ror_reg:
      case OP_mvn_rsr:
        return ENC_1DST_REG_2SRC_REG_0SRC_IMM_1;

      case OP_mul:
        return ENC_1DST_REG_2SRC_REG_0SRC_IMM_2;

      case OP_cmn_rsr:    case OP_cmp_rsr:
      case OP_teq_rsr:    case OP_tst_rsr:
        return ENC_1DST_REG_2SRC_REG_0SRC_IMM_3;

      case OP_ldrd_reg:
        return ENC_1DST_REG_2SRC_REG_0SRC_IMM_4;

      case OP_qadd:       case OP_qadd16:
      case OP_qadd8:      case OP_qdadd:
      case OP_qsub:       case OP_strh_reg:
      case OP_ldrh_reg:   case OP_ldrht:
      case OP_ldrsbt:     case OP_ldrsh_reg:
      case OP_strd_reg:   case OP_ldrsht:
      case OP_swp:        case OP_swpb:
      case OP_strex:      case OP_strexb:
      case OP_strexd:     case OP_strexh:
      case OP_sadd16:     case OP_sasx:
      case OP_ssub16:     case OP_sadd8:
      case OP_ssub8:      case OP_qasx:
      case OP_qsax:       case OP_qsub16:
      case OP_qsub8:      case OP_shadd16:
      case OP_shadd8:     case OP_shsax:
      case OP_shsub16:    case OP_shsub8:
        return ENC_1DST_REG_2SRC_REG_0SRC_IMM_5;

      case OP_stm:        case OP_stmia:
      case OP_stmea:      case OP_stmda:
      case OP_stmed:      case OP_stmdb:
      case OP_stmfd:      case OP_ldm:
      case OP_ldmda:      case OP_ldmfa: 
      case OP_ldmia:      case OP_ldmfd:
      case OP_ldmib:      case OP_ldmed:
        return ENC_0DST_REG_1SRC_REGLIST; 

      case OP_pop:        case OP_push:
        return ENC_1DST_REG_1SRC_REGLIST; 

      case OP_b:          case OP_bl:
      case OP_blx_imm:    case OP_blx_reg:
      case OP_bx:         case OP_bxj:
        return BRANCH_INSTR;

      case OP_mrc:        case OP_mrc2:
        return COPROC_MRC;
      case OP_mcr:        case OP_mcr2:
        return COPROC_MCR;

      default:
        return INVALID_ENCODING;
    }
}

bool
opcode_is_zero_extend( int opc )
{
  if( opc == OP_add_sp_imm || opc == OP_bkpt ||
      opc == OP_ldc_imm    || opc == OP_ldc2_imm ||
      opc == OP_ldc_lit    || opc == OP_ldc2_lit ||
      opc == OP_ldr_imm    ||
      opc == OP_ldr_lit    || opc == OP_ldrb_imm ||
      opc == OP_ldrb_lit   || opc == OP_ldrbt    ||
      opc == OP_ldrd_imm   || opc == OP_ldrd_lit ||
      opc == OP_ldrh_imm   || opc == OP_ldrh_lit ||
      opc == OP_ldrht      || opc == OP_ldrsb_imm ||
      opc == OP_ldrsb_lit  || opc == OP_ldrsbt   ||
      opc == OP_ldrsh_imm  || opc == OP_ldrsh_lit ||
      opc == OP_ldrsht     || opc == OP_ldrt     ||
      opc == OP_pld_imm    || opc == OP_pldw_imm ||
      opc == OP_pld_lit    || opc == OP_pli_imm  ||
      opc == OP_pli_lit    || opc == OP_stc      ||
      opc == OP_stc2       || opc == OP_str_imm  ||
      opc == OP_strb_imm   || opc == OP_strbt    ||
      opc == OP_strd_imm   || opc == OP_strh_imm ||
      opc == OP_strht      || opc == OP_strt     ||
      opc == OP_sub_sp_imm || opc == OP_svc      )
    return true;
  else
    return false;
}

bool
opcode_is_sign_extend( int opc )
{
  return !opcode_is_zero_extend( opc );
}

bool
opcode_is_unconditional(int opc)
{
   if( opc == OP_cps     || opc == OP_setend  || opc == OP_pli_imm  ||
       opc == OP_pli_lit || opc == OP_pld_imm || opc == OP_pldw_imm ||
       opc == OP_pld_lit || opc == OP_clrex   || opc == OP_dsb      ||
       opc == OP_dmb     || opc == OP_isb     || opc == OP_pli_reg  ||
       opc == OP_pld_reg || opc == OP_pldw_reg|| opc == OP_srs      ||
       opc == OP_rfe     || opc == OP_blx_imm  ||
       opc == OP_ldc_imm || opc == OP_ldc2_imm|| opc == OP_ldc_lit  ||
       opc == OP_ldc2_lit || opc == OP_stc    || opc == OP_stc2     ||
       opc == OP_mcrr    || opc == OP_mcrr2   || opc == OP_mrrc     ||
       opc == OP_mrrc2   || opc == OP_cdp     || opc == OP_cdp2     ||
       opc == OP_mcr     || opc == OP_mcr2    || opc == OP_mrc      ||
       opc == OP_mrc2 )
     return true;
   else
     return false;
}

bool
opcode_is_other_relative( int opc )
{
  if( opc == OP_adr )
    return true;
  else
    return false;

}

bool 
opcode_is_possible_pc_read( int opc )
{
  //Add any possible pc read opcodes here
  if( opc == OP_add_reg || opc == OP_add_imm || 
      opc == OP_sub_reg || opc == OP_sub_imm )
    return true;
  else
    return false;
}

bool 
opcode_is_relative_load( int opc )
{
  if( opc == OP_ldc_lit   || opc == OP_ldc2_lit ||
      opc == OP_ldr_lit   || opc == OP_ldrb_lit ||
      opc == OP_ldrd_lit  || opc == OP_ldrh_lit ||
      opc == OP_ldrsb_lit || opc == OP_ldrsh_lit ||
      opc == OP_pld_lit   || opc == OP_pldw_lit ||
      opc == OP_pli_lit )
    return true;
  else
    return false;

}

bool 
opcode_is_cti(int opc)
{
   //A move instr to r15 is a control transfer instr.
   // Caller needs to verify that instr dst 1 is r15.
   // This will return true if the opcode could be a cti
   if( opc == OP_b || opc == OP_bl || opc == OP_blx_imm ||
       opc == OP_blx_reg || opc == OP_bx || 
       opc == OP_bxj || opc == OP_mov_reg || opc == OP_mov_imm ||
       (opc >= OP_ldr_imm && opc <= OP_ldrt ) || //All load instrs
       opc == OP_add_imm || opc == OP_sub_imm ||
       opc == OP_add_reg || opc == OP_sub_reg ||
       opc == OP_pop )
     return true;
   else
     return false;
}

bool
opcode_is_branch(int opc)
{
    return (opc == OP_b || opc == OP_bl || OP_blx_imm ||
            opc == OP_blx_reg || opc == OP_bx || opc == OP_bxj );
}

bool
instr_is_branch(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return opcode_is_branch(opc);
}

/* An exit CTI is a control-transfer instruction whose target
 * is a pc (and not an instr_t pointer).  This routine assumes
 * that no other input operands exist in a CTI.
 * An undecoded instr cannot be an exit cti.
 * This routine does NOT try to decode an opcode in a Level 1 or Level
 * 0 routine, and can thus be called on Level 0 routines.  
 */
bool
instr_is_exit_cti(instr_t *instr)
{
    int opc;
    opnd_t opnd;

    if (!instr_operands_valid(instr) || /* implies !opcode_valid */
        !instr_ok_to_mangle(instr))
        return false;

    return instr_is_cti( instr );

#if 0
    if (!instr_operands_valid(instr) || /* implies !opcode_valid */
        !instr_ok_to_mangle(instr))
        return false;

    if (instr_is_cti(instr) ) {
        /* far pc should only happen for mangle's call to here */
        return opnd_is_pc(instr_get_target(instr));
    }
    else
    {
       opc = instr_get_opcode(instr);

       if( opc == OP_mov_reg )
       {
           if( instr->dsts != NULL )
           {
             opnd = instr->dsts[0];

             if( opnd.kind == REG_kind )
             {
               if( opnd.value.reg == REG_R15 )
                 return true;
             }
           }
       }
    }

    return false;
#endif
}

bool
instr_is_unconditional(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return opcode_is_unconditional(opc);
}


bool 
instr_is_mov(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return (opc == OP_mov_imm || opc == OP_mov_reg || opc == OP_movt ); 
}


bool 
opcode_is_call(int opc)
{
    //SJF Treat branch link instrs as return instrs as
    // they store the pc to allow a return 
    return( opc == OP_bl || opc == OP_blx_imm || opc == OP_blx_reg );
}

// Shell function to stop compile errors.
// Remove this once other functons converted 
bool
instr_is_call(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    return opcode_is_call(opc);
}

bool
instr_is_pc_read( instr_t* instr )
{
  opnd_t opnd;

  ASSERT( (instr != NULL) );

  if( !opcode_is_possible_pc_read( instr->opcode ))
    return false;
  else
  {
    switch( instr->opcode)
    {
      case OP_add_reg:
      case OP_add_imm:
      case OP_sub_reg:
      case OP_sub_imm:
         //Check the source
         opnd = instr->src0;

         if( opnd.kind == REG_kind )
         {
           if( opnd.value.reg == REG_RR15 )
             return true;
         }
        break;

      default:
        break;
    }
  }

  return false;
}

//Returns true if instr is a mov_reg/imm that writes to the pc
DR_API
bool
instr_is_mov_br(instr_t* instr)
{
   int opc = instr_get_opcode(instr);
   opnd_t opnd;

   if( opc == OP_mov_reg || opc == OP_mov_imm || 
       ( opc >= OP_ldr_imm && opc <= OP_ldrt ) ||
       opc == OP_add_imm || opc == OP_sub_imm ||
       opc == OP_add_reg || opc == OP_sub_reg )
   {
       //Make sure there are dsts
       if( instr->dsts != NULL )
       {
         opnd = instr->dsts[0];

         if( opnd.kind == REG_kind )
         {
           if( opnd.value.reg == REG_RR15 )
             return true;
         }
      }
   }
   else if( opc == OP_pop )
   {
     if( instr->src0.kind == REG_LIST_kind )
     {
       if( ( instr->src0.value.reg_list & REGLIST_R15 ) == REGLIST_R15 )
       {
         return true;
       }
     }
   }
  
   return false;
}


DR_API
int
instr_get_cond(instr_t *instr)
{
   if( instr != NULL )
     return instr->cond;
   else
     return -1;
}

DR_API
bool
instr_is_mbr(instr_t *instr)    /* Multi path??? branch */
{
   int opc = instr_get_opcode(instr);
   opnd_t opnd;

   /* Only branch instruction that allows reg as src */
   if( opc == OP_blx_reg || opc == OP_bx || opc == OP_bxj  )
     return true;
   else
     return instr_is_mov_br( instr );
}


DR_API
int
invert_cond_code( int cond )
{
  if( cond > COND_INVALID || cond < COND_EQUAL )
    return -1;

  switch( cond )
  {
    case COND_ALWAYS:
      return COND_ALWAYS;
    case COND_EQUAL:
      return COND_NOT_EQUAL;
    case COND_NOT_EQUAL:
      return COND_EQUAL;
    case COND_CARRY_SET:
      return COND_CARRY_CLEAR;
    case COND_CARRY_CLEAR:
      return COND_CARRY_SET;
    case COND_MINUS:
      return COND_PLUS;
    case COND_PLUS:
      return COND_MINUS;
    case COND_OVERFLOW:
      return COND_NO_OVERFLOW;
    case COND_NO_OVERFLOW:
      return COND_OVERFLOW;
    case COND_HIGHER:
      return COND_LOWER_OR_SAME;
    case COND_LOWER_OR_SAME:
      return COND_HIGHER;
    case COND_SIGNED_GREATER_THAN_OR_EQUAL:
      return COND_SIGNED_LESS_THAN;
    case COND_SIGNED_LESS_THAN:
      return COND_SIGNED_GREATER_THAN_OR_EQUAL;
    case COND_SIGNED_GREATER_THAN:
      return COND_SIGNED_LESS_THAN_OR_EQUAL;
    case COND_SIGNED_LESS_THAN_OR_EQUAL:
      return COND_SIGNED_GREATER_THAN;

    default:
      return -1;
  }
}


DR_API
bool
instr_is_cbr(instr_t *instr)    /* Conditional branch */
{
   int cond = instr_get_cond(instr);
   int opc = instr_get_opcode(instr);

   if( opc != OP_b       && opc != OP_bl      && opc != OP_bx  &&
       opc != OP_blx_imm && opc != OP_blx_reg && opc != OP_bxj )
   {
     if( !instr_is_mov_br( instr ))
       return false;
   }

   return (cond != COND_ALWAYS);
}

bool
instr_is_ubr(instr_t *instr)      /* unconditional branch */
{
   int cond = instr_get_cond(instr);
   int opc = instr_get_opcode(instr);

   if( opc != OP_b && opc != OP_bl && opc != OP_bx &&
       opc != OP_blx_imm && opc != OP_blx_reg )
   {
     if( !instr_is_mov_br( instr ))
       return false;
   }

   return (cond == COND_ALWAYS);
}


bool
instr_is_cti(instr_t *instr)      /* any control-transfer instruction */
{
    return (instr_is_ubr(instr) || instr_is_cbr(instr) || instr_is_mbr(instr));
}


/* SJF If it is a mov instr where it writes to R15 from R14 
       then it is a return instruction */
bool
instr_is_return(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    bool dst_r15 = false, src_r14 = false;
    opnd_t opnd;

    if (opc == OP_mov_reg)
    {
      if( instr->dsts != NULL )
      {
        opnd = instr->dsts[0];
 
        if( opnd.kind == REG_kind )
        {
           if( opnd.value.reg == DR_REG_R15 )
             dst_r15 = true;
        }
      }

      opnd = instr->src0;

      if( opnd.kind == REG_kind )
      {
         if( opnd.value.reg == DR_REG_R14 )
           src_r14 = true;
      }
    }

    return( dst_r15 && src_r14 );
}

bool
instr_is_syscall(instr_t *instr)
{
    int opc = instr_get_opcode(instr);

    if (opc == OP_svc)
        return true;

    return false;
}

/* looks for mov_imm and mov_st and xor w/ src==dst,
 * returns the constant they set their dst to
 */
bool
instr_is_mov_constant(instr_t *instr, ptr_int_t *value)
{
/* SJF Moves constant value into reg. Might be more. */
    int opc = instr_get_opcode(instr);
    if (opc == OP_eor_reg ) {
        if (opnd_same(instr_get_src(instr, 0), instr_get_dst(instr, 0))) {
            *value = 0;
            return true;
        } else
            return false;
    } else if (opc == OP_mov_imm) {
        opnd_t op = instr_get_src(instr, 0);
        if (opnd_is_immed_int(op)) {
            *value = opnd_get_immed_int(op);
            return true;
        } else
            return false;
    }
    return false;
}

bool
instr_is_floating_ex(instr_t *instr, dr_fp_type_t *type OUT)
{
    int opc = instr_get_opcode(instr);

    switch (opc) {
        /* TODO Add floating instrs here */

    default: return false;
    }
}

bool 
instr_is_floating(instr_t *instr)
{
    return instr_is_floating_ex(instr, NULL);
}

/* Returns true iff instr is a label meta-instruction */
bool 
instr_is_label(instr_t *instr)
{
    return instr_opcode_valid(instr) && instr_get_opcode(instr) == OP_LABEL;
}

/* Returns true iff instr is an "undefined" instruction (ud2) */
bool 
instr_is_undefined(instr_t *instr)
{
/* SJF No ARM undefined instruction opcode so return false */ 
  return false;
}

DR_API
/* Given a cbr, change the opcode (and potentially branch hint
 * prefixes) to that of the inverted branch condition.
 */
void
instr_invert_cbr(instr_t *instr)
{
    int opc = instr_get_opcode(instr);
    CLIENT_ASSERT(instr_is_cbr(instr), "instr_invert_cbr: instr not a cbr");
#ifdef NO
//TODO SJF Can just invert the cond code here 
    if (instr_is_cti_short_rewrite(instr, NULL)) {
        /* these all look like this:
                     jcxz cx_zero
                     jmp-short cx_nonzero
            cx_zero: jmp foo
            cx_nonzero:
         */
        if (instr_get_raw_byte(instr, 1) == 2) {
            CLIENT_ASSERT(instr_get_raw_byte(instr, 3) == 5,
                          "instr_invert_cbr: cti_short_rewrite is corrupted");
            /* swap targets of the short jumps: */
            instr_set_raw_byte(instr, 1, (byte)7); /* target cx_nonzero */
            instr_set_raw_byte(instr, 3, (byte)0); /* target next instr, cx_zero */
            /* with inverted logic we don't need jmp-short but we keep it in
             * case we get inverted again */
        } else {
            /* re-invert */
            CLIENT_ASSERT(instr_get_raw_byte(instr, 1) == 7 &&
                          instr_get_raw_byte(instr, 3) == 0,
                          "instr_invert_cbr: cti_short_rewrite is corrupted");
            instr_set_raw_byte(instr, 1, (byte)2);
            instr_set_raw_byte(instr, 3, (byte)5);
        }
    } else if (opc == OP_b) {
        switch (opc) {
        case OP_b:   opc = OP_b; break;
        default: CLIENT_ASSERT(false, "instr_invert_cbr: unknown opcode"); break;
        }
        instr_set_opcode(instr, opc);
    } else
        CLIENT_ASSERT(false, "instr_invert_cbr: unknown opcode");
#endif //NO
}

DR_API
/**
 * PR 266292:
 * Assumes that instr is a meta instruction (!instr_ok_to_mangle())
 * and an instr_is_cti_short() (8-bit reach).  Converts instr's opcode
 * to a long form (32-bit reach).  If instr's opcode is OP_loop* or
 * OP_jecxz, converts it to a sequence of multiple instructions (which
 * is different from instr_is_cti_short_rewrite()).  Each added instruction
 * is marked !instr_ok_to_mangle().
 * Returns the long form of the instruction, which is identical to \p instr
 * unless \p instr is OP_loop* or OP_jecxz, in which case the return value
 * is the final instruction in the sequence, the long jump to the taken target.
 * \note DR automatically converts non-meta short ctis to long form.
 */
instr_t *
instr_convert_short_meta_jmp_to_long(dcontext_t *dcontext, instrlist_t *ilist,
                                     instr_t *instr)
{
    return convert_to_near_rel_meta(dcontext, ilist, instr);
}

/* Given cpsr, returns whether or not the conditional branch opc would be taken */
/* TODO Need to pass cond codes in here maybe instead of opcode. */
bool
opc_branch_taken(int opc, reg_t cpsr)
{
    switch (opc) {
    case OP_b: 
      return false; 

    default:
        CLIENT_ASSERT(false, "instr_jcc_taken: unknown opcode");
        return false;
    }
}


/* Given cpsr, returns whether or not the conditional branch instr would be taken */
bool
instr_branch_taken(instr_t *instr, reg_t cpsr)
{
    int opc = instr_get_opcode(instr);
    CLIENT_ASSERT(instr_is_branch(instr),
                  "instr_branch_taken: instr not a branch");
    return opc_branch_taken(opc, cpsr);
}

/* Given a machine state, returns whether or not the cbr instr would be taken
 * if the state is before execution (pre == true) or after (pre == false).
 */
bool
instr_cbr_taken(instr_t *instr, priv_mcontext_t *mcontext, bool pre)
{
    return instr_branch_taken(instr, mcontext->cpsr);
}


DR_API
/* Converts a cmovcc opcode \p cmovcc_opcode to the OP_jcc opcode that
 * tests the same bits in eflags.
 */
int
instr_cmovcc_to_jcc(int cmovcc_opcode)
{
    int jcc_opc = OP_INVALID;
/* TODO SJF is this necessary anymore?? cond codes determine the 
	conditions the opcode has nothing to do with it anymore.
	So conversion between opcodes seems useless 
    if (cmovcc_opcode >= OP_cmovo && cmovcc_opcode <= OP_cmovnle) {
        jcc_opc = cmovcc_opcode - OP_cmovo + OP_jo;
    } else {
        switch (cmovcc_opcode) {
        case OP_fcmovb:   jcc_opc = OP_jb;   break;
        case OP_fcmove:   jcc_opc = OP_jz;   break;
        case OP_fcmovbe:  jcc_opc = OP_jbe;  break;
        case OP_fcmovu:   jcc_opc = OP_jp;   break;
        case OP_fcmovnb:  jcc_opc = OP_jnb;  break;
        case OP_fcmovne:  jcc_opc = OP_jnz;  break;
        case OP_fcmovnbe: jcc_opc = OP_jnbe; break;
        case OP_fcmovnu:  jcc_opc = OP_jnp;  break;
        default:
            CLIENT_ASSERT(false, "invalid cmovcc opcode");
            return OP_INVALID;
        }
    }
*/
    return jcc_opc;
}

bool
instr_uses_fp_reg(instr_t *instr)
{
    int a;
    opnd_t curop;
    for (a=0; a<instr_num_dsts(instr); a++) {
        curop = instr_get_dst(instr,a);
        if (opnd_is_reg(curop) && reg_is_fp(opnd_get_reg(curop)))
            return true;
        else if (opnd_is_memory_reference(curop)) {
            if (reg_is_fp(opnd_get_base(curop)))
                return true;
            else if (reg_is_fp(opnd_get_index(curop)))
                return true;
        }
    }
    
    for (a=0; a<instr_num_srcs(instr); a++) {
        curop = instr_get_src(instr,a);
        if (opnd_is_reg(curop) && reg_is_fp(opnd_get_reg(curop)))
            return true;
        else if (opnd_is_memory_reference(curop)) {
            if (reg_is_fp(opnd_get_base(curop)))
                return true;
            else if (reg_is_fp(opnd_get_index(curop)))
                return true;
        }
    }
    return false;
}

bool
reg_is_gpr(reg_id_t reg)
{
    return (reg >= REG_RR0 && reg <= REG_RR15);
}


/*TODO SJG Segments ??? */
bool
reg_is_segment(reg_id_t reg)
{
    return (reg >= SEG_ES && reg <= SEG_GS);
}

bool
reg_is_qwr(reg_id_t reg)
{
    return (reg>=REG_START_QWR && reg<=REG_STOP_QWR);
}

bool
reg_is_dwr(reg_id_t reg)
{
    return (reg>=REG_START_DWR && reg<=REG_STOP_DWR) ||
        reg_is_qwr(reg);
}

bool
reg_is_swr(reg_id_t reg)
{
    return (reg>=REG_START_SWR && reg<=REG_STOP_SWR);
}

bool
reg_is_fp(reg_id_t reg)
{
    return (reg>=REG_START_FLOAT && reg<=REG_STOP_FLOAT);
}

/***********************************************************************
 * instr_t creation routines
 * To use 16-bit data sizes, must call set_prefix after creating instr
 * To support this, all relevant registers must be of eAX form!
 * FIXME: how do that?
 * will an all-operand replacement work, or do some instrs have some
 * var-size regs but some const-size also?
 *
 * XXX: what if want eflags or modrm info on constructed instr?!?
 *
 * fld pushes onto top of stack, call that writing to ST0 or ST7?
 * f*p pops the stack -- not modeled at all!
 * should floating point constants be doubles, not floats?!?
 *
 * opcode complaints:
 * OP_imm vs. OP_st
 * OP_ret: build routines have to separate ret_imm and ret_far_imm
 * others, see FIXME's in instr_create.h
 */

instr_t * 
instr_create_0dst_0src(dcontext_t *dcontext, int opcode, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 0, 0);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_0dst_1src(dcontext_t *dcontext, int opcode, opnd_t src, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 0, 1);
    instr_set_src(in, 0, src);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_0dst_2src(dcontext_t *dcontext, int opcode,
                       opnd_t src1, opnd_t src2, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 0, 2);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_0dst_3src(dcontext_t *dcontext, int opcode,
                       opnd_t src1, opnd_t src2, opnd_t src3, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 0, 3);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_src(in, 2, src3);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_1dst_0src(dcontext_t *dcontext, int opcode, opnd_t dst, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 1, 0);
    instr_set_dst(in, 0, dst);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_1dst_1src(dcontext_t *dcontext, int opcode,
                       opnd_t dst, opnd_t src, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 1, 1);
    instr_set_dst(in, 0, dst);
    instr_set_src(in, 0, src);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_1dst_2src(dcontext_t *dcontext, int opcode,
                       opnd_t dst, opnd_t src1, opnd_t src2, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 1, 2);
    instr_set_dst(in, 0, dst);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_1dst_3src(dcontext_t *dcontext, int opcode,
                       opnd_t dst, opnd_t src1, opnd_t src2, opnd_t src3, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 1, 3);
    instr_set_dst(in, 0, dst);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_src(in, 2, src3);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_1dst_5src(dcontext_t *dcontext, int opcode,
                       opnd_t dst, opnd_t src1, opnd_t src2, opnd_t src3,
                       opnd_t src4, opnd_t src5, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 1, 5);
    instr_set_dst(in, 0, dst);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_src(in, 2, src3);
    instr_set_src(in, 3, src4);
    instr_set_src(in, 4, src5);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_2dst_0src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 2, 0);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_2dst_1src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t src, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 2, 1);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_src(in, 0, src);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_2dst_2src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t src1, opnd_t src2, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 2, 2);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_2dst_3src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t src1, opnd_t src2, opnd_t src3, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 2, 3);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_src(in, 2, src3);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_2dst_4src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2,
                       opnd_t src1, opnd_t src2, opnd_t src3, opnd_t src4, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 2, 4);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_src(in, 2, src3);
    instr_set_src(in, 3, src4);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_3dst_0src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 3, 0);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_dst(in, 2, dst3);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_3dst_3src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3,
                       opnd_t src1, opnd_t src2, opnd_t src3, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 3, 3);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_dst(in, 2, dst3);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_src(in, 2, src3);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_3dst_4src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3,
                       opnd_t src1, opnd_t src2, opnd_t src3, opnd_t src4, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 3, 4);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_dst(in, 2, dst3);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_src(in, 2, src3);
    instr_set_src(in, 3, src4);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_3dst_5src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3,
                       opnd_t src1, opnd_t src2, opnd_t src3,
                       opnd_t src4, opnd_t src5, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 3, 5);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_dst(in, 2, dst3);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_src(in, 2, src3);
    instr_set_src(in, 3, src4);
    instr_set_src(in, 4, src5);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_4dst_1src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3, opnd_t dst4,
                       opnd_t src, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 4, 1);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_dst(in, 2, dst3);
    instr_set_dst(in, 3, dst4);
    instr_set_src(in, 0, src);
    instr_set_cond(in, cond);
    return in;
}

instr_t * 
instr_create_4dst_4src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3, opnd_t dst4,
                       opnd_t src1, opnd_t src2, opnd_t src3, opnd_t src4, int cond)
{
    instr_t *in = instr_build(dcontext, opcode, 4, 4);
    instr_set_dst(in, 0, dst1);
    instr_set_dst(in, 1, dst2);
    instr_set_dst(in, 2, dst3);
    instr_set_dst(in, 3, dst4);
    instr_set_src(in, 0, src1);
    instr_set_src(in, 1, src2);
    instr_set_src(in, 2, src3);
    instr_set_src(in, 3, src4);
    instr_set_cond(in, cond);
    return in;
}

/* TODO SJF No pop or push instrs in ARM. Yes there is
instr_t *
instr_create_popa(dcontext_t *dcontext)
{
    instr_t *in = instr_build(dcontext, OP_popa, 8, 2);
    instr_set_dst(in, 0, opnd_create_reg(REG_RRR13));
    instr_set_dst(in, 1, opnd_create_reg(REG_EAX));
    instr_set_dst(in, 2, opnd_create_reg(REG_EBX));
    instr_set_dst(in, 3, opnd_create_reg(REG_ECX));
    instr_set_dst(in, 4, opnd_create_reg(REG_EDX));
    instr_set_dst(in, 5, opnd_create_reg(REG_EBP));
    instr_set_dst(in, 6, opnd_create_reg(REG_ESI));
    instr_set_dst(in, 7, opnd_create_reg(REG_EDI));
    instr_set_src(in, 0, opnd_create_reg(REG_RRR13));
    instr_set_src(in, 1, opnd_create_base_disp(REG_RRR13, REG_NULL, 0, 0, OPSZ_32_short16));
    return in;
}

instr_t *
instr_create_pusha(dcontext_t *dcontext)
{
    instr_t *in = instr_build(dcontext, OP_pusha, 2, 8);
    instr_set_dst(in, 0, opnd_create_reg(REG_RRR13));
    instr_set_dst(in, 1, opnd_create_base_disp(REG_RRR13, REG_NULL, 0, -32,
                                               OPSZ_32_short16));
    instr_set_src(in, 0, opnd_create_reg(REG_RRR13));
    instr_set_src(in, 1, opnd_create_reg(REG_EAX));
    instr_set_src(in, 2, opnd_create_reg(REG_EBX));
    instr_set_src(in, 3, opnd_create_reg(REG_ECX));
    instr_set_src(in, 4, opnd_create_reg(REG_EDX));
    instr_set_src(in, 5, opnd_create_reg(REG_EBP));
    instr_set_src(in, 6, opnd_create_reg(REG_ESI));
    instr_set_src(in, 7, opnd_create_reg(REG_EDI));
    return in;
}
*/

/****************************************************************************/
/* build instructions from raw bits
 * convention: give them OP_UNDECODED opcodes
 */

instr_t *
instr_create_raw_1byte(dcontext_t *dcontext, byte byte1)
{
    instr_t *in = instr_build_bits(dcontext, OP_UNDECODED, 1);
    instr_set_raw_byte(in, 0, byte1);
    return in;
}

instr_t *
instr_create_raw_2bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2)
{
    instr_t *in = instr_build_bits(dcontext, OP_UNDECODED, 2);
    instr_set_raw_byte(in, 0, byte1);
    instr_set_raw_byte(in, 1, byte2);
    return in;
}

instr_t *
instr_create_raw_3bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2, byte byte3)
{
    instr_t *in = instr_build_bits(dcontext, OP_UNDECODED, 3);
    instr_set_raw_byte(in, 0, byte1);
    instr_set_raw_byte(in, 1, byte2);
    instr_set_raw_byte(in, 2, byte3);
    return in;
}

instr_t *
instr_create_raw_4bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2, byte byte3,
                        byte byte4)
{
    instr_t *in = instr_build_bits(dcontext, OP_UNDECODED, 4);
    instr_set_raw_byte(in, 0, byte1);
    instr_set_raw_byte(in, 1, byte2);
    instr_set_raw_byte(in, 2, byte3);
    instr_set_raw_byte(in, 3, byte4);
    return in;
}

instr_t *
instr_create_raw_5bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2, byte byte3,
                        byte byte4, byte byte5)
{
    instr_t *in = instr_build_bits(dcontext, OP_UNDECODED, 5);
    instr_set_raw_byte(in, 0, byte1);
    instr_set_raw_byte(in, 1, byte2);
    instr_set_raw_byte(in, 2, byte3);
    instr_set_raw_byte(in, 3, byte4);
    instr_set_raw_byte(in, 4, byte5);
    return in;
}

instr_t *
instr_create_raw_6bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2, byte byte3,
                        byte byte4, byte byte5,
                        byte byte6)
{
    instr_t *in = instr_build_bits(dcontext, OP_UNDECODED, 6);
    instr_set_raw_byte(in, 0, byte1);
    instr_set_raw_byte(in, 1, byte2);
    instr_set_raw_byte(in, 2, byte3);
    instr_set_raw_byte(in, 3, byte4);
    instr_set_raw_byte(in, 4, byte5);
    instr_set_raw_byte(in, 5, byte6);
    return in;
}

instr_t *
instr_create_raw_7bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2, byte byte3,
                        byte byte4, byte byte5,
                        byte byte6, byte byte7)
{
    instr_t *in = instr_build_bits(dcontext, OP_UNDECODED, 7);
    instr_set_raw_byte(in, 0, byte1);
    instr_set_raw_byte(in, 1, byte2);
    instr_set_raw_byte(in, 2, byte3);
    instr_set_raw_byte(in, 3, byte4);
    instr_set_raw_byte(in, 4, byte5);
    instr_set_raw_byte(in, 5, byte6);
    instr_set_raw_byte(in, 6, byte7);
    return in;
}

instr_t *
instr_create_raw_8bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2, byte byte3,
                        byte byte4, byte byte5,
                        byte byte6, byte byte7,
                        byte byte8)
{
    instr_t *in = instr_build_bits(dcontext, OP_UNDECODED, 8);
    instr_set_raw_byte(in, 0, byte1);
    instr_set_raw_byte(in, 1, byte2);
    instr_set_raw_byte(in, 2, byte3);
    instr_set_raw_byte(in, 3, byte4);
    instr_set_raw_byte(in, 4, byte5);
    instr_set_raw_byte(in, 5, byte6);
    instr_set_raw_byte(in, 6, byte7);
    instr_set_raw_byte(in, 7, byte8);
    return in;
}

instr_t *
instr_create_nbyte_nop(dcontext_t *dcontext, uint num_bytes, bool raw)
{
    CLIENT_ASSERT(num_bytes != 0, "instr_create_nbyte_nop: 0 bytes passed");
    CLIENT_ASSERT(num_bytes <= 1, "instr_create_nbyte_nop: > 4 bytes not supported");
    /* INSTR_CREATE_nop*byte creates nop according to dcontext->x86_mode.
     * In x86_to_x64, we want to create x64 nop, but dcontext may be in x86 mode.
     * As a workaround, we call INSTR_CREATE_RAW_nop*byte here if in x86_to_x64.
     */
    if (raw IF_X64(|| DYNAMO_OPTION(x86_to_x64))) {
        switch(num_bytes) {
        case 1 :
            return INSTR_CREATE_RAW_nop1byte(dcontext, COND_ALWAYS);
        }
    } else {
        switch(num_bytes) {
        case 1 :
            return INSTR_CREATE_RAW_nop1byte(dcontext, COND_ALWAYS);
        }
    }
    CLIENT_ASSERT(false, "instr_create_nbyte_nop: invalid parameters");
    return NULL;
}

DR_API
/* Borrowed from optimize.c, prob. belongs here anyways, could make it more
 * specific to the ones we create above, but know it works as is FIXME */
/* return true if this instr is a nop, does not check for all types of nops 
 * since there are many, these seem to be the most common */
bool 
instr_is_nop(instr_t *inst)
{
    /* XXX: could check raw bits for 0x90 to avoid the decoding if raw */
    int opcode = instr_get_opcode(inst);

    if (opcode == OP_nop)
        return true;

    return false;
}

void 
instrlist_preinsert_move_32bits_to_reg(instrlist_t *ilist, dcontext_t *dcontext, 
                                reg_id_t target_reg, reg_id_t scratch, int target, instr_t* rel_instr, int cond )
{
    int value=0;
    instr_t* instr;

    ASSERT(( ilist != NULL ));

    instrlist_meta_preinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
            (dcontext, opnd_create_reg(target_reg), OPND_CREATE_IMM12(0), cond));

    //Add the value bit by bit
    //Top 8 bits
    value = ((int)target & 0xff000000) >> 24;

    instrlist_meta_preinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), cond));

    //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(8), cond);
    instr_set_shift_type(dcontext, instr, ROTATE_RIGHT); //Shift it by 8

    instrlist_meta_preinsert(ilist, rel_instr, instr);

    //Second 8 bits
    value = ((int)target & 0x00ff0000) >> 16;

    instrlist_meta_preinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), cond));

    //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(16), cond);
    instr_set_shift_type(dcontext, instr, ROTATE_RIGHT); //Shift it by 16

    instrlist_meta_preinsert(ilist, rel_instr, instr);
    //Third 8 bits
    value = ((int)target & 0x0000ff00) >> 8;

    instrlist_meta_preinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), cond));

      //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(24), cond);
    instr_set_shift_type(dcontext, instr, ROTATE_RIGHT); //Shift it by 24

    instrlist_meta_preinsert(ilist, rel_instr, instr);

    //Last 8 bits
    value = ((int)target & 0x000000ff);

    instrlist_meta_preinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), cond));

    //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(0), cond);
    instr_set_shift_type(dcontext, instr, LOGICAL_LEFT); //Shift it by 0

    instrlist_meta_preinsert(ilist, rel_instr, instr);
}

#ifndef STANDALONE_DECODER
/****************************************************************************/
/* dcontext convenience routines */


//SJF New opnd create functions.
// To do a load or store to dcontext with an offset from a base address
// Use mov_imm to get the offset into a reg then use ldr_reg to 
// load the value

static opnd_t
dcontext_opnd_common(dcontext_t *dcontext, bool absolute, reg_id_t basereg,
                     int offs, opnd_size_t size)
{
    /* offs is not raw offset, but includes upcontext size, so we
     * can tell unprotected from normal
     */
    if (TEST(SELFPROT_DCONTEXT, dynamo_options.protect_mask) &&
        offs < sizeof(unprotected_context_t)) {
        return opnd_create_base_disp(absolute ? REG_NULL :
                                  ((basereg == REG_NULL) ? REG_RR6 : basereg),
                                     REG_NULL, 0,
                                     ((int)(ptr_int_t)(absolute ?
                                            dcontext->upcontext.separate_upcontext : 0))
                                     + offs, size);
    } else {
        if (offs >= sizeof(unprotected_context_t))
            offs -= sizeof(unprotected_context_t);
        return opnd_create_base_disp(absolute ? REG_NULL :
                                     ((basereg == REG_NULL) ? REG_RR7 : basereg),
                                     REG_NULL, 0,
                                     ((int)(ptr_int_t)
                                      (absolute ? dcontext : 0)) + offs, size);
    }
}

opnd_t
opnd_create_dcontext_field_sz(dcontext_t *dcontext, int offs, opnd_size_t sz)
{
    return dcontext_opnd_common(dcontext, true, REG_NULL, offs, sz);
}

opnd_t
opnd_create_dcontext_field(dcontext_t *dcontext, int offs)
{
    return dcontext_opnd_common(dcontext, true, REG_NULL, offs, OPSZ_PTR);
}

/* use basereg==REG_NULL to get default (xdi, or xsi for upcontext) */
opnd_t
opnd_create_dcontext_field_via_reg_sz(dcontext_t *dcontext, reg_id_t basereg,
                                      int offs, opnd_size_t sz)
{
    return dcontext_opnd_common(dcontext, false, basereg, offs, sz);
}

/* use basereg==REG_NULL to get default (xdi, or xsi for upcontext) */
opnd_t
opnd_create_dcontext_field_via_reg(dcontext_t *dcontext, reg_id_t basereg, int offs)
{
    return dcontext_opnd_common(dcontext, false, basereg, offs, OPSZ_PTR);
}

opnd_t
opnd_create_dcontext_field_byte(dcontext_t *dcontext, int offs)
{
    return dcontext_opnd_common(dcontext, true, REG_NULL, offs, OPSZ_1);
}

void 
instrlist_postinsert_move_32bits_to_reg(instrlist_t *ilist, dcontext_t *dcontext, 
                                reg_id_t target_reg, reg_id_t scratch, int target, instr_t* rel_instr )
{
    int value=0;
    instr_t* instr;

    ASSERT(( ilist != NULL ));

    instrlist_meta_postinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
            (dcontext, opnd_create_reg(target_reg), OPND_CREATE_IMM12(0), COND_ALWAYS));

    //Add the value bit by bit
    //Top 8 bits
    value = ((int)target & 0xff000000) >> 24;

    instrlist_meta_postinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), COND_ALWAYS));

    //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(8), COND_ALWAYS);
    instr_set_shift_type(dcontext, instr, ROTATE_RIGHT); //Shift it by 8

    instrlist_meta_postinsert(ilist, rel_instr, instr);

    //Second 8 bits
    value = ((int)target & 0x00ff0000) >> 16;

    instrlist_meta_postinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), COND_ALWAYS));

    //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(16), COND_ALWAYS);
    instr_set_shift_type(dcontext, instr, ROTATE_RIGHT); //Shift it by 16

    instrlist_meta_postinsert(ilist, rel_instr, instr);
    //Third 8 bits
    value = ((int)target & 0x0000ff00) >> 8;

    instrlist_meta_postinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), COND_ALWAYS));

      //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(24), COND_ALWAYS);
    instr_set_shift_type(dcontext, instr, ROTATE_RIGHT); //Shift it by 24

    instrlist_meta_postinsert(ilist, rel_instr, instr);

    //Last 8 bits
    value = ((int)target & 0x000000ff);

    instrlist_meta_postinsert(ilist, rel_instr, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), COND_ALWAYS));

    //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(0), COND_ALWAYS);
    instr_set_shift_type(dcontext, instr, LOGICAL_LEFT); //Shift it by 0

    instrlist_meta_postinsert(ilist, rel_instr, instr);
}


void 
instrlist_append_move_32bits_to_reg(instrlist_t *ilist, dcontext_t *dcontext, 
                                reg_id_t target_reg, reg_id_t scratch, int target, int cond )
{
    int value=0;
    instr_t* instr;

    ASSERT(( ilist != NULL ));

    instrlist_meta_append(ilist, INSTR_CREATE_mov_imm
            (dcontext, opnd_create_reg(target_reg), OPND_CREATE_IMM12(0), cond));

    //Add the value bit by bit
    //Top 8 bits
    value = ((int)target & 0xff000000) >> 24;

    instrlist_meta_append(ilist, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), cond));

    //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(8), cond);
    instr_set_shift_type(dcontext, instr, ROTATE_RIGHT); //Shift it by 8

    instrlist_meta_append(ilist, instr);

    //Second 8 bits
    value = ((int)target & 0x00ff0000) >> 16;

    instrlist_meta_append(ilist, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), cond));

    //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(16), cond);
    instr_set_shift_type(dcontext, instr, ROTATE_RIGHT); //Shift it by 16

    instrlist_meta_append(ilist, instr);
    //Third 8 bits
    value = ((int)target & 0x0000ff00) >> 8;

    instrlist_meta_append(ilist, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), cond));

      //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(24), cond);
    instr_set_shift_type(dcontext, instr, ROTATE_RIGHT); //Shift it by 24

    instrlist_meta_append(ilist, instr);

    //Last 8 bits
    value = ((int)target & 0x000000ff);

    instrlist_meta_append(ilist, INSTR_CREATE_mov_imm
        (dcontext, opnd_create_reg(scratch), OPND_CREATE_IMM12(value), cond));

    //Rotate right by 8 to get top bits back in place
    instr = INSTR_CREATE_orr_reg
                (dcontext, opnd_create_reg(target_reg), opnd_create_reg(target_reg),
                 opnd_create_reg(scratch),
                 OPND_CREATE_IMM5(0), cond);
    instr_set_shift_type(dcontext, instr, LOGICAL_LEFT); //Shift it by 0

    instrlist_meta_append(ilist, instr);
}

void
instr_create_restore_from_dcontext(instrlist_t *ilist, dcontext_t *dcontext, reg_id_t reg, 
                                   int offs, int where, instr_t* rel_instr, bool absolute)
{
    int scratch  = REG_RR8;
    int scratch2 = REG_RR9;

    //Backup up scratch regs
    if( reg != REG_RR8 && reg != REG_RR9 )
    {
      switch( where )
      {
        case INSERT_APPEND:
          instrlist_meta_append( ilist, INSTR_CREATE_push(dcontext,
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
        case INSERT_PRE:
          instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_push(dcontext,
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
        case INSERT_POST:
          instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_push(dcontext,
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
      }
    }
    else
    {
      scratch  = REG_RR6;
      scratch2 = REG_RR7;

      switch( where )
      {
        case INSERT_APPEND:
          instrlist_meta_append( ilist, INSTR_CREATE_push(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
        case INSERT_PRE:
          instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_push(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
        case INSERT_POST:
          instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_push(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
      }
    }

    //Clobbers R8/R9 or R6/R7 
    if( where == INSERT_APPEND )
    {
      instrlist_append_move_32bits_to_reg( ilist, dcontext, scratch, scratch2, 
                                           (((int)(ptr_int_t)(absolute ? dcontext : 0)) + offs), COND_ALWAYS );

      if( reg >= REG_RR0 && reg <= REG_RR15 )
      {
        instrlist_meta_append( ilist, INSTR_CREATE_ldr_imm(dcontext, opnd_create_reg(reg),
                                        opnd_create_mem_reg(scratch),  
                                        OPND_CREATE_IMM12(0), COND_ALWAYS ));
      }
      else if( reg == REG_CPSR )
      {
        instrlist_meta_append( ilist, INSTR_CREATE_ldr_imm(dcontext, opnd_create_reg(scratch2),
                                        opnd_create_mem_reg(scratch),  
                                        OPND_CREATE_IMM12(0), COND_ALWAYS ));

        instrlist_meta_append( ilist, INSTR_CREATE_msr_cpsr(dcontext, scratch2));
      }
      else
        CLIENT_ASSERT(false,
                    "instr_create_restore_from_dcontext: invalid reg");
    }
    else if( where == INSERT_PRE )
    {
      instrlist_preinsert_move_32bits_to_reg( ilist, dcontext, scratch, scratch2, 
                                           (((int)(ptr_int_t)(absolute ? dcontext : 0)) + offs), rel_instr, COND_ALWAYS );

      if( reg >= REG_RR0 && reg <= REG_RR15 )
      {
        instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_ldr_imm(dcontext, opnd_create_reg(reg),
                                        opnd_create_mem_reg(REG_RR8),
                                        OPND_CREATE_IMM12(0), COND_ALWAYS ));
      }
      else if( reg == REG_CPSR )
      {
        instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_ldr_imm(dcontext, opnd_create_reg(scratch2),
                                        opnd_create_mem_reg(scratch),
                                        OPND_CREATE_IMM12(0), COND_ALWAYS ));

        instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_msr_cpsr(dcontext, scratch2));
      }
      else
        CLIENT_ASSERT(false,
                    "instr_create_restore_from_dcontext: invalid reg");

    }
    else if( where == INSERT_POST )
    {
      instrlist_postinsert_move_32bits_to_reg( ilist, dcontext, scratch, scratch2, 
                                           (((int)(ptr_int_t)(absolute ? dcontext : 0)) + offs), rel_instr );


      if( reg >= REG_RR0 && reg <= REG_RR15 )
      {
        instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_ldr_imm(dcontext, opnd_create_reg(reg),
                                        opnd_create_mem_reg(REG_RR8),
                                        OPND_CREATE_IMM12(0), COND_ALWAYS ));
      }
      else if( reg == REG_CPSR )
      {
        instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_ldr_imm(dcontext, opnd_create_reg(scratch2),
                                        opnd_create_mem_reg(scratch),
                                        OPND_CREATE_IMM12(0), COND_ALWAYS ));

        instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_msr_cpsr(dcontext, scratch2));
      }
      else
        CLIENT_ASSERT(false,
                    "instr_create_restore_from_dcontext: invalid reg");
    }
    else
      CLIENT_ASSERT(false,
                    "instr_create_restore_from_dcontext: invalid insert position");

   //Restore scratch regs
   if( reg != REG_RR8 && reg != REG_RR9 )
    {
      switch( where )
      {
        case INSERT_APPEND:
          instrlist_meta_append( ilist, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
        case INSERT_PRE:
          instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
        case INSERT_POST:
          instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
      }
    }
    else
    {
      switch( where )
      {
        case INSERT_APPEND:
          instrlist_meta_append( ilist, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
        case INSERT_PRE:
          instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
        case INSERT_POST:
          instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
      }
    }
}

instr_t *
instr_create_save_to_dcontext(instrlist_t *ilist, dcontext_t *dcontext, reg_id_t reg, 
                                   int offs, int where, instr_t* rel_instr, bool absolute)
{
    int target = (int)(ptr_int_t)(absolute ? dcontext : 0) + offs;
    int value=0;
    int target_reg = REG_RR8;
    int scratch = REG_RR9;
    instr_t* instr;

    //Backup up scratch regs
    if( reg != REG_RR8 && reg != REG_RR9 )
    {
      switch( where )
      {
        case INSERT_APPEND:
          instrlist_meta_append( ilist, INSTR_CREATE_push(dcontext, 
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
        case INSERT_PRE:
          instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_push(dcontext, 
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
        case INSERT_POST:
          instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_push(dcontext, 
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
      }
    }
    else
    {
      target_reg = REG_RR6;
      scratch = REG_RR7;

      switch( where )
      {
        case INSERT_APPEND:
          instrlist_meta_append( ilist, INSTR_CREATE_push(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
        case INSERT_PRE:
          instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_push(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
        case INSERT_POST:
          instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_push(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
      }

    }

    if( where == INSERT_APPEND )
    {
      instrlist_append_move_32bits_to_reg( ilist, dcontext, target_reg, scratch, 
                                           (((int)(ptr_int_t)(absolute ? dcontext : 0)) + offs), COND_ALWAYS );

      if( reg >= REG_RR0 && reg <= REG_RR15 )
      {
        //Save reg to the correct address calced above
        instrlist_meta_append( ilist, INSTR_CREATE_str_imm(dcontext, opnd_create_reg(reg),
                               opnd_create_mem_reg(target_reg), OPND_CREATE_IMM12(0), COND_ALWAYS ));
      }
      else if( reg == REG_CPSR )
      {
        instrlist_meta_append( ilist, INSTR_CREATE_mrs_cpsr(dcontext, scratch));

        instrlist_meta_append( ilist, INSTR_CREATE_str_imm(dcontext, opnd_create_reg(scratch),
                                        opnd_create_mem_reg(target_reg),
                                        OPND_CREATE_IMM12(0), COND_ALWAYS ));
      }
      else
        CLIENT_ASSERT(false,
                      "instr_create_save_to_dcontext: invalid insert position");
     

    }
    else if( where == INSERT_PRE )
    {
      instrlist_preinsert_move_32bits_to_reg( ilist, dcontext, target_reg, scratch, 
                                           (((int)(ptr_int_t)(absolute ? dcontext : 0)) + offs), rel_instr, COND_ALWAYS );


      if( reg >= REG_RR0 && reg <= REG_RR15 )
      {
        //Save reg to the correct address calced above
        instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_str_imm(dcontext, opnd_create_reg(reg),
                               opnd_create_mem_reg(target_reg), OPND_CREATE_IMM12(0), COND_ALWAYS ));
      }
      else if( reg == REG_CPSR )
      {
        instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_mrs_cpsr(dcontext, scratch));

        instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_str_imm(dcontext, opnd_create_reg(scratch),
                                        opnd_create_mem_reg(target_reg),
                                        OPND_CREATE_IMM12(0), COND_ALWAYS ));
      }
      else
        CLIENT_ASSERT(false,
                      "instr_create_save_to_dcontext: invalid insert position");

    }
    else if( where == INSERT_POST )
    {
      instrlist_postinsert_move_32bits_to_reg( ilist, dcontext, target_reg, scratch, 
                                           (((int)(ptr_int_t)(absolute ? dcontext : 0)) + offs), rel_instr );

      if( reg >= REG_RR0 && reg <= REG_RR15 )
      {
        //Save reg to the correct address calced above
        instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_str_imm(dcontext, opnd_create_reg(reg),
                               opnd_create_mem_reg(target_reg), OPND_CREATE_IMM12(0), COND_ALWAYS ));
      }
      else if( reg == REG_CPSR )
      {
        instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_mrs_cpsr(dcontext, scratch));

        instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_str_imm(dcontext, opnd_create_reg(scratch),
                                        opnd_create_mem_reg(target_reg),
                                        OPND_CREATE_IMM12(0), COND_ALWAYS ));
      }
      else
        CLIENT_ASSERT(false,
                      "instr_create_save_to_dcontext: invalid insert position");
    }
    else
      CLIENT_ASSERT(false,
                    "instr_create_save_to_dcontext: invalid insert position");


   //Restore scratch regs
   if( reg != REG_RR8 && reg != REG_RR9 )
    {
      switch( where )
      {
        case INSERT_APPEND:
          instrlist_meta_append( ilist, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
        case INSERT_PRE:
          instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
        case INSERT_POST:
          instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R8|REGLIST_R9),
                                                COND_ALWAYS ));
          break;
      }
    }
    else
    {
      switch( where )
      {
        case INSERT_APPEND:
          instrlist_meta_append( ilist, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
        case INSERT_PRE:
          instrlist_meta_preinsert( ilist, rel_instr, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
        case INSERT_POST:
          instrlist_meta_postinsert( ilist, rel_instr, INSTR_CREATE_pop(dcontext,
                                                opnd_create_reg_list(REGLIST_R6|REGLIST_R7),
                                                COND_ALWAYS ));
          break;
      }
    }
}

/* Use basereg==REG_NULL to get default (xdi, or xsi for upcontext) 
 * Auto-magically picks the mem opnd size to match reg if it's a GPR.
 */
instr_t *
instr_create_restore_from_dc_via_reg(dcontext_t *dcontext, reg_id_t basereg,
                                     reg_id_t reg, int offs)
{
/*  SJF Ignore this for now
    opnd_t memopnd = opnd_create_dcontext_field_via_reg_sz
        (dcontext, basereg, offs, reg_get_size(reg));

    return INSTR_CREATE_ldr_reg(dcontext, opnd_create_reg(reg), 
                                opnd_create_reg(basereg), opnd_create_reg(REG_NULL), 
                                OPND_CREATE_IMM5(0), COND_ALWAYS );
*/

  CLIENT_ASSERT( false, "Unfinished function \"instr_create_restore_from_dc_via_reg\" reached" );
}

/* Use basereg==REG_NULL to get default (xdi, or xsi for upcontext) 
 * Auto-magically picks the mem opnd size to match reg if it's a GPR.
 */
instr_t *
instr_create_save_to_dc_via_reg(dcontext_t *dcontext, reg_id_t basereg,
                                reg_id_t reg, int offs)
{
/* SJF Ignore for now 
    opnd_t memopnd = opnd_create_dcontext_field_via_reg_sz
                        (dcontext, basereg, offs, reg_get_size(reg));
    return INSTR_CREATE_str_reg(dcontext, opnd_create_reg(reg), memopnd,
                                opnd_create_reg(REG_NULL), OPND_CREATE_IMM5(0), COND_ALWAYS);
*/
  CLIENT_ASSERT( false, "Unfinished function \"instr_create_save_to_dc_via_reg\" reached" );
}

instr_t *
instr_create_save_immed_to_dcontext(dcontext_t *dcontext, int immed, int offs)
{
    opnd_t memopnd = opnd_create_dcontext_field(dcontext, offs);
    /* PR 244737: thread-private scratch space needs to fixed for x64 */
    IF_X64(ASSERT_NOT_IMPLEMENTED(false));
    return INSTR_CREATE_str_imm(dcontext, memopnd, opnd_create_reg(REG_NULL), OPND_CREATE_INT32(immed), COND_ALWAYS);
}

void
instr_create_branch_via_dcontext(instrlist_t* ilist, dcontext_t *dcontext, int offs)
{
 //SJF Clobbers r7 and r8

    //Calculate memory address and put into reg
    instrlist_meta_append( ilist, INSTR_CREATE_mov_imm( dcontext, opnd_create_reg(REG_RR8),
                                  OPND_CREATE_IMM12(offs), 
                                  COND_ALWAYS ));

    //load value from mem address in reg 8 into reg 7
    instrlist_meta_append(ilist, INSTR_CREATE_ldr_reg(dcontext, opnd_create_reg(REG_RR7),
                                                      opnd_create_mem_reg(REG_RR13),  
                                                      opnd_create_reg(REG_RR8),
                                                      OPND_CREATE_IMM5(0), COND_ALWAYS ));

    //Create an indirect branch. Which is just a 'mov pc, reg'
    instrlist_meta_append(ilist, INSTR_CREATE_branch_ind(dcontext, opnd_create_reg(REG_RR7)));
 
    return; 
}


/* there is no corresponding save routine since we no longer support
 * keeping state on the stack while code other than our own is running
 * (in the same thread)
 */
void
instr_create_restore_dynamo_stack(instrlist_t *ilist, dcontext_t *dcontext, 
                                  int where, instr_t* rel_instr, bool absolute)
{
    return instr_create_restore_from_dcontext(ilist, dcontext, REG_RR13, 
                                              DSTACK_OFFSET, where, rel_instr, absolute);
}

#ifdef RETURN_STACK
instr_t *
instr_create_restore_dynamo_return_stack(dcontext_t *dcontext)
{
    return instr_create_restore_from_dcontext(dcontext, REG_RR13,
                                              TOP_OF_RSTACK_OFFSET);
}

instr_t *
instr_create_save_dynamo_return_stack(dcontext_t *dcontext)
{
    return instr_create_save_to_dcontext(dcontext, REG_RR13,
                                         TOP_OF_RSTACK_OFFSET);
}
#endif

opnd_t
update_dcontext_address(opnd_t op, dcontext_t *old_dcontext,
                        dcontext_t *new_dcontext)
{
    int offs;
    CLIENT_ASSERT(opnd_is_near_base_disp(op) &&
           opnd_get_base(op) == REG_NULL &&
           opnd_get_index(op) == REG_NULL, "update_dcontext_address: invalid opnd");
    IF_X64(ASSERT_NOT_IMPLEMENTED(false));
    offs = opnd_get_disp(op) - (uint)(ptr_uint_t)old_dcontext;
    if (offs >= 0 && offs < sizeof(dcontext_t)) {
        /* don't pass raw offset, add in upcontext size */
        offs += sizeof(unprotected_context_t);
        return opnd_create_dcontext_field(new_dcontext, offs);
    }
    /* some fields are in a separate memory region! */
    else {
        CLIENT_ASSERT(TEST(SELFPROT_DCONTEXT, dynamo_options.protect_mask),
                      "update_dcontext_address: inconsistent layout");
        IF_X64(ASSERT_NOT_IMPLEMENTED(false));
        offs = opnd_get_disp(op) -
            (uint)(ptr_uint_t)(old_dcontext->upcontext.separate_upcontext);
        if (offs >= 0 && offs < sizeof(unprotected_context_t)) {
            /* raw offs is what we want for upcontext */
            return opnd_create_dcontext_field(new_dcontext, offs);
        }
    }
    /* not a dcontext offset: just return original value */
    return op;
}

opnd_t
opnd_create_tls_slot(int offs)
{
    return opnd_create_sized_tls_slot(offs, OPSZ_PTR);
}

opnd_t
opnd_create_sized_tls_slot(int offs, opnd_size_t size)
{
    /* We do not request disp_short_addr or force_full_disp, letting
     * encode_base_disp() choose whether to use the 0x67 addr prefix
     * (assuming offs is small).
     */
    return opnd_create_far_base_disp(SEG_TLS, REG_NULL, REG_NULL, 0, offs, size);
}

/* make sure to keep in sync w/ emit_utils.c's insert_spill_or_restore() */
bool
instr_raw_is_tls_spill(byte *pc, reg_id_t reg, ushort offs)
{
    ASSERT_NOT_IMPLEMENTED(reg != REG_RR0);

#ifdef NO
    /* looking for:   67 64 89 1e e4 0e    addr16 mov    %ebx -> %fs:0xee4   */
    /* ASSUMPTION: when addr16 prefix is used, prefix order is fixed */
    return ((*pc == ADDR_PREFIX_OPCODE && 
            *(pc+1) == TLS_SEG_OPCODE && 
            *(pc+2) == MOV_REG2MEM_OPCODE &&
            /* 0x1e for ebx, 0x0e for ecx, 0x06 for eax */
            *(pc+3) == MODRM_BYTE(0/*mod*/, reg_get_bits(reg), 6/*rm*/) &&
            *((ushort*)(pc+4)) == os_tls_offset(offs)) ||
        /* PR 209709: allow for no addr16 prefix */
        (*pc == TLS_SEG_OPCODE && 
         *(pc+1) == MOV_REG2MEM_OPCODE &&
         /* 0x1e for ebx, 0x0e for ecx, 0x06 for eax */
         *(pc+2) == MODRM_BYTE(0/*mod*/, reg_get_bits(reg), 6/*rm*/) &&
         *((uint*)(pc+4)) == os_tls_offset(offs)));
#endif
   return false;
}

/* this routine may upgrade a level 1 instr */
static bool
instr_check_tls_spill_restore(instr_t *instr, bool *spill, reg_id_t *reg, int *offs)
{
    opnd_t regop, memop;
    CLIENT_ASSERT(instr != NULL,
                  "internal error: tls spill/restore check: NULL argument");
#ifdef NO
//TODO SJF INSTR
    if (instr_get_opcode(instr) == OP_mov_st) {
        regop = instr_get_src(instr, 0);
        memop = instr_get_dst(instr, 0);
        if (spill != NULL)
            *spill = true;
    } else if (instr_get_opcode(instr) == OP_mov_ld) {
        regop = instr_get_dst(instr, 0);
        memop = instr_get_src(instr, 0);
        if (spill != NULL)
            *spill = false;
    } else if (instr_get_opcode(instr) == OP_xchg) {
        /* we use xchg to restore in dr_insert_mbr_instrumentation */
        regop = instr_get_src(instr, 0);
        memop = instr_get_dst(instr, 0);
        if (spill != NULL)
            *spill = false;
    } else
        return false;
    if (opnd_is_far_base_disp(memop) &&
        opnd_get_segment(memop) == SEG_TLS && 
        opnd_is_abs_base_disp(memop) &&
        opnd_is_reg(regop)) {
        if (reg != NULL)
            *reg = opnd_get_reg(regop);
        if (offs != NULL)
            *offs = opnd_get_disp(memop);
        return true;
    }
#endif
    return false;
}

/* if instr is level 1, does not upgrade it and instead looks at raw bits,
 * to support identification w/o ruining level 0 in decode_fragment, etc.
 */
bool
instr_is_tls_spill(instr_t *instr, reg_id_t reg, ushort offs)
{
    reg_id_t check_reg;
    int check_disp;
    bool spill;
    return (instr_check_tls_spill_restore(instr, &spill, &check_reg, &check_disp) &&
            spill && check_reg == reg && check_disp == os_tls_offset(offs));
}

/* if instr is level 1, does not upgrade it and instead looks at raw bits,
 * to support identification w/o ruining level 0 in decode_fragment, etc.
 */
bool
instr_is_tls_restore(instr_t *instr, reg_id_t reg, ushort offs)
{
    reg_id_t check_reg;
    int check_disp;
    bool spill;
    return (instr_check_tls_spill_restore(instr, &spill, &check_reg, &check_disp) &&
            !spill && (reg == REG_NULL || check_reg == reg) &&
            check_disp == os_tls_offset(offs));
}

/* if instr is level 1, does not upgrade it and instead looks at raw bits,
 * to support identification w/o ruining level 0 in decode_fragment, etc.
 */
bool
instr_is_tls_xcx_spill(instr_t *instr)
{
    if (instr_raw_bits_valid(instr)) {
        /* avoid upgrading instr */
        return instr_raw_is_tls_spill(instr_get_raw_bits(instr),
                                      REG_RR1, MANGLE_XCX_SPILL_SLOT);
    } else
        return instr_is_tls_spill(instr, REG_RR1, MANGLE_XCX_SPILL_SLOT);
}

/* this routine may upgrade a level 1 instr */
static bool
instr_check_mcontext_spill_restore(dcontext_t *dcontext, instr_t *instr,
                                   bool *spill, reg_id_t *reg, int *offs)
{
#ifdef NO
//TODO SJF
    opnd_t regop, memop;
    if (instr_get_opcode(instr) == OP_mov_st) {
        regop = instr_get_src(instr, 0);
        memop = instr_get_dst(instr, 0);
        if (spill != NULL)
            *spill = true;
    } else if (instr_get_opcode(instr) == OP_mov_ld) {
        regop = instr_get_dst(instr, 0);
        memop = instr_get_src(instr, 0);
        if (spill != NULL)
            *spill = false;
    } else if (instr_get_opcode(instr) == OP_xchg) {
        /* we use xchg to restore in dr_insert_mbr_instrumentation */
        regop = instr_get_src(instr, 0);
        memop = instr_get_dst(instr, 0);
        if (spill != NULL)
            *spill = false;
    } else
        return false;
    if (opnd_is_near_base_disp(memop) &&
        opnd_is_abs_base_disp(memop) &&
        opnd_is_reg(regop)) {
        byte *pc = (byte *) opnd_get_disp(memop);
        byte *mc = (byte *) get_mcontext(dcontext);
        if (pc >= mc && pc < mc + sizeof(priv_mcontext_t)) {
            if (reg != NULL)
                *reg = opnd_get_reg(regop);
            if (offs != NULL)
                *offs = pc - (byte *)dcontext;
            return true;
        }
    }
    return false;
#endif
}

bool
instr_is_reg_spill_or_restore(dcontext_t *dcontext, instr_t *instr,
                              bool *tls, bool *spill, reg_id_t *reg)
{
    int check_disp;
    reg_id_t myreg;
    CLIENT_ASSERT(instr != NULL, "internal error: NULL argument");
    if (reg == NULL)
        reg = &myreg;
    if (instr_check_tls_spill_restore(instr, spill, reg, &check_disp)) {
        int offs = reg_spill_tls_offs(*reg);
        if (offs != -1 && check_disp == os_tls_offset((ushort)offs)) {
            if (tls != NULL)
                *tls = true;
            return true;
        }
    }
    if (dcontext != GLOBAL_DCONTEXT &&
        instr_check_mcontext_spill_restore(dcontext, instr, spill,
                                           reg, &check_disp)) {
        int offs = opnd_get_reg_dcontext_offs(dr_reg_fixer[*reg]);
        if (offs != -1 && check_disp == offs) {
            if (tls != NULL)
                *tls = false;
            return true;
        }
    }
    return false;
}

/* N.B. : client meta routines (dr_insert_* etc.) should never use anything other
 * then TLS_XAX_SLOT unless the client has specified a slot to use as we let the
 * client use the rest. */
instr_t *
instr_create_save_to_tls(dcontext_t *dcontext, reg_id_t reg, ushort offs)
{
    return INSTR_CREATE_str_reg(dcontext, opnd_create_reg(reg), opnd_create_tls_slot(os_tls_offset(offs)), 
                                opnd_create_reg(REG_NULL), OPND_CREATE_IMM5(0), COND_ALWAYS);
}

instr_t *
instr_create_restore_from_tls(dcontext_t *dcontext, reg_id_t reg, ushort offs)
{
    return INSTR_CREATE_ldr_reg(dcontext, opnd_create_reg(reg), 
                               opnd_create_tls_slot(os_tls_offset(offs)),
                                opnd_create_reg(REG_NULL), OPND_CREATE_IMM5(0), COND_ALWAYS );
}

/* For -x86_to_x64, we can spill to 64-bit extra registers (xref i#751). */
instr_t *
instr_create_save_to_reg(dcontext_t *dcontext, reg_id_t reg1, reg_id_t reg2)
{
    return INSTR_CREATE_mov_reg(dcontext, opnd_create_reg(reg2), opnd_create_reg(reg1), COND_ALWAYS);
}

instr_t *
instr_create_restore_from_reg(dcontext_t *dcontext, reg_id_t reg1, reg_id_t reg2)
{
    return INSTR_CREATE_mov_reg(dcontext, opnd_create_reg(reg1), opnd_create_reg(reg2), COND_ALWAYS);
}

uint
move_mm_reg_opcode(bool aligned16, bool aligned32)
{
#ifdef NO
//TODO SJF
    if (YMM_ENABLED()) {
        /* must preserve ymm registers */
        return (aligned32 ? OP_vmovdqa : OP_vmovdqu);
    }
    else if (proc_has_feature(FEATURE_SSE2)) {
        return (aligned16 ? OP_movdqa : OP_movdqu);
    } else {
        CLIENT_ASSERT(proc_has_feature(FEATURE_SSE), "running on unsupported processor");
        return (aligned16 ? OP_movaps : OP_movups);
    }
#endif
}

#endif /* !STANDALONE_DECODER */

/****************************************************************************/
