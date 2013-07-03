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

/* decode.c -- a full arm decoder */

#include "../globals.h"
#include "arch.h"
#include "instr.h"
#include "decode.h"
#include "decode_fast.h"
#include <string.h> /* for memcpy */

/*
 * XXX i#431: consider cpuid features when deciding invalid instrs:
 * for core DR, it doesn't really matter: the only bad thing is thinking
 * a valid instr is invalid, esp decoding its size improperly.
 * but for completeness and use as disassembly library might be nice.
 *
 * XXX (these are very old):
 * 1) several opcodes gdb thinks bad/not bad -- changes to ISA?
 * 2) why does gdb use Ex, Ed, & Ev for all float opcodes w/ modrm < 0xbf?
 *    a float instruction's modrm cannot specify a register, right?
 *    sizes are single-real => d, double-real => q, extended-real = 90 bits,
 *    14/28 bytes, and 98/108 bytes!
 *    should address sizes all be 'v'?
 * 3) there don't seem to be any immediate float values...?!?
 * 4) fld (0xd9 0xc0-7) in Table A-10 has 2 operands in different order
 *    than expected, plus asm prints using just 2nd one
 * 5) I don't see T...is there a T?  gdb has it for 0f26mov
 */

/* N.B.: must justify each assert, since we do not want to assert on a bad
 * instruction -- we want to fail gracefully and have the caller deal with it
 */

#ifdef DEBUG
/* case 10450: give messages to clients */
/* we can't undef ASSERT b/c of DYNAMO_OPTION */
# undef ASSERT_TRUNCATE
# undef ASSERT_BITFIELD_TRUNCATE
# undef ASSERT_NOT_REACHED
# define ASSERT_TRUNCATE DO_NOT_USE_ASSERT_USE_CLIENT_ASSERT_INSTEAD
# define ASSERT_BITFIELD_TRUNCATE DO_NOT_USE_ASSERT_USE_CLIENT_ASSERT_INSTEAD
# define ASSERT_NOT_REACHED DO_NOT_USE_ASSERT_USE_CLIENT_ASSERT_INSTEAD
#endif

/* used for VEX decoding */
#define xx  TYPE_NONE, OPSZ_NA
static const instr_info_t escape_instr =
    {ESCAPE,  0x000000, "(bad)", xx, xx, xx, xx, xx, 0, 0, 0};
static const instr_info_t escape_38_instr =
    {ESCAPE_3BYTE_38,  0x000000, "(bad)", xx, xx, xx, xx, xx, 0, 0, 0};
static const instr_info_t escape_3a_instr =
    {ESCAPE_3BYTE_3a,  0x000000, "(bad)", xx, xx, xx, xx, xx, 0, 0, 0};
#undef xx

#ifdef X64
/* PR 302344: used for shared traces -tracedump_origins where we
 * need to change the mode but we have no dcontext
 */
static bool initexit_x86_mode = DEFAULT_X86_MODE;

/*
 * The decode and encode routines use a per-thread persistent flag that
 * indicates whether to treat code as 32-bit (x86) or 64-bit (x64).  This
 * routine sets that flag to the indicated value and returns the old value.  Be
 * sure to restore the old value prior to any further application execution to
 * avoid problems in mis-interpreting application code.
 */
bool
set_x86_mode(dcontext_t *dcontext, bool x86)
{
    bool old_mode;
    /* We would disallow but some early init routines need to use global heap */
    if (dcontext == GLOBAL_DCONTEXT)
        dcontext = get_thread_private_dcontext();
    /* Support GLOBAL_DCONTEXT or NULL for standalone/static modes */
    if (dcontext == NULL || dcontext == GLOBAL_DCONTEXT) {
        ASSERT(!dynamo_initialized || dynamo_exited || dcontext == GLOBAL_DCONTEXT);
        old_mode = initexit_x86_mode;
        initexit_x86_mode = x86;
    } else {
        old_mode = dcontext->x86_mode;
        dcontext->x86_mode = x86;
    }
    return old_mode;
}

/*
 * The decode and encode routines use a per-thread persistent flag that
 * indicates whether to treat code as 32-bit (x86) or 64-bit (x64).  This
 * routine returns the value of that flag.
 */
bool
get_x86_mode(dcontext_t *dcontext)
{
    /* We would disallow but some early init routines need to use global heap */
    if (dcontext == GLOBAL_DCONTEXT)
        dcontext = get_thread_private_dcontext();
    /* Support GLOBAL_DCONTEXT or NULL for standalone/static modes */
    if (dcontext == NULL || dcontext == GLOBAL_DCONTEXT) {
        ASSERT(!dynamo_initialized || dynamo_exited || dcontext == GLOBAL_DCONTEXT);
        return initexit_x86_mode;
    } else
        return dcontext->x86_mode;
}
#endif

/****************************************************************************
 * All code below based on tables in the ``Intel Architecture Software
 * Developer's Manual,'' Volume 2: Instruction Set Reference, 2001.
 */

#if defined(DEBUG) && !defined(STANDALONE_DECODER) /* currently only used in ASSERTs */
static bool
is_variable_size(opnd_size_t sz)
{
    /* SJF No variable regs for now */
    return false;
}
#endif

opnd_size_t resolve_var_reg_size(opnd_size_t sz, bool is_reg)
{
    return sz;
}

/* Like all our code, we assume cs specifies default data and address sizes.
 * This routine assumes the size varies by data, NOT by address!
 */
opnd_size_t
resolve_variable_size(decode_info_t *di/*IN: x86_mode, prefixes*/,
                      opnd_size_t sz, bool is_reg)
{
/* SJF No more variable reg sizes */
    switch (sz) {
    }
    return sz;
}

opnd_size_t
resolve_variable_size_dc(dcontext_t *dcontext, opnd_size_t sz, bool is_reg)
{
    decode_info_t di;
    return resolve_variable_size(&di, sz, is_reg);
}

opnd_size_t
resolve_addr_size(decode_info_t *di/*IN: x86_mode, prefixes*/)
{
    /* Only 4 byte addr size */
    return OPSZ_4;
/*
    if (TEST(PREFIX_ADDR, di->prefixes))
        return (X64_MODE(di) ? OPSZ_4 : OPSZ_2);
    else
        return (X64_MODE(di) ? OPSZ_8 : OPSZ_4);
*/
}

bool
optype_is_indir_reg(int optype)
{
    /* TODO All registers in ARM can be indirect registers 
            Not every one in intel can. Is this right? */
    return true;
}

opnd_size_t
indir_var_reg_size(decode_info_t *di, int optype)
{
    /* TODO Complete this */
    switch (optype) {
      case TYPE_REG:
          return OPSZ_4;

    default: CLIENT_ASSERT(false, "internal error: invalid indir reg type");
    }
    return OPSZ_0;
}

/* Returns multiplier of the operand size to use as the base-disp offs */
int
indir_var_reg_offs_factor(int optype)
{
    /* TODO ??? */
    return 0;
}

/****************************************************************************
 * Reading all bytes of instruction
 */

static byte *
read_immed(byte *pc, decode_info_t *di, opnd_size_t size, ptr_int_t *result)
{
    size = resolve_variable_size(di, size, false);

    /* all data immediates are sign-extended.  we use the compiler's casts with
     * signed types to do our sign extensions for us.
     */
    switch (size) {
    case OPSZ_1:
    case OPSZ_4_8:
        *result = (ptr_int_t) (char) *pc; /* sign-extend */
        pc++;
        break;
    case OPSZ_2:
    case OPSZ_4_16:
        *result = (ptr_int_t) *((short*)pc); /* sign-extend */
        pc += 2;
        break;
    case OPSZ_4:
        *result = (ptr_int_t) *((int*)pc); /* sign-extend */
        pc += 4;
        break;
    case OPSZ_4_3:
        *result = (ptr_int_t) (*((char*)pc) & 0x7); /* only get 3 bits */
        pc += 0;  /* Not read an entire byte here. So dont inc pc??? */
        break;
    case OPSZ_4_4:
        *result = (ptr_int_t) (*((char*)pc) & 0xf); /* only get 3 bits */
        pc += 0;  /* Not read an entire byte here. So dont inc pc??? */
        break;
    case OPSZ_4_5:
        *result = (ptr_int_t) (*((short*)pc) & 0x1f); /* only get 3 bits */
        pc += 0;  /* Read 5 bit here. So inc pc by zero??? */
        break;
    case OPSZ_4_6:
        *result = (ptr_int_t) (*((short*)pc) & 0x3f); /* only get 3 bits */
        pc += 0;  /* Read 6 bits here. So inc pc by zero??? */
        break;
    case OPSZ_4_10:
        *result = (ptr_int_t) (*((int*)pc) & 0x3ff); /* only get 3 bits */
        pc += 1;  /* Read one byte + 2 bits here. So inc pc by two??? */
        break;
    case OPSZ_4_12:
        *result = (ptr_int_t) (*((int*)pc) & 0xfff); /* only get 12 bits */
        pc += 1;  /* Read one byte + 4 bits here. So inc pc by one??? */
        break;
    case OPSZ_4_24:
        *result = (ptr_int_t) (*((int*)pc) & 0xffffff); /* only get 24 bits */
        pc += 3;  /* Read three bytes here. So inc pc by three??? */
        break;

    default:
        /* called internally w/ instr_info_t fields or hardcoded values,
         * so ok to assert */
        CLIENT_ASSERT(false, "decode immediate: unknown size");
    }
    return pc;
}

/* reads any trailing immed bytes */
static byte *
read_operand(byte *pc, decode_info_t *di, byte optype, opnd_size_t opsize)
{
    ptr_int_t val = 0;
    opnd_size_t size = opsize;
    switch (optype) {
#ifdef NO
//SJF Remove types that are not needed or understood 
    case TYPE_A:
        {
            CLIENT_ASSERT(!X64_MODE(di), "x64 has no type A instructions");
#ifdef IA32_ON_IA64
            /* somewhat hacked dispatch on size */
            if (opsize == OPSZ_4_short2) {
                pc = read_immed(pc, di, opsize, &val);
                break;
            }
#endif
            /* ok b/c only instr_info_t fields passed */
/*
            CLIENT_ASSERT(opsize == OPSZ_6_irex10_short4, "decode A operand error");
*/
            if (TEST(PREFIX_DATA, di->prefixes)) {
                /* 4-byte immed */
                pc = read_immed(pc, di, OPSZ_4, &val);
                /* ok b/c only instr_info_t fields passed */
                CLIENT_ASSERT(di->size_immed == OPSZ_NA &&
                              di->size_immed2 == OPSZ_NA, "decode A operand error");
                di->size_immed = resolve_variable_size(di, opsize, false);
                ASSERT(di->size_immed == OPSZ_4);
                di->immed = val;
            } else {
                /* 6-byte immed */
                ptr_int_t val2 = 0;
                /* little-endian: segment comes last */
                pc = read_immed(pc, di, OPSZ_4, &val2);
                pc = read_immed(pc, di, OPSZ_2, &val);

                /* ok b/c only instr_info_t fields passed */
                CLIENT_ASSERT(di->size_immed == OPSZ_NA &&
                              di->size_immed2 == OPSZ_NA, "decode A operand error");
                di->size_immed = resolve_variable_size(di, opsize, false);
                ASSERT(di->size_immed == OPSZ_6);
                di->size_immed2 = resolve_variable_size(di, opsize, false);
                di->immed = val;
                di->immed2 = val2;
            }
            return pc;
        }
#endif //NO
    case TYPE_I:
        {
            pc = read_immed(pc, di, opsize, &val);
            break;
        }
    case TYPE_J:
        {
            byte *end_pc;
            pc = read_immed(pc, di, opsize, &val);
            if (di->orig_pc != di->start_pc) {
                CLIENT_ASSERT(di->start_pc != NULL,
                              "internal decode error: start pc not set");
                end_pc = di->orig_pc + (pc - di->start_pc);
            } else
                end_pc = pc;
            /* convert from relative offset to absolute target pc */
            val = ((ptr_int_t)end_pc) + val;
        }
    case TYPE_O:
        {
            /* no modrm byte, offset follows directly.  this is address-sized,
             * so 64-bit for x64, and addr prefix affects it. */
            size = resolve_addr_size(di);
            pc = read_immed(pc, di, size, &val);
            break;
        }
    default:
        return pc;
    }
    if (di->size_immed == OPSZ_NA) {
        di->size_immed = size;
        di->immed = val;
    } else {
        /* ok b/c only instr_info_t fields passed */
        CLIENT_ASSERT(di->size_immed2 == OPSZ_NA, "decode operand error");
        di->size_immed2 = size;
        di->immed2 = val;
    }
    return pc;
}

/* Given the potential first vex byte at pc, reads any subsequent vex
 * bytes (and any prefix bytes) and sets the appropriate prefix flags in di.
 * Sets info to the entry for the first opcode byte, and pc to point past
 * the first opcode byte.
 */
static byte *
read_vex(byte *pc, decode_info_t *di, byte instr_byte,
         const instr_info_t **ret_info INOUT, bool *is_vex)
{
#ifdef NO //TODO SJF// vex_prefix_extensions no longer exists
    int idx;
    const instr_info_t *info;
    byte vex_last = 0, vex_pp;
    ASSERT(ret_info != NULL && *ret_info != NULL && is_vex != NULL);
    info = *ret_info;
    ASSERT(info->type == VEX_PREFIX_EXT);
    /* If 32-bit mode and mod selects for memory, this is not vex */
    if (X64_MODE(di) || TESTALL(MODRM_BYTE(3, 0, 0), *pc))
        idx = 1;
    else
        idx = 0;
    info = &vex_prefix_extensions[info->code][idx];
    if (idx == 0) {
        /* not vex */
        *ret_info = info;
        *is_vex = false;
        return pc;
    }
    *is_vex = true;
    if (TESTANY(PREFIX_REX_ALL | PREFIX_LOCK, di->prefixes) ||
        di->data_prefix || di->rep_prefix || di->repne_prefix) {
        /* #UD if combined w/ VEX prefix */
        *ret_info = &invalid_instr;
        return pc;
    }

    /* read 2nd vex byte */
    instr_byte = *pc;
    pc++;

    if (info->code == PREFIX_VEX_2B) {
        /* fields are: R, vvvv, L, PP.  R is inverted. */
        vex_last = instr_byte;
        if (!TEST(0x80, vex_last))
            di->prefixes |= PREFIX_REX_R;
        /* 2-byte vex implies leading 0x0f */
        *ret_info = &escape_instr;
        /* rest are shared w/ 3-byte form's final byte */
    } else if (info->code == PREFIX_VEX_3B) {
        byte vex_mm;
        /* fields are: R, X, B, m-mmmm.  R, X, and B are inverted. */
        if (!TEST(0x80, instr_byte))
            di->prefixes |= PREFIX_REX_R;
        if (!TEST(0x40, instr_byte))
            di->prefixes |= PREFIX_REX_X;
        if (!TEST(0x20, instr_byte))
            di->prefixes |= PREFIX_REX_B;
        vex_mm = instr_byte & 0x1f;
        /* our strategy is to decode through the regular tables w/ a vex-encoded
         * flag, to match Intel manuals and vex implicit-prefix flags
         */
        if (vex_mm == 1) {
            *ret_info = &escape_instr;
        } else if (vex_mm == 2) {
            *ret_info = &escape_38_instr;
        } else if (vex_mm == 3) {
            *ret_info = &escape_3a_instr;
        } else {
            /* #UD: reserved for future use */
            *ret_info = &invalid_instr;
            return pc;
        }
        
        /* read 3rd vex byte */
        vex_last = *pc;
        pc++;
        /* fields are: W, vvvv, L, PP */
        /* Intel docs say vex.W1 behaves just like rex.w except in cases
         * where rex.w is ignored, so no need for a PREFIX_VEX_W flag
         */
        if (TEST(0x80, vex_last))
            di->prefixes |= PREFIX_REX_W;
        /* rest are shared w/ 2-byte form's final byte */
    } else
        CLIENT_ASSERT(false, "internal vex decoding error");

    /* shared vex fields */
    vex_pp = vex_last & 0x03;
    di->vex_vvvv = (vex_last & 0x78) >> 3;
    if (TEST(0x04, vex_last))
        di->prefixes |= PREFIX_VEX_L;
    if (vex_pp == 0x1)
        di->data_prefix = true;
    else if (vex_pp == 0x2)
        di->rep_prefix = true;
    else if (vex_pp == 0x3)
        di->repne_prefix = true;

    di->vex_encoded = true;
    return pc;
#endif //NO
}

/* Disassembles the instruction at pc into the data structures ret_info
 * and di.  Does NOT set or read di->len.
 * Returns a pointer to the pc of the next instruction.
 * If just_opcode is true, does not decode the immeds and returns NULL
 * (you must call decode_next_pc to get the next pc, but that's faster
 * than decoding the immeds)
 * Returns NULL on an invalid instruction
 */
static byte *
read_instruction(byte *pc, byte *orig_pc,
                 const instr_info_t **ret_info, decode_info_t *di,
                 bool just_opcode _IF_DEBUG(bool report_invalid))
{
    DEBUG_DECLARE(byte *post_suffix_pc = NULL;)
    byte instr_byte, temp, instr_type;
    const instr_info_t *info;
    bool vex_noprefix = false;

    /* initialize di */
    /* though we only need di->start_pc for full decode rip-rel (and
     * there only post-read_instruction()) and decode_from_copy(), and
     * di->orig_pc only for decode_from_copy(), we assume that
     * high-perf decoding uses decode_cti() and live w/ the extra
     * writes here for decode_opcode() and decode_eflags_usage().
     */
    di->start_pc = pc;
    di->orig_pc = orig_pc;
    di->size_immed = OPSZ_NA;
    di->size_immed2 = OPSZ_NA;
    /* FIXME: set data and addr sizes to current mode
     * for now I assume always 32-bit mode (or 64 for X64_MODE(di))!
     */
    
    do {
        instr_byte = *pc;
        pc++;
        temp = (instr_byte << 4);  
        temp = (temp >> 5);
        instr_type = instr_byte;
        
        switch( instr_type )
        {
        }


    } while (true);

    /* if just want opcode, stop here!  faster for caller to
     * separately call decode_next_pc than for us to decode immeds!  
     */
    if (just_opcode) {
        *ret_info = info;
        return NULL;
    }

    /************* Decode operands **************/

    /* return values */
    *ret_info = info;

    return pc;
}

/****************************************************************************
 * Full decoding
 */

/* Caller must check for rex.{r,b} extensions before calling this routine */
static reg_id_t
reg8_alternative(decode_info_t *di, reg_id_t reg, uint prefixes)
{
    /* TODO Any 8 bit alternatives for ARM??? No I think */
    return reg;
}

/* which register within modrm we're decoding */
typedef enum {
    DECODE_REG_RREG,
    DECODE_REG_BASE,
    DECODE_REG_INDEX,
    DECODE_REG_RRM,
} decode_reg_t;

/* Pass in the raw opsize, NOT a size passed through resolve_variable_size(),
 * to avoid allowing OPSZ_6_irex10_short4 w/ data16
 */
static reg_id_t
decode_reg(decode_reg_t which_reg, decode_info_t *di, byte optype, opnd_size_t opsize)
{
    bool extend = false;
    byte reg = 0;

    switch (optype) {
      case TYPE_INDIR_E:
      case TYPE_FLOATMEM:
        /* GPR: fall-through since variable subset of full register */
        break;
      default:
        CLIENT_ASSERT(false, "internal unknown reg error");
    }

    /* Do not allow a register for 'p' or 'a' types.  FIXME: maybe *_far_ind_* should
     * use TYPE_INDIR_M instead of TYPE_INDIR_E?  What other things are going to turn
     * into asserts or crashes instead of invalid instrs based on events as fragile
     * as these decode routines moving sizes around?
     */
/*
    if (opsize != OPSZ_6_irex10_short4 && opsize != OPSZ_8_short4)
        opsize = resolve_variable_size(di, opsize, true);
*/

    /* SJF Only 32 bit values allowed for registers*/
    switch (opsize) 
    {
      case OPSZ_4:
        return (extend? (REG_START_32 + 8 + reg) : (REG_START_32 + reg));
      default:
        /* ok to assert since params controlled by us */
        CLIENT_ASSERT(false, "decode error: unknown register size");
        return REG_NULL;
    }
}

#ifdef NO 
static bool
decode_modrm(decode_info_t *di, byte optype, opnd_size_t opsize,
             opnd_t *reg_opnd, opnd_t *rm_opnd)
{
    /* for x64, addr prefix affects only base/index and truncates final addr:
     * modrm + sib table is the same
     */
    bool addr16 = !X64_MODE(di) && TEST(PREFIX_ADDR, di->prefixes);

    if (reg_opnd != NULL) {
        reg_id_t reg = decode_reg(DECODE_REG_RREG, di, optype, opsize);
        if (reg == REG_NULL)
            return false;
        *reg_opnd = opnd_create_reg(reg);
    }

    if (rm_opnd != NULL) {
        reg_id_t base_reg = REG_NULL;
        int disp = 0;
        reg_id_t index_reg = REG_NULL;
        int scale = 0;
        char memtype = TYPE_M;
        opnd_size_t memsize = resolve_addr_size(di);
        bool encode_zero_disp, force_full_disp;
        if (di->has_disp)
            disp = di->disp;
        else
            disp = 0;
        if (di->has_sib) {
            CLIENT_ASSERT(!addr16,
                          "decode error: x86 addr16 cannot have a SIB byte");
            if (di->index == 4 &&
                /* rex.x enables r12 as index */
                (!X64_MODE(di) || !TEST(PREFIX_REX_X, di->prefixes))) {
                /* no scale/index */
                index_reg = REG_NULL;
            } else {
                index_reg = decode_reg(DECODE_REG_INDEX, di, memtype, memsize);
                if (index_reg == REG_NULL) {
                    CLIENT_ASSERT(false, "decode error: !index: internal modrm error");
                    return false;
                }
                if (di->scale == 0)
                    scale = 1;
                else if (di->scale == 1)
                    scale = 2;
                else if (di->scale == 2)
                    scale = 4;
                else if (di->scale == 3)
                    scale = 8;
            }
            if (di->base == 5 && di->mod == 0) {
                /* no base */
                base_reg = REG_NULL;
            } else {
                base_reg = decode_reg(DECODE_REG_BASE, di, memtype, memsize);
                if (base_reg == REG_NULL) {
                    CLIENT_ASSERT(false, "decode error: internal modrm decode error");
                    return false;
                }
            }
        } else {
            if ((!addr16 && di->mod == 0 && di->rm == 5) ||
                (addr16 && di->mod == 0 && di->rm == 6)) {
                /* just absolute displacement, or rip-relative for x64 */
#ifdef X64
                if (X64_MODE(di)) {
                    /* rip-relative: convert from relative offset to absolute target pc */
                    byte *addr;
                    CLIENT_ASSERT(di->start_pc != NULL,
                                  "internal decode error: start pc not set");
                    if (di->orig_pc != di->start_pc)
                        addr = di->orig_pc + di->len + di->disp;
                    else
                        addr = di->start_pc + di->len + di->disp;
                    if (TEST(PREFIX_ADDR, di->prefixes)) {
                        /* Need to clear upper 32 bits.
                         * Debuggers do not display this truncation, though
                         * both Intel and AMD manuals describe it.
                         * I did verify it w/ actual execution.
                         */
                        ASSERT_NOT_TESTED();
                        addr = (byte *) ((ptr_uint_t)addr & 0xffffffff);
                    }
                    *rm_opnd = opnd_create_far_rel_addr
                        (di->seg_override, (void *) addr,
                         resolve_variable_size(di, opsize, false));
                    return true;
                } else
#endif
                    base_reg = REG_NULL;
                index_reg = REG_NULL;
            } else if (di->mod == 3) {
                /* register */
                reg_id_t rm_reg = decode_reg(DECODE_REG_RRM, di, optype, opsize);
                if (rm_reg == REG_NULL) /* no assert since happens, e.g., ff d9 */
                    return false;
                else {
                    *rm_opnd = opnd_create_reg(rm_reg);
                    return true;
                }
            } else {
                /* non-sib reg-based memory address */
                if (addr16) {
                    /* funny order requiring custom decode */
                    switch (di->rm) {
                    case 0: base_reg = REG_BX; index_reg = REG_SI; scale = 1; break;
                    case 1: base_reg = REG_BX; index_reg = REG_DI; scale = 1; break;
                    case 2: base_reg = REG_BP; index_reg = REG_SI; scale = 1; break;
                    case 3: base_reg = REG_BP; index_reg = REG_DI; scale = 1; break;
                    case 4: base_reg = REG_SI; break;
                    case 5: base_reg = REG_DI; break;
                    case 6: base_reg = REG_BP;
                        CLIENT_ASSERT(di->mod != 0,
                                      "decode error: %bp cannot have mod 0");
                        break;
                    case 7: base_reg = REG_BX; break;
                    default: CLIENT_ASSERT(false, "decode error: unknown modrm rm");
                        break;
                    }
                } else {
                    /* single base reg */
                    base_reg = decode_reg(DECODE_REG_RRM, di, memtype, memsize);
                    if (base_reg == REG_NULL) {
                        CLIENT_ASSERT(false,
                                      "decode error: !base: internal modrm decode error");
                        return false;
                    }
                }
            }
           
        }
        /* We go ahead and preserve the force bools if the original really had a 0
         * disp; up to user to unset bools when changing disp value (FIXME: should
         * we auto-unset on first mod?)
         */
        encode_zero_disp = di->has_disp && disp == 0 &&
            /* there is no bp base without a disp */
            (!addr16 || base_reg != REG_BP);
        force_full_disp = di->has_disp && disp >= INT8_MIN && disp <= INT8_MAX &&
            di->mod == 2;
        if (di->seg_override != REG_NULL) {
            *rm_opnd = opnd_create_far_base_disp_ex
                (di->seg_override, base_reg, index_reg, scale, disp,
                 resolve_variable_size(di, opsize, false),
                 encode_zero_disp, force_full_disp,
                 TEST(PREFIX_ADDR, di->prefixes));
        } else {
            /* Note that OP_{jmp,call}_far_ind does NOT have a far base disp
             * operand: it is a regular base disp containing 6 bytes that
             * specify a segment selector and address.  The opcode must be
             * examined to know how to interpret those 6 bytes.
             */
            *rm_opnd = opnd_create_base_disp_ex
                (base_reg, index_reg, scale, disp,
                 resolve_variable_size(di, opsize, false),
                 encode_zero_disp, force_full_disp,
                 TEST(PREFIX_ADDR, di->prefixes));
        }
    }
    return true;
}
#endif

static ptr_int_t
get_immed(decode_info_t *di, opnd_size_t opsize)
{
    ptr_int_t val = 0;
    if (di->size_immed == OPSZ_NA) {
        /* ok b/c only instr_info_t fields passed */
        CLIENT_ASSERT(di->size_immed2 != OPSZ_NA, "decode immediate size error");
        val = di->immed2;
        di->size_immed2 = OPSZ_NA; /* mark as used up */
    } else {
        /* ok b/c only instr_info_t fields passed */
        CLIENT_ASSERT(di->size_immed != OPSZ_NA, "decode immediate size error");
        val = di->immed;
        di->size_immed = OPSZ_NA; /* mark as used up */
    }
    return val;
}

/* Also takes in reg8 for TYPE_REG_EX mov_imm */
reg_id_t
resolve_var_reg(decode_info_t *di/*IN: x86_mode, prefixes*/,
                reg_id_t reg32, bool addr, bool can_shrink
                _IF_X64(bool default_64) _IF_X64(bool can_grow)
                _IF_X64(bool extendable))
{
#ifdef NO
//TODO SJF
#ifdef X64
    if (extendable && X64_MODE(di) && di->prefixes != 0/*optimization*/) {
        /* Note that Intel's table 3-1 on +r possibilities is incorrect:
         * it lists rex.r, while Table 2-4 lists rex.b which is correct.
         */
        if (TEST(PREFIX_REX_B, di->prefixes))
            reg32 = reg32 + 8;
        else
            reg32 = reg8_alternative(di, reg32, di->prefixes);
    }
#endif

    if (addr) {
#ifdef X64
        if (X64_MODE(di)) {
            CLIENT_ASSERT(default_64, "addr-based size must be default 64");
            if (!can_shrink || !TEST(PREFIX_ADDR, di->prefixes))
                return reg_32_to_64(reg32);
            /* else leave 32 (it's addr32 not addr16) */
        } else
#endif
            if (can_shrink && TEST(PREFIX_ADDR, di->prefixes))
                return reg_32_to_16(reg32);
    } else {
#ifdef X64
        /* rex.w trumps data prefix */
        if (X64_MODE(di) &&
            ((can_grow && TEST(PREFIX_REX_W, di->prefixes)) ||
             (default_64 && (!can_shrink || !TEST(PREFIX_DATA, di->prefixes)))))
            return reg_32_to_64(reg32);
        else
#endif
            if (can_shrink && TEST(PREFIX_DATA, di->prefixes))
                return reg_32_to_16(reg32);
    }
#endif //NO
    return reg32;
}

static reg_id_t
ds_seg(decode_info_t *di)
{
    return SEG_DS;
}

static bool
decode_operand(decode_info_t *di, byte optype, opnd_size_t opsize, opnd_t *opnd)
{
    /* resolving here, for non-reg, makes for simpler code: though the
     * most common types don't need this.
     */
    opnd_size_t ressize = resolve_variable_size(di, opsize, false);
    switch (optype) {
    case TYPE_NONE: 
        *opnd = opnd_create_null();
        return true;
    case TYPE_REG:
        *opnd = opnd_create_reg(opsize);
        return true;
    case TYPE_FLOATMEM:
        /* ??? What do */
        return false;
    case TYPE_I:
        *opnd = opnd_create_immed_int(get_immed(di, opsize), ressize);
        return true;
    case TYPE_1:
        CLIENT_ASSERT(opsize == OPSZ_0, "internal decode inconsistency");
        *opnd = opnd_create_immed_int(1, ressize);
        return true;
    case TYPE_FLOATCONST:
        CLIENT_ASSERT(opsize == OPSZ_0, "internal decode inconsistency");
        /* i#386: avoid floating-point instructions */
        *opnd = opnd_create_immed_float_zero();
        return true;
    case TYPE_J:
        /* just ignore other segment prefixes -- don't assert */
        *opnd = opnd_create_pc((app_pc)get_immed(di, opsize));
        return true;
    case TYPE_A: 
        {
          return false; //SJF ??
        }
    case TYPE_O:
        {
            /* no modrm byte, offset follows directly */
            ptr_int_t immed = get_immed(di, resolve_addr_size(di));
            *opnd = opnd_create_far_abs_addr(SEG_DS, (void *) immed, ressize);
            return true;
        }
    case TYPE_INDIR_REG:
        /* FIXME: how know data size?  for now just use reg size: our only use
         * of this does not have a varying hardcoded reg, fortunately. */
        *opnd = opnd_create_base_disp(opsize, REG_NULL, 0, 0, reg_get_size(opsize));
        return true;
    default:
        /* ok to assert, types coming only from instr_info_t */
        CLIENT_ASSERT(false, "decode error: unknown operand type");
    }
    return false;
}

/****************************************************************************
 * Exported routines
 */

/* Decodes only enough of the instruction at address pc to determine
 * its eflags usage, which is returned in usage as EFLAGS_ constants
 * or'ed together.
 * This corresponds to halfway between Level 1 and Level 2: a Level 1 decoding
 * plus eflags information (usually only at Level 2).
 * Returns the address of the next byte after the decoded instruction.
 * Returns NULL on decoding an invalid instruction.
 *
 * N.B.: an instruction that has an "undefined" effect on eflags is considered
 * to write to eflags.  This is fine since programs shouldn't be reading
 * eflags after an undefined modification to them, but a weird program that
 * relies on some undefined eflag thing might behave differently under dynamo
 * than not!
 */
byte *
decode_cpsr_usage(dcontext_t *dcontext, byte *pc, uint *usage)
{
    const instr_info_t *info;
    decode_info_t di;

    /* don't decode immeds, instead use decode_next_pc, it's faster */
    read_instruction(pc, pc, &info, &di, true /* just opcode */ _IF_DEBUG(true));
    *usage = info->cpsr;
    pc = decode_next_pc(dcontext, pc);
    /* failure handled fine -- we'll go ahead and return the NULL */

    return pc;
}


byte *
decode_opcode_usage(dcontext_t *dcontext, byte *pc, uint *usage)
{
    const instr_info_t *info;
    decode_info_t di;

    /* don't decode immeds, instead use decode_next_pc, it's faster */
    read_instruction(pc, pc, &info, &di, true /* just opcode */ _IF_DEBUG(true));
    *usage = info->opcode;
    pc = decode_next_pc(dcontext, pc);
    /* failure handled fine -- we'll go ahead and return the NULL */

    return pc;
}

/* Decodes the opcode and eflags usage of instruction at address pc
 * into instr.
 * This corresponds to a Level 2 decoding.
 * Assumes that instr is already initialized, but uses the x86/x64 mode
 * for the current thread rather than that set in instr.
 * If caller is re-using same instr struct over multiple decodings,
 * should call instr_reset or instr_reuse.
 * Returns the address of the next byte after the decoded instruction.
 * Returns NULL on decoding an invalid instruction.
 */
byte *
decode_opcode(dcontext_t *dcontext, byte *pc, instr_t *instr)
{
    const instr_info_t *info;
    decode_info_t di;
    int sz;
#ifdef X64
    /* PR 251479: we need to know about all rip-relative addresses.
     * Since change/setting raw bits invalidates, we must set this
     * on every return. */
    uint rip_rel_pos;
#endif
    IF_X64(di.x86_mode = instr_get_x86_mode(instr));
    /* when pass true to read_instruction it doesn't decode immeds,
     * so have to call decode_next_pc, but that ends up being faster
     * than decoding immeds!
     */
    read_instruction(pc, pc, &info, &di, true /* just opcode */
                     _IF_DEBUG(!TEST(INSTR_IGNORE_INVALID, instr->flags)));
    sz = decode_sizeof(dcontext, pc, NULL _IF_X64(&rip_rel_pos));
    IF_X64(instr_set_x86_mode(instr, get_x86_mode(dcontext)));
    instr_set_opcode(instr, info->type);
    /* read_instruction sets opcode to OP_INVALID for illegal instr.
     * decode_sizeof will return 0 for _some_ illegal instrs, so we
     * check it first since it's faster than instr_valid, but we have to
     * also check instr_valid to catch all illegal instrs.
     */
    if (sz == 0 || !instr_valid(instr)) {
        CLIENT_ASSERT(!instr_valid(instr), "decode_opcode: invalid instr");
        return NULL;
    }
    /* operands are NOT set */
    instr_set_operands_valid(instr, false);
    /* raw bits are valid though and crucial for encoding */
    instr_set_raw_bits(instr, pc, sz);
    /* must set rip_rel_pos after setting raw bits */
    IF_X64(instr_set_rip_rel_pos(instr, rip_rel_pos));
    return pc + sz;
}

#if defined(DEBUG) && !defined(STANDALONE_DECODER)
/* PR 215143: we must resolve variable sizes at decode time */
static bool
check_is_variable_size(opnd_t op)
{
    if (opnd_is_memory_reference(op) ||
        /* reg_get_size() fails on fp registers since no OPSZ for them */
        (opnd_is_reg(op) && !reg_is_fp(opnd_get_reg(op))))
        return !is_variable_size(opnd_get_size(op));
    /* else no legitimate size to check */
    return true;
}
#endif

/* Decodes the instruction at address pc into instr, filling in the
 * instruction's opcode, cpsr usage, and operands.
 * This corresponds to a Level 3 decoding.
 * Assumes that instr is already initialized
 * If caller is re-using same instr struct over multiple decodings,
 * should call instr_reset or instr_reuse.
 * Returns the address of the next byte after the decoded instruction.
 * Returns NULL on decoding an invalid instruction.
 */
static byte *
decode_common(dcontext_t *dcontext, byte *pc, byte *orig_pc, instr_t *instr)
{
    const instr_info_t *info;
    decode_info_t di;
    byte *next_pc;
    int instr_num_dsts = 0, instr_num_srcs = 0;
    opnd_t dsts[8];
    opnd_t srcs[8];

    CLIENT_ASSERT(instr->opcode == OP_INVALID || instr->opcode == OP_UNDECODED,
                  "decode: instr is already decoded, may need to call instr_reset()");

    next_pc = read_instruction(pc, orig_pc, &info, &di, false /* not just opcode,
                                                                 decode operands too */
                               _IF_DEBUG(!TEST(INSTR_IGNORE_INVALID, instr->flags)));
    instr_set_opcode(instr, info->type);
    IF_X64(instr_set_x86_mode(instr, di.x86_mode));
    /* failure up to this point handled fine -- we set opcode to OP_INVALID */
    if (next_pc == NULL) {
        LOG(THREAD, LOG_INTERP, 3, "decode: invalid instr at "PFX"\n", pc);
        CLIENT_ASSERT(!instr_valid(instr), "decode: invalid instr");
        return NULL;
    }
    /* since we don't use set_src/set_dst we must explicitly say they're valid */
    instr_set_operands_valid(instr, true);
    /* read_instruction doesn't set di.len since only needed for rip-relative opnds */
    IF_X64(CLIENT_ASSERT_TRUNCATE(di.len, int, next_pc - pc,
                                  "internal truncation error"));
    di.len = (int) (next_pc - pc);

    /*************** Decode operands *****************/

    /* now copy operands into their real slots */
    instr_set_num_opnds(dcontext, instr, instr_num_dsts, instr_num_srcs);
    if (instr_num_dsts > 0) {
        memcpy(instr->dsts, dsts, instr_num_dsts*sizeof(opnd_t));
    }
    if (instr_num_srcs > 0) {
        /* remember that src0 is static */
        instr->src0 = srcs[0];
        if (instr_num_srcs > 1) {
            memcpy(instr->srcs, &(srcs[1]), (instr_num_srcs-1)*sizeof(opnd_t));
        }
    }

    if (orig_pc != pc) {
        /* We do not want to copy when encoding and condone an invalid
         * relative target
         */
        instr_set_raw_bits_valid(instr, false);
        instr_set_translation(instr, orig_pc);
    } else {
        /* we set raw bits AFTER setting all srcs and dsts b/c setting
         * a src or dst marks instr as having invalid raw bits
         */
        instr_set_raw_bits(instr, pc, (uint)(next_pc - pc));
    }

    return next_pc;

 decode_invalid:
    instr_set_operands_valid(instr, false);
    instr_set_opcode(instr, OP_INVALID);

    return NULL;
}

byte *
decode(dcontext_t *dcontext, byte *pc, instr_t *instr)
{
    return decode_common(dcontext, pc, pc, instr);
}

byte *
decode_from_copy(dcontext_t *dcontext, byte *copy_pc, byte *orig_pc, instr_t *instr)
{
    return decode_common(dcontext, copy_pc, orig_pc, instr);
}

const instr_info_t *
get_next_instr_info(const instr_info_t * info)
{
    return (const instr_info_t *)(info->code);
}

byte 
decode_first_opcode_byte(int opcode)
{
#ifdef NO
//TODO SJF
    const instr_info_t * info = op_instr[opcode];
    return (byte)((info->opcode & 0x00ff0000) >> 16);
#endif //NO
   return (byte) 0;
}

DR_API
const char * 
decode_opcode_name(int opcode)
{
#ifdef NO
//TODO SJF
    const instr_info_t * info = op_instr[opcode];
    return info->name;
#endif //NO
   return (byte) 0;
}

#ifdef DECODE_UNIT_TEST
# include "instr_create.h"

/* FIXME: Tried putting this inside a separate unit-decode.c file, but
 *        required creating a unit-decode_table.c file.  Since the
 *        infrastructure is not fully set up, currently leaving this here
 * FIXME: beef up to check if something went wrong
 */
static bool
unit_check_decode_ff_opcode() {
    static int do_once = 0;
    instr_t instr;
    byte modrm, sib;
    byte raw_bytes[] = { 0xff, 0x0, 0x0, 
                         0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                         0xab, 0xbc, 0xcd, 0xde, 0xef, 0xfa,
                       };
    app_pc next_pc = NULL;

    for (modrm = 0x0; modrm < 0xff; modrm++) {
        raw_bytes[1] = modrm;
        for(sib = 0x0; sib < 0xff; sib++) {
            raw_bytes[2] = sib;

            /* set up instr for decode_opcode */
            instr_init(GLOBAL_DCONTEXT, &instr);
            instr.bytes = raw_bytes;
            instr.length = 15;
            instr_set_raw_bits_valid(&instr, true);
            instr_set_operands_valid(&instr, false);

            next_pc = decode_opcode(GLOBAL_DCONTEXT, instr.bytes, &instr);
            if (next_pc != NULL &&
                instr.opcode != OP_INVALID && instr.opcode != OP_UNDECODED) {
                print_file(STDERR, "## %02x %02x %02x len=%d\n",
                    instr.bytes[0], instr.bytes[1], instr.bytes[2], instr.length);
            }
        }
    }
    return 0;
}

/* Standalone building is still broken so I tested this by calling
 * from a real DR build.
 */
#define CHECK_ENCODE_OPCODE(dcontext, instr, pc, opc, ...) \
    instr = INSTR_CREATE_##opc(dcontext, ## __VA_ARGS__);  \
    instr_encode(dcontext, instr, pc);                 \
    instr_reset(dcontext, instr);                      \
    decode(dcontext, pc, instr);                       \
    /* FIXME: use EXPECT */                            \
    CLIENT_ASSERT(instr_get_opcode(instr) == OP_##opc, "unit test"); \
    instr_destroy(dcontext, instr);

/* FIXME: case 8212: add checks for every single instr type */
static bool
unit_check_sse3()
{
    dcontext_t *dcontext = get_thread_private_dcontext();
    byte buf[32];
    instr_t *instr;
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, mwait);
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, monitor);
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, haddpd,
                        opnd_create_reg(REG_XMM7), opnd_create_reg(REG_XMM2));
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, haddps,
                        opnd_create_reg(REG_XMM7), opnd_create_reg(REG_XMM2));
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, hsubpd,
                        opnd_create_reg(REG_XMM7), opnd_create_reg(REG_XMM2));
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, hsubps,
                        opnd_create_reg(REG_XMM7), opnd_create_reg(REG_XMM2));
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, addsubpd,
                        opnd_create_reg(REG_XMM7), opnd_create_reg(REG_XMM2));
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, addsubps,
                        opnd_create_reg(REG_XMM7), opnd_create_reg(REG_XMM2));
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, lddqu,
                        opnd_create_reg(REG_XMM7),
                        opnd_create_base_disp(REG_NULL, REG_NULL, 0, 0, OPSZ_16));
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, movsldup,
                        opnd_create_reg(REG_XMM7), opnd_create_reg(REG_XMM2));
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, movshdup,
                        opnd_create_reg(REG_XMM7), opnd_create_reg(REG_XMM2));
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, movddup,
                        opnd_create_reg(REG_XMM7), opnd_create_reg(REG_XMM2));
    /* not sse3 but I fixed it at same time so here to test */
    CHECK_ENCODE_OPCODE(dcontext, instr, buf, cmpxchg8b,
                        opnd_create_base_disp(REG_NULL, REG_NULL, 0, 0, OPSZ_8));
    return true;
}

int main()
{
    bool res;
    standalone_init();
    res = unit_check_sse3();
    res = unit_check_decode_ff_opcode() && res;
    return res;
}

#endif /* DECODE_UNIT_TEST */

