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

instr_info_t* decode_data_processing_and_els(byte* instr_word, 
                                             decode_info_t* di, bool just_opcode,
                                             opnd_t* dsts, opnd_t* srcs, 
                                             int* numdsts, int* numsrcs)
{
    instr_info_t *info = NULL;
    uint        opc = 0, temp = 0;
    bool        s_bit = false;
     

    opc |= (instr_word[0] & 0x1) << 4;

    opc |= (instr_word[1] >> 4);

    temp = (instr_word[1] << 7); 
    temp = (temp >> 7);

    s_bit = (bool)temp;
        

    return info;
}

instr_info_t* decode_data_processing_imm(byte* instr_word, 
                                         decode_info_t* di, bool just_opcode,
                                         opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    instr_info_t *info = NULL;

    return info;
}

instr_info_t* decode_load_store1(byte* instr_word, 
                                 decode_info_t* di, bool just_opcode,
                                 opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    instr_info_t *info = NULL;

    return info;
}

instr_info_t* decode_load_store2_and_media(byte* instr_word, 
                                           decode_info_t* di, bool just_opcode,
                                           opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    instr_info_t *info = NULL;

    return info;
}

instr_info_t* decode_load_store_multiple(byte* instr_word, 
                                        decode_info_t* di, bool just_opcode,
                                        opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    instr_info_t *info = NULL;

    return info;
}

instr_info_t* decode_branch(byte* instr_word, 
                            decode_info_t* di, bool just_opcode,
                            opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    /* OP_b, OP_bl, OP_blx */
    instr_info_t *info = NULL;
    uint  immed = 0;

    byte bit = instr_word[0] & (1 << 0);

    if( bit == 0 )//OP_b
    {
       di->opcode = OP_b; 
    }
    else
    {
       di->opcode = OP_bl; 
    }

    info = &op_instr[di->opcode];

    if( just_opcode )
      return info;

    /* SJF Check that the dsts and srcs are valid 
       arrays if flagged for operand decoding*/
    ASSERT( srcs != NULL && dsts != NULL ); 

    /* Decode imm here */

    immed |= (instr_word[1] << 16); 
    immed |= (instr_word[2] << 8);
    immed |= (instr_word[3]);

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_24);
    *numsrcs++;

    return info;
}

instr_info_t* decode_coprocessor_data_movement(byte* instr_word,
                                               decode_info_t* di, bool just_opcode,
                                               opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    instr_info_t *info = NULL;

    return info;
}

instr_info_t* decode_advanced_coprocessor(byte* instr_word,
                                          decode_info_t* di, bool just_opcode,
                                          opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    instr_info_t *info = NULL;

    return info;
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
                 bool just_opcode _IF_DEBUG(bool report_invalid),
                 opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs )
{
    DEBUG_DECLARE(byte *post_suffix_pc = NULL;)
    byte instr_byte, temp, instr_type;
    instr_info_t* info;
    bool vex_noprefix = false;
    byte instr_word[4] = {0};

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
    
    instr_word[0] = *pc;
    pc++;
    instr_word[1] = *pc;
    pc++;
    instr_word[2] = *pc;
    pc++;
    instr_word[3] = *pc;
    pc++;
    temp = (instr_word[0] << 4);  
    temp = (temp >> 5);
    instr_type = temp;
    
    switch( instr_type )
    {
        case INSTR_TYPE_DATA_PROCESSING_AND_ELS:
          info = decode_data_processing_and_els(instr_word, di, just_opcode, 
                                                dsts, srcs, numdsts, numsrcs); 
          break;
        case INSTR_TYPE_DATA_PROCESSING_IMM:
          info = decode_data_processing_imm(instr_word, di, just_opcode,
                                            dsts, srcs, numdsts, numsrcs); 
          break;
        case INSTR_TYPE_LOAD_STORE1:
          info = decode_load_store1(instr_word, di, just_opcode,
                                    dsts, srcs, numdsts, numsrcs); 
          break;
        case INSTR_TYPE_LOAD_STORE2_AND_MEDIA:
          info = decode_load_store2_and_media(instr_word, di, just_opcode, 
                                              dsts, srcs, numdsts, numsrcs); 
          break;
        case INSTR_TYPE_LOAD_STORE_MULTIPLE:
          info = decode_load_store_multiple(instr_word, di, just_opcode, 
                                            dsts, srcs, numdsts, numsrcs); 
          break;
        case INSTR_TYPE_BRANCH:
          info = decode_branch(instr_word, di, just_opcode,
                               dsts, srcs, numdsts, numsrcs); 
          break;
        case INSTR_TYPE_COPROCESSOR_DATA_MOVEMENT:
          info = decode_coprocessor_data_movement(instr_word, di, just_opcode, 
                                                  dsts, srcs, numdsts, numsrcs); 
          break;
        case INSTR_TYPE_ADVANCED_COPROCESSOR_AND_SYSCALL:
          info = decode_advanced_coprocessor(instr_word, di, just_opcode,
                                             dsts, srcs, numdsts, numsrcs); 
          break;
        default:
          CLIENT_ASSERT(false, "decode_error: unknown instr_type");
          break;
    }

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

static reg_id_t
ds_seg(decode_info_t *di)
{
    return SEG_DS;
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
    read_instruction(pc, pc, &info, &di, true /* just opcode */ _IF_DEBUG(true),
                     NULL, NULL, NULL, NULL);
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
    read_instruction(pc, pc, &info, &di, true /* just opcode */ _IF_DEBUG(true),
                     NULL, NULL, NULL, NULL);
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
                     _IF_DEBUG(!TEST(INSTR_IGNORE_INVALID, instr->flags)),
                     NULL, NULL, NULL, NULL);
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
                               _IF_DEBUG(!TEST(INSTR_IGNORE_INVALID, instr->flags)), 
                                dsts, srcs, &instr_num_dsts, &instr_num_srcs);
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

