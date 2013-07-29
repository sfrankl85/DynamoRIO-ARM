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

/* encode.c -- an x86 encoder */

#include "../globals.h"
#include "arch.h"
#include "instr.h"
#include "decode.h"
#include "disassemble.h"
#include "decode_fast.h"

#include <string.h> /* memcpy, memset */

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

/* level at which encoding attempts get dumped out...lots of logging! */
#define ENC_LEVEL 6

const char * const type_names[] = {
    "TYPE_NONE",
    "TYPE_A", /* immediate that is absolute address */
    "TYPE_I", /* immediate */
    "TYPE_J", /* immediate that is relative offset of EIP */
    "TYPE_M", /* modrm select mem addr */
    "TYPE_O", /* immediate that is memory offset */
    "TYPE_P",
    "TYPE_1",
    "TYPE_FLOATCONST",
    "TYPE_FLOATMEM",
    "TYPE_REG",
    "TYPE_CO_REG",
    "TYPE_INDIR_E",
    "TYPE_INDIR_REG",
};

/* order corresponds to enum of REG_ and SEG_ constants */
const char * const reg_names[] = {
    "<NULL>",
    "r0",   "r1",   "r2",   "r3",   "r4",   "r5",   "r6",   "r7"
    "r8",   "r9",   "r10",  "r11",  "r12",  "r13",  "r14",  "r15"
    "q0",   "q1",   "q2",   "q3",   "q4",   "q5",   "q6",   "q7"
    "q8",   "q9",   "q10",  "q11",  "q12",  "q13",  "q14",  "q15"
    "d0",   "d1",   "d2",   "d3",   "d4",   "d5",   "d6",   "d7"
    "d8",   "d9",   "d10",  "d11",  "d12",  "d13",  "d14",  "d15"
    "d16",  "d17",  "d18",  "d19",  "d20",  "d21",  "d22",  "d23"
    "d24",  "d25",  "d26",  "d27",  "d28",  "d29",  "d30",  "d31"
    "s0",   "s1",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7"
    "s8",   "s9",   "s10",  "s11",  "s12",  "s13",  "s14",  "s15"
    "s16",  "s17",  "s18",  "s19",  "s20",  "s21",  "s22",  "s23"
    "s24",  "s25",  "s26",  "s27",  "s28",  "s29",  "s30",  "s31"
    "<invalid>",
    "es",   "cs",   "ss",   "ds",   "fs",   "gs",

    "debug1","debug2", "control1", "control2", "cpsr"
    /* XXX: when you update here, update dr_reg_fixer[] in instr.c too */
};

const char * const size_names[] = {
    "<invalid>"/* was <NULL> */,
    "<invalid>"/* was rax */,  "<invalid>"/* was rcx */,
    "<invalid>"/* was rdx */,  "<invalid>"/* was rbx */,
    "<invalid>"/* was rsp */,  "<invalid>"/* was rbp */,
    "<invalid>"/* was rsi */,  "<invalid>"/* was rdi */,
    "<invalid>"/* was r8 */,   "<invalid>"/* was r9 */,
    "<invalid>"/* was r10 */,  "<invalid>"/* was r11 */,
    "<invalid>"/* was r12 */,  "<invalid>"/* was r13 */,
    "<invalid>"/* was r14 */,  "<invalid>"/* was r15 */,
    "<invalid>"/* was eax */,  "<invalid>"/* was ecx */,
    "<invalid>"/* was edx */,  "<invalid>"/* was ebx */,
    "<invalid>"/* was esp */,  "<invalid>"/* was ebp */,
    "<invalid>"/* was esi */,  "<invalid>"/* was edi */,
    "<invalid>"/* was r8d */,  "<invalid>"/* was r9d */,
    "<invalid>"/* was r10d */, "<invalid>"/* was r11d */,
    "<invalid>"/* was r12d */, "<invalid>"/* was r13d */,
    "<invalid>"/* was r14d */, "<invalid>"/* was r15d */,
    "<invalid>"/* was ax */,   "<invalid>"/* was cx */,
    "<invalid>"/* was dx */,   "<invalid>"/* was bx */,
    "<invalid>"/* was sp */,   "<invalid>"/* was bp */,
    "<invalid>"/* was si */,   "<invalid>"/* was di */,
    "<invalid>"/* was r8w */,  "<invalid>"/* was r9w */,
    "<invalid>"/* was r10w */, "<invalid>"/* was r11w */,
    "<invalid>"/* was r12w */, "<invalid>"/* was r13w */,
    "<invalid>"/* was r14w */, "<invalid>"/* was r15w */,
    "<invalid>"/* was al */,   "<invalid>"/* was cl */,
    "<invalid>"/* was dl */,   "<invalid>"/* was bl */,
    "<invalid>"/* was ah */,   "<invalid>"/* was ch */,
    "<invalid>"/* was dh */,   "<invalid>"/* was bh */,
    "<invalid>"/* was r8l */,  "<invalid>"/* was r9l */,
    "<invalid>"/* was r10l */, "<invalid>"/* was r11l */,
    "<invalid>"/* was r12l */, "<invalid>"/* was r13l */,
    "<invalid>"/* was r14l */, "<invalid>"/* was r15l */,
    "<invalid>"/* was spl */,  "<invalid>"/* was bpl */,
    "<invalid>"/* was sil */,  "<invalid>"/* was dil */,
    "<invalid>"/* was mm0 */,  "<invalid>"/* was mm1 */,
    "<invalid>"/* was mm2 */,  "<invalid>"/* was mm3 */,
    "<invalid>"/* was mm4 */,  "<invalid>"/* was mm5 */,
    "<invalid>"/* was mm6 */,  "<invalid>"/* was mm7 */,
    "<invalid>"/* was xmm0 */, "<invalid>"/* was xmm1 */,
    "<invalid>"/* was xmm2 */, "<invalid>"/* was xmm3 */,
    "<invalid>"/* was xmm4 */, "<invalid>"/* was xmm5 */,
    "<invalid>"/* was xmm6 */, "<invalid>"/* was xmm7 */,
    "<invalid>"/* was xmm8 */, "<invalid>"/* was xmm9 */,
    "<invalid>"/* was xmm10 */,"<invalid>"/* was xmm11 */,
    "<invalid>"/* was xmm12 */,"<invalid>"/* was xmm13 */,
    "<invalid>"/* was xmm14 */,"<invalid>"/* was xmm15 */,
    "<invalid>"/* was st0 */,  "<invalid>"/* was st1 */,
    "<invalid>"/* was st2 */,  "<invalid>"/* was st3 */,
    "<invalid>"/* was st4 */,  "<invalid>"/* was st5 */,
    "<invalid>"/* was st6 */,  "<invalid>"/* was st7 */,
    "<invalid>"/* was es */,   "<invalid>"/* was cs */,
    "<invalid>"/* was ss */,   "<invalid>"/* was ds */,
    "<invalid>"/* was fs */,   "<invalid>"/* was gs */,
    "<invalid>"/* was dr0 */,  "<invalid>"/* was dr1 */,
    "<invalid>"/* was dr2 */,  "<invalid>"/* was dr3 */,
    "<invalid>"/* was dr4 */,  "<invalid>"/* was dr5 */,
    "<invalid>"/* was dr6 */,  "<invalid>"/* was dr7 */,
    "<invalid>"/* was dr8 */,  "<invalid>"/* was dr9 */,
    "<invalid>"/* was dr10 */, "<invalid>"/* was dr11 */,
    "<invalid>"/* was dr12 */, "<invalid>"/* was dr13 */,
    "<invalid>"/* was dr14 */, "<invalid>"/* was dr15 */,
    "<invalid>"/* was cr0 */,  "<invalid>"/* was cr1 */,
    "<invalid>"/* was cr2 */,  "<invalid>"/* was cr3 */,
    "<invalid>"/* was cr4 */,  "<invalid>"/* was cr5 */,
    "<invalid>"/* was cr6 */,  "<invalid>"/* was cr7 */,
    "<invalid>"/* was cr8 */,  "<invalid>"/* was cr9 */,
    "<invalid>"/* was cr10 */, "<invalid>"/* was cr11 */,
    "<invalid>"/* was cr12 */, "<invalid>"/* was cr13 */,
    "<invalid>"/* was cr14 */, "<invalid>"/* was cr15 */,
    "<invalid>"/* was <invalid> */,
    "OPSZ_NA", 
    "OPSZ_1",
    "OPSZ_2",
    "OPSZ_4",
    "OPSZ_10",
    "OPSZ_14",
    "OPSZ_16",
    "OPSZ_24",
    "OPSZ_28",
    "OPSZ_32",
    "OPSZ_40",
    "OPSZ_94",
    "OPSZ_108",
    "OPSZ_512",
    "OPSZ_4_2",
    "OPSZ_4_3",
    "OPSZ_4_4",
    "OPSZ_4_5",
    "OPSZ_4_6",
    "OPSZ_4_8",
    "OPSZ_4_10",
    "OPSZ_4_12", 
    "OPSZ_4_16",
    "OPSZ_4_24",
};

#if defined(DEBUG) && defined(INTERNAL) && !defined(STANDALONE_DECODER)
/* These operand types store a reg_id_t as their operand "size" */
static bool
template_optype_is_reg(int optype)
{
    switch (optype) {
    case TYPE_REG:
    case TYPE_INDIR_REG:
        return true;
    }
    return false;
}
#endif

/***************************************************************************
 * Functions to see if instr operands match instr_info_t template
 */

static bool
type_instr_uses_reg_bits(int type)
{
        return false;
}

static bool
type_uses_modrm_bits(int type)
{
        return false;
}

/* Helper routine that sets/checks rex.w or data prefix, if necessary, for
 * variable-sized OPSZ_ constants that the user asks for.  We try to be flexible
 * setting/checking only enough prefix flags to ensure that the final template size
 * is one of the possible sizes in the request.
 */
static bool
size_ok_varsz(decode_info_t *di/*prefixes field is IN/OUT; x86_mode is IN*/,
              opnd_size_t size_op, opnd_size_t size_template,
              uint prefix_data_addr)
{
    /* FIXME: this code is getting long and complex: is there a better way?
     * Any way to resolve these var sizes further first?  Doesn't seem like it.
     */
    /* if identical sizes we shouldn't be called */
    CLIENT_ASSERT(size_op != size_template, "size_ok_varsz: internal decoding error");

    switch (size_op) 
    {
        default:
            CLIENT_ASSERT(false, "size_ok_varsz() internal decoding error (invalid size)");
            break;
    }
    return false;
}

static opnd_size_t
resolve_var_x64_size(decode_info_t *di/*x86_mode is IN*/,
                     opnd_size_t sz, bool addr_short4)
{
    return sz;
}

/* Caller should resolve the OPSZ_*_reg* sizes prior to calling this
 * routine, as here we don't know the operand types
 * Note that this routine modifies prefixes, so it is not idempotent; the
 * prefixes are stateful and are kept around as each operand is checked to
 * ensure the later ones are ok w/ prefixes needed for the earlier ones.
 */
static bool
size_ok(decode_info_t *di/*prefixes field is IN/OUT; x86_mode is IN*/,
        opnd_size_t size_op, opnd_size_t size_template, bool addr)
{
    uint prefix_data_addr = (addr ? PREFIX_ADDR : PREFIX_DATA);
    /* for OPSZ_4x8_short2, does the addr prefix select 4 instead of 2 bytes? */
    bool addr_short4 = X64_MODE(di) && addr;

    /* These should just return the size_template passed in */
    size_template = resolve_var_x64_size(di, size_template, addr_short4);
    size_op = resolve_var_x64_size(di, size_op, addr_short4);

    /* prefix doesn't come into play below here: do a direct comparison */

    DOLOG(4, LOG_EMIT, {
        if (size_op != size_template) {
            LOG(THREAD_GET, LOG_EMIT, ENC_LEVEL, "size_ok: %s != %s\n",
                size_names[size_op], size_names[size_template]);
        }
    });
    return (size_op == size_template);
}

static bool
mask_ok( opnd_t opnd )
{
  if( opnd.kind == MASK_kind )
  {
    if( opnd.value.mask == MASK_WRITE_NSCVQ_FLAGS ||
        opnd.value.mask == MASK_WRITE_G_FLAG ||
        opnd.value.mask == MASK_WRITE_ALL )
        return true;
    else
        return false;
  }
  else
    return false;
}

/* We assume size_ok() is called ahead of time to check whether a prefix
 * is needed.
 */
static bool
immed_size_ok(decode_info_t *di/*prefixes field is IN/OUT; x86_mode is IN*/,
              ptr_int_t immed, opnd_size_t opsize)
{
    opsize = resolve_variable_size(di, opsize, false);
    switch (opsize) {
    case OPSZ_1:
    case OPSZ_4_8:
        return (immed >= INT8_MIN && immed <= INT8_MAX);
    case OPSZ_2: /* unsigned max is 65535 */
    case OPSZ_4_16:
        return (immed >= INT16_MIN && immed <= INT16_MAX);
    case OPSZ_4:
        return true;
    case OPSZ_4_3:
        return (immed >= INT3_MIN && immed <= INT3_MAX);
    case OPSZ_4_4:
        return (immed >= INT4_MIN && immed <= INT4_MAX);
    case OPSZ_4_5:
        return (immed >= INT5_MIN && immed <= INT5_MAX);
    case OPSZ_4_6:
        return (immed >= INT6_MIN && immed <= INT6_MAX);
    case OPSZ_4_10:
        return (immed >= INT10_MIN && immed <= INT10_MAX);
    case OPSZ_4_12:
        return (immed >= INT12_MIN && immed <= INT12_MAX);
    case OPSZ_4_24:
        return (immed >= INT24_MIN && immed <= INT24_MAX);
    default:
        CLIENT_ASSERT(false, "encode error: immediate has unknown size");
        return false;
    }
}

/* prefixes that aren't set by size_ok */
static bool
reg_set_ext_prefixes(decode_info_t *di/*prefixes field is IN/OUT; x86_mode is IN*/,
                     reg_id_t reg, uint which_rex)
{
    return true; /* for use in && series */
}

static bool
reg_size_ok(decode_info_t *di/*prefixes field is IN/OUT; x86_mode is IN*/,
            reg_id_t reg, int optype, opnd_size_t opsize, bool addr)
{
    /* It's ok to have an operand of type mmx or xmm but half-size (e.g., movddup) */ 
    /* SJF TODO CHECK THIS IS CORRECT. This func needs to work */

    /* This should work for all the cases now as no var regs */
    if (size_ok(di, reg_get_size(reg), resolve_var_reg_size(opsize, true), addr)) {
        return true;
    }
    return false;
}

static bool
reg_rm_selectable(reg_id_t reg)
{
    /* TODO SJF Check */
    return (reg >= REG_START_64 && reg <= REG_STOP_DWR) ||
         (reg >= REG_START_QWR && reg <= REG_STOP_QWR);
}

static bool
mask_value_ok(int mask)
{
  if( mask >= UNKNOWN_MASK && mask <= WRITE_ALL_MASK )
    return true;
  else
    return false;
}

static bool
mem_size_ok(decode_info_t *di/*prefixes field is IN/OUT; x86_mode is IN*/,
            opnd_t opnd, int optype, opnd_size_t opsize)
{
    opsize = resolve_var_reg_size(opsize, false);
    if (!opnd_is_memory_reference(opnd))
        return false;
    return (size_ok(di, opnd_get_size(opnd), opsize, false/*!addr*/) &&
            (!opnd_is_base_disp(opnd) ||
             opnd_get_base(opnd) == REG_NULL ||
             reg_size_ok(di, opnd_get_base(opnd), TYPE_M,
                         OPSZ_4,
                         true/*addr*/)) &&
            (!opnd_is_base_disp(opnd) ||
             opnd_get_index(opnd) == REG_NULL ||
             reg_size_ok(di, opnd_get_index(opnd), TYPE_M,
                         OPSZ_4,
                         true/*addr*/)));
}

static bool
opnd_type_ok(decode_info_t *di/*prefixes field is IN/OUT; x86_mode is IN*/,
             opnd_t opnd, int optype, opnd_size_t opsize)
{

    DOLOG(ENC_LEVEL, LOG_EMIT, {
        dcontext_t *dcontext = get_thread_private_dcontext();
        LOG(THREAD, LOG_EMIT, ENC_LEVEL, "opnd_type_ok on operand ");
        opnd_disassemble(dcontext, opnd, THREAD);
        if (!opnd_is_pc(opnd) && !opnd_is_instr(opnd)) {
            LOG(THREAD, LOG_EMIT, ENC_LEVEL, "with size %s (%d bytes)\n",
                size_names[opnd_get_size(opnd)],
                opnd_size_in_bytes(opnd_get_size(opnd)));
        }
        LOG(THREAD, LOG_EMIT, ENC_LEVEL,
            "\tvs. template type %s with size %s (%d bytes)\n",
            type_names[optype], 
            template_optype_is_reg(optype) ?
            reg_names[opsize] : size_names[opsize],
            template_optype_is_reg(optype) ?
            opnd_size_in_bytes(reg_get_size(opsize)) : opnd_size_in_bytes(opsize));
    });

    switch (optype) {
    case TYPE_NONE: 
        return opnd_is_null(opnd);
    case TYPE_A:
        {
            return (opnd_is_far_pc(opnd) || opnd_is_far_instr(opnd));
        }
    case TYPE_O:  //For the mask value
        return (opnd_is_mask(opnd) && mask_value_ok(opnd_get_mask_value(opnd)));

    case TYPE_REG:
        /* SJF Changed opnd_get_reg to opnd_get_size. Looks like a mistake to me */
        return (opnd_is_reg(opnd) && opnd_get_size(opnd) == opsize);
    case TYPE_FLOATMEM:
    case TYPE_M: 
        return opnd_is_mem_reg(opnd);
        //return mem_size_ok(di, opnd, optype, opsize); SJF Old
    case TYPE_I:
        return ((opnd_is_immed_int(opnd) &&
                 size_ok(di, opnd_get_size(opnd), opsize, false/*!addr*/) &&
                 immed_size_ok(di, opnd_get_immed_int(opnd), opsize)));
    case TYPE_S:
        return opnd_is_mask( opnd ) && mask_ok( opnd );
    case TYPE_J:
        /* SJF This is the type used to store a branch target in an
               immed value. Need to rewrite to correct addr */
        return (opnd_is_near_pc(opnd));
    case TYPE_P: /* SJF Offset type */
        return false;
    default:
        CLIENT_ASSERT(false, "encode error: type ok: unknown operand type");
        return false;
    }
}

const instr_info_t *
instr_info_extra_opnds(const instr_info_t *info)
{
    return NULL;
}

/* macro for speed so we don't have to pass opnds around */
#define TEST_OPND(di, iitype, iisize, iinum, inst_num, get_op)   \
    if (iitype != TYPE_NONE) {                                   \
        if (inst_num < iinum)                                    \
            return false;                                        \
        if (!opnd_type_ok(di, get_op, iitype, iisize))           \
            return false;                                        \
        if (type_instr_uses_reg_bits(iitype)) {                  \
            if (!opnd_is_null(using_reg_bits) &&                 \
                !opnd_same(using_reg_bits, get_op))              \
                return false;                                    \
            using_reg_bits = get_op;                             \
        } else if (type_uses_modrm_bits(iitype)) {               \
            if (!opnd_is_null(using_modrm_bits) &&               \
                !opnd_same(using_modrm_bits, get_op))            \
                return false;                                    \
            using_modrm_bits = get_op;                           \
        }                                                        \
    } else if (inst_num >= iinum)                                \
        return false;

/* May be called a 2nd time to check size prefix consistency.
 * FIXME optimization: in 2nd pass we only need to call opnd_type_ok()
 * and don't need to check reg, modrm, numbers, etc.
 */
static bool
encoding_possible_pass(decode_info_t *di, instr_t *in, const instr_info_t * ii)
{
    DEBUG_DECLARE(dcontext_t *dcontext = get_thread_private_dcontext();)
    /* make sure multiple operands aren't using same modrm bits */
    opnd_t using_reg_bits = opnd_create_null();
    opnd_t using_modrm_bits = opnd_create_null();

    /* for efficiency we separately test 2 dsts, 3 srcs */
    TEST_OPND(di, ii->dst1_type, ii->dst1_size, 1, in->num_dsts, instr_get_dst(in, 0));
    TEST_OPND(di, ii->dst2_type, ii->dst2_size, 2, in->num_dsts, instr_get_dst(in, 1));
    TEST_OPND(di, ii->src1_type, ii->src1_size, 1, in->num_srcs, instr_get_src(in, 0));
    TEST_OPND(di, ii->src2_type, ii->src2_size, 2, in->num_srcs, instr_get_src(in, 1));
    TEST_OPND(di, ii->src3_type, ii->src3_size, 3, in->num_srcs, instr_get_src(in, 2));

    return true;
}

/* Does not check operands beyond 2 dsts and 3 srcs! 
 * Modifies in's prefixes to reflect whether operand or data size
 * prefixes are required.
 * Assumes caller has set di->x86_mode (i.e., ignores in's mode).
 */
static bool
encoding_possible(decode_info_t *di, instr_t *in, const instr_info_t * ii)
{
    DEBUG_DECLARE(dcontext_t *dcontext = get_thread_private_dcontext();)
    if (ii == NULL || in == NULL)
        return false;
    LOG(THREAD, LOG_EMIT, ENC_LEVEL, "\nencoding_possible on "PFX"\n", ii->instr_type);

    /* For size prefixes we use the di prefix field since that's what
     * the decode.c routines use; we transfer to the instr's prefix field
     * when done.  The first
     * operand that would need a prefix to match its template sets the
     * prefixes.  Rather than force operands that don't want prefixes
     * to say so (thus requiring a 3-value field: uninitialized,
     * prefix, and no-prefix, and extra work in the common case) we
     * instead do a 2nd pass if any operand wanted a prefix.
     * If an operand wants no prefix and the flag is set, the match fails.
     * I.e., first pass: does anyone want a prefix?  If so, 2nd pass: does
     * everyone want a prefix?  We also re-check the immed sizes on the 2nd
     * pass.
     *
     * If an operand specifies a variable-sized size, it will take on either of
     * the default size or the prefix size.
     */
    if (!encoding_possible_pass(di, in, ii))
        return false;
    LOG(THREAD, LOG_EMIT, ENC_LEVEL, "\ttemplate match : "PFX"\n");
    return true;
}

/* exported, looks at all possible instr_info_t templates
 */
bool
instr_is_encoding_possible(instr_t *instr)
{
    const instr_info_t * info = get_encoding_info(instr);
    return (info != NULL);
}

/* looks at all possible instr_info_t templates, returns first match
 * returns NULL if no encoding is possible
 */
const instr_info_t *
get_encoding_info(instr_t *instr)
{
    const instr_info_t * info = instr_get_instr_info(instr);
    decode_info_t di = {0};
    IF_X64(di.x86_mode = instr_get_x86_mode(instr));

    while (!encoding_possible(&di, instr, info)) {
        info = get_next_instr_info(info);
        /* SJF Removed. stop when hit end of list or when hit extra operand tables (OP_CONTD) */
        if (info == NULL) {
            return NULL;
        }
    }
    return info;
}

/* num is 0-based */
byte
instr_info_opnd_type(const instr_info_t *info, bool src, int num)
{
    if (num < 0) {
        CLIENT_ASSERT(false, "internal decode error");
        return TYPE_NONE;
    }
    if ((src && num >= 3) || (!src && num >= 2)) {
        const instr_info_t *nxt = instr_info_extra_opnds(info);
        if (nxt == NULL) {
            CLIENT_ASSERT(false, "internal decode error");
            return TYPE_NONE;
        } else
            return instr_info_opnd_type(nxt, src, src ? (num - 3) : (num - 2));
    } else {
        if (src) {
            if (num == 0)
                return info->src1_type;
            else if (num == 1)
                return info->src2_type;
            else if (num == 2)
                return info->src3_type;
            else {
                CLIENT_ASSERT(false, "internal decode error");
                return TYPE_NONE;
            }
        } else {
            if (num == 0)
                return info->dst1_type;
            else if (num == 1)
                return info->dst2_type;
            else {
                CLIENT_ASSERT(false, "internal decode error");
                return TYPE_NONE;
            }
        }
    }
    return TYPE_NONE;
}

/***************************************************************************
 * Actual encoding
 */

static void
encode_base_disp(decode_info_t * di, opnd_t opnd)
{
    reg_id_t base, index;
    int scale, disp;
    /* in 64-bit mode, addr prefix simply truncates registers and final address */

    /* user can use opnd_create_abs_addr() but it will internally be a base-disp
     * if its disp is 32-bit: if it's larger it has to be TYPE_O and not get here!
     */
    CLIENT_ASSERT(opnd_is_base_disp(opnd),
                  "encode error: operand type mismatch (expecting base_disp type)");

    base = opnd_get_base(opnd);
    index = opnd_get_index(opnd);
    scale = opnd_get_scale(opnd);
    disp = opnd_get_disp(opnd);
    if (base == REG_NULL && index == REG_NULL) {
    } else {
         if (disp >= INT8_MIN && disp <= INT8_MAX &&
                   !opnd_is_disp_force_full(opnd)) {
            /* 8-bit disp */
        } else {
            /* 32/16-bit disp */
        }
    }
}

static void
set_immed(decode_info_t *di, ptr_int_t val, opnd_size_t opsize)
{
    if (di->size_immed == OPSZ_NA) {
        di->immed = val;
        di->size_immed = opsize;
    } else {
        CLIENT_ASSERT(di->size_immed2 == OPSZ_NA,
                      "encode error: >4-byte immed encoding error");
        di->immed2 = val;
        di->size_immed2 = opsize;
    }
}

static byte *
get_mem_instr_addr(decode_info_t *di, opnd_t opnd)
{
    CLIENT_ASSERT(opnd_is_mem_instr(opnd), "internal encode error");
    return di->final_pc + ((ptr_int_t)opnd_get_instr(opnd)->note - di->cur_note) +
        opnd_get_mem_instr_disp(opnd);
}

static void
encode_operand(decode_info_t *di, int optype, opnd_size_t opsize, opnd_t opnd)
{
    switch (optype) {
    case TYPE_NONE: 
    case TYPE_REG:
    case TYPE_INDIR_REG:
        return;
    case TYPE_FLOATMEM:
    case TYPE_M:
        CLIENT_ASSERT(opnd_is_memory_reference(opnd),
                      "encode error: M operand must be mem ref");
        /* fall through */

        if (opnd_is_memory_reference(opnd)) {
            if (opnd_is_far_memory_reference(opnd)) {
            }
            if (opnd_is_mem_instr(opnd)) {
                byte *addr = get_mem_instr_addr(di, opnd);
                    encode_base_disp(di, opnd_create_abs_addr(addr, opnd_get_size(opnd)));
                di->has_instr_opnds = true;
            } else {
                    encode_base_disp(di, opnd);
            }
        } else {
            CLIENT_ASSERT(opnd_is_reg(opnd),
                          "encode error: not a memory address");
        }
        return;

    case TYPE_I:
        if (opnd_is_near_instr(opnd)) {
            /* allow instr as immed, that means we want to put in the 4/8-byte
             * pc of target instr as the immed
             * This only works if the instr has no other immeds!
             */
            instr_t *target_instr = opnd_get_instr(opnd);
            ptr_uint_t target = (ptr_uint_t)target_instr->note - di->cur_note;
            /* We don't know the encode pc yet, so we put it in as pc-relative and
             * fix it up later
             */
            set_immed(di, (ptr_uint_t)target, opsize);
            /* this immed is pc-relative except it needs to have the
             * instruction length subtracted from it -- we indicate that
             * like this:
             */
            CLIENT_ASSERT(di->size_immed2 == OPSZ_NA,
                          "encode error: immed size already set");
            di->size_immed2 = resolve_variable_size(di, opsize, false);
            /* And now we ask to be adjusted to become an absolute pc: */
            di->size_immed = OPSZ_16; /* == immed needs +pc */
            di->has_instr_opnds = true;
        } else {
            CLIENT_ASSERT(opnd_is_immed_int(opnd), "encode error: opnd not immed int");
            set_immed(di, opnd_get_immed_int(opnd), opsize);
        }
        return;
    case TYPE_J:
        {
            ptr_uint_t target;
            /* Since we don't know pc values right now, we convert
             * from an absolute pc to a relative offset in encode_immed.
             * Here we simply set the immed to the absolute pc target.
             */
            if (opnd_is_near_instr(opnd)) {
                /* assume the note fields have been set with relative offsets
                 * from some start pc, and that our caller put our note in
                 * di->cur_note
                 */
                instr_t *target_instr = opnd_get_instr(opnd);
                target = (ptr_uint_t)target_instr->note - di->cur_note;
                /* target is now a pc-relative target, so we can encode as is */
                set_immed(di, target, opsize);
                /* this immed is pc-relative except it needs to have the
                 * instruction length subtracted from it -- we indicate that
                 * like this:
                 */
                CLIENT_ASSERT(di->size_immed2 == OPSZ_NA,
                              "encode error: immed size already set");
                di->size_immed2 = opsize;
                di->size_immed = OPSZ_10; /* == immed needs -length */
                di->has_instr_opnds = true;
            } else {
                CLIENT_ASSERT(opnd_is_near_pc(opnd), "encode error: opnd not pc");
                target = (ptr_uint_t) opnd_get_pc(opnd);
                set_immed(di, target, opsize);
                /* here's how we indicate that this immed needs to
                 * be pc-relativized, we take advantage of the fact that all
                 * TYPE_J do not have other immeds in the same instruction:
                 */
                CLIENT_ASSERT(di->size_immed2 == OPSZ_NA,
                              "encode error: immed size already set");
                di->size_immed2 = opsize;
                di->size_immed = OPSZ_512; /* == immed needs relativizing */
            }
            return;
        }
    case TYPE_O:
        {
            ptr_int_t addr;
            CLIENT_ASSERT(opnd_is_abs_addr(opnd) ||
                          /* rel addr => abs if won't reach */
                          IF_X64(opnd_is_rel_addr(opnd) ||)
                          (!X64_MODE(di) && opnd_is_mem_instr(opnd)),
                          "encode error: O operand must be absolute mem ref");
            if (opnd_is_mem_instr(opnd)) {
                addr = (ptr_int_t) get_mem_instr_addr(di, opnd);
                di->has_instr_opnds = true;
            } else
                addr = (ptr_int_t) opnd_get_addr(opnd);
            if (opnd_is_far_abs_addr(opnd)) {
              //SJF ???
            }
            set_immed(di, addr, resolve_addr_size(di));
            return;
        }

    default:
        CLIENT_ASSERT(false, "encode error: unknown operand type");
    }
}


/* special-case (==fast) encoder for cti instructions 
 * this routine cannot handle indirect branches or rets or far jmp/call;
 * it can handle loop/jecxz but it does NOT check for data16!
 */
static byte *
encode_cti(instr_t *instr, byte *copy_pc, byte *final_pc, bool check_reachable
           _IF_DEBUG(bool assert_reachable))
{
    byte *pc = copy_pc;
    const instr_info_t * info = instr_get_instr_info(instr);
    opnd_t opnd;
    ptr_uint_t target;

#ifdef NO
//SJF Need to convert to encode branch
    /* output opcode */
    /* first opcode byte */
    *pc = (byte)((info->opcode & 0x00ff0000) >> 16); 
    pc++;
    /* second opcode byte, if there is one */
    if (TEST(OPCODE_TWOBYTES, info->opcode)) {
        *pc = (byte)((info->opcode & 0x0000ff00) >> 8); 
        pc++;
    }
    ASSERT(!TEST(OPCODE_THREEBYTES, info->opcode)); /* no cti has 3 opcode bytes */

    /* we assume only one operand: 1st src == jump target, but we do
     * not check that, for speed
     */
    opnd = instr_get_target(instr);
    if (opnd_is_near_pc(opnd)) {
        target = (ptr_uint_t) opnd_get_pc(opnd);
    } else if (opnd_is_near_instr(opnd)) {
        instr_t *in = opnd_get_instr(opnd);
        target = (ptr_uint_t)final_pc + ((ptr_uint_t)in->note - (ptr_uint_t)instr->note);
    } else {
        target = 0; /* avoid compiler warning */
        CLIENT_ASSERT(false, "encode_cti error: opnd must be near pc or near instr");
    }

    if (instr_is_cti_short(instr)) {
        /* 8-bit offset */
        ptr_int_t offset;
        /* offset is from start of next instr */
        offset = target - ((ptr_int_t)(pc + 1 - copy_pc + final_pc));
        if (check_reachable && !(offset >= INT8_MIN && offset <= INT8_MAX)) {
            CLIENT_ASSERT(!assert_reachable,
                          "encode_cti error: target beyond 8-bit reach");
            return NULL;
        }
        *((char *)pc) = (char) offset;
        pc++;
    } else {
        /* 32-bit offset */
        /* offset is from start of next instr */
        ptr_int_t offset = target - ((ptr_int_t)(pc + 4 - copy_pc + final_pc));
#ifdef X64
        if (check_reachable && !REL32_REACHABLE_OFFS(offset)) {
            CLIENT_ASSERT(!assert_reachable,
                          "encode_cti error: target beyond 32-bit reach");
            return NULL;
        }
#endif
        *((int *)pc) = (int) offset;
        pc += 4;
    }
#endif//NO
    return pc;
}

/* PR 251479: support general re-relativization.
 * Takes in a level 0-3 instruction and encodes it by copying its
 * raw bytes to dst_pc. For x64, if it is marked as having a rip-relative 
 * displacement, that displacement is re-relativized to reach
 * its current target from the encoded location.
 * Returns NULL on failure to encode (due to reachability).
 */
byte *
copy_and_re_relativize_raw_instr(dcontext_t *dcontext, instr_t *instr,
                                 byte *dst_pc, byte *final_pc)
{
    byte *orig_dst_pc = dst_pc;
    ASSERT(instr_raw_bits_valid(instr));
    /* FIXME i#731: if want to support ctis as well, need
     * instr->rip_rel_disp_sz and need to set both for non-x64 as well
     * in decode_sizeof(): or only in decode_cti()?
     */
    /* For PR 251646 we have special support for mangled jecxz/loop* */
    memcpy(dst_pc, instr->bytes, instr->length);

    return orig_dst_pc + instr->length;
}

/******************************************************************************
 
                SJF: ARM Specific encoding instructions                        *

******************************************************************************/


int
convert_immed_to_shifted_immed( int immed_int, int sz )
{
  bool fin = false;
  int  shifts=0;
  int  shift_int = 0;

  switch( sz )
  {
    case OPSZ_4_12:
      //SJF TODO Check if immed cannot fit in 8 bits. If not then shift it
      if( immed_int > INT8_MAX || immed_int < INT8_MIN )
      {
        do
        {
          if( ( immed_int & 0x3 ) == 0x0 ) //Ok to shift
          {
            immed_int = (immed_int >> 2);

            if( immed_int <= INT8_MAX && immed_int >= INT8_MIN )
              fin = true;

            shifts++;
          }
        } while( !fin );

        shift_int |= (shifts<<8);  

        shift_int |= (immed_int&0xff);

        return shift_int;
      }
      else
        return immed_int;
      break;

    default:
      //FAIL
      break;
  }
}



byte* 
write_word_to_fcache( byte* pc, byte* word )
{
   //Word should now be an instruction. MSB encoding
   *((byte *)pc) = word[3];
   pc++;
   *((byte *)pc) = word[2];
   pc++;
   *((byte *)pc) = word[1];
   pc++;
   *((byte *)pc) = word[0];
   pc++;

   return pc;
}

/* The first 12 bits can be encoded from the cond, instr_type, opcode and
   the flag decode information. Is the same across most instructions( aprt from
   branch and special purpose ones so put in separate functions */
void
encode_bits_31_to_20(decode_info_t* di, instr_t* instr, instr_info_t* info, byte* word)
{
    uint  instr_type;
    byte        b, t;

    /*************** Encode condition code **************/
    if( instr_is_unconditional( instr ) )
    {
        //Encode unconditional
        b = 0xf0;
        word[0] |= b; 
    }
    else
    {
        b = instr->cond;
        word[0] |= (b << 4); 
    }

    /**************** Encode instr type bits[27, 25] *****************/

    instr_type = instr_info_get_instr_type( info );

    b = instr_get_instr_type_value( instr_type );

    word[0] |= (b << 1);

    /**************** Encode opcode bits[24, 20] *****************/

    //get first bit of opcode
    b = 16; //0001 0000
    b &= (byte) info->opcode;
    word[0] |= (b >> 4); 

    //get last 4 bits of opcode
    b = 15; //0000 1111 
    b &= (byte) info->opcode;
    word[1] |= (b << 4);

    /**************** Encode flags is necessary for instr *************/

    //Add s bit if necessary
    if( instr_has_s_flag( instr ))
    {
      t = instr->s_flag ? 0x10 : 0 ;
      word[1] |= t; 
    }

    //Add w bit if necessary
    if( instr_has_w_flag( instr ))
    {
      t = instr->w_flag ? 0x20 : 0 ;
      word[1] |= t;
    }

    //Add d bit if necessary
    if( instr_has_d_flag( instr ))
    {
      t = instr->d_flag ? 0x40 : 0 ;
      word[1] |= t;
    }

    //Add u bit if necessary
    if( instr_has_u_flag( instr ))
    {
      t = instr->u_flag ? 0x80 : 0 ;
      word[1] |= t;
    }

    //Add p bit if necessary
    if( instr_has_p_flag( instr ))
    {
      t = instr->p_flag ? 0x1 : 0 ;
      word[0] |= t;
    }
}

void
encode_bits_7_to_4(decode_info_t* di, instr_t* instr, instr_info_t* info, byte* word)
{
  //Encode the '2nd' opcode in bits[7,4] if needed.
  //Also adds the shift type if required

  if( instr_is_shift_type( instr ))
  {
    switch( di->shift_type )
    {
      case LOGICAL_LEFT:
      case LOGICAL_RIGHT:
      case ARITH_RIGHT:
      case ROTATE_RIGHT:
        word[3] |= (di->shift_type << 5);
        break;

      default:
        break;
    }
  }

  //Just add the opcode here. If not needed and 0 will make no difference
  if( word[3] != 0x0 )
    word[3] |= info->opcode2;

}


byte*
encode_1dst_reg_2src_reg_1src_imm(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0000010S | Rn | Rd | imm5 | type | 0 | Rm |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */

    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );
    
    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b << 4);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }    
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[1] |= b;
            break;

          case BASE_DISP_kind:
            //TODO Recalcualte mem location here?
            b = opnd.value.base_disp.base_reg;

            b--; //To get actual reg number
            word[1] |= b;
            break;

          case MEM_REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[1] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    // SRC 2
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            
            b--; //To get actual reg number
            word[3] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    //SRC 3
    {
        opnd = instr_get_src(instr, 2);

        switch( opnd.kind )
        {
          //For _reg opcodes
          case IMMED_INTEGER_kind:
            b = convert_immed_to_shifted_immed( opnd.value.immed_int, OPSZ_4_12 );

            word[2] |= (b >> 1);

            b = (convert_immed_to_shifted_immed( opnd.value.immed_int, OPSZ_4_12 ) & 0x1);

            word[3] |= (b << 7 );
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }
    }

    encode_bits_7_to_4( di, instr, info, word );


    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_1src_reg_0src_imm_2(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | xxxxxxxS | Rn | Rt | xxxx | xxxx | xxxx 

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */

    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b << 4);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number

            word[1] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_1src_reg_0src_imm(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | xxxxxxxS | xxxx | Rd | xxxx | xxxx | Rm

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */

    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b << 4);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number

            word[3] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_2src_reg_0src_imm(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | xxxxxxxS | xxxx | Rd | Rs | xxxx | Rm

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b << 4);
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }    
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            
            b--; //To get actual reg number
            word[2] |= b;
            break;

          case BASE_DISP_kind:
            //TODO Recalcualte mem location here?
            b = opnd.value.base_disp.base_reg;

            b--; //To get actual reg number
            word[1] |= b;
            break;

          case MEM_REG_kind:
            b = opnd.value.reg;
    
            b--; //To get actual reg number
            word[1] |= b;
            break;


          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    // SRC 2
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            
            b--; //To get actual reg number
            word[2] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_1src_reg_1src_imm_3(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0001101S | Rn | 0000 | imm5 | 010 | Rm |
    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[1] |= b;
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            
            b--; //To get actual reg number
            word[3] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    // SRC 2
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case IMMED_INTEGER_kind:
            b = (opnd.value.immed_int>>2);
            
            word[2] |= b;

            b = (opnd.value.immed_int);

            word[3] = (b << 7);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_1src_reg_1src_imm(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0001101S | 0000 | Rd | imm5 | 010 | Rm |
    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b << 4);
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            

            b--; //To get actual reg number
            word[3] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    // SRC 2
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case IMMED_INTEGER_kind:
            b = (opnd.value.immed_int>>2);
            
            word[2] |= b;

            b = (opnd.value.immed_int);
            b &= 0x3;

            word[3] = (b << 7);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }
    }

    encode_bits_7_to_4( di, instr, info, word );


    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_0src_reg_1src_imm_3(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0010000S | 0000 | Rt | I4Hi | xxxx | I4Lo |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );


    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b<<4);
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }
    }

    // SRC 1
    //TODO Encode the second opcode here
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case IMMED_INTEGER_kind:
            b = (opnd.value.immed_int>>4);
            
            word[2] |= b;

            b = (opnd.value.immed_int);
            b &= 0xf;

            word[3] = b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}


byte*
encode_1dst_reg_0src_reg_1src_imm_2(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0010000S | 0000 | Rt | I12 |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );


    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b<<4);
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case IMMED_INTEGER_kind:
            b = (opnd.value.immed_int>>9);
            
            word[2] |= b;

            b = (opnd.value.immed_int);
            b &= 0xff;

            word[3] = b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_0src_reg_1src_imm(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0010000S | Rn | 0000 | I12 |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );


    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[1] |= b;
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case IMMED_INTEGER_kind:
            b = (opnd.value.immed_int>>9);
            
            word[2] |= b;

            b = (opnd.value.immed_int);
            b &= 0xff;

            word[3] = b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_1src_reg_1src_imm_4(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0010000S | Rn | Rd | I4Hi | xxxx | I4Lo

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );


    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b << 4);
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            
            b--; //To get actual reg number
            word[1] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    // SRC 2
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case IMMED_INTEGER_kind:
            b = (opnd.value.immed_int>>4);
            
            word[2] |= b;

            b = (opnd.value.immed_int);
            b &= 0xf;

            word[3] = b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_1src_reg_1src_imm_2(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0010000S | Rn | Rd | I12 |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );


    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b << 4);
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            
            b--; //To get actual reg number
            word[1] |= b;
            break;

          //For reg values that store mem address
          //TODO Recalcualte mem address??
          case BASE_DISP_kind:
            b = opnd.value.base_disp.base_reg;
            
            b--; //To get actual reg number
            word[1] |= b;
            break;

          case MEM_REG_kind:
            b = opnd.value.reg;
            
            b--; //To get actual reg number
            word[1] |= b;
            break;
            

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    // SRC 2
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case IMMED_INTEGER_kind:
            b = convert_immed_to_shifted_immed( opnd.value.immed_int, OPSZ_4_12 );

            b = (b >> 8);
            
            word[2] |= b;

            b = convert_immed_to_shifted_immed( opnd.value.immed_int, OPSZ_4_12 );
            b &= 0xff;

            word[3] = b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_0dst_reg_1src_imm_1src_mask(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 00010100 | mask | 00 | 1111 | I12 |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************** Encode operands here *****************/

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);      
 
        switch( opnd.kind )
        {
          case IMMED_INTEGER_kind:
            b = (opnd.value.immed_int>>8);

            word[2] |= b;

            b = (opnd.value.immed_int);
            b &= 0xff;

            word[3] = b;
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }    
    }

    // SRC 2
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case MASK_kind:
            b = opnd.value.mask;

            word[1] |= (b<<2);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }


    //TODO Need to write to bits[7,4] if mul(1001)

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_0dst_reg_1src_reg_1src_mask(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 00010100 | mask | 00 | 1111 | 0000 | 0000 | Rn |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************** Encode operands here *****************/

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[3] |= b;
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }    
    }

    // SRC 2
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case MASK_kind:
            b = opnd.value.mask;

            word[1] |= (b<<2);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }


    //TODO Need to write to bits[7,4] if mul(1001)

    encode_bits_7_to_4( di, instr, info, word );


    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_0dst_reg_1src_reg_0src_imm(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 00010000 | 1111 | Rd | 0000 | 0000 | 0000 |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************** Encode operands here *****************/

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[2] |= (b<<4);
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }    
    }

    encode_bits_7_to_4( di, instr, info, word );

   //Word should now be an instruction. MSB encoding
   *((byte *)pc) = word[0];
   pc++;
   *((byte *)pc) = word[1];
   pc++;
   *((byte *)pc) = word[2];
   pc++;
   *((byte *)pc) = word[3];
   pc++;

   return pc;
}


byte*
encode_1dst_reg_2src_reg_0src_imm_2(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0000000S | Rd | 0000 | Rm | 1001 | Rn |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /* 
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************** Encode operands here *****************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 0);      
 
        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;

            b--; //To get actual reg number
            word[1] |= b;
            break;
            
          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
            
        }    
    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 0);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            
            b--; //To get actual reg number
            word[2] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    // SRC 2
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            
            b--; //To get actual reg number
            word[3] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;

        }
    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_2src_reg_0src_imm_5(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0000001x | Rn | Rt | xxxx | 1001 | Rm |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /*
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */

    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************* Encode operands *************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[2] |= (b<<4);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[1] |= (b);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 2 
    {
        opnd = instr_get_src(instr, 2);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[3] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_2src_reg_0src_imm_4(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0000001x | 0000 | Rn | Rt | 1001 | Rm |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /*
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */

    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************* Encode operands *************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[2] |= (b<<4);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[1] |= (b);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 2 
    {
        opnd = instr_get_src(instr, 2);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[3] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_2src_reg_0src_imm_3(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0000001x | Rn | 0000 | Rs | 1001 | Rm |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /*
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */

    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************* Encode operands *************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[1] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[3] |= (b);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 2 
    {
        opnd = instr_get_src(instr, 2);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[2] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_1dst_reg_3src_reg_0src_imm(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 0000001S | Rd | Ra | Rm | 1001 | Rn |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /*
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */

    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************* Encode operands *************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[2] |= (b << 4);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[3] |= (b);
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 2 
    {
        opnd = instr_get_src(instr, 2);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[1] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 3
    {
        opnd = instr_get_src(instr, 3);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[2] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte* 
encode_0dst_reg_1src_reglist(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 100010W1 | xxxx | Rl |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /*
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************* Encode operands *************/

    // SRC 1
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = (opnd.value.reg >> 8);

            word[2] |= b;

            b = opnd.value.reg;
            /* Last byte is all the reg list */
            word[3] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte* 
encode_1dst_reg_1src_reglist(decode_info_t* di, instr_t* instr, byte* pc)
{
    // | cond | 100010W1 | Rn | Rl |

    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /*
       Instruction encoded as 31-0
       |cond|instr_type|opcode|operands/flags|
     */
    info = instr_get_instr_info(instr);

    if( info == NULL )
        CLIENT_ASSERT(false, "instr_encode error: invalid info" );

    encode_bits_31_to_20( di, instr, info, word );

    /************* Encode operands *************/

    // DST 1
    {
        opnd = instr_get_dst(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = opnd.value.reg;
            b--;

            b &= 0xf;//0000 1111

            word[1] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    // SRC 1
    {
        opnd = instr_get_src(instr, 1);

        switch( opnd.kind )
        {
          case REG_kind:
            b = (opnd.value.reg >> 8);
        
            word[2] |= b;

            b = opnd.value.reg;
            /* Last byte is all the reg list */
            word[3] |= b;
            break;

          default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
            break;
        }

    }

    encode_bits_7_to_4( di, instr, info, word );

    pc = write_word_to_fcache(pc, word );

   return pc;
}

byte*
encode_branch_instrs(decode_info_t* di, instr_t* instr, byte* pc)
{
    byte word[4] = {0};  //Instr encoding in byte array
    uint        opc;
    byte        b, t;
    uint        opc_bits;
    opnd_t      opnd;
    instr_info_t* info;
    uint  instr_type;

    opc = instr_get_opcode(instr);

    /*
       Instruction encoded as 31-0
       |cond|1010|imm24|
     */

    /*********** Encode condition code. TODO Move to decode_info_t *********/

    if( instr_is_unconditional( instr ) )
    {
        //Encode unconditional
        b = 0xf0;
        word[0] |= b;
    }
    else
    {
        b = 0;
        b &= instr->cond;
        word[0] |= (b << 4);
    }


    switch( opc )
    {
        case OP_b:
          word[0] |= 0xa;
          break;
        case OP_bl:
          word[0] |= 0xb;
          break;
        case OP_blx_imm:
          word[0] |= 0xa;
          /* TODO Set H flag */
          break;
          
        case OP_blx_reg:
          word[0] |= 0x1;
          word[1] = 0x2f;
          word[2] = 0xff;

          word[3] |= (0x3 << 4);

          opnd = instr_get_src(instr, 0);

          switch( opnd.kind )
          {
            case REG_kind:
              b = opnd.value.reg;
              b--;

              b &= 0xf;//0000 1111

              word[3] |= b;
              break;

            default:
              CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
              break;
          }
          
          break;
    }

    // If not blx_reg then encodes address as 24 bit immed
    if( opc != OP_blx_reg )
    {
          opnd = instr_get_src(instr, 0);

          switch( opnd.kind )
          {
            case PC_kind:
              /* TODO Calc offset */

              b = (byte)(opnd.value.immed_int >> 16);
              word[1] = b;

              b = (byte)(opnd.value.immed_int >> 8);
              word[2] = b;

              b = (byte)(opnd.value.immed_int & 0xff);

              word[3] = b;
              break;

            default:
              CLIENT_ASSERT(false, "instr_encode error: invalid opnd type" );
              break;
          }

    }

    pc = write_word_to_fcache(pc, word );

   // Have a separate function for branch instrs to calc correct address
   // Branch instrs are pretty simple anyway
   return pc;
}

byte*
encode_data_processing_and_els(decode_info_t* di, instr_t* instr, byte* pc)
{
    uint opc;
    byte* nxt_pc = pc;

    opc = instr_get_opcode(instr);

    switch( opc )
    {
        /* Switch to instruction encoding function 
           based on opcode 1. Can switch between different encodings
           in the sub functions */
        case OP_and_reg: //C
        case OP_adc_reg: //C
        case OP_add_reg: //C
          nxt_pc = encode_1dst_reg_2src_reg_1src_imm(di, instr, pc);
          break;
        case OP_cmp_reg: //C
        case OP_cmn_reg: //C
        case OP_teq_reg: //C
        case OP_tst_reg: //C
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm_3(di, instr, pc);
          break;
        case OP_sub_reg: //C
        case OP_sbc_reg: //C
        case OP_rsc_reg: //C
        case OP_rsb_reg: //C
        case OP_orr_reg: //C
        case OP_eor_reg: //C
        case OP_bic_reg: //C
          nxt_pc = encode_1dst_reg_2src_reg_1src_imm(di, instr, pc);
          break;
        case OP_mvn_reg: //C
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm(di, instr, pc);
          break;
        case OP_mov_reg: //C
          nxt_pc = encode_1dst_reg_1src_reg_0src_imm(di, instr, pc);
          break;
        case OP_lsl_reg: //C
        case OP_lsr_reg: //C
        case OP_asr_reg: //C
        case OP_ror_reg: //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm(di, instr, pc);
          break;
        case OP_rrx:
          nxt_pc = encode_1dst_reg_1src_reg_0src_imm(di, instr, pc);
          break;
        case OP_lsl_imm: //C
        case OP_lsr_imm: //C
        case OP_asr_imm: //C
        case OP_ror_imm: //C
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm(di, instr, pc);
          break;
        case OP_add_sp_imm: //C
          nxt_pc = encode_1dst_reg_0src_reg_1src_imm(di, instr, pc);
          break;
        case OP_add_sp_reg: //C
        case OP_sub_sp_reg: //C
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm(di, instr, pc);
          break;
        case OP_sub_sp_imm: //C
          nxt_pc = encode_1dst_reg_0src_reg_1src_imm_2(di, instr, pc);
          break;
        case OP_cmn_rsr: //C
        case OP_cmp_rsr: //C
        case OP_teq_rsr: //C
        case OP_tst_rsr: //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm_3(di, instr, pc);
          break;
        case OP_sub_rsr: //C
        case OP_rsb_rsr: //C
        case OP_and_rsr: //C
        case OP_add_rsr: //C
        case OP_adc_rsr: //C
        case OP_sbc_rsr: //C
        case OP_rsc_rsr: //C
        case OP_orr_rsr: //C
        case OP_bic_rsr: //C
        case OP_eor_rsr: //C
          nxt_pc = encode_1dst_reg_3src_reg_0src_imm(di, instr, pc);
          break;
        case OP_mvn_rsr: //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm(di, instr, pc);
          break;
          //Multiply instrs
        case OP_mul: //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm_2(di, instr, pc);
          break;
        case OP_mls: //C
        case OP_mla: //C
        case OP_smlabb: //C
        case OP_smlabt: //C
        case OP_smlatb: //C
        case OP_smlatt: //C
          nxt_pc = encode_1dst_reg_3src_reg_0src_imm(di, instr, pc);
          break;
        case OP_umaal:
        case OP_umull:
        case OP_umlal:
        case OP_smull:
        case OP_smlal:
        case OP_qadd: //C
        case OP_qadd16: //C
        case OP_qadd8: //C
        case OP_qdadd: //C
        case OP_qsub:  //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm_5(di, instr, pc);
          break;
        case OP_qdsub:
        case OP_smlawb:
        case OP_smlawt:
        case OP_smulwb:
        case OP_smulwt:
        case OP_smlalbb:
        case OP_smlalbt:
        case OP_smlaltb:
        case OP_smlaltt:
        case OP_smulbb:
        case OP_smulbt:
        case OP_smultb:
        case OP_smultt:
          break;
          //Extra load/store
        case OP_strh_reg: //C
        case OP_ldrh_reg: //C
        case OP_ldrht: //C
        case OP_ldrsbt: //C
        case OP_ldrsh_reg: //C
        case OP_strd_reg: //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm_5(di, instr, pc);
          break;
        case OP_strh_imm: //C
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm_4(di ,instr, pc);
          break;
        case OP_ldrd_reg: //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm_4(di, instr, pc);
          break;
        case OP_ldrd_imm: //C
        case OP_ldrh_imm: //C
        case OP_ldrsb_imm: //C
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm_4(di, instr, pc);
          break;
        case OP_ldrd_lit: //C
        case OP_ldrh_lit: //C
        case OP_ldrsb_lit: //C
        case OP_ldrsh_lit:
          nxt_pc = encode_1dst_reg_0src_reg_1src_imm_3(di, instr, pc);
          break;
        case OP_strd_imm: //C
        case OP_strht: //C
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm_4(di, instr, pc);
          break;
        case OP_ldrsh_imm:
          break;
        case OP_ldrsht: //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm_5(di, instr, pc);
          break;
          //Synchro primitves
        case OP_swp:
        case OP_swpb:
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm_5(di, instr, pc);
          break;
        case OP_strex:  //C
        case OP_strexb: //C
        case OP_strexd: //C
        case OP_strexh: //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm_5(di, instr, pc);
          break;
        case OP_ldrex: //C
        case OP_ldrexb: //C
        case OP_ldrexd: //C
        case OP_ldrexh: //C
          nxt_pc = encode_1dst_reg_1src_reg_0src_imm_2(di, instr, pc);
          break;
        //misc
        case OP_cps:
        case OP_setend:
          //Add encode func 
          break;
        case OP_msr_imm: //C
          nxt_pc = encode_0dst_reg_1src_imm_1src_mask(di, instr, pc);
          break;
        case OP_msr_reg: //C
          nxt_pc = encode_0dst_reg_1src_reg_1src_mask(di, instr, pc);
          break;
        case OP_mrs: //C
          nxt_pc = encode_0dst_reg_1src_reg_0src_imm(di, instr, pc);
          break;
        default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opcode for instr_type" );
            break;
    }

    return nxt_pc;
}

byte*
encode_data_processing_imm_and_misc(decode_info_t* di, instr_t* instr, byte* pc)
{
    uint opc;
    byte* nxt_pc = pc;

    opc = instr_get_opcode(instr);

    switch( opc )
    {
        case OP_adr: //C
        case OP_cmn_imm: //C
        case OP_cmp_imm: //C
        case OP_teq_imm: //C
        case OP_tst_imm: //C
          nxt_pc = encode_1dst_reg_0src_reg_1src_imm(di, instr, pc);
          break;
        case OP_mvn_imm: //C
        case OP_mov_imm: //C
          nxt_pc = encode_1dst_reg_0src_reg_1src_imm_2(di, instr, pc);
          break;
        case OP_sub_imm: //C
        case OP_sbc_imm: //C
        case OP_rsc_imm: //C
        case OP_rsb_imm: //C
        case OP_orr_imm: //C
        case OP_bic_imm: //C
        case OP_eor_imm: //C
        case OP_and_imm: //C
        case OP_add_imm: //C
        case OP_adc_imm: //C < Flag to indicate checked 
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm_2(di, instr, pc);
          break;
        //Extar instrs
        case OP_nop:
        case OP_yield:
        case OP_wfe:
        case OP_wfi:
        case OP_sev:
        case OP_dbg:
          break;
        //Misc
        case OP_bx:
        case OP_clz:
        case OP_bxj:
        case OP_blx_imm:
        case OP_blx_reg:
        case OP_bkpt:
          break;
        //case OP_smc:
        default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opcode for instr_type" );
            break;
    }

    return nxt_pc;
}

byte*
encode_load_store_1_and_misc(decode_info_t* di, instr_t* instr, byte* pc)
{
    uint opc;
    byte* nxt_pc = pc;

    opc = instr_get_opcode(instr);

    switch( opc )
    {
        case OP_str_imm: //C
        case OP_ldr_imm: //C
        case OP_ldrb_imm: //C
        case OP_strb_imm: //C
        case OP_strt: //C
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm_2(di, instr, pc);
          break;
        case OP_ldrt: //C
          nxt_pc = encode_1dst_reg_2src_reg_1src_imm(di, instr, pc);
          break;
        case OP_strbt: //C
        case OP_ldrbt: //C
          nxt_pc = encode_1dst_reg_1src_reg_1src_imm_2(di, instr, pc);
          break;
        case OP_ldr_lit:
        case OP_ldrb_lit:
          nxt_pc = encode_1dst_reg_0src_reg_1src_imm_2(di, instr, pc);
          break;
        //misc
        case OP_pli_imm:
        case OP_pli_lit:
        case OP_pli_reg:
        case OP_pld_imm:
        case OP_pldw_imm:
        case OP_pld_lit:
        case OP_clrex:
        case OP_dsb:
        case OP_dmb:
        case OP_isb:
          break;
        default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opcode for instr_type" );
            break;
    }

    return nxt_pc;
}

byte*
encode_load_store_2_and_media(decode_info_t* di, instr_t* instr, byte* pc)
{
    uint opc;
    byte* nxt_pc = pc;

    opc = instr_get_opcode(instr);


    switch( opc )
    {
        case OP_ldr_reg:  //C
        case OP_ldrb_reg: //C
        case OP_str_reg:  //C
        case OP_strb_reg: //C
          nxt_pc = encode_1dst_reg_2src_reg_1src_imm(di, instr, pc);
          break;
        //Media instrs
        case OP_usad8:
        case OP_usada8:
        case OP_sbfx:
        case OP_bfc:
        case OP_bfi:
        case OP_ubfx:
          break;
        // Parallel arith
        case OP_sadd16: //C
        case OP_sasx: //C
        case OP_ssub16: //C
        case OP_sadd8: //C
        case OP_ssub8: //C
        case OP_qasx: //C
        case OP_qsax: //C
        case OP_qsub16: //C
        case OP_qsub8: //C
        case OP_shadd16: //C
        case OP_shadd8: //C
        case OP_shsax: //C
        case OP_shsub16: //C
        case OP_shsub8: //C
          nxt_pc = encode_1dst_reg_2src_reg_0src_imm_5(di, instr, pc);
          break;
        //case OP_add8:
        //case OP_sub8:
        //case OP_shasx:
        case OP_uadd16:
        case OP_uasx:
        case OP_usax:
        case OP_usub16:
        case OP_uadd8:
        case OP_usub8:
        case OP_uqadd16:
        case OP_uqasx:
        case OP_uqsax:
        //case OP_uqsub16:
        case OP_uqadd8:
        //case OP_uqsub8:
        case OP_uhadd16:
        //case OP_uhasx:
        case OP_uhsax:
        case OP_uhsub16:
        case OP_uhadd8:
        case OP_uhsub8:
          break;
        //Packing/Unpacking saturation and reversal
        case OP_pkh:
        case OP_ssat:
        case OP_usat:
        case OP_sxtab16:
        //case OP_sxtb16:
        case OP_ssat16:
        case OP_sxtab:
        //case OP_sxtb:
        case OP_sxtah:
        //case OP_sxth:
        case OP_uxtab16:
        case OP_uxtb16:
        case OP_usat16:
        case OP_uxtab:
        case OP_uxtb:
          break;
        case OP_sel: //C
        case OP_rbit: //C
        case OP_rev: //C
        case OP_rev16: //C
        case OP_revsh: //C
          nxt_pc = encode_1dst_reg_1src_reg_0src_imm(di, instr, pc);
          break;
        case OP_uxtah:
        case OP_uxth:
          break;
        //Signed Multiple
        case OP_smlad:
        case OP_smuad:
        case OP_smlsd:
        case OP_smusd:
        case OP_smlald:
        case OP_smlsld:
        case OP_smmla:
        case OP_smmul:
        case OP_smmls:
          break;
        //misc
        case OP_pli_reg:
        case OP_pld_reg:
        case OP_pldw_reg:
          break;
        default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opcode for instr_type" );
            break;
    }

    return nxt_pc;
}

uint
encode_load_store_multiple(decode_info_t* di, instr_t* instr, byte* pc)
{
    uint opc;
    byte* nxt_pc = pc;

    opc = instr_get_opcode(instr);

    switch( opc )
    {
        //Store/load multiple
        case OP_stm: //C
        case OP_stmia://C
        case OP_stmea://C
        case OP_stmda://C
        case OP_stmed://C
        case OP_stmdb://C
        case OP_stmfd://C
        case OP_ldm: //C
        case OP_ldmda: //C
        case OP_ldmfa: //C
        case OP_ldmia: //C 
        case OP_ldmfd: //C
        case OP_ldmib: //C
        case OP_ldmed: //C
          nxt_pc = encode_1dst_reg_1src_reglist(di, instr, pc);
          break;
        //Uncond instrs
        case OP_srs:
        case OP_rfe:
          break;
        case OP_pop: //C
        case OP_push://C
          nxt_pc = encode_0dst_reg_1src_reglist(di, instr, pc);
          break;
        default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opcode for instr_type" );
            break;
    }

    return nxt_pc;
}

byte*
encode_branch(decode_info_t* di, instr_t* instr, byte* pc)
{
    uint opc;
    byte* nxt_pc = pc;

    opc = instr_get_opcode(instr);

    switch( opc )
    {
        case OP_b:
        case OP_bl:
        case OP_blx_imm:
        case OP_blx_reg:
          nxt_pc = encode_branch_instrs(di, instr, pc);
          break;
        default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opcode for instr_type" );
            break;
    }

    return nxt_pc;
}

byte*
encode_coprocessor_data_movement(decode_info_t* di, instr_t* instr, byte* pc)
{
    uint opc;
    byte* nxt_pc;

    opc = instr_get_opcode(instr);

    switch( opc )
    {
        case OP_ldc_imm:
        case OP_ldc2_imm:
        case OP_ldc_lit:
        case OP_ldc2_lit:
        case OP_stc:
        case OP_stc2:
        case OP_mcrr:
        case OP_mcrr2:
        case OP_mrrc:
        case OP_mrrc2:
          break;

        default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opcode for instr_type" );
            break;
    }

    return nxt_pc;
}

byte*
encode_advanced_coprocessor_and_syscall(decode_info_t* di, instr_t* instr, byte* pc)
{
    uint opc;
    byte* nxt_pc = pc;

    opc = instr_get_opcode(instr);

    switch( opc )
    {
        case OP_cdp:
        case OP_cdp2:
        case OP_mcr:
        case OP_mcr2:
        case OP_mrc:
        case OP_mrc2:
          break;
        default:
            CLIENT_ASSERT(false, "instr_encode error: invalid opcode for instr_type" );
            break;
    }

    return nxt_pc;
}
 

/* Encodes instrustion instr.  The parameter copy_pc points
 * to the address of this instruction in the fragment cache.
 * Checks for and fixes pc-relative instructions.  
 * N.B: if instr is a jump with an instr_t target, the caller MUST set the note
 * field in the target instr_t prior to calling instr_encode on the jump instr.
 * 
 * Returns the pc after the encoded instr, or NULL if the instruction cannot be encoded.  
 * Note that if instr_is_label(instr) will encoded as a 0-byte instruction.
 * If a pc-relative operand cannot reach its target:
 *   If reachable == NULL, we assert and encoding fails (returning NULL);
 *   Else, encoding continues, and *reachable is set to false.
 * Else, if reachable != NULL, *reachable is set to true.
 */
static byte *
instr_encode_common(dcontext_t *dcontext, instr_t *instr, byte *copy_pc, byte *final_pc,
                    bool check_reachable, bool *has_instr_opnds/*OUT OPTIONAL*/
                    _IF_DEBUG(bool assert_reachable))
{
    const instr_info_t * info;
    decode_info_t di;
    int sz=0;

    /* pointer to and into the instruction binary */
    byte *cache_pc = copy_pc;
    byte *field_ptr = cache_pc;
    byte *disp_relativize_at = NULL;
    uint opc, instr_type;
    bool output_initial_opcode = false;
    
    if (has_instr_opnds != NULL)
        *has_instr_opnds = false;

    /* first handle the already-encoded instructions */
    if (instr_raw_bits_valid(instr)) {
        CLIENT_ASSERT(check_reachable, "internal encode error: cannot encode raw "
                      "bits and ignore reachability");
        /* copy raw bits, possibly re-relativizing */
        return copy_and_re_relativize_raw_instr(dcontext, instr, cache_pc, final_pc);
    }
    CLIENT_ASSERT(instr_operands_valid(instr), "instr_encode error: operands invalid");

    /* fill out the other fields of di */
    /* used for PR 253327 addr32 rip-relative and instr_t targets */
    di.start_pc = cache_pc;
    di.final_pc = final_pc;

    di.size_immed = OPSZ_NA;
    di.size_immed2 = OPSZ_NA;

    info = instr_get_instr_info(instr);
    if (info == NULL) {
        CLIENT_ASSERT(instr_is_label(instr), "instr_encode: invalid instr");
        return (instr_is_label(instr) ? copy_pc : NULL);
    }

    if (!encoding_possible(&di, instr, info))
       return false;

    //The correct instr type is not encoded into the instr 
    //at this point so get it from the instr info
    instr_type = instr_info_get_instr_type(info);

    switch( instr_type )
    {
        case INSTR_TYPE_UNDECODED:
          //Check for label here
          break;
        case INSTR_TYPE_DATA_PROCESSING_AND_ELS:
          field_ptr = encode_data_processing_and_els(&di, instr, field_ptr); 
          break;
        case INSTR_TYPE_DATA_PROCESSING_IMM:
          field_ptr = encode_data_processing_imm_and_misc(&di, instr, field_ptr); 
          break;
        case INSTR_TYPE_LOAD_STORE1:
          field_ptr = encode_load_store_1_and_misc(&di, instr, field_ptr); 
          break;
        case INSTR_TYPE_LOAD_STORE2_AND_MEDIA:
          field_ptr = encode_load_store_2_and_media(&di, instr, field_ptr); 
          break;
        case INSTR_TYPE_LOAD_STORE_MULTIPLE:
          field_ptr = encode_load_store_multiple(&di, instr, field_ptr); 
          break;
        case INSTR_TYPE_BRANCH:
          field_ptr = encode_branch(&di, instr, field_ptr); 
          break;
        case INSTR_TYPE_COPROCESSOR_DATA_MOVEMENT:
          field_ptr = encode_coprocessor_data_movement(&di, instr, field_ptr); 
          break;
        case INSTR_TYPE_ADVANCED_COPROCESSOR_AND_SYSCALL: 
          field_ptr = encode_advanced_coprocessor_and_syscall(&di, instr, field_ptr); 
          break;
        default:
            CLIENT_ASSERT(false, "instr_encode error: invalid instr_type");
            return;
        
    }

    /* instr_t* operand support */
    di.cur_note = (ptr_int_t) instr->note;
    
    //SJF Should be 4
    sz = decode_sizeof(dcontext, di.start_pc, 0);

    if( field_ptr == di.start_pc + sz )//Success
    {
        LOG(THREAD, LOG_EMIT, ENC_LEVEL, "\nwritten instruction '%x' at addr '%x'\n",
                   (int*)*(field_ptr-4), (int)(field_ptr-4) );
    }


#ifdef NO
/* TODO SJF Eh? */
/* Indirect branches */
    if ((instr_is_cbr(instr) &&
         (!instr_is_cti_loop(instr) ||
          /* no addr16 */
          reg_is_pointer_sized(opnd_get_reg(instr_get_src(instr, 1))))) ||
        /* no indirect or far */
        opc == OP_jmp_short || opc == OP_jmp || opc == OP_call) {
        if (!TESTANY(~(PREFIX_JCC_TAKEN|PREFIX_JCC_NOT_TAKEN), instr->prefixes)) {
            /* encode_cti cannot handle funny prefixes or indirect branches or rets */
            return encode_cti(instr, copy_pc, final_pc, check_reachable
                              _IF_DEBUG(assert_reachable));
        }
    } 

    if (di.seg_override != REG_NULL) {
        switch (di.seg_override) {
        case SEG_ES: *field_ptr = 0x26; break;
        case SEG_CS: *field_ptr = 0x2e; break;
        case SEG_SS: *field_ptr = 0x36; break;
        case SEG_DS: *field_ptr = 0x3e; break;
        case SEG_FS: *field_ptr = 0x64; break;
        case SEG_GS: *field_ptr = 0x65; break;
        default: CLIENT_ASSERT(false, "instr_encode error: unknown segment prefix");
        }
        field_ptr++;
    }
#endif

    if (has_instr_opnds != NULL)
        *has_instr_opnds = di.has_instr_opnds;
    return field_ptr;
}

/* completely ignores reachability failures */
byte *
instr_encode_ignore_reachability(dcontext_t *dcontext, instr_t *instr, byte *pc)
{
    return instr_encode_common(dcontext, instr, pc, pc, false, NULL _IF_DEBUG(false));
}

/* just like instr_encode but doesn't assert on reachability failures */
byte *
instr_encode_check_reachability(dcontext_t *dcontext, instr_t *instr, byte *pc,
                                bool *has_instr_opnds/*OUT OPTIONAL*/)
{
    return instr_encode_common(dcontext, instr, pc, pc, true, has_instr_opnds
                               _IF_DEBUG(false));
}

byte *
instr_encode_to_copy(dcontext_t *dcontext, instr_t *instr, byte *copy_pc, byte *final_pc)
{
    return instr_encode_common(dcontext, instr, copy_pc, final_pc, true, NULL
                               _IF_DEBUG(true));
}

byte *
instr_encode(dcontext_t *dcontext, instr_t *instr, byte *pc)
{
    return instr_encode_to_copy(dcontext, instr, pc, pc);
}

/* If has_instr_jmp_targets is true, this routine trashes the note field
 * of each instr_t to store the offset in order to properly encode
 * the relative pc for an instr_t jump target
 */
byte *
instrlist_encode_to_copy(dcontext_t *dcontext, instrlist_t *ilist, byte *copy_pc,
                         byte *final_pc, byte *max_pc, bool has_instr_jmp_targets)
{
    instr_t *inst;
    int len = 0;
    if (has_instr_jmp_targets || max_pc != NULL) {
        /* must set note fields first with offset, or compute length */
        for (inst = instrlist_first(ilist); inst; inst = instr_get_next(inst)) {
            if (has_instr_jmp_targets)
                instr_set_note(inst, (void *)(ptr_int_t)len);
            len += instr_length(dcontext, inst);
        }
    }
    if (max_pc != NULL &&
        (copy_pc + len > max_pc || POINTER_OVERFLOW_ON_ADD(copy_pc, len)))
        return NULL;
    for (inst = instrlist_first(ilist); inst != NULL; inst = instr_get_next(inst)) {
        byte *pc = instr_encode_to_copy(dcontext, inst, copy_pc, final_pc);
        if (pc == NULL)
            return NULL;
        final_pc += pc - copy_pc;
        copy_pc = pc;
    }
    return copy_pc;
}

byte *
instrlist_encode(dcontext_t *dcontext, instrlist_t *ilist, byte *pc,
                 bool has_instr_jmp_targets)
{
    return instrlist_encode_to_copy(dcontext, ilist, pc, pc, NULL, has_instr_jmp_targets);
}
