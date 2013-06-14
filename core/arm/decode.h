/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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

/* file "decode.h" */

#ifndef DECODE_H
#define DECODE_H


/* Prefix constants.  1st 5 are used in bitfields, rest are not.
 * We assume that the PREFIX_ constants are invalid as pointers for
 * our use in instr_info_t.code.
 */
/* DR_API EXPORT TOFILE dr_ir_instr.h */
/* DR_API EXPORT BEGIN */

/****************************************************************************
 * instr_t prefixes
 *
 * Note that prefixes that change the data or address size, or that
 * specify a different base segment, are not specified on a
 * whole-instruction level, but rather on individual operands (of
 * course with multiple operands they must all match).
 * The rep and repne prefixes are encoded directly into the opcodes.
 * 
 */
#define PREFIX_LOCK           0x1 /**< Makes the instruction's memory accesses atomic. */
#define PREFIX_JCC_NOT_TAKEN  0x2 /**< Branch hint: conditional branch is taken. */
#define PREFIX_JCC_TAKEN      0x4 /**< Branch hint: conditional branch is not taken. */

/* DR_API EXPORT END */

/* These are used only in the decoding tables.  We decode the
 * information into the operands.
 * For encoding these properties are specified in the operands,
 * with our encoder auto-adding the appropriate prefixes.
 */
#define PREFIX_DATA           0x0008
#define PREFIX_ADDR           0x0010
#define PREFIX_REX_W          0x0020
#define PREFIX_REX_R          0x0040
#define PREFIX_REX_X          0x0080
#define PREFIX_REX_B          0x0100
#define PREFIX_REX_GENERAL    0x0200 /* 0x40: only matters for SPL...SDL vs AH..BH */
#define PREFIX_REX_ALL        (PREFIX_REX_W|PREFIX_REX_R|PREFIX_REX_X|PREFIX_REX_B|\
                               PREFIX_REX_GENERAL)
#define PREFIX_SIZE_SPECIFIERS (PREFIX_DATA|PREFIX_ADDR|PREFIX_REX_ALL)

/* Unused except in decode tables (we encode the prefix into the opcodes) */
#define PREFIX_REP            0x0400
#define PREFIX_REPNE          0x0800

/* PREFIX_SEG_* is set by decode or decode_cti and is only a hint
 * to the caller.  Is ignored by encode in favor of the segment 
 * reg specified in the applicable opnds.  We rely on it being set during 
 * bb building.
 */
#define PREFIX_SEG_FS         0x1000
#define PREFIX_SEG_GS         0x2000

/* First two are only used during initial decode so if running out of
 * space could replace w/ byte value compare.
 */
#define PREFIX_VEX_2B    0x000004000
#define PREFIX_VEX_3B    0x000008000
#define PREFIX_VEX_L     0x000010000

/* We encode some prefixes in the operands themselves, such that we shouldn't
 * consider the whole-instr_t flags when considering equality of Instrs
 */
#define PREFIX_SIGNIFICANT (PREFIX_LOCK|PREFIX_JCC_TAKEN|PREFIX_JCC_TAKEN)

/* branch hints show up as segment modifiers 
#define SEG_JCC_NOT_TAKEN     SEG_CS
#define SEG_JCC_TAKEN         SEG_DS
SJF no longer needed
*/ 

/*
 o get rid of sI?  I sign-extend all the Ib's on decoding, many are
   actually sign-extended that aren't marked sIb
 o had to add size to immed_int and base_disp, don't have it for indir_reg!
   that's fine for encoding, aren't duplicate instrs differing on size of
   indir reg data, but should set it properly for later IR passes...
 o rewrite emit.c so does emit_inst only once (instr_length() does it!)
*/

/* bits used to encode info in instr_info_t's opcode field */
enum {
    OPCODE_TWOBYTES = 0x00000010,
    OPCODE_REG      = 0x00000020,
    OPCODE_MODRM    = 0x00000040,
    OPCODE_SUFFIX   = 0x00000080,
    OPCODE_THREEBYTES=0x00000008,
};

/* instr_info_t: each table entry is one of these
 * For reading all bytes of instruction, only need to know:
 * 1) prefixes + opcode boundary
 * 2) whether to read modrm byte, from modrm get sib and disp
 * 3) whether to read immed bytes (types A, I, sI, J, and O)
 * The rest of the types are for interpretation only
 *
 * We have room for 2 destinations and 3 sources
 *   Instrs with 2 dests include push, pop, edx:eax, xchg, rep lods
 * Exceptions:
 *   pusha = 8 sources
 *   popa = 8 destinations
 *   enter = 3 dests, 4 srcs (incl. 2 immeds)
 *   cpuid = 4 dests
 *   cmpxchg8b = 3 dests, 5 srcs
 *   movs = 3 dests, rest of string instrs w/ rep/repne have 3+ dests
 * Represent exceptions as sequence of instrs?
 *   All 5 exceptions have only one form, can use list field to
 *   point into separate table that holds types of extra operands.
 *
 * Separate immed field and only 2 srcs?
 * enter has 2 immeds, all other instrs have <=1
 * there are a number of instrs that need 3 srcs even ignoring immeds!
 *   (pusha,shld,shrd,cmpxchg,cmpxhchg8b,rep outs,rep cmps, rep scas)
 * => no separate immed field
 *
 * FIXMEs:
 * lea = computes addr, doesn't touch mem!  how encode?
 * in & out, ins & outs: are I/O ports in memory?!?
 * Should we model fp stack changes?!?
 * All i_eSP really read 0x4(esp) or some other offset, depending on
 *   if take esp value before or after instrs, etc.
 * punpck*, pshuf*: say "reads entire x-bits, only uses half of them"
 *   table is inconsistent in this: for punpck* it gives a memory size of x/2
 *   (b/c Intel's table gives that), for pshuf* (there are others too I think)
 *   gives size x (not present in Intel's table)
 */
typedef struct instr_info_t {
    unsigned int type; /* an OP_ constant or special type code below */
    /* EVERY arm instruction has an condition. bits 31-28 SJF TODO Commented out for now
    byte cond;
     */
    /* TODO opcodes in ARM are split across multiple sections of bits. May need two variables 
            to store or may be able to combine into one. */
    /* opcode: split into bytes
     * 0th (ms) = prefix byte, if byte 3's 1st nibble's bit 3 and bit 4 are both NOT set;
     *            modrm byte, if  byte 3's 1st nibble's bit 3 IS set.
     *            suffix byte, if  byte 3's 1st nibble's bit 4 IS set.
     * 1st = 1st byte of opcode
     * 2nd = 2nd byte of opcode (if there are 2)
     * 3rd (ls) = split into nibbles
     *   1st nibble (ms) = if bit 1 (OPCODE_TWOBYTES) set, opcode has 2 bytes
     *                     if bit 2 (OPCODE_REG) set, opcode has /n
     *                     if bit 3 (OPCODE_MODRM) set, opcode based on entire modrm
     *                       that modrm is stored as the byte 0.
     *                       if REQUIRES_VEX then this bit instead means that
     *                       this instruction must have vex.W set.
     *                     if bit 4 (OPCODE_SUFFIX) set, opcode based on suffix byte
     *                       that byte is stored as the byte 0
     *                       if REQUIRES_VEX then this bit instead means that
     *                       this instruction must have vex.L set.
     *                     FIXME: so we do not support an instr that has an opcode
     *                     dependent on both a prefix and the entire modrm or suffix!
     *   2nd nibble (ls) = bits 1-3 hold /n for OPCODE_REG
     *                     if bit 4 (OPCODE_THREEBYTES) is set, the opcode has
     *                       3 bytes, with the first being an implied 0x0f (so
     *                       the 2nd byte is stored as "1st" and 3rd as "2nd").
     */
    unsigned int opcode;
    const char *name;
    /* operands
     * the opnd_size_t will instead be reg_id_t for TYPE_*REG*
     */
    byte dst1_type;  opnd_size_t dst1_size;
    byte dst2_type;  opnd_size_t dst2_size;
    byte src1_type;  opnd_size_t src1_size;
    byte src2_type;  opnd_size_t src2_size;
    byte src3_type;  opnd_size_t src3_size;

    /* ARM opcodes are split across multiple bits. Soemtimes the second
       one isnt even used. It is used for regs or imms or whatever. */ 
    unsigned int opcode2;

    byte flags; /* modrm and extra operand flags */
    uint eflags; /* combination of read & write flags from instr.h */
    ptr_int_t code; /* for PREFIX: one of the PREFIX_ constants, or SEG_ constant
                     * for EXTENSION and *_EXT: index into extensions table
                     * for OP_: pointer to next entry of that opcode
                     *   may also point to extra operand table
                     */
} instr_info_t;


/* classification of instruction bytes up to modrm/disp/immed
 * these constants are used for instr_info_t.type field
 */
enum {
    /* not a valid opcode */
    INVALID = OP_LAST + 1,
    /* prefix byte */
    PREFIX,
    /* 0x0f = two-byte escape code */
    ESCAPE,
    /* floating point instruction escape code */
    FLOAT_EXT,
    /* opcode extension via reg field of modrm */
    EXTENSION,
    /* 2-byte instructions differing by presence of 0xf3/0x66/0xf2 prefixes */
    PREFIX_EXT,
    /* (rep prefix +) 1-byte-opcode string instruction */
    REP_EXT,
    /* (repne prefix +) 1-byte-opcode string instruction */
    REPNE_EXT,
    /* 2-byte instructions differing by mod bits of modrm */
    MOD_EXT,
    /* 2-byte instructions differing by rm bits of modrm */
    RM_EXT,
    /* 2-byte instructions whose opcode also depends on a suffix byte */
    SUFFIX_EXT,
    /* instructions that vary based on whether in 64-bit mode or not */
    X64_EXT,
    /* 3-byte opcodes beginning 0x0f 0x38 (SSSE3 and SSE4) */
    ESCAPE_3BYTE_38,
    /* 3-byte opcodes beginning 0x0f 0x3a (SSE4) */
    ESCAPE_3BYTE_3a,
    /* instructions differing if a rex prefix is present */
    REX_EXT,
    /* instructions differing based on whether part of a vex prefix */
    VEX_PREFIX_EXT,
    /* instructions differing based on whether vex-encoded */
    VEX_EXT,
    /* instructions differing based on whether vex-encoded and vex.L */
    VEX_L_EXT,
    /* instructions differing based on vex.W */
    VEX_W_EXT,
    /* else, from OP_ enum */
};

/* instr_info_t modrm/extra operands flags == single byte only! */
#define HAS_MODRM             0x01   /* else, no modrm */
#define HAS_EXTRA_OPERANDS    0x02   /* else, <= 2 dsts, <= 3 srcs */
/* if HAS_EXTRA_OPERANDS: */
#define EXTRAS_IN_CODE_FIELD  0x04   /* next instr_info_t pointed to by code field */
/* rather than split out into little tables of 32-bit vs OP_INVALID, we use a
 * flag to indicate opcodes that are invalid in particular modes:
 */
#define X86_INVALID           0x08
#define X64_INVALID           0x10
/* to avoid needing a single-valid-entry subtable in prefix_extensions */
#define REQUIRES_PREFIX       0x20
/* instr must be encoded using vex.  if this flag is not present, this instruction
 * is invalid if encoded using vex.
 */
#define REQUIRES_VEX          0x40

/* instr_info_t is used for table entries, it holds info that is constant
 * for all instances of an instruction.
 * All variable information is kept in this struct, which is used for
 * decoding and encoding.
 */
typedef struct decode_info_t {
    /* Holds address and data size prefixes, as well as the prefixes
     * that are shared as-is with instr_t (PREFIX_SIGNIFICANT).
     * We assume we're in the default mode (32-bit or 64-bit,
     * depending on our build) and that the address and data size
     * prefixes can be treated as absolute.
     */
    uint prefixes;
    byte seg_override; /* REG enum of seg, REG_NULL if none */
    /* modrm info */
    byte modrm;
    byte mod;
    byte reg;
    byte rm;
    bool has_sib;
    byte scale;
    byte index;
    byte base;
    bool has_disp;
    int disp;
    /* immed info */
    opnd_size_t size_immed;
    opnd_size_t size_immed2;
    ptr_int_t immed;
    ptr_int_t immed2; /* this additional field could be 32-bit on all platforms */
    /* These fields are only used when decoding rip-relative data refs */
    byte *start_pc;
    byte *final_pc;
    uint len;
    /* This field is only used when encoding rip-relative data refs.
     * To save space we could make it a union with disp.
     */
    byte *disp_abs;
#ifdef X64
    /* Since the mode when an instr_t is involved is per-instr rather than
     * per-dcontext we have our own field here instead of passing dcontext around.
     * It's up to the caller to set this field to match either the instr_t
     * or the dcontext_t field.
     */
    bool x86_mode;
#endif
    /* PR 302353: support decoding as though somewhere else */
    byte *orig_pc;
    /* these 3 prefixes may be part of opcode */
    bool data_prefix;
    bool rep_prefix;
    bool repne_prefix;
    byte vex_vvvv; /* vvvv bits for extra operand */
    bool vex_encoded;
    /* for instr_t* target encoding */
    ptr_int_t cur_note;
    bool has_instr_opnds;
} decode_info_t;


/* N.B.: if you change the type or size enums, change the string names for
 * them, kept in encode.c
 */

/* operand types have 2 parts, type and size */
enum {
    /* operand types */
    TYPE_NONE,
    TYPE_A, /* immediate that is absolute address */
    TYPE_I, /* immediate */
    TYPE_J, /* immediate that is relative offset of R13 */
    TYPE_M,
    TYPE_O, /* immediate that is memory offset */
    TYPE_1,
    TYPE_FLOATCONST,
    TYPE_FLOATMEM,
    /* TODO Do I need separate values here for the thumb regs. */
    TYPE_REG,     /* hardcoded register */
    TYPE_CO_REG,     /* hardcoded coprocessor register */
    TYPE_INDIR_E,
    TYPE_INDIR_REG,
    /* when adding new types, update type_names[] in encode.c */
};


/* PR 225845: Our IR does not try to specify the format of the operands or the
 * addressing mode in opnd_t.size: only the size.  Our decode table uses the
 * Intel opcode table "type" fields, and we used to use them for opnd_t.size.
 * They do say more than just the size, but in core code we use the TYPE_ to
 * tell us any formatting we need to know about, and we've always treated
 * identical sizes with different formatting identically: we do not distinguish
 * 128-bit packed doubles from 128-bit packed floats, e.g.  Would any client
 * want that distinction?  There are enough subtleties in the ISA that
 * dispatching by opcode is probably going to be necessary for the client anyway
 * (e.g., maskmovq only writes selected bytes).  Furthermore, many of the
 * distinctions in the OPSZ_ constants apply only to registers, with such
 * distinctions having no way to be specified when constructing an operand as we
 * do not use the size field for register operand types (we only use it for
 * immediates and memory references): to be complete in supplying formatting
 * information we would want to use that field.  Decision: we're only going to
 * provide size information.
 */

/* DR_API EXPORT TOFILE dr_ir_opnd.h */
/* DR_API EXPORT BEGIN */

/* Memory operand sizes (with Intel's corresponding size names noted).
 * For register operands, the DR_REG_ constants are used, which implicitly
 * state a size (e.g., DR_REG_CX is 2 bytes).
 * Use the type opnd_size_t for these values (we avoid typedef-ing the
 * enum, as its storage size is compiler-specific).  opnd_size_t is a
 * byte, so the largest value here needs to be <= 255.
 */
enum {
    /* register enum values are used for TYPE_*REG but we only use them
     * as opnd_size_t when we have the type available, so we can overlap
     * the two enums by adding new registers consecutively to the reg enum.
     * To maintain backward compatibility we keep the OPSZ_ constants
     * starting at the same spot, now midway through the reg enum:
     */
    OPSZ_NA = DR_REG_INVALID+1, /**< Sentinel value: not a valid size. */ /* = 140 */
    OPSZ_FIRST = OPSZ_NA,
    OPSZ_0,  /* "sizeless" */
    OPSZ_1, 
    OPSZ_2,
    OPSZ_3,
    OPSZ_4,
    OPSZ_5,
    OPSZ_6,
    OPSZ_8,
    OPSZ_10,
    OPSZ_12,
           
    OPSZ_16,
    OPSZ_14, 
    OPSZ_24, 
    OPSZ_28, 
    OPSZ_32, 
    OPSZ_40, 
    OPSZ_94, 
    OPSZ_108, 
    OPSZ_512, 

    /* Add new size here.  Also update size_names[] in encode.c. */
    OPSZ_LAST,
};

#ifdef X64
# define OPSZ_PTR OPSZ_8       /**< Operand size for pointer values. */
# define OPSZ_STACK OPSZ_8     /**< Operand size for stack push/pop operand sizes. */
#else
# define OPSZ_PTR OPSZ_4       /**< Operand size for pointer values. */
# define OPSZ_STACK OPSZ_4     /**< Operand size for stack push/pop operand sizes. */
#endif
#define OPSZ_VARSTACK OPSZ_4x8_short2 /**< Operand size for prefix-varying stack
                                       * push/pop operand sizes. */
#define OPSZ_REXVARSTACK OPSZ_4_rex8_short2 /* Operand size for prefix/rex-varying
                                             * stack push/pop like operand sizes. */

#define OPSZ_ret OPSZ_4x8_short2xi8 /**< Operand size for ret instruction. */
#define OPSZ_call OPSZ_ret         /**< Operand size for push portion of call. */

/* Convenience defines for specific opcodes */
#define OPSZ_lea OPSZ_0              /**< Operand size for lea memory reference. */
#define OPSZ_invlpg OPSZ_0           /**< Operand size for invlpg memory reference. */
#define OPSZ_xlat OPSZ_1             /**< Operand size for xlat memory reference. */
#define OPSZ_clflush OPSZ_1          /**< Operand size for clflush memory reference. */
#define OPSZ_prefetch OPSZ_1         /**< Operand size for prefetch memory references. */
#define OPSZ_lgdt OPSZ_6x10          /**< Operand size for lgdt memory reference. */
#define OPSZ_sgdt OPSZ_6x10          /**< Operand size for sgdt memory reference. */
#define OPSZ_lidt OPSZ_6x10          /**< Operand size for lidt memory reference. */
#define OPSZ_sidt OPSZ_6x10          /**< Operand size for sidt memory reference. */
#define OPSZ_bound OPSZ_8_short4     /**< Operand size for bound memory reference. */
#define OPSZ_maskmovq OPSZ_8         /**< Operand size for maskmovq memory reference. */
#define OPSZ_maskmovdqu OPSZ_16      /**< Operand size for maskmovdqu memory reference. */
#define OPSZ_fldenv OPSZ_28_short14  /**< Operand size for fldenv memory reference. */
#define OPSZ_fnstenv OPSZ_28_short14 /**< Operand size for fnstenv memory reference. */
#define OPSZ_fnsave OPSZ_108_short94 /**< Operand size for fnsave memory reference. */
#define OPSZ_frstor OPSZ_108_short94 /**< Operand size for frstor memory reference. */
#define OPSZ_fxsave OPSZ_512         /**< Operand size for fxsave memory reference. */
#define OPSZ_fxrstor OPSZ_512        /**< Operand size for fxrstor memory reference. */
/* DR_API EXPORT END */

enum {
    /* OPSZ_ constants not exposed to the user so ok to be shifted
     * by additions above
     */
    OPSZ_4_of_8 = OPSZ_LAST,  /* 32 bits, but can be half of MMX register */
    OPSZ_4_of_16, /* 32 bits, but can be part of XMM register */
    OPSZ_8_of_16, /* 64 bits, but can be half of XMM register */
    OPSZ_8_of_16_vex32, /* 64 bits, but can be half of XMM register; if
                         * vex.L then is 256 bits (YMM or memory)
                         */
    OPSZ_16_of_32, /* 128 bits: half of YMM */
    OPSZ_LAST_ENUM, /* note last is NOT inclusive */
};

#ifdef X64
# define OPSZ_STATS OPSZ_8
#else
# define OPSZ_STATS OPSZ_4
#endif

#define MODRM_BYTE(mod, reg, rm) ((byte) (((mod) << 6) | ((reg) << 3) | (rm)))

/* in decode.c, not exported to non-x86 files */
bool optype_is_indir_reg(int optype);
opnd_size_t resolve_var_reg_size(opnd_size_t sz, bool is_reg);
opnd_size_t resolve_variable_size(decode_info_t *di/*IN: x86_mode, prefixes*/,
                                  opnd_size_t sz, bool is_reg);
opnd_size_t resolve_variable_size_dc(dcontext_t *dcontext,
                                     uint prefixes, opnd_size_t sz, bool is_reg);
/* Also takes in reg8 for TYPE_REG_EX mov_imm */
reg_id_t resolve_var_reg(decode_info_t *di/*IN: x86_mode, prefixes*/,
                         reg_id_t reg32, bool addr, bool can_shrink
                         _IF_X64(bool default_64) _IF_X64(bool can_grow)
                         _IF_X64(bool extendable));
opnd_size_t resolve_addr_size(decode_info_t *di/*IN: x86_mode, prefixes*/);
opnd_size_t indir_var_reg_size(decode_info_t *di, int optype);
int indir_var_reg_offs_factor(int optype);

/* in encode.c, not exported to non-x86 files */
const instr_info_t * get_encoding_info(instr_t *instr);
const instr_info_t * instr_info_extra_opnds(const instr_info_t *info);
byte instr_info_opnd_type(const instr_info_t *info, bool src, int num);

extern const instr_info_t invalid_instr;

/* DR_API EXPORT TOFILE dr_ir_utils.h */

/* exported routines */

#define DEFAULT_X86_MODE IF_X64_ELSE(false, true)
/* for decode_info_t */
#define X64_MODE(di) IF_X64_ELSE(!(di)->x86_mode, false)
/* for dcontext_t */
#define X64_MODE_DC(dc) IF_X64_ELSE(!get_x86_mode(dc), false)
/* Currently we assume that code caches are always 64-bit in x86_to_x64.
 * Later, if needed, we can introduce a new field in dcontext_t (xref i#862).
 */
#define X64_CACHE_MODE_DC(dc) (X64_MODE_DC(dc) IF_X64(|| DYNAMO_OPTION(x86_to_x64)))


DR_API
/**
 * Decodes only enough of the instruction at address \p pc to determine
 * its eflags usage, which is returned in \p usage as EFLAGS_ constants
 * or'ed together.
 * Returns the address of the next byte after the decoded instruction.
 * Returns NULL on decoding an invalid instruction.
 */
#ifdef UNSUPPORTED_API
/**
 * This corresponds to halfway between Level 1 and Level 2: a Level 1 decoding
 * plus eflags information (usually only at Level 2).
 */
#endif
byte *
decode_eflags_usage(dcontext_t *dcontext, byte *pc, uint *usage);

DR_UNS_API
/**
 * Decodes the opcode and eflags usage of instruction at address \p pc
 * into \p instr.
 * The instruction's raw bits are set to valid and pointed at \p pc
 * (xref instr_get_raw_bits()).
 * Assumes that \p instr is already initialized, and uses the x86/x64 mode
 * set for it rather than the current thread's mode!
 * If caller is re-using same instr_t struct over multiple decodings,
 * caller should call instr_reset() or instr_reuse().
 * Returns the address of the next byte after the decoded instruction.
 * Returns NULL on decoding an invalid instr and sets opcode to OP_INVALID.
 */
byte *
decode_opcode(dcontext_t *dcontext, byte *pc, instr_t *instr);

DR_API
/**
 * Decodes the instruction at address \p pc into \p instr, filling in the
 * instruction's opcode, eflags usage, prefixes, and operands.
 * The instruction's raw bits are set to valid and pointed at \p pc
 * (xref instr_get_raw_bits()).
 * Assumes that \p instr is already initialized, but uses the x86/x64 mode
 * for the thread \p dcontext rather than that set in instr.
 * If caller is re-using same instr_t struct over multiple decodings,
 * caller should call instr_reset() or instr_reuse().
 * Returns the address of the next byte after the decoded instruction.
 * Returns NULL on decoding an invalid instr and sets opcode to OP_INVALID.
 */
#ifdef UNSUPPORTED_API
/**
 * This corresponds to a Level 3 decoding.
 */
#endif
byte *
decode(dcontext_t *dcontext, byte *pc, instr_t *instr);

DR_API
/**
 * Decodes the instruction at address \p copy_pc into \p instr as though
 * it were located at address \p orig_pc.  Any pc-relative operands have
 * their values calculated as though the instruction were actually at
 * \p orig_pc, though that address is never de-referenced.
 * The instruction's raw bits are not valid, but its translation field
 * (see instr_get_translation()) is set to \p orig_pc.
 * The instruction's opcode, eflags usage, prefixes, and operands are
 * all filled in.
 * Assumes that \p instr is already initialized, but uses the x86/x64 mode
 * for the thread \p dcontext rather than that set in instr.
 * If caller is re-using same instr_t struct over multiple decodings,
 * caller should call instr_reset() or instr_reuse().
 * Returns the address of the next byte after the decoded instruction
 * copy at \p copy_pc.
 * Returns NULL on decoding an invalid instr and sets opcode to OP_INVALID.
 */
#ifdef UNSUPPORTED_API
/**
 * This corresponds to a Level 3 decoding.
 */
#endif
byte *
decode_from_copy(dcontext_t *dcontext, byte *copy_pc, byte *orig_pc, instr_t *instr);

#ifdef CLIENT_INTERFACE
/* decode_as_bb() is defined in interp.c, but declared here so it will
 * be listed next to the other decode routines in the API headers.
 */
DR_API
/**
 * Client routine to decode instructions at an arbitrary app address,
 * following all the rules that DynamoRIO follows internally for
 * terminating basic blocks.  Note that DynamoRIO does not validate
 * that \p start_pc is actually the first instruction of a basic block.
 * \note Caller is reponsible for freeing the list and its instrs!
 */
instrlist_t *
decode_as_bb(void *drcontext, byte *start_pc);

/* decode_trace() is also in interp.c */
DR_API
/**
 * Decodes the trace with tag \p tag, and returns an instrlist_t of
 * the instructions comprising that fragment.  If \p tag is not a
 * valid tag for an existing trace, the routine returns NULL.  Clients
 * can use dr_trace_exists_at() to determine whether the trace exists.
 * \note Unlike the instruction list presented by the trace event, the
 * list here does not include any existing client modifications.  If
 * client-modified instructions are needed, it is the responsibility
 * of the client to record or recreate that list itself.
 * \note This routine does not support decoding thread-private traces
 * created by other than the calling thread.
 */
instrlist_t *
decode_trace(void *drcontext, void *tag);
#endif

const struct instr_info_t * get_next_instr_info(const instr_info_t * info);

DR_API
/**
 * Given an OP_ constant, returns the first byte of its opcode when
 * encoded as an IA-32 instruction.
 */
byte 
decode_first_opcode_byte(int opcode);

DR_API
/** Given an OP_ constant, returns the string name of its opcode. */
const char *
decode_opcode_name(int opcode);

/* DR_API EXPORT TOFILE dr_ir_opcodes.h */

/* exported tables */
extern const instr_info_t first_byte[];
extern const instr_info_t second_byte[];
extern const instr_info_t extensions[][8];
extern const instr_info_t prefix_extensions[][8];
extern const instr_info_t mod_extensions[][2];
extern const instr_info_t rm_extensions[][8];
extern const instr_info_t x64_extensions[][2];
extern const instr_info_t rex_extensions[][2];
extern const instr_info_t vex_prefix_extensions[][2];
extern const instr_info_t vex_extensions[][2];
extern const instr_info_t vex_L_extensions[][3];
extern const instr_info_t vex_W_extensions[][2];
extern const byte third_byte_38_index[256];
extern const byte third_byte_3a_index[256];
extern const instr_info_t third_byte_38[];
extern const instr_info_t third_byte_3a[];
extern const instr_info_t rep_extensions[][4];
extern const instr_info_t repne_extensions[][6];
extern const instr_info_t float_low_modrm[];
extern const instr_info_t float_high_modrm[][64];
extern const byte suffix_index[256];
extern const instr_info_t suffix_extensions[];
extern const instr_info_t extra_operands[];
/* table that translates opcode enums into pointers into above tables */
extern const instr_info_t * const op_instr[];
/* for debugging: printing out types and sizes */
extern const char * const type_names[];
extern const char * const size_names[];

#endif /* DECODE_H */
