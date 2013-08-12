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

uint 
lookup_opcode_from_opc( uint opc )
{
  int i;
  

  for( i=0; i<OP_AFTER_LAST-4; i++ )
  {
    if( armv7a_instrs[i].opcode == opc )
      return armv7a_instrs[i].type; 
  }

  return 0;
}

/****************************************************************************
 * Reading all bytes of instruction
 */

uint
convert_shifted_immed_to_immed( uint immed_int, int sz, bool sign_extend )
{
  int shifts = 0;
  int ret_immed=0;

  switch( sz )
  {
    case OPSZ_4_12:
      if( sign_extend )
      {
        shifts = ((immed_int & 0xf00) >> 8); //Top 4 bits
        ret_immed = (immed_int & 0xff);// Only want last 8 bits

        for( int i=0; i<shifts; i++ )
        {
          ret_immed = (ret_immed << 30 ) | (ret_immed >> 2);
        }
        return ret_immed;
      }
      else//Zero extend
      {
        ret_immed = (immed_int & 0xfff);// Only want 12 bits

        return ret_immed;
      }

    case OPSZ_4_24:
      ret_immed = (immed_int & 0xffffff) << 2; //Only want last 24 bits. Shift by two right

      //Sign extend
      if(( ret_immed & 0x2000000 ) == 0x2000000 )
        ret_immed |= 0xfc000000; //Set top bits

      return ret_immed;

    default:
      return immed_int;
  }
}

instr_info_t* decode_data_processing_and_els(byte* instr_word, 
                                             decode_info_t* di, bool just_opcode,
                                             opnd_t* dsts, opnd_t* srcs, 
                                             int* numdsts, int* numsrcs)
{
//OLD
    instr_info_t *info = NULL;
    uint        opc = 0, temp = 0, opcode =0;
    bool        s_flag = false;
     

    opc |= (instr_word[0] & 0x1) << 4;

    opc |= (instr_word[1] >> 4);

    temp = (instr_word[1] << 7); 
    temp = (temp >> 7);

    s_flag = (bool)temp;

    //Zero s bit
    opc &= 0x1e;
 

    //Lookup the opcode in the op_instrs table
    opcode = lookup_opcode_from_opc( opc );

    return info;
}

void
decode_1dst_reg_2src_reg_1src_imm( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, bool sign_extend )
{
    int reg, immed, type;
    //1st Dst
    reg = (instr_word[2] >> 4);
    
    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[1] & 0xf); 

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //3rd src
    immed = (instr_word[2] & 0xf);
    immed = immed << 1;

    immed |= (instr_word[3] >> 7);

    immed = convert_shifted_immed_to_immed( immed, OPSZ_4_5, sign_extend );

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_5);
    (*numsrcs)++;

    //Shift type
    type = (instr_word[3] & 0x60) >> 5;

    di->shift_type = type;
}

void
decode_1dst_reg_1src_reg_0src_imm_1( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;
}

void
decode_1dst_reg_1src_reg_0src_imm_2( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;
}

void 
decode_1dst_reg_2src_reg_0src_imm_1( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    reg = (instr_word[2] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

}


void
decode_1dst_reg_2src_reg_0src_imm_2( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg;

    //1st Dst
    reg = (instr_word[1] & 0xf);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    reg = (instr_word[2] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

}

void
decode_1dst_reg_2src_reg_0src_imm_3( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg;

    //1st Dst
    reg = (instr_word[1] & 0xf);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value; 
    (*numdsts)++;

    //1st src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value; 
    (*numsrcs)++;

    //2nd src
    reg = (instr_word[2] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value; 
    (*numsrcs)++;

}

void 
decode_1dst_reg_2src_reg_0src_imm_4( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value; 
    (*numdsts)++;

    //1st src
    reg = (instr_word[1] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;
}

void
decode_1dst_reg_2src_reg_0src_imm_5( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
   int reg;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value; 
    (*numdsts)++;

    //1st src
    reg = (instr_word[1] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;
}

void
decode_1dst_reg_0src_reg_1src_imm_1( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, bool sign_extend )
{
    int reg, immed;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value; 
    (*numdsts)++;

    //1st src
    immed = (instr_word[2] & 0xf);
    immed = immed << 8;

    immed |= (instr_word[3]);

    immed = convert_shifted_immed_to_immed( immed, OPSZ_4_12, sign_extend );

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_12);
    (*numsrcs)++;
}

void
decode_1dst_reg_0src_reg_1src_imm_2( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, bool sign_extend )
{
    int reg, immed;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    immed = (instr_word[2] & 0xf);
    immed = immed << 8;

    immed |= (instr_word[3]);

    immed = convert_shifted_immed_to_immed( immed, OPSZ_4_12, sign_extend );

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_12);
    (*numsrcs)++;

}

void
decode_1dst_reg_0src_reg_1src_imm_3( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, bool sign_extend )
{
    int reg, immed;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    immed = (instr_word[2] & 0xf);
    immed = immed << 4;

    immed |= (instr_word[3] & 0xf);

    immed = convert_shifted_immed_to_immed( immed, OPSZ_4_8, sign_extend );

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_8);
    (*numsrcs)++;
}

void
decode_1dst_reg_1src_reg_1src_imm_1( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, bool sign_extend )
{
    int reg, immed;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    immed = (instr_word[2] & 0xf);
    immed = immed << 1;

    immed |= (instr_word[3] >> 7);

    immed = convert_shifted_immed_to_immed( immed, OPSZ_4_5, sign_extend );

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_5);
    (*numsrcs)++;

    //Shift type
    di->shift_type = ((instr_word[3] & 0x60) >> 5);
}

void
decode_1dst_reg_1src_reg_1src_imm_2( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, bool sign_extend )
{
    int reg, immed;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[1] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    immed = (instr_word[2] & 0xf);
    immed = immed << 8;

    immed |= (instr_word[3]);

    immed = convert_shifted_immed_to_immed( immed, OPSZ_4_12, sign_extend );

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_12);
    (*numsrcs)++;
}

void
decode_1dst_reg_1src_reg_1src_imm_3( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, bool sign_extend )
{
    int reg, immed;

    //1st Dst
    reg = (instr_word[1] & 0xf);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    immed = (instr_word[2] & 0xf);
    immed = immed << 4;

    immed |= ((instr_word[3] & 0x80) >> 7);

    immed = convert_shifted_immed_to_immed( immed, OPSZ_4_5, sign_extend );

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_5);
    (*numsrcs)++;

    //Shift type
    di->shift_type = ((instr_word[3] & 0x60) >> 5);
}

void
decode_1dst_reg_1src_reg_1src_imm_4( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, bool sign_extend )
{
    int reg, immed;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[1] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    immed = (instr_word[2] & 0xf);
    immed = immed << 4;

    immed |= (instr_word[3] & 0xf);

    immed = convert_shifted_immed_to_immed( immed, OPSZ_4_8, sign_extend );

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_8);
    (*numsrcs)++;
}

void
decode_0dst_reg_1src_imm_1src_mask( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, bool sign_extend )
{
    int reg, immed;

    //1st src
    immed = (instr_word[2] & 0xf);
    immed = immed << 8;

    immed |= (instr_word[3]);

    immed = convert_shifted_immed_to_immed( immed, OPSZ_4_12, sign_extend );

    srcs[*numsrcs] = opnd_create_immed_int((ptr_int_t)(immed), OPSZ_4_12);
    (*numsrcs)++;

    //mask
    di->mask = ((instr_word[1] & 0xc) >> 2);
}

void
decode_0dst_reg_1src_reg_1src_mask( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg;

    //1st src 
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //mask
    di->mask = ((instr_word[1] & 0xc) >> 2);
}

void
decode_0dst_reg_1src_reg_0src_imm( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg;

    //1st src 
    reg = (instr_word[2] >> 4);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;
}

void
decode_1dst_reg_3src_reg_0src_imm( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg;

    //1st Dst
    reg = (instr_word[2] >> 4);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg = (instr_word[1] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //2nd src
    reg = (instr_word[3] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value; 
    (*numsrcs)++;

    //3rd src
    reg = (instr_word[2] & 0xf);

    srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numsrcs)++;

    //Shift type
    di->shift_type = ((instr_word[3] & 0x60) >> 5);
}

void
decode_0dst_reg_1src_reglist( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg_list;

    //1st Src  
    reg_list = (instr_word[2] << 8);
    reg_list |= (instr_word[3]);

    srcs[*numsrcs] = opnd_create_reg_list((reg_list_t)reg_list); 
    (*numsrcs)++;

}

void
decode_1dst_reg_1src_reglist( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs )
{
    int reg_list, reg;

    //1st dst 
    reg = (instr_word[1] & 0xf);

    dsts[*numdsts] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
    (*numdsts)++;

    //1st src
    reg_list = (instr_word[2] << 8);
    reg_list |= (instr_word[3]);

    srcs[*numsrcs] = opnd_create_reg_list((reg_list_t)reg_list); 
    (*numsrcs)++;
}

void
decode_branch_instrs( decode_info_t* di, byte* instr_word, opnd_t* dsts,
                                   opnd_t* srcs, int *numdsts, int *numsrcs, byte* pc )
{
    /* OP_b, OP_bl, OP_blx_imm, OP_blx_reg */
    int  reg =0, addr = 0;

    //1st src 
    if( di->opcode == OP_blx_reg ||
        di->opcode == OP_bx ||
        di->opcode == OP_bxj )
    {
      reg = (instr_word[3] & 0xf);

      srcs[*numsrcs] = opnd_create_reg((reg_id_t)(++reg)); //Increment to get correct REG_XX value;
      (*numsrcs)++;
    }
    else //OP_b, OP_bl, OP_blx_imm
    {
      addr =  (instr_word[1] << 16);
      addr |= (instr_word[2] << 8 );
      addr |= (instr_word[3]);

      addr = convert_shifted_immed_to_immed( addr, OPSZ_4_24, true );

      //Convert the relative address to an absolute one here(+8 for actual pc pos)
      addr += pc + 8;

      srcs[*numsrcs] = opnd_create_pc((app_pc)(addr));
      (*numsrcs)++;
    }
}

void
decode_operands( decode_info_t* di, int encoding, byte* instr_word, opnd_t* dsts, 
                 opnd_t* srcs, int *numdsts, int *numsrcs, byte* pc, bool sign_extend )
{
    switch( encoding )
    {
      case ENC_1DST_REG_1SRC_REG_0SRC_IMM_1:
        decode_1dst_reg_1src_reg_0src_imm_1(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs );
        break;
      case ENC_1DST_REG_1SRC_REG_0SRC_IMM_2:
        decode_1dst_reg_1src_reg_0src_imm_2(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs );
        break;
      case ENC_1DST_REG_2SRC_REG_0SRC_IMM_1:
        decode_1dst_reg_2src_reg_0src_imm_1(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs );
        break;
      case ENC_1DST_REG_2SRC_REG_0SRC_IMM_2:
        decode_1dst_reg_2src_reg_0src_imm_2(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs );
        break;
      case ENC_1DST_REG_2SRC_REG_0SRC_IMM_3:
        decode_1dst_reg_2src_reg_0src_imm_3(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs );
        break;
      case ENC_1DST_REG_2SRC_REG_0SRC_IMM_4:
        decode_1dst_reg_2src_reg_0src_imm_4(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs );
        break;
      case ENC_1DST_REG_2SRC_REG_0SRC_IMM_5:
        decode_1dst_reg_2src_reg_0src_imm_5(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs );
        break;
      case ENC_1DST_REG_0SRC_REG_1SRC_IMM_1: 
        decode_1dst_reg_0src_reg_1src_imm_1(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs, sign_extend );
        break;
      case ENC_1DST_REG_0SRC_REG_1SRC_IMM_2:
        decode_1dst_reg_0src_reg_1src_imm_2(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs, sign_extend );
        break;
      case ENC_1DST_REG_0SRC_REG_1SRC_IMM_3:
        decode_1dst_reg_0src_reg_1src_imm_3(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs, sign_extend );
        break;
      case ENC_1DST_REG_1SRC_REG_1SRC_IMM_1:
        decode_1dst_reg_1src_reg_1src_imm_1(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs, sign_extend );
        break;
      case ENC_1DST_REG_1SRC_REG_1SRC_IMM_2:
        decode_1dst_reg_1src_reg_1src_imm_2(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs, sign_extend );
        break;
      case ENC_1DST_REG_1SRC_REG_1SRC_IMM_3:
        decode_1dst_reg_1src_reg_1src_imm_3(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs, sign_extend );
        break;
      case ENC_1DST_REG_1SRC_REG_1SRC_IMM_4:
        decode_1dst_reg_1src_reg_1src_imm_4(di, instr_word, dsts, 
                                            srcs, numdsts, numsrcs, sign_extend );
        break;
      case ENC_0DST_REG_1SRC_IMM_1SRC_MASK:
        decode_0dst_reg_1src_imm_1src_mask(di, instr_word, dsts, 
                                           srcs, numdsts, numsrcs, sign_extend );
        break;
      case ENC_0DST_REG_1SRC_REG_1SRC_MASK:
        decode_0dst_reg_1src_reg_1src_mask(di, instr_word, dsts, 
                                           srcs, numdsts, numsrcs );
        break;
      case ENC_0DST_REG_1SRC_REG_0SRC_IMM:
        decode_0dst_reg_1src_reg_0src_imm(di, instr_word, dsts, 
                                          srcs, numdsts, numsrcs );
        break;
      case ENC_1DST_REG_2SRC_REG_1SRC_IMM:
        decode_1dst_reg_2src_reg_1src_imm(di, instr_word, dsts, 
                                          srcs, numdsts, numsrcs, sign_extend );
        break;
      case ENC_1DST_REG_3SRC_REG_0SRC_IMM:
        decode_1dst_reg_3src_reg_0src_imm(di, instr_word, dsts, 
                                          srcs, numdsts, numsrcs );
        break;
      case ENC_0DST_REG_1SRC_REGLIST:
        decode_0dst_reg_1src_reglist(di, instr_word, dsts, 
                                     srcs, numdsts, numsrcs );
        break;
      case ENC_1DST_REG_1SRC_REGLIST:
        decode_1dst_reg_1src_reglist(di, instr_word, dsts, 
                                     srcs, numdsts, numsrcs );
        break;
      case BRANCH_INSTR:
        decode_branch_instrs(di, instr_word, dsts, 
                             srcs, numdsts, numsrcs, pc );
        break;

      default:
        //Fail
        break;
    }
}

instr_info_t* decode_data_processing_register_shifted_register(byte* instr_word,
                                                               decode_info_t* di, bool just_opcode,
                                                               opnd_t* dsts, opnd_t* srcs, 
                                                               int* numdsts, int* numsrcs)
{
    int encoding;

    if( ((instr_word[0] & 0x1) == 0 ) && //op1 == 0000x
        ((instr_word[1] & 0xe0) == 0 ))
    {
      di->opcode = OP_and_rsr; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op1 == 0001x
             ((instr_word[1] & 0xe0) == 0x20 ))
    {
      di->opcode = OP_eor_rsr; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op1 == 0010x
             ((instr_word[1] & 0xe0) == 0x40 ))
    {
      di->opcode = OP_sub_rsr; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op1 == 0011x
             ((instr_word[1] & 0xe0) == 0x60 ))
    {
      di->opcode = OP_rsb_rsr; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op1 == 0100x
             ((instr_word[1] & 0xe0) == 0x80 ))
    {
      di->opcode = OP_add_rsr; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op1 == 0101x
             ((instr_word[1] & 0xe0) == 0xa0 ))
    {
      di->opcode = OP_adc_rsr; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op1 == 0110x
             ((instr_word[1] & 0xe0) == 0xc0 ))
    {
      di->opcode = OP_sbc_rsr;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op1 == 0111x
             ((instr_word[1] & 0xe0) == 0xe0 ))
    {
      di->opcode = OP_rsc_rsr;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op1 == 10001
             ((instr_word[1] & 0xf0) == 0x10 ))
    {
      di->opcode = OP_tst_rsr;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op1 == 10011
             ((instr_word[1] & 0xf0) == 0x30 ))
    {
      di->opcode = OP_teq_rsr;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op1 == 10101
             ((instr_word[1] & 0xf0) == 0x50 ))
    {
      di->opcode = OP_cmp_rsr;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op1 == 10111
             ((instr_word[1] & 0xf0) == 0x70 ))
    {
      di->opcode = OP_cmn_rsr;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op1 == 1100x
             ((instr_word[1] & 0xe0) == 0x80 ))
    {
      di->opcode = OP_orr_rsr;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op1 == 1101x
             ((instr_word[1] & 0xe0) == 0xa0 ))
    {
      if( ((instr_word[3] & 0x60) == 0 )) //op2 == 00
      { 
        di->opcode = OP_lsl_reg;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else if( ((instr_word[3] & 0x60) == 0x20 )) //op2 == 01
      {
        di->opcode = OP_lsr_reg;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else if( ((instr_word[3] & 0x60) == 0x40 )) //op2 == 10
      {
        di->opcode = OP_asr_reg;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else if( ((instr_word[3] & 0x60) == 0x60 )) //op2 == 11
      {
        di->opcode = OP_ror_reg;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op1 == 1110x
             ((instr_word[1] & 0xe0) == 0xc0 ))
    {
      di->opcode = OP_bic_rsr;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op1 == 1111x
             ((instr_word[1] & 0xe0) == 0xe0 ))
    {
      di->opcode = OP_mvn_rsr;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ) );


    return op_instr[di->opcode];
}

instr_info_t* decode_data_processing_imm(byte* instr_word,
                                         decode_info_t* di, bool just_opcode,
                                         opnd_t* dsts, opnd_t* srcs, 
                                         int* numdsts, int* numsrcs)
{
    int encoding;

    if( ((instr_word[0] & 0x1) == 0 ) && //op == 0000x
        ((instr_word[1] & 0xe0) == 0 ))
    {
      di->opcode = OP_and_imm; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op == 0001x
             ((instr_word[1] & 0xe0) == 0x20 ))
    {
      di->opcode = OP_eor_imm; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op == 0010x
             ((instr_word[1] & 0xe0) == 0x40 ))
    {
      if( ((instr_word[1] & 0xf) != 0xf)) //Rn != 1111(r15)
      {
        di->opcode = OP_sub_imm; 
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else
      {
        di->opcode = OP_adr; //Encoding A2
        di->encoding = A2_ENCODING; 
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op == 0011x
             ((instr_word[1] & 0xe0) == 0x60 ))
    {
      di->opcode = OP_rsb_imm; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op == 0100x
             ((instr_word[1] & 0xe0) == 0x80 ))
    {
      if( ((instr_word[1] & 0xf) != 0xf)) //Rn != 1111(r15)
      {
        di->opcode = OP_add_imm;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else
      {
        di->opcode = OP_adr;
        di->encoding = A1_ENCODING; 
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op == 0101x
             ((instr_word[1] & 0xe0) == 0xa0 ))
    {
      di->opcode = OP_adc_imm;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op == 0110x
             ((instr_word[1] & 0xe0) == 0xc0 ))
    {
      di->opcode = OP_sbc_imm;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0 ) && //op == 0111x
             ((instr_word[1] & 0xe0) == 0xe0 ))
    {
      di->opcode = OP_rsc_imm;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op == 10000
             ((instr_word[1] & 0xf0) == 0x0 ))
    {
      di->opcode = OP_mov_imm;
      di->encoding = A2_ENCODING;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op == 10001
             ((instr_word[1] & 0xf0) == 0x10 ))
    {
      di->opcode = OP_tst_imm;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op == 10011
             ((instr_word[1] & 0xf0) == 0x30 ))
    {
      di->opcode = OP_teq_imm;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op == 10101
             ((instr_word[1] & 0xf0) == 0x50 ))
    {
      di->opcode = OP_cmp_imm;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op == 10111
             ((instr_word[1] & 0xf0) == 0x70 ))
    {
      di->opcode = OP_cmn_imm;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op == 1100x
             ((instr_word[1] & 0xe0) == 0x80 ))
    {
      di->opcode = OP_orr_imm;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op == 1101x
             ((instr_word[1] & 0xe0) == 0xa0 ))
    {
      di->opcode = OP_mov_imm;
      di->encoding = A1_ENCODING;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op == 1110x
             ((instr_word[1] & 0xe0) == 0xc0 ))
    {
      di->opcode = OP_bic_imm;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1 ) && //op == 1111x
             ((instr_word[1] & 0xe0) == 0xe0 ))
    {
      di->opcode = OP_mvn_imm;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
}

instr_info_t* decode_misc(byte* instr_word,
                          decode_info_t* di, bool just_opcode,
                          opnd_t* dsts, opnd_t* srcs, 
                          int* numdsts, int* numsrcs)
{
  // | cond | 000 | 10 | op | 0 | op1 |    | 0 | op2 |     |
  int encoding;

  if( (instr_word[0] & 0xf0 ) == 0x50 ) //op2 == 0101
  {
    if( ((instr_word[0] & 0x1) == 0x1) && //op1 == 10000
             ((instr_word[1] & 0xf0) == 0x0 ))
    {
      di->opcode = OP_qadd;
    }
    else if( ((instr_word[0] & 0x1) == 0x1) && //op1 == 10010
             ((instr_word[1] & 0xf0) == 0x20 ))
    {
      di->opcode = OP_qsub;
    }
    else if( ((instr_word[0] & 0x1) == 0x1) && //op1 == 10100
             ((instr_word[1] & 0xf0) == 0x40 ))
    {
      di->opcode = OP_qdadd;
    }
    else if( ((instr_word[0] & 0x1) == 0x1) && //op1 == 10110
             ((instr_word[1] & 0xf0) == 0x60 ))
    {
      di->opcode = OP_qdsub;
    }
  }
  else if( (instr_word[0] & 0xf0 ) == 0x0 ) //op2 == 0000
  {
    if( (instr_word[1] & 0x20) == 0x0 ) //op == x0
    {
      di->opcode = OP_mrs;
    }
    else if( (instr_word[1] & 0x60) == 0x20 ) //op == 01
    {
      //TODO Record app or sys level here based on op1
      di->opcode = OP_msr_reg;
    }
    else if( (instr_word[1] & 0x60) == 0x60 ) //op == 11 
    {
      //TODO Record app or sys level here based on op1
      di->opcode = OP_msr_reg;
    }
  }
  else if( (instr_word[0] & 0xf0 ) == 0x10 ) //op2 == 0001
  {
    if( (instr_word[1] & 0x60) == 0x20 ) //op == 01 
    {
      di->opcode = OP_bx;
    }
    else if( (instr_word[1] & 0x60) == 0x60 ) //op == 11
    {
      di->opcode = OP_clz;
    }
  }
  else if( (instr_word[0] & 0xf0 ) == 0x20 ) //op2 == 0010
  {
    if( (instr_word[1] & 0x60) == 0x20 ) //op == 01 
    {
      di->opcode = OP_bxj; 
    }
  }
  else if( (instr_word[0] & 0xf0 ) == 0x30 ) //op2 == 0011
  {
    if( (instr_word[1] & 0x60) == 0x20 ) //op == 01 
    {
      di->opcode = OP_blx_reg;
    }
  }
  else if( (instr_word[0] & 0xf0 ) == 0x70 ) //op2 == 0111
  {
    if( (instr_word[1] & 0x60) == 0x20 ) //op == 01 
    {
      di->opcode = OP_bkpt;
    }
    else if( (instr_word[1] & 0x60) == 0x60 ) //op == 11 
    {
      di->opcode = OP_UNDECODED;
      //di->opcode = OP_smc; SJF Missing opcode
    }
  }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
}

instr_info_t* decode_halfword_mul_and_mla(byte* instr_word,
                                          decode_info_t* di, bool just_opcode,
                                          opnd_t* dsts, opnd_t* srcs, 
                                          int* numdsts, int* numsrcs)
{
    // | cond | 0001 | 0 | op1 | 0 |     | 1 | | op | 0 |    |

    int encoding;

    if( ((instr_word[1] & 0x60) == 0 ))  //op1 == 00
    {
      if( (instr_word[3] & 0x60) == 0 )    //MN = 00
        di->opcode = OP_smlabb;
      else if( (instr_word[3] & 0x60) == 0x20 ) //MN = 01
        di->opcode = OP_smlabt;
      else if( (instr_word[3] & 0x60) == 0x40 ) //MN = 10
        di->opcode = OP_smlatb;
      else if( (instr_word[3] & 0x60) == 0x60 ) //MN = 11
        di->opcode = OP_smlatt;
    }
    else if( ((instr_word[1] & 0x60) == 0x20 ) &&  //op1 == 01
             ((instr_word[3] & 0x20) == 0x0 ) )  //op == 0 
    {
      if( (instr_word[3] & 0x40) == 0 )    //M = 0
        di->opcode = OP_smlawb;
      else if( (instr_word[3] & 0x40) == 0x40 ) //M = 1
        di->opcode = OP_smlawt;
    }
    else if( ((instr_word[1] & 0x60) == 0x20 ) &&  //op1 == 01
             ((instr_word[3] & 0x20) == 0x20 ) )  //op == 1 
    {
      if( (instr_word[3] & 0x40) == 0 )    //M = 0
        di->opcode = OP_smulwb;
      else if( (instr_word[3] & 0x40) == 0x40 ) //M = 1
        di->opcode = OP_smulwt;
    }
    else if( ((instr_word[1] & 0x60) == 0x20 ) )  //op1 == 10
    {
      if( (instr_word[3] & 0x60) == 0 )    //MN = 00
        di->opcode = OP_smlalbb;
      else if( (instr_word[3] & 0x60) == 0x20 ) //MN = 01
        di->opcode = OP_smlalbt;
      else if( (instr_word[3] & 0x60) == 0x40 ) //MN = 10
        di->opcode = OP_smlaltb;
      else if( (instr_word[3] & 0x60) == 0x60 ) //MN = 11
        di->opcode = OP_smlaltt;
    }
    else if( ((instr_word[1] & 0x60) == 0x60 ) )  //op1 == 11
    {
      if( (instr_word[3] & 0x60) == 0 )    //MN = 00
        di->opcode = OP_smulbb;
      else if( (instr_word[3] & 0x60) == 0x20 ) //MN = 01
        di->opcode = OP_smulbt;
      else if( (instr_word[3] & 0x60) == 0x40 ) //MN = 10
        di->opcode = OP_smultb;
      else if( (instr_word[3] & 0x60) == 0x60 ) //MN = 11
        di->opcode = OP_smultt;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
}


instr_info_t* decode_mul_and_mla(byte* instr_word,
                                 decode_info_t* di, bool just_opcode,
                                 opnd_t* dsts, opnd_t* srcs, 
                                 int* numdsts, int* numsrcs)
{
    // | cond | 0000 | op |    | 1001 |    |
    int encoding;

    if( ((instr_word[1] & 0xe0) == 0 ))  //op == 000x
    {
      di->opcode = OP_mul; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[1] & 0xe0) == 0x20 ))  //op == 001x
    {
      di->opcode = OP_mla;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[1] & 0xf0) == 0x40 ))  //op == 0100
    {
      di->opcode = OP_umaal;
    }
    else if( ((instr_word[1] & 0xe0) == 0x60 ))  //op == 0110 
    {
      di->opcode = OP_mls;
    }
    else if( ((instr_word[1] & 0xe0) == 0x80 ))  //op == 100x 
    {
      di->opcode = OP_umull;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[1] & 0xe0) == 0xa0 ))  //op == 101x 
    {
      di->opcode = OP_umlal;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[1] & 0xe0) == 0xc0 ))  //op == 110x 
    {
      di->opcode = OP_smull;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[1] & 0xe0) == 0xe0 ))  //op == 111x 
    {
      di->opcode = OP_smlal;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];

}

instr_info_t* decode_extra_load_store_unpriv_1(byte* instr_word,
                                               decode_info_t* di, bool just_opcode,
                                               opnd_t* dsts, opnd_t* srcs,
                                               int* numdsts, int* numsrcs)
{
   int encoding;

   if( ((instr_word[1] & 0x10 ) == 0x0 )) //op == 0 
   {
      di->opcode = OP_strht;
      di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
      di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
      di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;

      if( (instr_word[1] & 0x40) == 0x40 )
        di->encoding = A1_ENCODING;
      else
        di->encoding = A2_ENCODING;
   }
   else //op == 1
   {
      di->opcode = OP_ldrht; //Encoding A1 and A2 only diff is bit[22], A1=0, A2=1
      di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
      di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
      di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;

      //Need to store A1 or A2. A1 = 0, A2 = 1. Hence the negation
      di->encoding = !((instr_word[1] & 0x40) == 0x40);
   }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
 
}

instr_info_t* decode_extra_load_store_unpriv_2(byte* instr_word,
                                               decode_info_t* di, bool just_opcode,
                                               opnd_t* dsts, opnd_t* srcs,
                                               int* numdsts, int* numsrcs)
{
   int encoding;
   
   if( ((instr_word[3] & 0x10) == 0x0) ) //op2 == x0
   {
     if( ((instr_word[1] & 0x10 ) == 0x0 )) //op == 0 
     {
       //FAIL
     }
     else //op == 1
     {
        di->opcode = OP_ldrsbt; //Encoding A1 and A2
        di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
        di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
        di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;

        //Need to store A1 or A2. A1 = 0, A2 = 1. Hence the negation
        di->encoding = !((instr_word[1] & 0x40) == 0x40);
     }
   }
   else
   {
     if( ((instr_word[1] & 0x10 ) == 0x0 )) //op == 0 
     {
       //FAIL
     }
     else //op == 1
     {
        di->opcode = OP_ldrsht;
        di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
        di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
        di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;

        //Need to store A1 or A2. A1 = 0, A2 = 1. Hence the negation
        di->encoding = !((instr_word[1] & 0x40) == 0x40);
     }
   }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
}

instr_info_t* decode_extra_load_store_2(byte* instr_word,
                                        decode_info_t* di, bool just_opcode,
                                        opnd_t* dsts, opnd_t* srcs,
                                        int* numdsts, int* numsrcs)
{
    int encoding;
    //TODO Decode publw? flags into di for all load/store instrs

    if( ((instr_word[3] & 0xf0 ) == 0xd0 )) //op2 == 1101
    {
      if( (instr_word[1] & 0x50) == 0 ) //op1 == xx0x0
      {
        di->opcode = OP_ldrd_reg;
        di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
        di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
        di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
      }
      else if( (instr_word[1] & 0x50) == 0x10 ) //op1 == xx0x1
      {
        di->opcode = OP_ldrsb_reg;
        di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
        di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
        di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
      }
      else if( (instr_word[1] & 0x50) == 0x40 ) //op1 == xx1x0
      {
        if( (instr_word[1] & 0xf) == 0xf ) //Rn == 1111 
        {
          di->opcode = OP_ldrd_lit;
          di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
          di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
          di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
        }
        else
        {
          di->opcode = OP_ldrd_imm;
          di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
          di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
          di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
        }
      }
      else if( (instr_word[1] & 0x50) == 0x50 ) //op1 == xx1x1
      {
        if( (instr_word[1] & 0xf) == 0xf ) //Rn == 1111 
        {
          di->opcode = OP_ldrsb_lit;
          di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
          di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
          di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
        }
        else
        {
          di->opcode = OP_ldrsb_imm;
          di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
          di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
          di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
        }
      }
    }
    else if( ((instr_word[3] & 0xf0 ) == 0xf0 )) //op2 == 1111
    {
      if( (instr_word[1] & 0x50) == 0 ) //op1 == xx0x0
      {
        di->opcode = OP_strd_reg;
        di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
        di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
        di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
      }
      else if( (instr_word[1] & 0x50) == 0x10 ) //op1 == xx0x1
      {
        di->opcode = OP_ldrsh_reg;
        di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
        di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
        di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
      }
      else if( (instr_word[1] & 0x50) == 0x40 ) //op1 == xx1x0
      {
        di->opcode = OP_strd_imm;
        di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
        di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
        di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
      }
      else if( (instr_word[1] & 0x50) == 0x50 ) //op1 == xx1x1
      {
        if( (instr_word[1] & 0xf) == 0xf ) //Rn == 1111 
        {
          di->opcode = OP_ldrsh_lit;
          di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
          di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
          di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
        }
        else
        {
          di->opcode = OP_ldrsh_imm;
          di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
          di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
          di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
        }
      }

    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
}

instr_info_t* decode_extra_load_store_1(byte* instr_word,
                                        decode_info_t* di, bool just_opcode,
                                        opnd_t* dsts, opnd_t* srcs,
                                        int* numdsts, int* numsrcs)
{
    //TODO Decode publw? flags into di for all load/store instrs
    int encoding;

    if( (instr_word[1] & 0x50) == 0 ) //op1 == xx0x0
    {
      di->opcode = OP_strh_reg;
      di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
      di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
      di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
    }
    else if( (instr_word[1] & 0x50) == 0x10 ) //op1 == xx0x1
    {
      di->opcode = OP_ldrh_reg;
      di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
      di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
      di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
    }
    else if( (instr_word[1] & 0x50) == 0x40 ) //op1 == xx1x0
    {
      di->opcode = OP_strh_imm;
      di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
      di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
      di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
    }
    else if( (instr_word[1] & 0x50) == 0x50 ) //op1 == xx1x1
    {
      if( (instr_word[1] & 0xf) == 0xf ) //Rn == 1111 
      {
        di->opcode = OP_ldrh_lit;
        di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
        di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
        di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
      }
      else
      {
        di->opcode = OP_ldrh_imm;
        di->p_flag  = ((instr_word[0] & 0x1) == 0 ) ? false : true;
        di->u_flag  = ((instr_word[1] & 0x80) == 0 ) ? false : true;
        di->w_flag  = ((instr_word[1] & 0x20) == 0 ) ? false : true;
      }
    }
  
    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
}

instr_info_t* decode_syncro_prims(byte* instr_word,
                                  decode_info_t* di, bool just_opcode,
                                  opnd_t* dsts, opnd_t* srcs, 
                                  int* numdsts, int* numsrcs)
{
    int encoding;

    if( ((instr_word[1] & 0xb0) == 0 ) ) //op1 == 0x00
    {
      if( (instr_word[1] & 0x40) == 0)
        di->opcode = OP_swp;
      else
        di->opcode = OP_swpb;
    }
    else if( ((instr_word[1] & 0xf0) == 0x80 ) ) //op1 == 1000 
    {
      di->opcode = OP_strex;
    }
    else if( ((instr_word[1] & 0xf0) == 0x90 ) ) //op1 == 1001 
    {
      di->opcode = OP_ldrex;
    }
    else if( ((instr_word[1] & 0xf0) == 0xa0 ) ) //op1 == 1010 
    {
      di->opcode = OP_strexd;
    }
    else if( ((instr_word[1] & 0xf0) == 0xb0 ) ) //op1 == 1011 
    {
      di->opcode = OP_ldrexd;
    }
    else if( ((instr_word[1] & 0xf0) == 0xc0 ) ) //op1 == 1100 
    {
      di->opcode = OP_strexb;
    }
    else if( ((instr_word[1] & 0xf0) == 0xd0 ) ) //op1 == 1101 
    {
      di->opcode = OP_ldrexb;
    }
    else if( ((instr_word[1] & 0xf0) == 0xe0 ) ) //op1 == 1110
    {
      di->opcode = OP_strexh;
    }
    else if( ((instr_word[1] & 0xf0) == 0xf0 ) ) //op1 == 1111
    {
      di->opcode = OP_ldrexh;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
}

instr_info_t* decode_msr_and_hints(byte* instr_word,
                                   decode_info_t* di, bool just_opcode,
                                   opnd_t* dsts, opnd_t* srcs,
                                   int* numdsts, int* numsrcs)
{
    int encoding;

    // | cond | 00110 | op | 10 | op1 |    | op2 |

    if( (instr_word[1] & 0x40) == 0 ) //op == 0
    {
      if( (instr_word[1] & 0xf) == 0 ) //op1 == 0000
      {
        if( instr_word[3] == 0 ) //op2 == 00000000
          di->opcode = OP_nop;
        else if ( instr_word[3] == 0x1 ) //op2 == 00000001
          di->opcode = OP_yield;
        else if ( instr_word[3] == 0x2 ) //op2 == 00000010
          di->opcode = OP_wfe;
        else if ( instr_word[3] == 0x3 ) //op2 == 00000011
          di->opcode = OP_wfi;
        else if ( instr_word[3] == 0x4 ) //op2 == 00000100
          di->opcode = OP_sev;
        else if ( (instr_word[3] & 0xf0) == 0xf0 ) //op2 == 11110000
          di->opcode = OP_dbg;
      }
      else if( (instr_word[1] & 0xf) == 0x4) //op1 == 0100
      {
        //App level
        di->opcode = OP_msr_imm; 
      }
      else if( (instr_word[1] & 0xb) == 0x8) //op1 == 1x00
      {
        //App level
        //TODO Flag the x value soemwhere for some reason ?
        di->opcode = OP_msr_imm; 
      }
      else if( (instr_word[1] & 0x3) == 0x1) //op1 == xx01 
      {
        //System level
        di->opcode = OP_msr_imm; 
      }
      else if( (instr_word[1] & 0x3) == 0x1) //op1 == xx1x 
      {
        //System level
        //TODO Flag the x value soemwhere for some reason ?
        di->opcode = OP_msr_imm; 
      }
    }
    else
    {
      //System level
      di->opcode = OP_msr_imm; 
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );

    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
}

instr_info_t* decode_data_processing_register(byte* instr_word,
                                              decode_info_t* di, bool just_opcode,
                                              opnd_t* dsts, opnd_t* srcs, 
                                              int* numdsts, int* numsrcs)
{
    instr_info_t *info = NULL;
    uint opcode = 0, s_flag = 0, reg = 0, immed = 0;
    int  encoding = UNKNOWN_ENCODING;

    if( ((instr_word[0] & 0x1) == 0 ) && //op1 == 0000x
        ((instr_word[1] & 0xe0) == 0 ))
    {
      di->opcode = OP_and_reg; 
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0) && //op1 == 0001x
             ((instr_word[1] & 0xe0) == 0x20))
    {
      di->opcode = OP_eor_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0) && //op1 == 0010x
             ((instr_word[1] & 0xe0) == 0x40))
    {
      di->opcode = OP_sub_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0) && //op1 == 0011x
             ((instr_word[1] & 0xe0) == 0x60))
    {
      di->opcode = OP_rsb_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0) && //op1 == 0100x
             ((instr_word[1] & 0xe0) == 0x80))
    {
      di->opcode = OP_add_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0) && //op1 == 0101x
             ((instr_word[1] & 0xe0) == 0xa0))
    {
      di->opcode = OP_adc_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0) && //op1 == 0110x
             ((instr_word[1] & 0xe0) == 0xc0))
    {
      di->opcode = OP_sbc_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 0) && //op1 == 0111x
             ((instr_word[1] & 0xe0) == 0xe0))
    {
      di->opcode = OP_rsc_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1) && //op1 == 10001 
             ((instr_word[1] & 0xf0) == 0x10))
    {
      di->opcode = OP_tst_reg;
    }
    else if( ((instr_word[0] & 0x1) == 1) && //op1 == 10011 
             ((instr_word[1] & 0xf0) == 0x30))
    {
      di->opcode = OP_teq_reg;
    }
    else if( ((instr_word[0] & 0x1) == 1) && //op1 == 10101 
             ((instr_word[1] & 0xf0) == 0x50))
    {
      di->opcode = OP_cmp_reg;
    }
    else if( ((instr_word[0] & 0x1) == 1) && //op1 == 10111 
             ((instr_word[1] & 0xf0) == 0x70))
    {
      di->opcode = OP_cmn_reg;
    }
    else if( ((instr_word[0] & 0x1) == 1) && //op1 == 1100x 
             ((instr_word[1] & 0xe0) == 0x80))
    {
      di->opcode = OP_orr_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1) && //op1 == 1101x 
             ((instr_word[1] & 0xe0) == 0xa0))
    {
      if( ((instr_word[2] & 0xf) == 0) && //op2 == 00000
          ((instr_word[3] & 0x80) == 0) &&
          ((instr_word[3] & 0x60) == 0 ) ) //op3 == 00
      {
        di->opcode = OP_mov_reg;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else if( (((instr_word[2] & 0xf) != 0) || //op2 != 00000
                ((instr_word[3] & 0x80) != 0)) && 
               ((instr_word[3] & 0x60) == 0 ) ) //op3 == 00
      {
        di->opcode = OP_lsl_imm;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else if( (((instr_word[2] & 0xf) != 0) || //op2 != 00000
                ((instr_word[3] & 0x80) != 0)) && 
               ((instr_word[3] & 0x60) == 0x20 ) ) //op3 == 01
      {
        di->opcode = OP_lsr_imm;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else if( (((instr_word[2] & 0xf) != 0) || //op2 != 00000
                ((instr_word[3] & 0x80) != 0)) && 
               ((instr_word[3] & 0x60) == 0x40 ) ) //op3 == 10
      {
        di->opcode = OP_asr_imm;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else if( (((instr_word[2] & 0xf) == 0) && //op2 == 00000
                ((instr_word[3] & 0x80) == 0)) && 
               ((instr_word[3] & 0x60) == 0x60 ) ) //op3 == 11
      {
        di->opcode = OP_rrx;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }
      else if( (((instr_word[2] & 0xf) != 0) || //op2 != 00000
                ((instr_word[3] & 0x80) != 0)) && 
               ((instr_word[3] & 0x60) == 0x60 ) ) //op3 == 11
      {
        di->opcode = OP_ror_imm;
        di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
      }

    }
    else if( ((instr_word[0] & 0x1) == 1) && //op1 == 1110x 
             ((instr_word[1] & 0xe0) == 0xc0))
    {
      di->opcode = OP_bic_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }
    else if( ((instr_word[0] & 0x1) == 1) && //op1 == 1111x 
             ((instr_word[1] & 0xe0) == 0xe0))
    {
      di->opcode = OP_mvn_reg;
      di->s_flag  = ((instr_word[1] & 0x10) == 0 ) ? false : true;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING), 
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word, 
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];
}


instr_info_t* decode_data_processing_and_misc(byte* instr_word,
                            decode_info_t* di, bool just_opcode,
                            opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    // | cond | 00 | op | op1 |     | Rd |  op2   |
    instr_info_t *info = NULL;

    if( (instr_word[0] & 0x2 ) == 0 ) //op == 0
    {
        if( ((instr_word[0] & 0x1) != 1 ) || //op1 != 10xx0
            ((instr_word[1] & 0x90) != 0) )
        {
          if( (instr_word[3] & 0x10) == 0 )  //op2 == xxx0
          {
            info = decode_data_processing_register(instr_word, di, just_opcode, 
                                                   dsts, srcs, numdsts, numsrcs);
          }
          else if( (instr_word[3] & 0x90) == 0x10 ) //op2 == 0xx1
          {
            info = decode_data_processing_register_shifted_register(instr_word, di, just_opcode, 
                                                                    dsts, srcs, numdsts, numsrcs);
          }
        }
        else if( ((instr_word[0] & 0x1) == 1) && //op1 == 10xx0
                 ((instr_word[1] & 0x90) == 0))
        {
          if( (instr_word[3] & 0x80) == 0 ) //op2 == 0xxx
            info = decode_misc(instr_word, di, just_opcode, 
                               dsts, srcs, numdsts, numsrcs);
          else if( (instr_word[3] & 0x90) == 0x80 ) //op2 == 1xx0
            info = decode_halfword_mul_and_mla(instr_word, di, just_opcode, 
                                               dsts, srcs, numdsts, numsrcs);
        }
        else if( ((instr_word[0] & 0x1) == 0) &&    //op1 == 0xxxx 
                 ((instr_word[3] & 0xf0) == 0x90 )) // op2 == 1001
        {
          info = decode_mul_and_mla(instr_word, di, just_opcode, 
                                    dsts, srcs, numdsts, numsrcs);
        }
        else if( ((instr_word[0] & 0x1) == 1) &&    //op1 == 1xxxx 
                 ((instr_word[3] & 0xf0) == 0x90 )) // op2 == 1001
        {
          info = decode_syncro_prims(instr_word, di, just_opcode, 
                                     dsts, srcs, numdsts, numsrcs);
        }
        else if( ((instr_word[0] & 0x1 ) != 0 ) ||  //op1 != 0xx1x
                 ((instr_word[1] & 0x20 ) != 0x20 ))
        {
          if( ((instr_word[3] & 0xf0 ) == 0xb0 )) //op2 == 1011
            info = decode_extra_load_store_1(instr_word, di, just_opcode, 
                                             dsts, srcs, numdsts, numsrcs);
          else if ((instr_word[3] & 0xd0) == 0xd0) //op2 == 11x1
            info = decode_extra_load_store_2(instr_word, di, just_opcode,
                                             dsts, srcs, numdsts, numsrcs);
        }
        else if( ((instr_word[0] & 0x1 ) == 0 ) && //op1 == 0xx1x
                 ((instr_word[1] & 0x20) == 0x20))
        {
          if( ((instr_word[3] & 0xf0 ) == 0xb0 )) //op2 == 1011
            info = decode_extra_load_store_unpriv_1(instr_word, di, just_opcode,
                                                     dsts, srcs, numdsts, numsrcs);
          else if ((instr_word[3] & 0xd0) == 0xd0) //op2 == 11x1
            info = decode_extra_load_store_unpriv_2(instr_word, di, just_opcode,
                                                     dsts, srcs, numdsts, numsrcs);
        }
        else
        {
          CLIENT_ASSERT(false, "decode.c:decode_data_processing_and_misc: invalid instruction read" );
        }
    }
    else //op == 1
    {
        if( ((instr_word[0] & 0x1) != 1 ) || //op1 != 10xx0
            ((instr_word[1] & 0x90) != 0) )
        {
            info = decode_data_processing_imm(instr_word, di, just_opcode, 
                                              dsts, srcs, numdsts, numsrcs);
        }
        else if( ((instr_word[0] & 0x1) == 1) && //op1 == 10000
                 ((instr_word[1] & 0xf0) == 0 )) 
        {
          //decode_16bit_imm_load
        }
        else if( ((instr_word[0] & 0x1) == 1) && //op1 == 10100
                 ((instr_word[1] & 0xf0) == 0x40) )
        {
          //decode_high_halfword_16bit_imm_load
        }
        else if( ((instr_word[0] & 0x1) == 1) && //op1 == 10x10
                 ((instr_word[1] & 0xf0) == 0x20) )
        {
            info = decode_msr_and_hints(instr_word, di, just_opcode,
                                        dsts, srcs, numdsts, numsrcs);
        }
    }

    return info;
}

instr_info_t* decode_load_store_word_and_ubyte1(byte* instr_word,
                            decode_info_t* di, bool just_opcode,
                            opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    // | cond | 01 | A | op1 | Rn |     | B |    |

    instr_info_t *info = NULL;
    int encoding;

    if( (instr_word[0] & 0x2 ) == 0 ) //A == 0
    {
        if( ((instr_word[1] & 0x50) == 0 ) && //op1 == xx0x0 not 0x010
            (((instr_word[0] & 0x1) != 0 ) ||
             ((instr_word[1] & 0x70) != 0x20 )) )
        {
          if( ((instr_word[0] & 0x1)  == 0x1 ) && //op1 == 10010
              ((instr_word[1] & 0xf0) == 0x20 ))
          {
            di->opcode = OP_push; 
            di->encoding = A1_ENCODING;
          }
          else
            di->opcode = OP_str_imm; 
        }
        else if(((instr_word[0] & 0x1) == 0 ) && //op1 == 0x010
                ((instr_word[1] & 0x70 ) == 0x20 ))
        {
          di->opcode = OP_strt; 
          di->encoding = A1_ENCODING;
        }
        else if(((instr_word[1] & 0x50) == 0x10 ) && //op1 == xx0x1 not 0x011
                (((instr_word[0] & 0x1) != 0 ) ||
                 ((instr_word[1] & 0x70) != 0x30 )) )
        {
          if( (instr_word[0] & 0x1) == 0 &&
              (instr_word[1] & 0xf) == 0x9) //op1 == 01001
          {
            di->opcode = OP_pop;
            di->encoding = A2_ENCODING;
          }
          else if( (instr_word[0] & 0x1) == 0 &&
                   (instr_word[1] & 0xf) == 0xb) //op1 == 01011
          {
            di->opcode = OP_pop;
            di->encoding = A1_ENCODING;
          }
          else
          {
            if( (instr_word[1] & 0xf) == 0xf)
              di->opcode = OP_ldr_lit; 
            else
              di->opcode = OP_ldr_imm; 
          }
        }
        else if(((instr_word[0] & 0x1) == 0 ) && //op1 == 0x011
                ((instr_word[1] & 0x70 ) == 0x30 ))
        {
          di->opcode = OP_ldrt;
          di->encoding = A1_ENCODING;
        }
        else if(((instr_word[1] & 0x50) == 0x40 ) && //op1 == xx1x0 not 0x110
                (((instr_word[0] & 0x1) != 0 ) ||
                 ((instr_word[1] & 0x70) != 0x60 )) )
        {
          di->opcode = OP_strb_imm;
        }
        else if(((instr_word[0] & 0x1) == 0 ) && //op1 == 0x110
                ((instr_word[1] & 0x70 ) == 0x60 ))
        {
          di->opcode = OP_strbt;
          di->encoding = A1_ENCODING;
        }
        else if(((instr_word[1] & 0x50) == 0x50 ) && //op1 == xx1x1 not 0x111
                (((instr_word[0] & 0x1) != 0 ) ||
                 ((instr_word[1] & 0x70) != 0x70 )) )
        {
          if( (instr_word[1] & 0xf) == 0xf)
            di->opcode = OP_ldrb_lit;
          else
            di->opcode = OP_ldrb_imm;
        }
        else if(((instr_word[0] & 0x1) == 0 ) && //op1 == 0x111
                ((instr_word[1] & 0x70 ) == 0x70 ))
        {
          di->opcode = OP_ldrbt;
          di->encoding = A1_ENCODING;
        }
    }
    else if( (instr_word[0] & 0x2 ) == 0x2 ) //A == 1
    {
        if( ((instr_word[1] & 0x50) == 0 ) && //op1 == xx0x0 not 0x010
            (((instr_word[0] & 0x1) != 0 ) ||
             ((instr_word[1] & 0x70) != 0x20 )) )
        {
          di->opcode = OP_str_reg;
        }
        else if(((instr_word[0] & 0x1) == 0 ) && //op1 == 0x010
                ((instr_word[1] & 0x70 ) == 0x20 ))
        {
          di->opcode = OP_strt;
          di->encoding = A2_ENCODING;
        }
        else if(((instr_word[1] & 0x50) == 0x10 ) && //op1 == xx0x1 not 0x011
                (((instr_word[0] & 0x1) != 0 ) ||
                 ((instr_word[1] & 0x70) != 0x30 )) )
        {
          di->opcode = OP_ldr_reg;
        }
        else if(((instr_word[0] & 0x1) == 0 ) && //op1 == 0x011
                ((instr_word[1] & 0x70 ) == 0x30 ))
        {
          di->opcode = OP_ldrt;
          di->encoding = A2_ENCODING;
        }
        else if(((instr_word[1] & 0x50) == 0x40 ) && //op1 == xx1x0 not 0x110
                (((instr_word[0] & 0x1) != 0 ) ||
                 ((instr_word[1] & 0x70) != 0x60 )) )
        {
          di->opcode = OP_strb_reg;
        }
        else if(((instr_word[0] & 0x1) == 0 ) && //op1 == 0x110
                ((instr_word[1] & 0x70 ) == 0x60 ))
        {
          di->opcode = OP_strbt;
          di->encoding = A2_ENCODING;
        }
        else if(((instr_word[1] & 0x50) == 0x50 ) && //op1 == xx1x1 not 0x111
                (((instr_word[0] & 0x1) != 0 ) ||
                 ((instr_word[1] & 0x70) != 0x70 )) )
        {
          di->opcode = OP_ldrb_reg;
        }
        else if(((instr_word[0] & 0x1) == 0 ) && //op1 == 0x111
                ((instr_word[1] & 0x70 ) == 0x70 ))
        {
          di->opcode = OP_ldrbt; //Encoding A2
          di->encoding = A2_ENCODING;
        }
        //NOTE SJF Moved decode_media to here 
        else if( (instr_word[0] & 0x1 ) == 0  &&
                 (instr_word[1] & 0xc0) == 0 ) //op1 == 000xx
        {
          return decode_parallel_signed_arith(instr_word, di, just_opcode,
                                              dsts, srcs, numdsts, numsrcs);
        }
        else if( (instr_word[0] & 0x1 ) == 0  &&
                 (instr_word[1] & 0xc0) == 0x40 ) //op1 == 001xx
        {
          return decode_parallel_unsigned_arith(instr_word, di, just_opcode,
                                                dsts, srcs, numdsts, numsrcs);
        }
        else if( (instr_word[0] & 0x1 ) == 0  &&
                 (instr_word[1] & 0x80) == 0x80 ) //op1 == 01xxx
        {
          return decode_parallel_pack_unpack(instr_word, di, just_opcode,
                                             dsts, srcs, numdsts, numsrcs);
        }
        else if( (instr_word[0] & 0x1 ) == 1  &&
                 (instr_word[1] & 0x80) == 0x0 ) //op1 == 10xxx
        {
          return decode_signed_mul(instr_word, di, just_opcode,
                                   dsts, srcs, numdsts, numsrcs);
        }
        else if( (instr_word[0] & 0x1 ) == 1 &&     //op1 == 11000
                 (instr_word[1] & 0xf0) == 0x80 )
        {
          if( (instr_word[2] & 0xf0) == 0xf0 )
            di->opcode = OP_usad8;
          else
            di->opcode = OP_usada8;
        }
        else if( (instr_word[0] & 0x1 ) == 1  &&
                 (instr_word[1] & 0xe0) == 0xa0 ) //op1 == 1101x 
        {
          if( (instr_word[3] & 0x60) == 0x40 )    //op2 == x10
            di->opcode = OP_sbfx;
        }
        else if( (instr_word[0] & 0x1 ) == 1  &&
                 (instr_word[1] & 0xe0) == 0xc0 ) //op1 == 1110x 
        {
          if( (instr_word[3] & 0x60) == 0x0 )     //op2 == x00
          {
            if( (instr_word[2] & 0xf0) == 0xf0 )
              di->opcode = OP_bfc;
            else
              di->opcode = OP_bfi;
          }
        }
        else if( (instr_word[0] & 0x1 ) == 1  &&
                 (instr_word[1] & 0xe0) == 0xe0 ) //op1 == 1111x 
        {
          if( (instr_word[3] & 0x60) == 0x40 )     //op2 == x10
            di->opcode = OP_ubfx;
        }
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_load_store_word_and_ubyte1: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode));

    return op_instr[di->opcode];
}


instr_info_t* decode_load_store_word_and_ubyte2(byte* instr_word,
                            decode_info_t* di, bool just_opcode,
                            opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    // | cond | 01 | A | op1 | Rn |     | B |    |
    instr_info_t *info = NULL;

    //TODO Add OP_ldrbt encoding A2 here
    

    return info;
}

instr_info_t* decode_parallel_unsigned_arith(byte* instr_word,
                                             decode_info_t* di, bool just_opcode,
                                           opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    // | cond | 011 001 | op1 |        | op2 | 1 |       |
    int encoding;

    if( (instr_word[1] & 0x30 ) == 0x10 ) //op1 == 01
    {
      if( (instr_word[3] & 0xe0) == 0x0 ) //op2 == 000
        di->opcode = OP_uadd16;
      else if( (instr_word[3] & 0xe0) == 0x20 ) //op2 == 001
        di->opcode = OP_uasx;
      else if( (instr_word[3] & 0xe0) == 0x40 ) //op2 == 010
        di->opcode = OP_usax;
      else if( (instr_word[3] & 0xe0) == 0x60 ) //op2 == 011
        di->opcode = OP_usub16;
      else if( (instr_word[3] & 0xe0) == 0x80 ) //op2 == 100 
        di->opcode = OP_uadd8;
      else if( (instr_word[3] & 0xe0) == 0xe0 ) //op2 == 111 
        di->opcode = OP_usub8;
    }
    else if( (instr_word[1] & 0x30 ) == 0x20 ) //op1 == 10
    {
      if( (instr_word[3] & 0xe0) == 0x0 ) //op2 == 000
        di->opcode = OP_uqadd16;
      else if( (instr_word[3] & 0xe0) == 0x20 ) //op2 == 001
        di->opcode = OP_uqasx;
      else if( (instr_word[3] & 0xe0) == 0x40 ) //op2 == 010
        di->opcode = OP_uqsax;
      else if( (instr_word[3] & 0xe0) == 0x60 ) //op2 == 011
        //di->opcode = OP_uqsub16; SJF Missing opcode
        di->opcode = OP_UNDECODED; 
      else if( (instr_word[3] & 0xe0) == 0x80 ) //op2 == 100 
        di->opcode = OP_uqadd8;
      else if( (instr_word[3] & 0xe0) == 0xe0 ) //op2 == 111 
        //di->opcode = OP_uqsub8; SJF Missing opcode
        di->opcode = OP_UNDECODED; 
    }
    else if( (instr_word[1] & 0x30 ) == 0x30 ) //op1 == 11
    {
      if( (instr_word[3] & 0xe0) == 0x0 ) //op2 == 000
        di->opcode = OP_uhadd16;
      else if( (instr_word[3] & 0xe0) == 0x20 ) //op2 == 001
        //di->opcode = OP_uhasx; SJF Missing opcode
        di->opcode = OP_UNDECODED; 
      else if( (instr_word[3] & 0xe0) == 0x40 ) //op2 == 010
        di->opcode = OP_uhsax;
      else if( (instr_word[3] & 0xe0) == 0x60 ) //op2 == 011
        di->opcode = OP_uhsub16;
      else if( (instr_word[3] & 0xe0) == 0x80 ) //op2 == 100 
        di->opcode = OP_uhadd8;
      else if( (instr_word[3] & 0xe0) == 0xe0 ) //op2 == 111 
        di->opcode = OP_uhsub8;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];

}

instr_info_t* decode_parallel_signed_arith(byte* instr_word,
                                           decode_info_t* di, bool just_opcode,
                                           opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    // | cond | 011 000 | op1 |        | op2 | 1 |       |
    int encoding;

    if( (instr_word[1] & 0x30 ) == 0x10 ) //op1 == 01
    {
      if( (instr_word[3] & 0xe0) == 0x0 ) //op2 == 000
        di->opcode = OP_sadd16;
      else if( (instr_word[3] & 0xe0) == 0x20 ) //op2 == 001
        di->opcode = OP_sasx;
      else if( (instr_word[3] & 0xe0) == 0x40 ) //op2 == 010
        di->opcode = OP_ssax;
      else if( (instr_word[3] & 0xe0) == 0x60 ) //op2 == 011
        di->opcode = OP_ssub16;
      else if( (instr_word[3] & 0xe0) == 0x80 ) //op2 == 100 
        di->opcode = OP_sadd8;
      else if( (instr_word[3] & 0xe0) == 0xe0 ) //op2 == 111 
        di->opcode = OP_ssub8;
    }
    else if( (instr_word[1] & 0x30 ) == 0x20 ) //op1 == 10
    {
      if( (instr_word[3] & 0xe0) == 0x0 ) //op2 == 000
        di->opcode = OP_qadd16;
      else if( (instr_word[3] & 0xe0) == 0x20 ) //op2 == 001
        di->opcode = OP_qasx;
      else if( (instr_word[3] & 0xe0) == 0x40 ) //op2 == 010
        di->opcode = OP_qsax;
      else if( (instr_word[3] & 0xe0) == 0x60 ) //op2 == 011
        di->opcode = OP_qsub16;
      else if( (instr_word[3] & 0xe0) == 0x80 ) //op2 == 100 
        di->opcode = OP_qadd8;
      else if( (instr_word[3] & 0xe0) == 0xe0 ) //op2 == 111 
        di->opcode = OP_qsub8;
    }
    else if( (instr_word[1] & 0x30 ) == 0x30 ) //op1 == 11
    {
      if( (instr_word[3] & 0xe0) == 0x0 ) //op2 == 000
        di->opcode = OP_shadd16;
      else if( (instr_word[3] & 0xe0) == 0x20 ) //op2 == 001
        //di->opcode = OP_shasx; SJF Missing opcode
        di->opcode = OP_UNDECODED;
      else if( (instr_word[3] & 0xe0) == 0x40 ) //op2 == 010
        di->opcode = OP_shsax;
      else if( (instr_word[3] & 0xe0) == 0x60 ) //op2 == 011
        di->opcode = OP_shsub16;
      else if( (instr_word[3] & 0xe0) == 0x80 ) //op2 == 100 
        di->opcode = OP_shadd8;
      else if( (instr_word[3] & 0xe0) == 0xe0 ) //op2 == 111 
        di->opcode = OP_shsub8;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ));

    return op_instr[di->opcode];

}

instr_info_t* decode_signed_mul(byte* instr_word,
                                decode_info_t* di, bool just_opcode,
                                opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    // | cond | 011 10 | op1 |    |  A   |    | op2 | 1 |       |
    int encoding;

    if( (instr_word[1] & 0x70) == 0x0 ) //op1 == 000
    {
      if( (instr_word[3] & 0xc0) == 0x0) //op2 == 00x
      {
        if( (instr_word[2] & 0xf0) == 0xf0 ) //A == 1111
        {
          di->opcode = OP_smuad;
          if( (instr_word[3] & 0x10) == 0x10 )
            di->m_flag = true;
          else
            di->m_flag = false;
        }
        else
        {
          di->opcode = OP_smlad;
          if( (instr_word[3] & 0x10) == 0x10 )
            di->m_flag = true;
          else
            di->m_flag = false;

        }
      }
      else if( (instr_word[3] & 0xc0) == 0x40) //op2 == 01x
      {
        if( (instr_word[2] & 0xf0) == 0xf0 ) //A == 1111
        {
          di->opcode = OP_smusd;
          if( (instr_word[3] & 0x10) == 0x10 )
            di->m_flag = true;
          else
            di->m_flag = false;
        }
        else
        {
          di->opcode = OP_smlsd;
          if( (instr_word[3] & 0x10) == 0x10 )
            di->m_flag = true;
          else
            di->m_flag = false;

        }
      }
    }
    else if( (instr_word[1] & 0x70) == 0x40 ) //op1 == 100
    {
      if( (instr_word[3] & 0xc0) == 0x0) //op2 == 00x
      {
          di->opcode = OP_smlald;
          if( (instr_word[3] & 0x10) == 0x10 )
            di->m_flag = true;
          else
            di->m_flag = false;

      }
      else if( (instr_word[3] & 0xc0) == 0x40) //op2 == 01x
      {
          di->opcode = OP_smlsld;
          if( (instr_word[3] & 0x10) == 0x10 )
            di->m_flag = true;
          else
            di->m_flag = false;
      }
    }
    else if( (instr_word[1] & 0x70) == 0x50 ) //op1 == 101
    {
      if( (instr_word[3] & 0xc0) == 0x0) //op2 == 00x
      {
        if( (instr_word[2] & 0xf0) == 0xf0 ) //A == 1111
        {
          di->opcode = OP_smmul;
          if( (instr_word[3] & 0x10) == 0x10 )
            di->r_flag = true;
          else
            di->r_flag = false;
        }
        else
        {
          di->opcode = OP_smmla;
          if( (instr_word[3] & 0x10) == 0x10 )
            di->r_flag = true;
          else
            di->r_flag = false;

        }
      }
      else if( (instr_word[3] & 0xc0) == 0xc0) //op2 == 11x
      {
          di->opcode = OP_smmls;
          if( (instr_word[3] & 0x10) == 0x10 )
            di->r_flag = true;
          else
            di->r_flag = false;
      }
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ) );

    return op_instr[di->opcode];

}


instr_info_t* decode_parallel_pack_unpack(byte* instr_word,
                                           decode_info_t* di, bool just_opcode,
                                           opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    // | cond | 011 01 | op1 |  A  |     | op2 | 1 |       |
    int encoding;

    if( (instr_word[1] & 0x70) == 0x0 ) //op1 == 000
    {
      if( (instr_word[3] & 0x20) == 0x0) //op2 == xx0
      {
        di->opcode = OP_pkh;
        //TODO Set tb? bit here
      }
      else if( (instr_word[3] & 0xe0) == 0x60) //op2 == 011 
      {
        if( (instr_word[1] & 0xf) == 0xf)
          //di->opcode = OP_sxtb16; SJF Missing opcode
          di->opcode = OP_UNDECODED;
        else
          di->opcode = OP_sxtab16;
      }
      else if( (instr_word[3] & 0xe0) == 0xa0) //op2 == 101 
      {
        di->opcode = OP_UNDECODED;
        //di->opcode = OP_sxtb; SJF Missing opcode
      }
    }
    else if( (instr_word[1] & 0x60) == 0x20 ) //op1 == 01x
    {
      if( (instr_word[3] & 0x20) == 0x0) //op2 == xx0
      {
        di->opcode = OP_ssat;
        //TODO Set sat bits
      }
      else if( ((instr_word[1] & 0x70) == 0x20 )) //op1 == 010
      {
        if( (instr_word[3] & 0xe0) == 0x20) //op2 == 001 
        {
          di->opcode = OP_ssat16; 
        }
        else if( (instr_word[3] & 0xe0) == 0x20) //op2 == 011 
        {
          if( (instr_word[1] & 0xf) == 0xf)
            //di->opcode = OP_sxtb; SJF Missing opcode
            di->opcode = OP_UNDECODED;
          else
            di->opcode = OP_sxtab;
        }
      }
      else if( ((instr_word[1] & 0x70) == 0x30 )) //op1 == 011
      {
        if( (instr_word[3] & 0xe0) == 0x20) //op2 == 001 
        {
          di->opcode = OP_rev;
        }
        else if( (instr_word[3] & 0xe0) == 0x20) //op2 == 011 
        {
          if( (instr_word[1] & 0xf) == 0xf)
            di->opcode = OP_UNDECODED;
            //di->opcode = OP_sxth; SJF Missing opcode
          else
            di->opcode = OP_sxtah;
        }
        else if( (instr_word[3] & 0xe0) == 0xa0) //op2 == 101 
        {
          di->opcode = OP_rev16;
        }
      }
    }
    else if( (instr_word[1] & 0x70) == 0x40 ) //op1 == 100
    {
      if( (instr_word[3] & 0xe0) == 0x20) //op2 == 011 
      {
        if( (instr_word[1] & 0xf) == 0xf)
          di->opcode = OP_uxtb16;
        else
          di->opcode = OP_uxtab16;
      }
    }
    else if( (instr_word[1] & 0x60) == 0x60 ) //op1 == 11x
    {
      if( (instr_word[3] & 0x20) == 0x0) //op2 == xx0
      {
        di->opcode = OP_usat;
        //TODO Set sat bits
      }
      else if( (instr_word[1] & 0x70) == 0x60 ) //op1 == 110
      {
        if( (instr_word[3] & 0xe0) == 0x20) //op2 == 001
        {
          di->opcode = OP_usat16;
        }
        else if( (instr_word[3] & 0xe0) == 0x60) //op2 == 011
        {
          if( (instr_word[1] & 0xf) == 0xf)
            di->opcode = OP_uxtb;
          else
            di->opcode = OP_uxtab;
        }
      }
      else if( (instr_word[1] & 0x70) == 0x70 ) //op1 == 111
      {
        if( (instr_word[3] & 0xe0) == 0x20) //op2 == 001
        {
          di->opcode = OP_rbit;
        }
        else if( (instr_word[3] & 0xe0) == 0x60) //op2 == 011
        {
          if( (instr_word[1] & 0xf) == 0xf)
            di->opcode = OP_uxth;
          else
            di->opcode = OP_uxtah;
        }
        else if( (instr_word[3] & 0xe0) == 0xa0) //op2 == 101
        {
          di->opcode = OP_revsh;
        }
      }
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ) );

    return op_instr[di->opcode];

}

instr_info_t* decode_media(byte* instr_word,
                            decode_info_t* di, bool just_opcode,
                            opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    // | cond | 011 | op1 |     | Rd |      | op2  | 1 | Rn |
    instr_info_t *info = NULL;
    int encoding;

    if( (instr_word[0] & 0x1 ) == 0  &&
        (instr_word[1] & 0xc0) == 0 ) //op1 == 000xx
    {
      return decode_parallel_signed_arith(instr_word, di, just_opcode,
                                          dsts, srcs, numdsts, numsrcs);
    }
    else if( (instr_word[0] & 0x1 ) == 0  &&
             (instr_word[1] & 0xc0) == 0x40 ) //op1 == 001xx
    {
      return decode_parallel_unsigned_arith(instr_word, di, just_opcode,
                                            dsts, srcs, numdsts, numsrcs);
    }
    else if( (instr_word[0] & 0x1 ) == 0  &&
             (instr_word[1] & 0x80) == 0x80 ) //op1 == 01xxx
    {
      return decode_parallel_pack_unpack(instr_word, di, just_opcode,
                                         dsts, srcs, numdsts, numsrcs);
    }
    else if( (instr_word[0] & 0x1 ) == 1  &&
             (instr_word[1] & 0x80) == 0x0 ) //op1 == 10xxx
    {
      return decode_signed_mul(instr_word, di, just_opcode,
                               dsts, srcs, numdsts, numsrcs);
    }
    else if( (instr_word[0] & 0x1 ) == 1 &&     //op1 == 11000
             (instr_word[1] & 0xf0) == 0x80 )
    {
      if( (instr_word[2] & 0xf0) == 0xf0 )
        di->opcode = OP_usad8;
      else
        di->opcode = OP_usada8;
    }
    else if( (instr_word[0] & 0x1 ) == 1  &&
             (instr_word[1] & 0xe0) == 0xa0 ) //op1 == 1101x 
    {
      if( (instr_word[3] & 0x60) == 0x40 )    //op2 == x10
        di->opcode = OP_sbfx;
    }
    else if( (instr_word[0] & 0x1 ) == 1  &&
             (instr_word[1] & 0xe0) == 0xc0 ) //op1 == 1110x 
    {
      if( (instr_word[3] & 0x60) == 0x0 )     //op2 == x00
      {
        if( (instr_word[2] & 0xf0) == 0xf0 )
          di->opcode = OP_bfc;
        else
          di->opcode = OP_bfi;
      }
    }
    else if( (instr_word[0] & 0x1 ) == 1  &&
             (instr_word[1] & 0xe0) == 0xe0 ) //op1 == 1111x 
    {
      if( (instr_word[3] & 0x60) == 0x40 )     //op2 == x10
        di->opcode = OP_ubfx;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ) );

    return op_instr[di->opcode];
}

instr_info_t* decode_system_call_and_coprocessor(byte* instr_word,
                            decode_info_t* di, bool just_opcode,
                            opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs)
{
    // | cond | 11 | op1 | Rn |      | coproc  |    | op |    |
    instr_info_t *info = NULL;
    int encoding;

    if( ((instr_word[0] & 0x3 ) == 0 ) &&
        (((instr_word[0] & 0x3  ) != 0 ) ||
         ((instr_word[1] & 0xa0 ) != 0 )))//op1 == 0xxxxx not 000x0x
    {
      if(( instr_word[2] & 0xe ) == 0xa )
      {
        //return decode_ext_reg_load_store
      }
    }
    else if( ((instr_word[0] & 0x3 ) == 0  &&
              (instr_word[1] & 0x10) == 0 ) &&
             (((instr_word[0] & 0x3  ) != 0 ) ||
              ((instr_word[1] & 0xa0 ) != 0 )) )//op1 == 0xxxx0 not 000x0x
    {
      if(( instr_word[2] & 0xe ) != 0xa )
      {
        di->opcode = OP_stc;
      }
    }
    else if( ((instr_word[0] & 0x3 ) == 0  &&
              (instr_word[1] & 0x10) == 0x10 ) &&
             (((instr_word[0] & 0x3  ) != 0 ) ||
              ((instr_word[1] & 0xa0 ) != 0 )) )//op1 == 0xxxx1 not 000x0x
    {
      if(( instr_word[2] & 0xe ) != 0xa )
      {
        if( (instr_word[1] & 0xf) == 0xf )
          di->opcode = OP_ldc_lit;
        else
          di->opcode = OP_ldc_imm;
      }
    }
    else if( (instr_word[0] & 0x3 ) == 0  && //op1 == 00000x
             (instr_word[1] & 0xe0) == 0x40 )
    {
      if(( instr_word[2] & 0xe ) == 0xa )
      {
        //return decode_64_bit_transfers
      }
    }
    else if( (instr_word[0] & 0x3 ) == 0  &&  //op1 == 00010x
             (instr_word[1] & 0xe0) == 0x40 ) 
    {
      if(( instr_word[2] & 0xe ) == 0xa )
      {
        //return decode_64_bit_transfers
      }
    }
    else if( (instr_word[0] & 0x3 ) == 0  &&  //op1 == 000100
             (instr_word[1] & 0xf0) == 0x40 )
    {
      if(( instr_word[2] & 0xe ) != 0xa )
      {
        if( (instr_word[0] & 0xf0) == 0xf0 )
          di->opcode = OP_mcrr2;
        else
          di->opcode = OP_mcrr;
      }
    }
    else if( (instr_word[0] & 0x3 ) == 0  &&  //op1 == 000101
             (instr_word[1] & 0xf0) == 0x50 )
    {
      if(( instr_word[2] & 0xe ) != 0xa )
      {
        if( (instr_word[0] & 0xf0) == 0xf0 )
          di->opcode = OP_mrrc2;
        else
          di->opcode = OP_mrrc;
      }
    }
    else if( (instr_word[0] & 0x3 ) == 0x2 ) //op1 == 10xxxx
    {
      if(( instr_word[3] & 0x10 ) == 0x0 ) //op == 0
      {
        if(( instr_word[2] & 0xe ) == 0xa ) //coproc == 101x
        {
          //return decode_vfp_data_processing
        }
        else //coproc != 101x
          di->opcode = OP_cdp;
      }
      else //op == 1
      {
        if(( instr_word[2] & 0xe ) == 0xa ) //coproc == 101x
        {
          //return decode_advanced_simd
        }
      }
    }
    else if( (instr_word[0] & 0x3 ) == 0x2 &&
             (instr_word[1] & 0x10) == 0x0) //op1 == 10xxx0
    {
      if(( instr_word[3] & 0x10 ) == 0x10 ) //op == 1
      {
        if(( instr_word[2] & 0xe ) != 0xa ) //coproc != 101x
        {
          di->opcode = OP_mcr;
        }
      }
    }
    else if( (instr_word[0] & 0x3 ) == 0x2 &&
             (instr_word[1] & 0x10) == 0x10) //op1 == 10xxx1
    {
      if(( instr_word[3] & 0x10 ) == 0x10 ) //op == 1
      {
        if(( instr_word[2] & 0xe ) != 0xa ) //coproc != 101x
        {
          di->opcode = OP_mrc;
        }
      }
    }
    else if( (instr_word[0] & 0x3 ) == 0x3 ) //op1 == 11xxxx
    {
      di->opcode = OP_svc;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, NULL, opcode_is_sign_extend( di->opcode ) );

    return op_instr[di->opcode];
}


instr_info_t* decode_branch(byte* instr_word,
                            decode_info_t* di, bool just_opcode,
                            opnd_t* dsts, opnd_t* srcs, int* numdsts, int* numsrcs, byte* pc)
{
    // | cond | 10 | op |   Rn    |  R   |          |
    int encoding;

    if( (instr_word[0] & 0x3 ) == 0x0 &&
        (instr_word[1] & 0xd0) == 0x0 ) //op == 0000x0
    {
      di->opcode = OP_stmda; 
    }
    else if( (instr_word[0] & 0x3 ) == 0x0 &&
             (instr_word[1] & 0xd0) == 0x10 ) //op == 0000x1
    {
      di->opcode = OP_ldmda;
    }
    else if( (instr_word[0] & 0x3 ) == 0x0 &&
             (instr_word[1] & 0xd0) == 0x80 ) //op == 0010x0
    {
      di->opcode = OP_stmia;
    }
    else if( (instr_word[0] & 0x3 ) == 0x0 &&
             (instr_word[1] & 0xd0) == 0x90 ) //op == 0010x1
    {
      di->opcode = OP_ldmia;
    }
    else if( (instr_word[0] & 0x3 ) == 0x1 &&
             (instr_word[1] & 0xd0) == 0x0 ) //op == 0100x0
    {
      di->opcode = OP_stmdb;   //SJF Equivalent to OP_push
    }
    else if( (instr_word[0] & 0x3 ) == 0x1 &&
             (instr_word[1] & 0xd0) == 0x10 ) //op == 0100x1
    {
      di->opcode = OP_ldmdb;
    }
    else if( (instr_word[0] & 0x3 ) == 0x1 &&
             (instr_word[1] & 0xd0) == 0x80 ) //op == 0110x0
    {
      di->opcode = OP_stmib;
    }
    else if( (instr_word[0] & 0x3 ) == 0x1 &&
             (instr_word[1] & 0xd0) == 0x90 ) //op == 0110x1
    {
      di->opcode = OP_ldmib;
    }
    else if( (instr_word[0] & 0x2 ) == 0x0 &&
             (instr_word[1] & 0x50) == 0x40 ) //op == 0xx1x0
    {
      di->opcode = OP_stm;
    }
    else if( (instr_word[0] & 0x2 ) == 0x0 &&
             (instr_word[1] & 0x50) == 0x50 ) //op == 0xx1x1
    {
      di->opcode = OP_ldm;
      if( (instr_word[2] & 0x80) == 0x80)
        di->r_flag = true;
      else
        di->r_flag = false;
    }
    else if( (instr_word[0] & 0x3 ) == 0x2 )  //op == 10xxxx
    {
      di->opcode = OP_b;
    }
    else if( (instr_word[0] & 0x3 ) == 0x3 )  //op == 11xxxx
    {
      di->opcode = OP_bl;
    }

    if( di->opcode == OP_UNDECODED )
      return NULL;

    if( just_opcode )
      return op_instr[di->opcode];

    encoding = opcode_get_encoding_type( di->opcode );

    CLIENT_ASSERT( (encoding != INVALID_ENCODING),
            "decode_data_processing_register: Invalid encoding" );

    //Make sure we have somewhere to store the dsts and srcs if needed 
    ASSERT( srcs != NULL && dsts != NULL );


    decode_operands( di, encoding, instr_word,
                     dsts, srcs, numdsts, numsrcs, pc, opcode_is_sign_extend( di->opcode ) );

    return op_instr[di->opcode];
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
    byte op = 0;

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
    //Set the opcode to undecodede to check for 
    // decode success or failure
    di->opcode = OP_UNDECODED;
    
    //Read word
    instr_word[3] = (byte*)*pc;
    pc++;
    instr_word[2] = (byte*)*pc;
    pc++;
    instr_word[1] = (byte*)*pc;
    pc++;
    instr_word[0] = (byte*)*pc;
    pc++;

    //Get and store the cond code 
    di->cond = (instr_word[0] >> 4);

    //Get the instr_type from bits[27,25]
    temp = (instr_word[0] << 4);  
    temp = (temp >> 5);
    instr_type = temp;

    /* Get the op from bit[4] to allow switch to encoding type */
    op = (instr_word[3] >> 4);
    op &= 0x1;  //Only want the first bit

    if( (instr_type & 0x6) == 0 ) // 00x
          info = decode_data_processing_and_misc(instr_word, di, just_opcode, 
                                                dsts, srcs, numdsts, numsrcs); 
    else if ( ((instr_type & 0x6) == 0x2) ) //01x
          info = decode_load_store_word_and_ubyte1(instr_word, di, just_opcode,
                                                   dsts, srcs, numdsts, numsrcs); 
/*
    else if ( (instr_type == 0x3) && (op == 0))//011 0
          info = decode_load_store_word_and_ubyte2(instr_word, di, just_opcode,
                                                   dsts, srcs, numdsts, numsrcs); 
    else if ( (instr_type == 0x3) && (op == 1))//011 1
          info = decode_media(instr_word, di, just_opcode, 
                              dsts, srcs, numdsts, numsrcs); 
*/
    else if ( (instr_type & 0x6) == 0x4) //10x
          info = decode_branch(instr_word, di, just_opcode,
                               dsts, srcs, numdsts, numsrcs, pc-4); 
    else if ( (instr_type & 0x6) == 0x6) //11x
          info = decode_system_call_and_coprocessor(instr_word, di, just_opcode, 
                                                    dsts, srcs, numdsts, numsrcs); 

    else
          CLIENT_ASSERT(false, "decode.c:read_instruction: invalid instruction read" );

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
    IF_X64(di.x86_mode = instr_get_x86_mode(instr));
    /* when pass true to read_instruction it doesn't decode immeds,
     * so have to call decode_next_pc, but that ends up being faster
     * than decoding immeds!
     */
    read_instruction(pc, pc, &info, &di, true /* just opcode */
                     _IF_DEBUG(!TEST(INSTR_IGNORE_INVALID, instr->flags)),
                     NULL, NULL, NULL, NULL);
    sz = decode_sizeof(dcontext, pc, NULL );
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

    //SJF Copy the flags across
    instr_set_flags_from_di( instr, &di );

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

