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

/* file "instr.h" -- x86-specific instr_t definitions and utilities */

#ifndef _INSTR_H_
#define _INSTR_H_ 1

#ifdef WINDOWS
/* disabled warning for
 *   "nonstandard extension used : bit field types other than int"
 * so we can use bitfields on our now-byte-sized reg_id_t type in opnd_t.
 */
# pragma warning( disable : 4214)
#endif

/* to avoid changing all our internal REG_ constants we define this for DR itself */
#define DR_REG_ENUM_COMPATIBILITY 1

/* to avoid duplicating code we use our own exported macros */
#define DR_FAST_IR 1

/* drpreinject.dll doesn't link in instr.c so we can't include our inline
 * functions.  We want to use our inline functions for the standalone decoder
 * and everything else, so we single out drpreinject.
 */
#ifdef RC_IS_PRELOAD
# undef DR_FAST_IR
#endif

/* can't include decode.h, it includes us, just declare struct */
struct instr_info_t;

/* The machine-specific IR consists of instruction lists,
   instructions, and operands.  You can find the instrlist_t stuff in
   the upper-level directory (shared infrastructure).  The
   declarations and interface functions (which insulate the system
   from the specifics of each constructs implementation) for opnd_t and
   instr_t appear below. */


/*************************
 ***       opnd_t        ***
 *************************/

/* DR_API EXPORT TOFILE dr_ir_opnd.h */
/* DR_API EXPORT BEGIN */
/****************************************************************************
 * OPERAND ROUTINES
 */
/**
 * @file dr_ir_opnd.h
 * @brief Functions and defines to create and manipulate instruction operands.
 */

/* DR_API EXPORT END */
/* DR_API EXPORT VERBATIM */
/* Catch conflicts if ucontext.h is included before us */
#if defined(DR_REG_ENUM_COMPATIBILITY) && (defined(REG_EAX) || defined(REG_RAX))
# error REG_ enum conflict between DR and ucontext.h!  Use DR_REG_ constants instead.
#endif
/* DR_API EXPORT END */

/* If INSTR_INLINE is already defined, that means we've been included by
 * instr.c, which wants to use C99 extern inline.  Otherwise, DR_FAST_IR
 * determines whether our instr routines are inlined.
 */
/* DR_API EXPORT BEGIN */
/* Inlining macro controls. */
#ifndef INSTR_INLINE
# ifdef DR_FAST_IR
#  define INSTR_INLINE inline
# else
#  define INSTR_INLINE
# endif
#endif

/* Enum to store the type of the instruction */
enum
{
  INSTR_TYPE_UNDECODED = 0,

  INSTR_TYPE_DATA_PROCESSING_AND_ELS, //and extra load/store instructions
  INSTR_TYPE_DATA_PROCESSING_IMM,
  INSTR_TYPE_LOAD_STORE1,
  INSTR_TYPE_LOAD_STORE2_AND_MEDIA,
  INSTR_TYPE_LOAD_STORE_MULTIPLE,
  INSTR_TYPE_BRANCH,
  INSTR_TYPE_COPROCESSOR_DATA_MOVEMENT,
  INSTR_TYPE_ADVANCED_COPROCESSOR_AND_SYSCALL,

  INSTR_TYPE_INVALID
}; 

enum
{
  MASK_UNDEFINED = 0,

  MASK_WRITE_NSCVQ_FLAGS,
  MASK_WRITE_G_FLAG,
  MASK_WRITE_ALL,
 
  MASK_INVALID
};

enum
{
  COND_EQUAL = 0,
  COND_NOT_EQUAL,
  COND_CARRY_SET,
  COND_CARRY_CLEAR,
  COND_MINUS,
  COND_PLUS,
  COND_OVERFLOW,
  COND_NO_OVERFLOW,
  COND_HIGHER,
  COND_LOWER_OR_SAME,
  COND_SIGNED_GREATER_THAN_OR_EQUAL,
  COND_SIGNED_LESS_THAN,
  COND_SIGNED_GREATER_THAN,
  COND_SIGNED_LESS_THAN_OR_EQUAL,
  COND_ALWAYS,

  COND_INVALID
};

#ifdef AVOID_API_EXPORT
/* We encode this enum plus the OPSZ_ extensions in bytes, so we can have
 * at most 256 total DR_REG_ plus OPSZ_ values.  Currently there are 165-odd.
 * Decoder assumes 32-bit, 16-bit, and 8-bit are in specific order
 * corresponding to modrm encodings.
 * We also assume that the DR_SEG_ constants are invalid as pointers for
 * our use in instr_info_t.code.
 * Also, reg_names array in encode.c corresponds to this enum order.
 * Plus, dr_reg_fixer array in instr.c.
 * Lots of optimizations assume same ordering of registers among
 * 32, 16, and 8  i.e. eax same position (first) in each etc.
 * reg_rm_selectable() assumes the GPR registers, mmx, and xmm are all in a row.
 */
#endif
enum {
#ifdef AVOID_API_EXPORT
    /* compiler gives weird errors for "REG_NONE" */
    /* PR 227381: genapi.pl auto-inserts doxygen comments for lines without any! */
#endif
    DR_REG_NULL, /**< Sentinel value indicating no register, for address modes. */

    /* Standard 32 bit ARM registers */
    DR_REG_R0,          DR_REG_R1,      DR_REG_R2,      DR_REG_R3,
    DR_REG_R4,          DR_REG_R5,      DR_REG_R6,      DR_REG_R7,
    DR_REG_R8,          DR_REG_R9,      DR_REG_R10,     DR_REG_R11,
    DR_REG_R12,         DR_REG_R13,     DR_REG_R14,     DR_REG_R15,

    /* All the neon/vfp registers below refer to the same registers but
       depending on the mode, different views are available. */
    /* NEON/VFPv3 16 * 128bit(quadword) shared registers */
    DR_REG_Q0,          DR_REG_Q1,      DR_REG_Q2,      DR_REG_Q3,
    DR_REG_Q4,          DR_REG_Q5,      DR_REG_Q6,      DR_REG_Q7,
    DR_REG_Q8,          DR_REG_Q9,      DR_REG_Q10,     DR_REG_Q11,
    DR_REG_Q12,         DR_REG_Q13,     DR_REG_Q14,     DR_REG_Q15,
 
    /* NEON/VFPv3 32 * 64bit(doubleword) shared registers */ 
    DR_REG_D0,          DR_REG_D1,      DR_REG_D2,      DR_REG_D3,
    DR_REG_D4,          DR_REG_D5,      DR_REG_D6,      DR_REG_D7,
    DR_REG_D8,          DR_REG_D9,      DR_REG_D10,     DR_REG_D11,
    DR_REG_D12,         DR_REG_D13,     DR_REG_D14,     DR_REG_D15,
    DR_REG_D16,         DR_REG_D17,     DR_REG_D18,     DR_REG_D19,
    DR_REG_D20,         DR_REG_D21,     DR_REG_D22,     DR_REG_D23,
    DR_REG_D24,         DR_REG_D25,     DR_REG_D26,     DR_REG_D27,
    DR_REG_D28,         DR_REG_D29,     DR_REG_D30,     DR_REG_D31,

    /* NEON/VFPv3 32 * 32bit(singleword) shared registers */ 
    DR_REG_S0,          DR_REG_S1,      DR_REG_S2,      DR_REG_S3,
    DR_REG_S4,          DR_REG_S5,      DR_REG_S6,      DR_REG_S7,
    DR_REG_S8,          DR_REG_S9,      DR_REG_S10,     DR_REG_S11,
    DR_REG_S12,         DR_REG_S13,     DR_REG_S14,     DR_REG_S15,
    DR_REG_S16,         DR_REG_S17,     DR_REG_S18,     DR_REG_S19,
    DR_REG_S20,         DR_REG_S21,     DR_REG_S22,     DR_REG_S23,
    DR_REG_S24,         DR_REG_S25,     DR_REG_S26,     DR_REG_S27,
    DR_REG_S28,         DR_REG_S29,     DR_REG_S30,     DR_REG_S31,

    DR_REG_INVALID, /**< Sentinel value indicating an invalid register. */

    /* segments (order from "Sreg" description in Intel manual) */
    DR_SEG_ES,   DR_SEG_CS,   DR_SEG_SS,   DR_SEG_DS,   DR_SEG_FS,   DR_SEG_GS,

    /*  SJF TODO Fake debug and control regs */
    DR_REG_DEBUG1,  DR_REG_DEBUG2, 
    DR_REG_CONTROL1,  DR_REG_CONTROL2, 

    DR_REG_CPSR,

#ifdef NO // TODO SJF Remove the debug regs for now.
    /* Coprocessor registers from the ARM tech manual ??? Is this right. All for CP15 */
    /* TODO Maybe rearrange these to group by function instead of location */
    /* c0 registers */
    DR_REG_MIDR,        DR_REG_CTR,     DR_REG_TCMTR,   DR_REG_TLBTR,
    DR_REG_MIDRA,       DR_REG_MPIDR,   DR_REG_REVIDR,  DR_REG_ID_PFR0,
    DR_REG_PFR1,        DR_REG_DFR0,    DR_REG_AFR0,    DR_REG_MMFR0,
    DR_REG_MMFR1,       DR_REG_MMFR2,   DR_REG_MMFR3,   DR_REG_ISAR0,  
    DR_REG_ISAR1,       DR_REG_ISAR2,   DR_REG_ISAR3,   DR_REF_ISAR4,      
    DR_REG_ISAR5,       DR_REG_CCSIDR,  DR_REG_CLIDR,   DR_REG_AIDR,       
    DR_REG_CSSELR,      DR_REG_VPIDR,   DR_REGVMPIDR,

    /* c1 registers */
    DR_REG_SCTLR,       DR_REG_ACTLR,   DR_REG_CPACR,   DR_REG_SCR,
    DR_REG_SDER,        DR_REG_NSACR,   DR_REG_HSCTLR,  DR_REG_HACTLR,
    DR_REG_HCR,         DR_REG_HDCR,    DR_REG_HCPTR,   DR_REG_HSTR,
    DR_REG_HACR,

    /* c2 registers */
    DR_REG_TTBR0,       DR_REG_TTBR1,   DR_REG_TTBCR,   DR_REG_HTCR,
    DR_REG_VTCR,

    /* c3 registers */
    DR_REG_DACR,

    /* c5 registers */
    DR_REG_DFSR,        DR_REG_IFSR,    DR_REG_ADFSR,   DR_REG_AIFSR,
    DR_REG_HADFSR,      DR_REG_HAIFSR,  DR_REG_HSR,

    /* c6 registers */
    DR_REG_DFAR,        DR_REG_IFAR,    DR_REG_HDFAR,   DR_REG_HIFAR,
    DR_REG_HPFAR,

    /* c7 registers */
    DR_REG_NOP,       DR_REG_ICIALLUIS, DR_REG_BPIALLIS, DR_REG_PAR,
    DR_REG_ICIALLU,   DR_REG_ICIMVAU,   DR_REG_CP15ISB, DR_REG_BPIALL,
    DR_REG_BPIMVA,      DR_REG_DCIMVAC, DR_REG_DCISW,   DR_REG_ATS1CPR,
    DR_REG_ATS1CPW,     DR_REG_ATS1CUR, DR_REG_ATS1CUW, DR_REG_ATS12NSOPR,
    DR_REG_ATS12NOSPW,  DR_REG_ATS12NSOUR,DR_REG_ATS12NSOUW, DR_REG_DCCMVAC,
    DR_REG_DCCSW,       DR_REG_CP15DSB, DR_REG_CP15DMB, DR_REG_DCCMVAU,
    DR_REG_NOP2,        DR_REG_DCCIMVAC, DR_REG_DCCISW, DR_REG_ATS1HR,
    DR_REG_ATS1HW,

    /* c8 registers */
    DR_REG_TLBIALLIS,   DR_REG_TLBIMVAIS,DR_REG_TLBIASIDIS, DR_REG_TLBIMVAAIS,
    DR_REG_ITLBIALL,    DR_REG_ITLBIMVA, DR_REG_ITLBIASID, DR_REG_DTLBIALL,
    DR_REG_DTLBIMVA,    DR_REG_DTLBIASID,DR_REG_TLBIALL,DR_REG_TLBIMVA,
    DR_REG_TLBBIASID,   DR_REG_TLBIMVAA, DR_REG_TLBIALLHIS, DR_REG_TLBIMVAHIS,
    DR_REG_TLBIALLNSNHIS,DR_REG_TLBIALLH,DR_REG_TLBIMVAH,DR_REG_TLBIALLNSNH,

    /* c9 registers */
    DR_REG_PMCR,        DR_REG_PMNCNTENSET,DR_REG_PMNCNTENCLR,DR_REG_PMOVSR,
    DR_REG_PMSWINC,     DR_REG_PMSELR,     DR_REG_PMCEID0,    DR_REG_PMCEID1,
    DR_REG_PMCCNTR,     DR_REG_PMXEVTYPER, DR_REG_PMXEVCNTR,  DR_REG_PMUSERENR,
    DR_REG_PMINTENSET,  DR_REG_PMINTENCLR, DR_REG_PMOVSSET,   DR_REG_L2CTR,
    DR_REG_L2ECTLR,

    /* c10 registers */
    DR_REG_PRRR,        DR_REG_MAIR0,   DR_REG_NMRR,    DR_REG_MAIR1,
    DR_REG_AMAIR0,      DR_REG_AMAIR1,  DR_REG_HMAIR0,  DR_REG_HMAIR1,
    DR_REG_HAMAIR0,     DR_REG_HAMAIR1,

    /* c12 registers */
    DR_REG_VBAR,        DR_REG_MVBAR,   DR_REG_ISR,     DR_REG_HVBAR,

    /* c13 registers */
    DR_REG_FCSEIDR,     DR_REG_CONTEXTIDR,DR_REG_TPIDRURW,DR_REG_TPIDRURO,
    DR_REG_TPIDRPRW,    DR_REG_HTPIDR,

    /* c14/generic timer registers */
    DR_REG_CNTFRQ,      DR_REG_CNTPCT,  DR_REG_CNTKCTL, DR_REG_CNTP_TVAL,
    DR_REG_CNTP_CTL,    DR_REG_CNTV_TVAL,DR_REG_CNTV_CTL,DR_REG_CNTVCT,
    DR_REG_CNTP_CVAL,   DR_REG_CNTV_CVAL,DR_REG_CNTVOFF, DR_REG_CNTHCTL,
    DR_REG_CNTHP_TVAL,  DR_REG_CNTHP_CTL, DR_REG_CNTHP_CVAL, 

    /* c15 registers */
    DR_REG_IL1DATA0,    DR_REG_IL1DATA1, DR_REG_IL1DATA2, DR_REG_DL1DATA0,
    DR_REG_DL1DATA1,    DR_REG_DL1DATA2, DR_REG_DLDATA3,  DR_REG_RAMINDEX,
    DR_REG_L2ACTLR,     DR_REG_L2PFR,    DR_REG_ACTLR2,   DR_REG_CBAR,

    /* Debug registers for CP14 */
    DR_REG_DBGDIDR,     DR_REG_DBGWFAR, DR_REG_DBGVCR,  DR_REG_DBGECR,
    DR_REG_DBGDTRRXE,   DR_REG_DBGITR,  DR_REG_DBGDSCRE,DR_REG_DBGDTRTXE,     
    DR_REG_DBGDRCR,     DR_REG_DBGEACR, DR_REG_DBGPCSR, DR_REG_DBGCIDSR,    
    DR_REG_DBGVIDSR,    DR_REG_DBGBVR0, DR_REG_DBGBVR1, DR_REG_DBGBVR2, 
    DR_REG_DBGBVR3,     DR_REG_DBGBVR4, DR_REG_DBGBVR5, DR_REG_DBGBCR0, 
    DR_REG_DBGBCR1,     DR_REG_DBGBCR2, DR_REG_DBGBCR3, DR_REG_DBGBCR4, 
    DR_REG_DBGBCR5,     DR_REG_DBGWVR0, DR_REG_DBGWVR1, DR_REG_DBGWVR2, 
    DR_REG_DBGWVR3,     DR_REG_DBGWCR0, DR_REG_DBGWCR1, DR_REG_DBGWCR2,
    DR_REG_DBGWCR3,     DR_REG_DBGXVR4, DR_REG_DBGXVR5, DR_REG_DBGOSLAR,
    DR_REG_DBGOSLSR,    DR_REG_DBGPRCR, DR_REG_DBGPRSR,
    /* TODO Add processor id registers */
    DR_REG_DBGITOCTRL,  DR_REG_DBGITISR,DR_REG_DBGITCTRL,DR_REG_DBGCLAIMSET,
    DR_REG_DBGCLAIMCLR, DR_REG_DBGLAR,  DR_REG_DBGLSR, DR_REG_DBGAUTHSTATUS,
    DR_REG_DBGDEVID2,   DR_REG_DBGDEVID1,DR_REG_DBGDEVID, DR_REG_DBGDEVTYPE,
    DR_REG_DBGPID4,     DR_REG_DBGPID5, DR_REG_DBGPID6, DR_REG_DBGPID7,
    DR_REG_DBGPID0,     DR_REG_DBGPID1, DR_REG_DBGPID2, DR_REG_DBGPID3,
    DR_REG_DBGCID0,     DR_REG_DBGCID1, DR_REG_DBGCID2, DR_REG_DBGCID3,
    DR_REG_DBGDSCRI,    DR_REG_DBGDTRRXI,DR_REG_DBGDTRTXI,DR_REG_DBGDRAR, 
    DR_REG_DBGOSDLR,    DR_REG_DBGDSAR,
#endif //NO


#ifdef AVOID_API_EXPORT
    /* Below here overlaps with OPSZ_ enum but all cases where the two
     * are used in the same field (instr_info_t operand sizes) have the type
     * and distinguish properly.
     */
#endif
};

/* we avoid typedef-ing the enum, as its storage size is compiler-specific */
#define REGLIST_R0   0x1
#define REGLIST_R1   0x2
#define REGLIST_R2   0x4
#define REGLIST_R3   0x8
#define REGLIST_R4   0x10
#define REGLIST_R5   0x20
#define REGLIST_R6   0x40
#define REGLIST_R7   0x80
#define REGLIST_R8   0x100
#define REGLIST_R9   0x200
#define REGLIST_R10  0x400
#define REGLIST_R11  0x800
#define REGLIST_R12  0x1000
#define REGLIST_R13  0x2000
#define REGLIST_R14  0x4000
#define REGLIST_R15  0x8000

/* TODO SJF Changed back to byte again as increase of instr_t struct was causing issues.
            I dont think I need all the debug regs anyway so a byte should be good enough */
typedef byte reg_id_t; /* contains a DR_REG_ enum value */
typedef int  reg_list_t; /* contains mask of regs 16 bits long */
/* Changed this to an int as a byte is too small to store all the new registers.
   TODO This may need changing back depending on whether my values in DR_REG_XXX 
        are correct or not */
typedef byte  opnd_size_t; /* contains a DR_REG_ or OPSZ_ enum value */

/* DR_API EXPORT END */
/* indexed by enum */
extern const char * const reg_names[];
extern const reg_id_t dr_reg_fixer[];
/* DR_API EXPORT BEGIN */

#define DR_REG_START_GPR DR_REG_R0 /**< Start of general register enum values */
# define DR_REG_STOP_GPR DR_REG_R14 /**< End of general register enum values */

/**< Number of general registers */
#define DR_NUM_GPR_REGS (DR_REG_STOP_GPR - DR_REG_START_GPR)
#define DR_REG_START_64    DR_REG_D0  /**< Start of 32-bit general register enum values */
#define DR_REG_STOP_64     DR_REG_D31 /**< End of 32-bit general register enum values */  
#define DR_REG_START_32    DR_REG_NULL /**< Start of 32-bit general register enum values */
#define DR_REG_STOP_32     DR_REG_R15 /**< End of 32-bit general register enum values */  
#define DR_REG_START_16    DR_REG_R0   /**< Start of 16-bit general register enum values */
#define DR_REG_STOP_16     DR_REG_R15 /**< End of 16-bit general register enum values */  
#define DR_REG_START_FLOAT DR_REG_Q0  /**< Start of floating-point-register enum values */
#define DR_REG_STOP_FLOAT  DR_REG_S31  /**< End of floating-point-register enum values */  
#define DR_REG_START_SEGMENT DR_SEG_ES /**< Start of segment register enum values */
#define DR_REG_STOP_SEGMENT  DR_SEG_GS /**< End of segment register enum values */  
#define DR_REG_START_DR    DR_REG_DEBUG1  /**< Start of debug register enum values */
#define DR_REG_STOP_DR     DR_REG_DEBUG2 /**< End of debug register enum values */  
#define DR_REG_START_CR    DR_REG_CONTROL1  /**< Start of control register enum values */
#define DR_REG_STOP_CR     DR_REG_CONTROL2 /**< End of control register enum values */  
/* VFPv3/NEON registers */
#define DR_REG_START_QWR   DR_REG_Q0	/* Start of quad word registers */
#define DR_REG_END_QWR     DR_REG_Q15  /* End of quad word registers */
#define DR_REG_START_DWR   DR_REG_D0   /* Start of double word registers */
#define DR_REG_END_DWR     DR_REG_D31  /* End of double word registers */
#define DR_REG_START_SWR   DR_REG_S0   /* Start of single word registers */
#define DR_REG_END_SWR     DR_REG_S31  /* End of single word registers */


/**
 * Last valid register enum value.  Note: DR_REG_INVALID is now smaller 
 * than this value.
 */
#define DR_REG_LAST_VALID_ENUM  DR_REG_CPSR 
#define DR_REG_LAST_ENUM        DR_REG_CPSR /**< Last value of register enums */
#define DR_REG_LIST_MIN         0       //0000 0000 0000 0000
#define DR_REG_LIST_MAX         0xffff  //1111 1111 1111 1111
/* DR_API EXPORT END */
#define REG_START_SPILL   DR_REG_R7
#define REG_STOP_SPILL    DR_REG_R14
#define REG_SPILL_NUM     (REG_STOP_SPILL - REG_START_SPILL + 1)

/* DR_API EXPORT VERBATIM */
/* Backward compatibility with REG_ constants (we now use DR_REG_ to avoid
 * conflicts with the REG_ enum in <sys/ucontext.h>: i#34).
 * Clients should set(DynamoRIO_REG_COMPATIBILITY ON) prior to
 * configure_DynamoRIO_client() to set this define.
 */
#ifdef DR_REG_ENUM_COMPATIBILITY

# define REG_NULL            DR_REG_NULL
# define REG_RR0              DR_REG_R0
# define REG_RR1              DR_REG_R1
# define REG_RR2              DR_REG_R2
# define REG_RR3              DR_REG_R3
# define REG_RR4              DR_REG_R4
# define REG_RR5              DR_REG_R5
# define REG_RR6              DR_REG_R6
# define REG_RR7              DR_REG_R7
# define REG_RR8              DR_REG_R8
# define REG_RR9              DR_REG_R9
# define REG_RR10             DR_REG_R10
# define REG_RR11             DR_REG_R11
# define REG_RR12             DR_REG_R12
# define REG_RR13             DR_REG_R13
# define REG_RR14             DR_REG_R14
# define REG_RR15             DR_REG_R15
# define REG_Q0               DR_REG_Q0
# define REG_Q1               DR_REG_Q1
# define REG_Q2               DR_REG_Q2
# define REG_Q3               DR_REG_Q3
# define REG_Q4               DR_REG_Q4
# define REG_Q5               DR_REG_Q5
# define REG_Q6               DR_REG_Q6
# define REG_Q7               DR_REG_Q7
# define REG_Q8               DR_REG_Q8
# define REG_Q9               DR_REG_Q9
# define REG_Q10              DR_REG_Q10
# define REG_Q11              DR_REG_Q11
# define REG_Q12              DR_REG_Q12
# define REG_Q13              DR_REG_Q13
# define REG_Q14              DR_REG_Q14
# define REG_Q15              DR_REG_Q15
# define REG_D0               DR_REG_D0
# define REG_D1               DR_REG_D1
# define REG_D2               DR_REG_D2
# define REG_D3               DR_REG_D3
# define REG_D4               DR_REG_D4
# define REG_D5               DR_REG_D5
# define REG_D6               DR_REG_D6
# define REG_D7               DR_REG_D7
# define REG_D8               DR_REG_D8
# define REG_D9               DR_REG_D9
# define REG_D10              DR_REG_D10
# define REG_D11              DR_REG_D11
# define REG_D12              DR_REG_D12
# define REG_D13              DR_REG_D13
# define REG_D14              DR_REG_D14
# define REG_D15              DR_REG_D15
# define REG_D16              DR_REG_D16
# define REG_D17              DR_REG_D17
# define REG_D18              DR_REG_D18
# define REG_D19              DR_REG_D19
# define REG_D20              DR_REG_D20
# define REG_D21              DR_REG_D21
# define REG_D22              DR_REG_D22
# define REG_D23              DR_REG_D23
# define REG_D24              DR_REG_D24
# define REG_D25              DR_REG_D25
# define REG_D26              DR_REG_D26
# define REG_D27              DR_REG_D27
# define REG_D28              DR_REG_D28
# define REG_D29              DR_REG_D29
# define REG_D30              DR_REG_D30
# define REG_D31              DR_REG_D31
# define REG_D32              DR_REG_D32
# define REG_S0               DR_REG_S0
# define REG_S1               DR_REG_S1
# define REG_S2               DR_REG_S2
# define REG_S3               DR_REG_S3
# define REG_S4               DR_REG_S4
# define REG_S5               DR_REG_S5
# define REG_S6               DR_REG_S6
# define REG_S7               DR_REG_S7
# define REG_S8               DR_REG_S8
# define REG_S9               DR_REG_S9
# define REG_S10              DR_REG_S10
# define REG_S11              DR_REG_S11
# define REG_S12              DR_REG_S12
# define REG_S13              DR_REG_S13
# define REG_S14              DR_REG_S14
# define REG_S15              DR_REG_S15
# define REG_S16              DR_REG_S16
# define REG_S17              DR_REG_S17
# define REG_S18              DR_REG_S18
# define REG_S19              DR_REG_S19
# define REG_S20              DR_REG_S20
# define REG_S21              DR_REG_S21
# define REG_S22              DR_REG_S22
# define REG_S23              DR_REG_S23
# define REG_S24              DR_REG_S24
# define REG_S25              DR_REG_S25
# define REG_S26              DR_REG_S26
# define REG_S27              DR_REG_S27
# define REG_S28              DR_REG_S28
# define REG_S29              DR_REG_S29
# define REG_S30              DR_REG_S30
# define REG_S31              DR_REG_S31
# define REG_S32              DR_REG_S32
# define REG_DEBUG1           DR_REG_DEBUG1
# define REG_DEBUG2           DR_REG_DEBUG2
# define REG_CONTROL1         DR_REG_CONTROL1 
# define REG_CONTROL2         DR_REG_CONTROL2
# define REG_CPSR             DR_REG_CPSR


# define REG_INVALID         DR_REG_INVALID
# define REG_START_FLOAT     DR_REG_START_FLOAT
# define REG_STOP_FLOAT      DR_REG_STOP_FLOAT
# define REG_START_SEGMENT   DR_REG_START_SEGMENT
# define REG_STOP_SEGMENT    DR_REG_STOP_SEGMENT
# define REG_START_16        DR_REG_START_16
# define REG_STOP_16         DR_REG_STOP_16
# define REG_START_32        DR_REG_START_32
# define REG_STOP_32         DR_REG_STOP_32
# define REG_START_64        DR_REG_START_64
# define REG_STOP_64         DR_REG_STOP_64
# define REG_START_DR        DR_REG_START_DR 
# define REG_STOP_DR         DR_REG_STOP_DR
# define REG_START_CR        DR_REG_START_CR
# define REG_STOP_CR         DR_REG_STOP_CR
# define REG_START_QWR       DR_REG_Q0	
# define REG_STOP_QWR        DR_REG_Q15
# define REG_START_DWR       DR_REG_D0
# define REG_STOP_DWR        DR_REG_D31
# define REG_START_SWR       DR_REG_S0
# define REG_STOP_SWR        DR_REG_S31
# define REG_LAST_ENUM       DR_REG_LAST_ENUM

/* SJF Change the segments to offsets instead of references to non
       existent regs for ARM. This allows me to calc the offset from these values
       and just ref that memory address directly. */
# define SEG_ES		     0x26 
# define SEG_CS		     0x2e 
# define SEG_SS		     0x36 
# define SEG_DS		     0x3e 
# define SEG_FS		     0x64 
# define SEG_GS		     0x65 


#endif /* DR_REG_ENUM_COMPATIBILITY */

/* ^^^^^ SJF renamed all the R E G_Rx to R E G_RRx as compiler was 
             complaining about duplicates in ucontext.h */

/* DR_API EXPORT END */

#ifndef INT8_MIN
# define INT3_MIN   -4
# define INT3_MAX   4
# define INT4_MIN   -8
# define INT4_MAX   8
# define INT5_MIN   0 
# define INT5_MAX   32 
# define INT6_MIN   -32
# define INT6_MAX   32 
# define INT8_MIN   0 
# define INT8_MAX   256 
# define INT10_MIN  -512
# define INT10_MAX  512 
# define INT12_MIN  -2048
# define INT12_MAX  2048 
# define INT16_MIN  SHRT_MIN
# define INT16_MAX  SHRT_MAX
# define INT22_MIN  -2097152
# define INT22_MAX  2097152 
# define INT24_MIN  -8388607 
# define INT24_MAX  8388608 
# define INT26_MIN  -67108863
# define INT26_MAX  67108864
# define INT32_MIN  INT_MIN
# define INT32_MAX  INT_MAX
#endif

/* typedef is in globals.h */
/* deliberately NOT adding doxygen comments to opnd_t fields b/c users
 * should use our macros
 */
/* DR_API EXPORT BEGIN */

#ifdef DR_FAST_IR

# define REG_SPECIFIER_BITS 8
# define SCALE_SPECIFIER_BITS 4

/**
 * opnd_t type exposed for optional "fast IR" access.  Note that DynamoRIO
 * reserves the right to change this structure across releases and does
 * not guarantee binary or source compatibility when this structure's fields
 * are directly accessed.  If the OPND_ macros are used, DynamoRIO does
 * guarantee source compatibility, but not binary compatibility.  If binary
 * compatibility is desired, do not use the fast IR feature.
 */
struct _opnd_t {
    byte kind;
    /* size field only used for immed_ints and addresses
     * it holds a OPSZ_ field from decode.h 
     * we need it so we can pick the proper instruction form for
     * encoding -- an alternative would be to split all the opcodes
     * up into different data size versions.
     */
    opnd_size_t size;
    /* To avoid increasing our union beyond 64 bits, we store additional data
     * needed for x64 operand types here in the alignment padding.
     */
    union {
        ushort far_pc_seg_selector; /* FAR_PC_kind and FAR_INSTR_kind */
        /* We could fit segment in value.base_disp but more consistent here */
        reg_id_t segment : REG_SPECIFIER_BITS; /* BASE_DISP_kind, REL_ADDR_kind,
                                                * and ABS_ADDR_kind */
        ushort disp;           /* MEM_INSTR_kind */
    } seg;
    union {
        /* all are 64 bits or less */
        /* NULL_kind has no value */
        ptr_int_t immed_int;   /* IMMED_INTEGER_kind */
        float immed_float;     /* IMMED_FLOAT_kind */
        /* PR 225937: today we provide no way of specifying a 16-bit immediate
         * (encoded as a data16 prefix, which also implies a 16-bit EIP,
         * making it only useful for far pcs)
         */
        app_pc pc;             /* PC_kind and FAR_PC_kind */
        /* For FAR_PC_kind and FAR_INSTR_kind, we use pc/instr, and keep the
         * segment selector (which is NOT a DR_SEG_ constant) in far_pc_seg_selector
         * above, to save space.
         */
        instr_t *instr;         /* INSTR_kind, FAR_INSTR_kind, and MEM_INSTR_kind */
        reg_id_t reg;           /* REG_kind */
        reg_list_t reg_list;
        struct {
            int disp;
            reg_id_t base_reg : REG_SPECIFIER_BITS;
            reg_id_t index_reg : REG_SPECIFIER_BITS;
            /* to get cl to not align to 4 bytes we can't use uint here
             * when we have reg_id_t elsewhere: it won't combine them
             * (gcc will). alternative is all uint and no reg_id_t. */
            byte scale : SCALE_SPECIFIER_BITS;
            byte/*bool*/ encode_zero_disp : 1;
            byte/*bool*/ force_full_disp : 1; /* don't use 8-bit even w/ 8-bit value */
            byte/*bool*/ disp_short_addr : 1; /* 16-bit (32 in x64) addr (disp-only) */
        } base_disp;            /* BASE_DISP_kind */
        void *addr;             /* REL_ADDR_kind and ABS_ADDR_kind */
        uint mask;              /* MASK_kind */
    } value;
};
#endif /* DR_FAST_IR */
/* DR_API EXPORT END */

/* We assert that our fields are packed properly in arch_init().
 * We could use #pragma pack to shrink x64 back down to 12 bytes (it's at 16
 * b/c the struct is aligned to its max field align which is 8), but
 * probably not much gain since in either case it's passed/returned as a pointer
 * and the temp memory allocated is 16-byte aligned (on Windows; for
 * Linux it is passed in two consecutive registers I believe, but
 * still 12 bytes vs 16 makes no difference).
 */
#define EXPECTED_SIZEOF_OPND (3*sizeof(uint) IF_X64(+4/*struct size padding*/))

/* deliberately NOT adding doxygen comments b/c users should use our macros */
/* DR_API EXPORT BEGIN */
#ifdef DR_FAST_IR
/** x86 operand kinds */
enum {
    NULL_kind,
    IMMED_INTEGER_kind,
    IMMED_FLOAT_kind,
    PC_kind,
    INSTR_kind,
    REG_kind,
    REG_LIST_kind,
    MEM_REG_kind,   /* SJF Memory address stored in a register type(for str, ldr, etc...)*/
    BASE_DISP_kind, /* optional DR_SEG_ reg + base reg + scaled index reg + disp */
    FAR_PC_kind,    /* a segment is specified as a selector value */
    FAR_INSTR_kind, /* a segment is specified as a selector value */
    MEM_INSTR_kind,
    MASK_kind,
    LAST_kind,      /* sentinal; not a valid opnd kind */
};
#endif /* DR_FAST_IR */
/* DR_API EXPORT END */

/* functions to build an operand */

DR_API
INSTR_INLINE
/** Returns an empty operand. */
opnd_t 
opnd_create_null(void);

DR_API
INSTR_INLINE
/* Creates a mask operand */
opnd_t
opnd_create_mask(uint mask);


DR_API
INSTR_INLINE
/** Returns a register operand (\p r must be a DR_REG_ constant). */
opnd_t 
opnd_create_reg(reg_id_t r);

DR_API
/** 
 * Returns an immediate integer operand with value \p i and size
 * \p data_size; \p data_size must be a OPSZ_ constant.
 */
opnd_t 
opnd_create_immed_int(ptr_int_t i, opnd_size_t data_size);

DR_API
/** 
 * Returns an immediate float operand with value \p f.
 * The caller's code should use proc_save_fpstate() or be inside a
 * clean call that has requested to preserve the floating-point state.
 */
opnd_t 
opnd_create_immed_float(float f);

/* not exported */
opnd_t
opnd_create_immed_float_zero(void);

DR_API
INSTR_INLINE
/** Returns a program address operand with value \p pc. */
opnd_t 
opnd_create_pc(app_pc pc);

DR_API
/**
 * Returns a far program address operand with value \p seg_selector:pc.
 * \p seg_selector is a segment selector, not a DR_SEG_ constant.
 */
opnd_t 
opnd_create_far_pc(ushort seg_selector, app_pc pc);

DR_API
/**
 * Returns an operand whose value will be the encoded address of \p
 * instr.  This operand can be used as an immediate integer or as a
 * direct call or jump target.  Its size is always #OPSZ_PTR.
 */
opnd_t 
opnd_create_instr(instr_t *instr);

DR_API
/**
 * Returns an operand whose value will be the encoded address of \p
 * instr.  This operand can be used as an immediate integer or as a
 * direct call or jump target.  Its size is always #OPSZ_PTR.
 */
opnd_t
opnd_create_mem_reg(reg_id_t reg);


DR_API
/**
 * Returns a far instr_t pointer address with value \p seg_selector:instr.
 * \p seg_selector is a segment selector, not a DR_SEG_ constant.
 */
opnd_t 
opnd_create_far_instr(ushort seg_selector, instr_t *instr);

DR_API
/**
 * Returns a memory reference operand whose value will be the encoded
 * address of \p instr plus the 16-bit displacement \p disp.  For 32-bit
 * mode, it will be encoded just like an absolute address
 * (opnd_create_abs_addr()); for 64-bit mode, it will be encoded just
 * like a pc-relative address (opnd_create_rel_addr()). This operand
 * can be used anywhere a regular memory operand can be used.  Its
 * size is always #OPSZ_PTR.
 *
 * \note This operand will return false to opnd_is_instr(), opnd_is_rel_addr(),
 * and opnd_is_abs_addr().  It is a separate type.
 */
opnd_t
opnd_create_mem_instr(instr_t *instr, short disp, opnd_size_t data_size);

DR_API
/** 
 * Returns a memory reference operand that refers to the address:
 * - disp(base_reg, index_reg, scale)
 *
 * or, in other words,
 * - base_reg + index_reg*scale + disp
 *
 * The operand has data size data_size (must be a OPSZ_ constant).
 * Both \p base_reg and \p index_reg must be DR_REG_ constants.
 * \p scale must be either 1, 2, 4, or 8.
 */
opnd_t 
opnd_create_base_disp(reg_id_t base_reg, reg_id_t index_reg, int scale, int disp,
                      opnd_size_t data_size);

DR_API
/** 
 * Returns a memory reference operand that refers to the address:
 * - disp(base_reg, index_reg, scale)
 *
 * or, in other words,
 * - base_reg + index_reg*scale + disp
 *
 * The operand has data size \p data_size (must be a OPSZ_ constant).
 * Both \p base_reg and \p index_reg must be DR_REG_ constants.
 * \p scale must be either 1, 2, 4, or 8.
 * Gives control over encoding optimizations:
 * -# If \p encode_zero_disp, a zero value for disp will not be omitted;
 * -# If \p force_full_disp, a small value for disp will not occupy only one byte.
 * -# If \p disp_short_addr, short (16-bit for 32-bit mode, 32-bit for
 *    64-bit mode) addressing will be used (note that this normally only
 *    needs to be specified for an absolute address; otherwise, simply
 *    use the desired short registers for base and/or index).
 *
 * (Both of those are false when using opnd_create_base_disp()).
 */
opnd_t
opnd_create_base_disp_ex(reg_id_t base_reg, reg_id_t index_reg, int scale,
                         int disp, opnd_size_t size,
                         bool encode_zero_disp, bool force_full_disp,
                         bool disp_short_addr);

DR_API
/** 
 * Returns a far memory reference operand that refers to the address:
 * - seg : disp(base_reg, index_reg, scale)
 *
 * or, in other words,
 * - seg : base_reg + index_reg*scale + disp
 *
 * The operand has data size \p data_size (must be a OPSZ_ constant).
 * \p seg must be a DR_SEG_ constant.
 * Both \p base_reg and \p index_reg must be DR_REG_ constants.
 * \p scale must be either 1, 2, 4, or 8.
 */
opnd_t 
opnd_create_far_base_disp(reg_id_t seg, reg_id_t base_reg, reg_id_t index_reg, int scale,
                          int disp, opnd_size_t data_size);

DR_API
/** 
 * Returns a far memory reference operand that refers to the address:
 * - seg : disp(base_reg, index_reg, scale)
 *
 * or, in other words,
 * - seg : base_reg + index_reg*scale + disp
 *
 * The operand has data size \p data_size (must be a OPSZ_ constant).
 * \p seg must be a DR_SEG_ constant.
 * Both \p base_reg and \p index_reg must be DR_REG_ constants.
 * scale must be either 1, 2, 4, or 8.
 * Gives control over encoding optimizations:
 * -# If \p encode_zero_disp, a zero value for disp will not be omitted;
 * -# If \p force_full_disp, a small value for disp will not occupy only one byte.
 * -# If \p disp_short_addr, short (16-bit for 32-bit mode, 32-bit for
 *    64-bit mode) addressing will be used (note that this normally only
 *    needs to be specified for an absolute address; otherwise, simply
 *    use the desired short registers for base and/or index).
 *
 * (All of these are false when using opnd_create_far_base_disp()).
 */
opnd_t
opnd_create_far_base_disp_ex(reg_id_t seg, reg_id_t base_reg, reg_id_t index_reg,
                             int scale, int disp, opnd_size_t size,
                             bool encode_zero_disp, bool force_full_disp,
                             bool disp_short_addr);

DR_API
/**
 * Returns a memory reference operand that refers to the address \p addr.
 * The operand has data size \p data_size (must be a OPSZ_ constant).
 *
 * If \p addr <= 2^32 (which is always true in 32-bit mode), this routine
 * is equivalent to
 * opnd_create_base_disp(DR_REG_NULL, DR_REG_NULL, 0, (int)addr, data_size).
 *
 * Otherwise, this routine creates a separate operand type with an
 * absolute 64-bit memory address.  Such an operand can only be
 * guaranteed to be encodable in absolute form as a load or store from
 * or to the rax (or eax) register.  It will automatically be
 * converted to a pc-relative operand (as though
 * opnd_create_rel_addr() had been called) if it is used in any other
 * way.
 */
opnd_t 
opnd_create_abs_addr(void *addr, opnd_size_t data_size);

DR_API
/**
 * Returns a memory reference operand that refers to the address
 * \p seg: \p addr.
 * The operand has data size \p data_size (must be a OPSZ_ constant).
 *
 * If \p addr <= 2^32 (which is always true in 32-bit mode), this routine
 * is equivalent to
 * opnd_create_far_base_disp(seg, DR_REG_NULL, DR_REG_NULL, 0, (int)addr, data_size).
 *
 * Otherwise, this routine creates a separate operand type with an
 * absolute 64-bit memory address.  Such an operand can only be
 * guaranteed to be encodable in absolute form as a load or store from
 * or to the rax (or eax) register.  It will automatically be
 * converted to a pc-relative operand (as though
 * opnd_create_far_rel_addr() had been called) if it is used in any
 * other way.
 */
opnd_t 
opnd_create_far_abs_addr(reg_id_t seg, void *addr, opnd_size_t data_size);

/* DR_API EXPORT BEGIN */
#ifdef X64
/* DR_API EXPORT END */
DR_API
/**
 * Returns a memory reference operand that refers to the address \p
 * addr, but will be encoded as a pc-relative address.  At emit time,
 * if \p addr is out of reach of a 32-bit signed displacement from the
 * next instruction, encoding will fail.
 *
 * DR guarantees that all of its code caches and heap are within the
 * same 2GB memory region.  DR also loads client libraries within
 * 32-bit reachability of its code caches and heap.  This means that
 * any static data or code in a client library, or any data allocated
 * using DR's API, is guaranteed to be reachable from code cache code.
 *
 * If \p addr is not pc-reachable at encoding time and this operand is
 * used in a load or store to or from the rax (or eax) register, an
 * absolute form will be used (as though opnd_create_abs_addr() had
 * been called).
 *
 * The operand has data size data_size (must be a OPSZ_ constant).
 *
 * To represent a 32-bit address (i.e., what an address size prefix
 * indicates), simply zero out the top 32 bits of the address before
 * passing it to this routine.
 *
 * \note For 64-bit DR builds only.
 */
opnd_t 
opnd_create_rel_addr(void *addr, opnd_size_t data_size);

DR_API
/**
 * Returns a memory reference operand that refers to the address \p
 * seg : \p addr, but will be encoded as a pc-relative address.  It is
 * up to the caller to ensure that the resulting address is reachable
 * via a 32-bit signed displacement from the next instruction at emit
 * time.
 *
 * DR guarantees that all of its code caches and heap are within the
 * same 2GB memory region.  DR also loads client libraries within
 * 32-bit reachability of its code caches and heap.  This means that
 * any static data or code in a client library, or any data allocated
 * using DR's API, is guaranteed to be reachable from code cache code.
 *
 * If \p addr is not pc-reachable at encoding time and this operand is
 * used in a load or store to or from the rax (or eax) register, an
 * absolute form will be used (as though opnd_create_far_abs_addr()
 * had been called).
 *
 * The operand has data size \p data_size (must be a OPSZ_ constant).
 *
 * To represent a 32-bit address (i.e., what an address size prefix
 * indicates), simply zero out the top 32 bits of the address before
 * passing it to this routine.
 *
 * \note For 64-bit DR builds only.
 */
opnd_t 
opnd_create_far_rel_addr(reg_id_t seg, void *addr, opnd_size_t data_size);
/* DR_API EXPORT BEGIN */
#endif
/* DR_API EXPORT END */

/* predicate functions */

/* Check if the operand kind and size fields are valid */
bool
opnd_is_valid(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is an empty operand. */
bool 
opnd_is_null(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is a register operand. */
bool 
opnd_is_reg(opnd_t opnd);

DR_API
INSTR_INLINE
/** Returns true iff \p opnd is an immediate (integer or float) operand. */
bool 
opnd_is_immed(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is an immediate integer operand. */
bool 
opnd_is_immed_int(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is an immediate float operand. */
bool 
opnd_is_immed_float(opnd_t opnd);

DR_API
INSTR_INLINE
/** Returns true iff \p opnd is a (near or far) program address operand. */
bool 
opnd_is_pc(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is a near (i.e., default segment) program address operand. */
bool 
opnd_is_near_pc(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is a far program address operand. */
bool 
opnd_is_far_pc(opnd_t opnd);

DR_API
INSTR_INLINE
/** Returns true iff \p opnd is a (near or far) instr_t pointer address operand. */
bool 
opnd_is_instr(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is a near instr_t pointer address operand. */
bool 
opnd_is_near_instr(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is a far instr_t pointer address operand. */
bool 
opnd_is_far_instr(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is a memory reference to an instr_t address operand. */
bool
opnd_is_mem_instr(opnd_t opnd);

DR_API
/** Returns true iff \p opnd is a (near or far) base+disp memory reference operand. */
bool 
opnd_is_base_disp(opnd_t opnd);

DR_API
INSTR_INLINE
/**
 * Returns true iff \p opnd is a near (i.e., default segment) base+disp memory
 * reference operand.
 */
bool 
opnd_is_near_base_disp(opnd_t opnd);

DR_API
INSTR_INLINE
/** Returns true iff \p opnd is a far base+disp memory reference operand. */
bool 
opnd_is_far_base_disp(opnd_t opnd);

DR_API
/** 
 * Returns true iff \p opnd is a (near or far) absolute address operand.
 * Returns true for both base-disp operands with no base or index and
 * 64-bit non-base-disp absolute address operands. 
 */
bool 
opnd_is_abs_addr(opnd_t opnd);

DR_API
/** 
 * Returns true iff \p opnd is a near (i.e., default segment) absolute address operand.
 * Returns true for both base-disp operands with no base or index and
 * 64-bit non-base-disp absolute address operands. 
 */
bool 
opnd_is_near_abs_addr(opnd_t opnd);

DR_API
/** 
 * Returns true iff \p opnd is a far absolute address operand.
 * Returns true for both base-disp operands with no base or index and
 * 64-bit non-base-disp absolute address operands. 
 */
bool 
opnd_is_far_abs_addr(opnd_t opnd);

/* DR_API EXPORT BEGIN */
#ifdef X64
/* DR_API EXPORT END */
DR_API
/**
 * Returns true iff \p opnd is a (near or far) pc-relative memory reference operand. 
 *
 * \note For 64-bit DR builds only.
 */
bool 
opnd_is_rel_addr(opnd_t opnd);

DR_API
INSTR_INLINE
/**
 * Returns true iff \p opnd is a near (i.e., default segment) pc-relative memory
 * reference operand. 
 *
 * \note For 64-bit DR builds only.
 */
bool 
opnd_is_near_rel_addr(opnd_t opnd);

DR_API
INSTR_INLINE
/**
 * Returns true iff \p opnd is a far pc-relative memory reference operand. 
 *
 * \note For 64-bit DR builds only.
 */
bool 
opnd_is_far_rel_addr(opnd_t opnd);
/* DR_API EXPORT BEGIN */
#endif
/* DR_API EXPORT END */

DR_API
/**
 * Returns true iff \p opnd is a (near or far) memory reference operand
 * of any type: base-disp, absolute address, or pc-relative address.
 *
 * \note For 64-bit DR builds only.
 */
bool 
opnd_is_memory_reference(opnd_t opnd);

DR_API
/**
 * Returns true iff \p opnd is a far memory reference operand
 * of any type: base-disp, absolute address, or pc-relative address.
 */
bool
opnd_is_far_memory_reference(opnd_t opnd);

DR_API
/**
 * Returns true iff \p opnd is a near memory reference operand
 * of any type: base-disp, absolute address, or pc-relative address.
 */
bool
opnd_is_near_memory_reference(opnd_t opnd);

/* accessor functions */

DR_API
/** 
 * Return the data size of \p opnd as a OPSZ_ constant.
 * If \p opnd is a register returns the result of opnd_reg_get_size()
 * called on the DR_REG_ constant.
 * Returns OPSZ_NA if \p opnd does not have a valid size.
 */
opnd_size_t
opnd_get_size(opnd_t opnd);

DR_API
/** 
 * Sets the data size of \p opnd.
 * Assumes \p opnd is an immediate integer or a memory reference.
 */
void   
opnd_set_size(opnd_t *opnd, opnd_size_t newsize);

DR_API
/** 
 * Assumes \p opnd is a register operand.
 * Returns the register it refers to (a DR_REG_ constant).
 */
reg_id_t  
opnd_get_reg(opnd_t opnd);

DR_API
/** Assumes opnd is an immediate integer, returns its value. */
ptr_int_t
opnd_get_immed_int(opnd_t opnd);

DR_API
/** 
 * Assumes \p opnd is an immediate float and returns its value. 
 * The caller's code should use proc_save_fpstate() or be inside a
 * clean call that has requested to preserve the floating-point state.
 */
float  
opnd_get_immed_float(opnd_t opnd);

DR_API
/** Assumes \p opnd is a (near or far) program address, returns its value. */
app_pc 
opnd_get_pc(opnd_t opnd);

DR_API
/** 
 * Assumes \p opnd is a far program address.
 * Returns \p opnd's segment, a segment selector (not a DR_SEG_ constant).
 */
ushort    
opnd_get_segment_selector(opnd_t opnd);

DR_API
/** Assumes \p opnd is an instr_t (near, far, or memory) operand and returns its value. */
instr_t*
opnd_get_instr(opnd_t opnd);

DR_API
/**
 * Assumes \p opnd is a memory instr operand.  Returns its displacement.
 */
short
opnd_get_mem_instr_disp(opnd_t opnd);

DR_API
/**
 * Assumes \p opnd is a (near or far) base+disp memory reference.  Returns the base
 * register (a DR_REG_ constant).
 */
reg_id_t
opnd_get_base(opnd_t opnd);

DR_API
/**
 * Assumes \p opnd is a (near or far) base+disp memory reference.
 * Returns the displacement. 
 */
int 
opnd_get_disp(opnd_t opnd);

DR_API
/** 
 * Assumes \p opnd is a (near or far) base+disp memory reference; returns whether
 * encode_zero_disp has been specified for \p opnd.
 */
bool
opnd_is_disp_encode_zero(opnd_t opnd);

DR_API
/** 
 * Assumes \p opnd is a (near or far) base+disp memory reference; returns whether
 * force_full_disp has been specified for \p opnd.
 */
bool
opnd_is_disp_force_full(opnd_t opnd);

DR_API
/** 
 * Assumes \p opnd is a (near or far) base+disp memory reference; returns whether
 * disp_short_addr has been specified for \p opnd.
 */
bool
opnd_is_disp_short_addr(opnd_t opnd);

DR_API
/** 
 * Assumes \p opnd is a (near or far) base+disp memory reference.
 * Returns the index register (a DR_REG_ constant).
 */
reg_id_t
opnd_get_index(opnd_t opnd);

DR_API
/** Assumes \p opnd is a (near or far) base+disp memory reference.  Returns the scale. */
int 
opnd_get_scale(opnd_t opnd);

DR_API
/** 
 * Assumes \p opnd is a (near or far) memory reference of any type.
 * Returns \p opnd's segment (a DR_SEG_ constant), or DR_REG_NULL if it is a near
 * memory reference.
 */
reg_id_t    
opnd_get_segment(opnd_t opnd);

DR_API
/** 
 * Assumes \p opnd is a (near or far) absolute or pc-relative memory reference,
 * or a base+disp memory reference with no base or index register.
 * Returns \p opnd's absolute address (which will be pc-relativized on encoding
 * for pc-relative memory references).
 */
void *
opnd_get_addr(opnd_t opnd);

DR_API
/** 
 * Returns the number of registers referred to by \p opnd. This will only
 * be non-zero for register operands and memory references.
 */
int 
opnd_num_regs_used(opnd_t opnd);

DR_API
/** 
 * Used in conjunction with opnd_num_regs_used(), this routine can be used
 * to iterate through all registers used by \p opnd.
 * The index values begin with 0 and proceed through opnd_num_regs_used(opnd)-1.
 */
reg_id_t
opnd_get_reg_used(opnd_t opnd, int index);

/* utility functions */

#ifdef DEBUG
void
reg_check_reg_fixer(void);
#endif

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ 32-bit register constant.
 * Returns the string name for \p reg.
 */
const char *
get_register_name(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ 32-bit register constant.
 * Returns the 16-bit version of \p reg.
 */
reg_id_t
reg_32_to_16(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ 32-bit register constant.
 * Returns the 8-bit version of \p reg (the least significant byte:
 * DR_REG_AL instead of DR_REG_AH if passed DR_REG_EAX, e.g.).  For 32-bit DR
 * builds, returns DR_REG_NULL if passed DR_REG_ESP, DR_REG_EBP, DR_REG_ESI, or
 * DR_REG_EDI.
 */
reg_id_t
reg_32_to_8(reg_id_t reg);

/* DR_API EXPORT BEGIN */
#ifdef X64
/* DR_API EXPORT END */
DR_API
/** 
 * Assumes that \p reg is a DR_REG_ 32-bit register constant.
 * Returns the 64-bit version of \p reg.
 *
 * \note For 64-bit DR builds only.
 */
reg_id_t
reg_32_to_64(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ 64-bit register constant.
 * Returns the 32-bit version of \p reg.
 *
 * \note For 64-bit DR builds only.
 */
reg_id_t
reg_64_to_32(reg_id_t reg);

DR_API
/** 
 * Returns true iff \p reg refers to an extended register only available
 * in 64-bit mode and not in 32-bit mode (e.g., R8-R15, XMM8-XMM15, etc.)
 *
 * \note For 64-bit DR builds only.
 */
bool 
reg_is_extended(reg_id_t reg);
/* DR_API EXPORT BEGIN */
#endif
/* DR_API EXPORT END */

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ 32-bit register constant.
 * If \p sz == OPSZ_2, returns the 16-bit version of \p reg.
 * For 64-bit versions of this library, if \p sz == OPSZ_8, returns 
 * the 64-bit version of \p reg.
 * Returns \p DR_REG_NULL when trying to get the 8-bit subregister of \p
 * DR_REG_ESI, \p DR_REG_EDI, \p DR_REG_EBP, or \p DR_REG_ESP in 32-bit mode.
 *
 * \deprecated Prefer reg_resize_to_opsz() which is more general.
 */
reg_id_t
reg_32_to_opsz(reg_id_t reg, opnd_size_t sz);

DR_API
/**
 * Given a general-purpose register of any size, returns a register in the same
 * class of the given size.  For example, given \p DR_REG_AX or \p DR_REG_RAX
 * and \p OPSZ_1, this routine will return \p DR_REG_AL.
 * Returns \p DR_REG_NULL when trying to get the 8-bit subregister of \p
 * DR_REG_ESI, \p DR_REG_EDI, \p DR_REG_EBP, or \p DR_REG_ESP in 32-bit mode.
 * For 64-bit versions of this library, if \p sz == OPSZ_8, returns the 64-bit
 * version of \p reg.
 */
reg_id_t
reg_resize_to_opsz(reg_id_t reg, opnd_size_t sz);

DR_API
/**  
 * Assumes that \p reg is a DR_REG_ register constant.
 * If reg is used as part of the calling convention, returns which
 * parameter ordinal it matches (0-based); otherwise, returns -1.
 */
int
reg_parameter_num(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to a General Purpose Register,
 * i.e., rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, or a subset.
 */
bool
reg_is_gpr(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to a segment (i.e., it's really a DR_SEG_
 * constant).
 */
bool
reg_is_segment(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to an xmm (128-bit SSE/SSE2) register
 * or a ymm (256-bit multimedia) register.
 */
bool 
reg_is_xmm(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to a qwr (128-bit multimedia) register.
 */
bool 
reg_is_qwr(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to an dwr (64-bit) register.
 */
bool 
reg_is_dwr(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to an swr (32-bit) register.
 */
bool 
reg_is_swr(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to a floating-point register.
 */
bool 
reg_is_fp(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to a 32-bit general-purpose register.
 */
bool 
reg_is_32bit(reg_id_t reg);

DR_API
/** 
 * Returns true iff \p opnd is a register operand that refers to a 32-bit
 * general-purpose register.
 */
bool 
opnd_is_reg_32bit(opnd_t opnd);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to a 64-bit general-purpose register.
 */
bool 
reg_is_64bit(reg_id_t reg);

DR_API
/** 
 * Returns true iff \p opnd is a register operand that refers to a 64-bit
 * general-purpose register.
 */
bool 
opnd_is_reg_64bit(opnd_t opnd);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff it refers to a pointer-sized general-purpose register.
 */
bool 
reg_is_pointer_sized(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ 32-bit register constant.
 * Returns the pointer-sized version of \p reg.
 */
reg_id_t
reg_to_pointer_sized(reg_id_t reg);

DR_API
/** 
 * Returns true iff \p opnd is a register operand that refers to a
 * pointer-sized general-purpose register.
 */
bool 
opnd_is_reg_pointer_sized(opnd_t opnd);

/* not exported */
int
opnd_get_reg_dcontext_offs(reg_id_t reg);

int
opnd_get_reg_mcontext_offs(reg_id_t reg);

DR_API
/** 
 * Assumes that \p r1 and \p r2 are both DR_REG_ constants.
 * Returns true iff \p r1's register overlaps \p r2's register
 * (e.g., if \p r1 == DR_REG_AX and \p r2 == DR_REG_EAX).
 */
bool 
reg_overlap(reg_id_t r1, reg_id_t r2);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns \p reg's representation as 3 bits in a modrm byte
 * (the 3 bits are the lower-order bits in the return value).
 */
byte
reg_get_bits(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns the OPSZ_ constant corresponding to the register size.
 * Returns OPSZ_NA if reg is not a DR_REG_ constant.
 */
opnd_size_t 
reg_get_size(reg_id_t reg);

DR_API
/** 
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff \p opnd refers to reg directly or refers to a register
 * that overlaps \p reg (e.g., DR_REG_AX overlaps DR_REG_EAX).
 */
bool 
opnd_uses_reg(opnd_t opnd, reg_id_t reg);

DR_API
/** Set the displacement of a memory reference operand \p opnd to \p disp. */
void
opnd_set_disp(opnd_t *opnd, int disp);

DR_API
/** 
 * Set the displacement and encoding controls of a memory reference operand:
 * - If \p encode_zero_disp, a zero value for \p disp will not be omitted;
 * - If \p force_full_disp, a small value for \p disp will not occupy only one byte.
 * -# If \p disp_short_addr, short (16-bit for 32-bit mode, 32-bit for
 *    64-bit mode) addressing will be used (note that this normally only
 *    needs to be specified for an absolute address; otherwise, simply
 *    use the desired short registers for base and/or index).
 */
void
opnd_set_disp_ex(opnd_t *opnd, int disp, bool encode_zero_disp, bool force_full_disp,
                 bool disp_short_addr);

DR_API
/** 
 * Assumes that both \p old_reg and \p new_reg are DR_REG_ constants.
 * Replaces all occurrences of \p old_reg in \p *opnd with \p new_reg.
 */
bool 
opnd_replace_reg(opnd_t *opnd, reg_id_t old_reg, reg_id_t new_reg);

DR_API
/** Returns true iff \p op1 and \p op2 are indistinguishable. 
 *  If either uses variable operand sizes, the default size is assumed.
 */
bool 
opnd_same(opnd_t op1,opnd_t op2);

DR_API
/** 
 * Returns true iff \p op1 and \p op2 are both memory references and they
 * are indistinguishable, ignoring data size.
 */
bool 
opnd_same_address(opnd_t op1,opnd_t op2);

DR_API
/** 
 * Returns true iff there exists some register that is referred to (directly
 * or overlapping) by both \p op1 and \p op2.
 */
bool 
opnd_share_reg(opnd_t op1, opnd_t op2);

DR_API
/** 
 * Returns true iff \p def, considered as a write, affects \p use.
 * Is conservative, so if both \p def and \p use are memory references,
 * will return true unless it can disambiguate them based on their
 * registers and displacement.
 */
bool 
opnd_defines_use(opnd_t def, opnd_t use);

DR_API
/** 
 * Assumes \p size is a OPSZ_ or a DR_REG_ constant.
 * If \p size is a DR_REG_ constant, first calls reg_get_size(\p size)
 * to get a OPSZ_ constant.
 * Returns the number of bytes the OPSZ_ constant represents.
 * If OPSZ_ is a variable-sized size, returns the default size,
 * which may or may not match the actual size decided up on at
 * encoding time (that final size depends on other operands).
 */
uint 
opnd_size_in_bytes(opnd_size_t size);

DR_API
/** 
 * Assumes \p size is a OPSZ_ or a DR_REG_ constant.
 * If \p size is a DR_REG_ constant, first calls reg_get_size(\p size)
 * to get a OPSZ_ constant.
 * Returns the number of bits the OPSZ_ constant represents.
 * If OPSZ_ is a variable-sized size, returns the default size,
 * which may or may not match the actual size decided up on at
 * encoding time (that final size depends on other operands).
 */
uint
opnd_size_in_bits(opnd_size_t size);


DR_API
/** 
 * Returns the appropriate OPSZ_ constant for the given number of bytes.
 * Returns OPSZ_NA if there is no such constant.
 * The intended use case is something like "opnd_size_in_bytes(sizeof(foo))" for
 * integer/pointer types.  This routine returns simple single-size
 * types and will not return complex/variable size types.
 */
opnd_size_t
opnd_size_from_bytes(uint bytes);

DR_API
/** 
 * Shrinks all 32-bit registers in \p opnd to their 16-bit versions.  
 * Also shrinks the size of immediate integers and memory references from
 * OPSZ_4 to OPSZ_2.
 */
opnd_t 
opnd_shrink_to_16_bits(opnd_t opnd);

/* DR_API EXPORT BEGIN */
#ifdef X64
/* DR_API EXPORT END */
DR_API
/** 
 * Shrinks all 64-bit registers in \p opnd to their 32-bit versions.  
 * Also shrinks the size of immediate integers and memory references from
 * OPSZ_8 to OPSZ_4.
 *
 * \note For 64-bit DR builds only.
 */
opnd_t 
opnd_shrink_to_32_bits(opnd_t opnd);
/* DR_API EXPORT BEGIN */
#endif
/* DR_API EXPORT END */

DR_API
/** 
 * Returns the value of the register \p reg, selected from the passed-in
 * register values.  Supports only general-purpose registers.
 * \p mc->flags must include DR_MC_CONTROL and DR_MC_INTEGER.
 */
reg_t
reg_get_value(reg_id_t reg, dr_mcontext_t *mc);

/* internal version */
reg_t
reg_get_value_priv(reg_id_t reg, priv_mcontext_t *mc);

DR_API
/**
 * Sets the register \p reg in the passed in mcontext \p mc to \p value.
 * \p mc->flags must include DR_MC_CONTROL and DR_MC_INTEGER.
 * \note Current release is limited to setting pointer-sized registers only
 * (no sub-registers, and no non-general-purpose registers).
 */
void
reg_set_value(reg_id_t reg, dr_mcontext_t *mc, reg_t value);

/* internal version */
void
reg_set_value_priv(reg_id_t reg, priv_mcontext_t *mc, reg_t value);

DR_API
/** 
 * Returns the effective address of \p opnd, computed using the passed-in 
 * register values.  If \p opnd is a far address, ignores that aspect
 * except for TLS references on Windows (fs: for 32-bit, gs: for 64-bit)
 * or typical fs: or gs: references on Linux.  For far addresses the
 * calling thread's segment selector is used.
 * \p mc->flags must include DR_MC_CONTROL and DR_MC_INTEGER.
 */
app_pc
opnd_compute_address(opnd_t opnd, dr_mcontext_t *mc);

/* internal version */
app_pc
opnd_compute_address_priv(opnd_t opnd, priv_mcontext_t *mc);


/*************************
 ***       instr_t       ***
 *************************/

/* instr_t structure
 * An instruction represented by instr_t can be in a number of states,
 * depending on whether it points to raw bits that are valid,
 * whether its operand and opcode fields are up to date, and whether
 * its eflags field is up to date.
 * Invariant: if opcode == OP_UNDECODED, raw bits should be valid.
 *            if opcode == OP_INVALID, raw bits may point to real bits,
 *              but they are not a valid instruction stream.
 *
 * CORRESPONDENCE WITH CGO LEVELS
 * Level 0 = raw bits valid, !opcode_valid, decode_sizeof(instr) != instr->len
 *   opcode_valid is equivalent to opcode != OP_INVALID && opcode != OP_UNDECODED
 * Level 1 = raw bits valid, !opcode_valid, decode_sizeof(instr) == instr->len
 * Level 2 = raw bits valid, opcode_valid, !operands_valid
 *   (eflags info is auto-derived on demand so not an issue)
 * Level 3 = raw bits valid, operands valid
 *   (we assume that if operands_valid then opcode_valid)
 * Level 4 = !raw bits valid, operands valid
 *
 * Independent of these is whether its raw bits were allocated for
 * the instr or not.
 */

/* DR_API EXPORT TOFILE dr_ir_instr.h */
/* For inlining, we need to expose some of these flags.  We bracket the ones we
 * want in export begin/end.  AVOID_API_EXPORT does not work because there are
 * nested ifdefs.
 */
/* DR_API EXPORT BEGIN */
#ifdef DR_FAST_IR
/* flags */
enum {
/* DR_API EXPORT END */
    /* these first flags are shared with the LINK_ flags and are
     * used to pass on info to link stubs 
     */
    /* used to determine type of indirect branch for exits */
    INSTR_DIRECT_EXIT           = LINK_DIRECT,
    INSTR_INDIRECT_EXIT         = LINK_INDIRECT,
    INSTR_RETURN_EXIT           = LINK_RETURN,
    /* JMP|CALL marks an indirect jmp preceded by a call (== a PLT-style ind call)
     * so use EXIT_IS_{JMP,CALL} rather than these raw bits
     */
    INSTR_CALL_EXIT             = LINK_CALL,
    INSTR_JMP_EXIT              = LINK_JMP,
    INSTR_IND_JMP_PLT_EXIT      = (INSTR_JMP_EXIT | INSTR_CALL_EXIT),
    INSTR_FAR_EXIT              = LINK_FAR,
    INSTR_BRANCH_SELFMOD_EXIT   = LINK_SELFMOD_EXIT,
#ifdef UNSUPPORTED_API
    INSTR_BRANCH_TARGETS_PREFIX = LINK_TARGET_PREFIX,
#endif
#ifdef X64
    /* PR 257963: since we don't store targets of ind branches, we need a flag
     * so we know whether this is a trace cmp exit, which has its own ibl entry
     */
    INSTR_TRACE_CMP_EXIT        = LINK_TRACE_CMP,
#endif
#ifdef WINDOWS
    INSTR_CALLBACK_RETURN       = LINK_CALLBACK_RETURN,
#else
    INSTR_NI_SYSCALL_INT        = LINK_NI_SYSCALL_INT,
#endif
    INSTR_NI_SYSCALL            = LINK_NI_SYSCALL,
    INSTR_NI_SYSCALL_ALL        = LINK_NI_SYSCALL_ALL,
    /* meta-flag */
    EXIT_CTI_TYPES              = (INSTR_DIRECT_EXIT | INSTR_INDIRECT_EXIT |
                                   INSTR_RETURN_EXIT | INSTR_CALL_EXIT |     
                                   INSTR_JMP_EXIT |
                                   INSTR_FAR_EXIT |
                                   INSTR_BRANCH_SELFMOD_EXIT |
#ifdef UNSUPPORTED_API
                                   INSTR_BRANCH_TARGETS_PREFIX |
#endif
#ifdef X64
                                   INSTR_TRACE_CMP_EXIT |
#endif
#ifdef WINDOWS
                                   INSTR_CALLBACK_RETURN |
#else
                                   INSTR_NI_SYSCALL_INT |
#endif
                                   INSTR_NI_SYSCALL),

    /* instr_t-internal flags (not shared with LINK_) */
    INSTR_OPERANDS_VALID        = 0x00010000,
    /* meta-flag */
    INSTR_FIRST_NON_LINK_SHARED_FLAG = INSTR_OPERANDS_VALID,
    INSTR_CPSR_VALID          = 0x00020000,
    INSTR_CPSR_6_VALID        = 0x00040000,
    INSTR_RAW_BITS_VALID        = 0x00080000,
    INSTR_RAW_BITS_ALLOCATED    = 0x00100000,
/* DR_API EXPORT BEGIN */
    INSTR_DO_NOT_MANGLE         = 0x00200000,
/* DR_API EXPORT END */
    INSTR_HAS_CUSTOM_STUB       = 0x00400000,
    /* used to indicate that an indirect call can be treated as a direct call */
    INSTR_IND_CALL_DIRECT       = 0x00800000,
#ifdef WINDOWS
    /* used to indicate that a syscall should be executed via shared syscall */
    INSTR_SHARED_SYSCALL        = 0x01000000,
#endif

#ifdef CLIENT_INTERFACE
    INSTR_CLOBBER_RETADDR       = 0x02000000,
#endif

    /* Signifies that this instruction may need to be hot patched and should
     * therefore not cross a cache line. It is not necessary to set this for
     * exit cti's or linkstubs since it is mainly intended for clients etc. 
     * Handling of this flag is not yet implemented */
    INSTR_HOT_PATCHABLE         = 0x04000000,
#ifdef DEBUG
    /* case 9151: only report invalid instrs for normal code decoding */
    INSTR_IGNORE_INVALID        = 0x08000000,
#endif
    /* Currently used for frozen coarse fragments with final jmps and
     * jmps to ib stubs that are elided: we need the jmp instr there
     * to build the linkstub_t but we do not want to emit it. */
    INSTR_DO_NOT_EMIT           = 0x10000000,
    /* PR 251479: re-relativization support: is instr->rip_rel_pos valid? */
    INSTR_RIP_REL_VALID         = 0x20000000,
#ifdef X64
    /* PR 278329: each instr stores its own x64/x86 mode */
    INSTR_X86_MODE              = 0x40000000,
#endif
    /* PR 267260: distinguish our own mangling from client-added instrs */
    INSTR_OUR_MANGLING          = 0x80000000,
/* DR_API EXPORT BEGIN */
};
#endif /* DR_FAST_IR */

/**
 * Data slots available in a label (instr_create_label()) instruction
 * for storing client-controlled data.  Accessible via
 * instr_get_label_data_area().
 */
typedef struct _dr_instr_label_data_t {
    ptr_uint_t data[4]; /**< Generic fields for storing user-controlled data */
} dr_instr_label_data_t;

#ifdef DR_FAST_IR
/* DR_API EXPORT END */
/* FIXME: could shrink prefixes, eflags, opcode, and flags fields
 * this struct isn't a memory bottleneck though b/c it isn't persistent
 */
/* DR_API EXPORT BEGIN */

/**
 * instr_t type exposed for optional "fast IR" access.  Note that DynamoRIO
 * reserves the right to change this structure across releases and does
 * not guarantee binary or source compatibility when this structure's fields
 * are directly accessed.  If the instr_ accessor routines are used, DynamoRIO does
 * guarantee source compatibility, but not binary compatibility.  If binary
 * compatibility is desired, do not use the fast IR feature.
 */
struct _instr_t {
    /* flags contains the constants defined above */
    uint    flags;

    /* raw bits of length length are pointed to by the bytes field */
    byte    *bytes;
    uint    length;

    /* translation target for this instr */
    app_pc  translation;

    /* SJF ARM specific fields here. 
           Cond is the 4 bit condition code
           instrtype is bits[27,25] and specifiy the class
           of instruciton that the instr belongs to(data processing/movement)
           opcode contains P,U,B,W,L,N,S flags( which determine opcode )
           depending on the instructions type. */
    byte    cond;
    byte    instr_type;
    byte    opcode;

    /* we dynamically allocate dst and src arrays b/c x86 instrs can have
     * up to 8 of each of them, but most have <=2 dsts and <=3 srcs, and we
     * use this struct for un-decoded instrs too
     */
    byte    num_dsts;
    byte    num_srcs;

    union {
        struct {
            /* for efficiency everyone has a 1st src opnd, since we often just
             * decode jumps, which all have a single source (==target)
             * yes this is an extra 10 bytes, but the whole struct is still < 64 bytes!
             */
            opnd_t    src0;
            opnd_t    *srcs; /* this array has 2nd src and beyond */
            opnd_t    *dsts;
        };
        dr_instr_label_data_t label_data;
    };

    /* SJF Flags 2 contains flags or possible op2 depening on instruction type */
    uint    flags2;   /* contains flags contained in bits[7,4] of the instr
                         May contain opcode for coprocessor instrs */ 
    uint    cpsr;     /* CPSR flags */

    /* this field is for the use of passes as an annotation.
     * it is also used to hold the offset of an instruction when encoding
     * pc-relative instructions.
     */
    void *note;

    /* fields for building instructions into instruction lists */
    instr_t   *prev;
    instr_t   *next;

    /*SJF Need the flags to be set in here as well 
          so they can be corectly encoded out to the fcache */
    bool p_flag; // Post indexed?
    bool u_flag; // plus/minus offset?
    bool s_flag; // set cpsr flags?
    bool w_flag; // write back?
    bool l_flag; //load/store
    bool b_flag; //word or byte?
    bool d_flag; //???
    bool h_flag; //???
    bool m_flag; //For signed multiplies 
    bool r_flag; //For stm to flag to overwrite cpsr with spsr 

    int  shift_type;

    /*Just for coprocessor instructions
    int opc1;
    int opc2;
    int coproc;
     */

}; /* instr_t */
#endif /* DR_FAST_IR */

/****************************************************************************
 * INSTR ROUTINES
 */
/**
 * @file dr_ir_instr.h
 * @brief Functions to create and manipulate instructions.
 */

/* DR_API EXPORT END */

/*** New instr flag functions ***/

DR_API
bool
instr_set_p_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_set_u_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_set_s_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_set_w_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_set_l_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_set_b_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_set_d_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_set_h_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_set_m_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_set_r_flag( dcontext_t* dcontext, instr_t* instr, bool val );

DR_API
bool
instr_has_p_flag( instr_t* instr );

DR_API
bool
instr_has_u_flag( instr_t* instr );

DR_API
bool
instr_has_s_flag( instr_t* instr );

DR_API
bool
instr_has_w_flag( instr_t* instr );

DR_API
bool
instr_has_l_flag( instr_t* instr );

DR_API
bool
instr_has_b_flag( instr_t* instr );

DR_API
bool
instr_has_d_flag( instr_t* instr );

DR_API
bool
instr_has_h_flag( instr_t* instr );

DR_API
bool
instr_has_m_flag( instr_t* instr );

DR_API
bool
instr_has_r_flag( instr_t* instr );

//Un relative instructions
void
instrlist_preinsert_move_32bits_to_reg(instrlist_t *ilist, dcontext_t *dcontext,
                                reg_id_t target_reg, reg_id_t scratch, int target, instr_t* rel_instr, int cond );

void
instrlist_append_move_32bits_to_reg(instrlist_t *ilist, dcontext_t *dcontext,
                                reg_id_t target_reg, reg_id_t scratch, int target, int cond );


instrlist_t*
instrlist_rewrite_relative_to_absolute( dcontext_t* dcontext, instrlist_t* ilist );



DR_API
/**
 * Returns an initialized instr_t allocated on the thread-local heap.
 * Sets the x86/x64 mode of the returned instr_t to the mode of dcontext.
 */
/* For -x86_to_x64, sets the mode of the instr to the code cache mode instead of
the app mode. */
instr_t*
instr_create(dcontext_t *dcontext);

DR_API
/** Initializes \p instr.
 * Sets the x86/x64 mode of \p instr to the mode of dcontext.
 */
void
instr_init(dcontext_t *dcontext, instr_t *instr);

DR_API
/**
 * Deallocates all memory that was allocated by \p instr.  This
 * includes raw bytes allocated by instr_allocate_raw_bits() and
 * operands allocated by instr_set_num_opnds().  Does not deallocate
 * the storage for \p instr itself.
 */
void
instr_free(dcontext_t *dcontext, instr_t *instr);

DR_API
/**
 * Performs both instr_free() and instr_init().
 * \p instr must have been initialized.
 */
void
instr_reset(dcontext_t *dcontext, instr_t *instr);

DR_API
/**
 * Frees all dynamically allocated storage that was allocated by \p instr,
 * except for allocated bits.
 * Also zeroes out \p instr's fields, except for raw bit fields,
 * whether \p instr is instr_ok_to_mangle(), and the x86 mode of \p instr.
 * \p instr must have been initialized.
 */
void
instr_reuse(dcontext_t *dcontext, instr_t *instr);

DR_API
/**
 * Performs instr_free() and then deallocates the thread-local heap
 * storage for \p instr.
 */
void
instr_destroy(dcontext_t *dcontext, instr_t *instr);

DR_API
INSTR_INLINE
/**
 * Returns the next instr_t in the instrlist_t that contains \p instr.
 * \note The next pointer for an instr_t is inside the instr_t data
 * structure itself, making it impossible to have on instr_t in
 * two different InstrLists (but removing the need for an extra data
 * structure for each element of the instrlist_t).
 */
instr_t*
instr_get_next(instr_t *instr);

DR_API
INSTR_INLINE
/** Returns the previous instr_t in the instrlist_t that contains \p instr. */
instr_t*
instr_get_prev(instr_t *instr);

DR_API
INSTR_INLINE
/** Sets the next field of \p instr to point to \p next. */
void
instr_set_next(instr_t *instr, instr_t *next);

DR_API
INSTR_INLINE
/** Sets the prev field of \p instr to point to \p prev. */
void
instr_set_prev(instr_t *instr, instr_t *prev);

DR_API
INSTR_INLINE
/**
 * Gets the value of the user-controlled note field in \p instr.
 * \note Important: is also used when emitting for targets that are other
 * instructions.  Thus it will be overwritten when calling instrlist_encode()
 * or instrlist_encode_to_copy() with \p has_instr_jmp_targets set to true.
 * \note The note field is copied (shallowly) by instr_clone().
 */
void *
instr_get_note(instr_t *instr);

DR_API
INSTR_INLINE
/** Sets the user-controlled note field in \p instr to \p value. */
void
instr_set_note(instr_t *instr, void *value);

DR_API
/** Return the taken target pc of the (direct branch) instruction. */
app_pc
instr_get_branch_target_pc(instr_t *cti_instr);

DR_API
/** Set the taken target pc of the (direct branch) instruction. */
void
instr_set_branch_target_pc(instr_t *cti_instr, app_pc pc);

DR_API
/**
 * Returns true iff \p instr is a conditional branch, unconditional branch,
 * or indirect branch with a program address target (NOT an instr_t address target)
 * and \p instr is ok to mangle.
 */
#ifdef UNSUPPORTED_API
/**
 * This routine does NOT try to decode an opcode in a Level 1 or Level
 * 0 routine, and can thus be called on Level 0 routines.
 */
#endif
bool
instr_is_exit_cti(instr_t *instr);

bool
instr_is_pc_read( instr_t* instr );


DR_API
/** Return true iff \p instr's opcode is OP_int, OP_into, or OP_int3. */
bool
instr_is_interrupt(instr_t *instr);

#ifdef UNSUPPORTED_API
DR_API
/**
 * Returns true iff \p instr has been marked as targeting the prefix of its
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
instr_branch_targets_prefix(instr_t *instr);

DR_API
/**
 * If \p val is true, indicates that \p instr's target fragment should be
 *   entered through its prefix, which restores ecx.
 * If \p val is false, indicates that \p instr should target the normal entry
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
instr_branch_set_prefix_target(instr_t *instr, bool val);
#endif /* UNSUPPORTED_API */

DR_UNS_API
/**
 * Returns true iff \p instr has been marked as a selfmod check failure
 * exit.
 */
bool
instr_branch_selfmod_exit(instr_t *instr);

DR_UNS_API
/**
 * If \p val is true, indicates that \p instr is a selfmod check failure exit.
 * If \p val is false, indicates otherwise.
 */
void
instr_branch_set_selfmod_exit(instr_t *instr, bool val);

DR_API
INSTR_INLINE
/**
 * Return true iff \p instr is not a meta-instruction
 * (see instr_set_ok_to_mangle() for more information).
 */
bool
instr_ok_to_mangle(instr_t *instr);

DR_API
/**
 * Sets \p instr to "ok to mangle" if \p val is true and "not ok to
 * mangle" if \p val is false.  An instruction that is "not ok to
 * mangle" is treated by DR as a "meta-instruction", distinct from
 * normal application instructions, and is not mangled in any way.
 * This is necessary to have DR not create an exit stub for a direct
 * jump.  All non-meta instructions that are added to basic blocks or
 * traces should have their translation fields set (via
 * #instr_set_translation(), or the convenience routine
 * #instr_set_meta_no_translation()) when recreating state at a fault;
 * meta instructions should not fault (unless such faults are handled
 * by the client) and are not considered
 * application instructions but rather added instrumentation code (see
 * #dr_register_bb_event() for further information on recreating).
 */
void
instr_set_ok_to_mangle(instr_t *instr, bool val);

DR_API
/**
 * A convenience routine that calls both
 * #instr_set_ok_to_mangle (instr, false) and
 * #instr_set_translation (instr, NULL).
 */
void
instr_set_meta_no_translation(instr_t *instr);

DR_API
#ifdef AVOID_API_EXPORT
/* This is hot internally, but unlikely to be used by clients. */
INSTR_INLINE
#endif
/** Return true iff \p instr is to be emitted into the cache. */
bool
instr_ok_to_emit(instr_t *instr);

DR_API
/**
 * Set \p instr to "ok to emit" if \p val is true and "not ok to emit"
 * if \p val is false.  An instruction that should not be emitted is
 * treated normally by DR for purposes of exits but is not placed into
 * the cache.  It is used for final jumps that are to be elided.
 */
void
instr_set_ok_to_emit(instr_t *instr, bool val);

#ifdef CUSTOM_EXIT_STUBS
DR_API
/**
 * If \p instr is not an exit cti, does nothing.
 * If \p instr is an exit cti, sets \p stub to be custom exit stub code
 * that will be inserted in the exit stub prior to the normal exit
 * stub code.  If \p instr already has custom exit stub code, that
 * existing instrlist_t is cleared and destroyed (using current thread's
 * context).  (If \p stub is NULL, any existing stub code is NOT destroyed.)
 * The creator of the instrlist_t containing \p instr is
 * responsible for destroying stub.
 * \note Custom exit stubs containing control transfer instructions to
 * other instructions inside a fragment besides the custom stub itself
 * are not fully supported in that they will not be decoded from the
 * cache properly as having instr_t targets.
 */
void
instr_set_exit_stub_code(instr_t *instr, instrlist_t *stub);

DR_API
/**
 * Returns the custom exit stub code instruction list that has been
 * set for this instruction.  If none exists, returns NULL.
 */
instrlist_t *
instr_exit_stub_code(instr_t *instr);
#endif

DR_API
/**
 * Returns the length of \p instr.
 * As a side effect, if instr_ok_to_mangle(instr) and \p instr's raw bits
 * are invalid, encodes \p instr into bytes allocated with
 * instr_allocate_raw_bits(), after which instr is marked as having
 * valid raw bits.
 */
int
instr_length(dcontext_t *dcontext, instr_t *instr);

/* not exported */
void instr_shift_raw_bits(instr_t *instr, ssize_t offs);
uint instr_branch_type(instr_t *cti_instr);
int instr_exit_branch_type(instr_t *instr);
void instr_exit_branch_set_type(instr_t *instr, uint type);

DR_API
/** Returns number of bytes of heap used by \p instr. */
int
instr_mem_usage(instr_t *instr);

DR_API
/**
 * Returns a copy of \p orig with separately allocated memory for
 * operands and raw bytes if they were present in \p orig.
 * Cloning an instruction with a non-zero \p note field is not
 * supported.
 */
instr_t *
instr_clone(dcontext_t *dcontext, instr_t *orig);

DR_API
/**
 * Convenience routine: calls
 * - instr_create(dcontext)
 * - instr_set_opcode(opcode)
 * - instr_set_num_opnds(dcontext, instr, num_dsts, num_srcs)
 *
 * and returns the resulting instr_t.
 */
instr_t *
instr_build(dcontext_t *dcontext, int opcode, int num_dsts, int num_srcs);

DR_API
/**
 * Convenience routine: calls 
 * - instr_create(dcontext)
 * - instr_set_opcode(instr, opcode)
 * - instr_allocate_raw_bits(dcontext, instr, num_bytes)
 *
 * and returns the resulting instr_t.
 */
instr_t *
instr_build_bits(dcontext_t *dcontext, int opcode, uint num_bytes);

DR_API
/**
 * Returns true iff \p instr's opcode is NOT OP_INVALID.
 * Not to be confused with an invalid opcode, which can be OP_INVALID or
 * OP_UNDECODED.  OP_INVALID means an instruction with no valid fields:
 * raw bits (may exist but do not correspond to a valid instr), opcode,
 * eflags, or operands.  It could be an uninitialized
 * instruction or the result of decoding an invalid sequence of bytes.
 */
bool 
instr_valid(instr_t *instr);

DR_API
/** Get the original application PC of \p instr if it exists. */
app_pc
instr_get_app_pc(instr_t *instr);

DR_API
/** Returns \p instr's opcode (an OP_ constant). */
int 
instr_get_opcode(instr_t *instr);

DR_API
/** Assumes \p opcode is an OP_ constant and sets it to be instr's opcode. */
void 
instr_set_opcode(instr_t *instr, int opcode);

const struct instr_info_t * 
instr_get_instr_info(instr_t *instr);

const struct instr_info_t *
get_instr_info(int opcode);

DR_API
INSTR_INLINE
/**
 * Returns the number of source operands of \p instr.
 *
 * \note Addressing registers used in destination memory references
 * (i.e., base, index, or segment registers) are not separately listed
 * as source operands.
 */
int 
instr_num_srcs(instr_t *instr);

DR_API
INSTR_INLINE
/**
 * Returns the number of destination operands of \p instr.
 */
int 
instr_num_dsts(instr_t *instr);

DR_API
/**
 * Assumes that \p instr has been initialized but does not have any
 * operands yet.  Allocates storage for \p num_srcs source operands
 * and \p num_dsts destination operands.
 */
void 
instr_set_num_opnds(dcontext_t *dcontext, instr_t *instr, int num_dsts, int num_srcs);

DR_API
/**
 * Returns \p instr's source operand at position \p pos (0-based).
 */
opnd_t 
instr_get_src(instr_t *instr, uint pos);

DR_API
/**
 * Returns \p instr's destination operand at position \p pos (0-based).
 */
opnd_t 
instr_get_dst(instr_t *instr, uint pos);

DR_API
/**
 * Sets \p instr's source operand at position \p pos to be \p opnd.
 * Also calls instr_set_raw_bits_valid(\p instr, false) and
 * instr_set_operands_valid(\p instr, true).
 */
void 
instr_set_src(instr_t *instr, uint pos, opnd_t opnd);

DR_API
/**
 * Sets \p instr's destination operand at position \p pos to be \p opnd.
 * Also calls instr_set_raw_bits_valid(\p instr, false) and
 * instr_set_operands_valid(\p instr, true).
 */
void 
instr_set_dst(instr_t *instr, uint pos, opnd_t opnd);

DR_API
/**
 * Assumes that \p cti_instr is a control transfer instruction
 * Returns the first source operand of \p cti_instr (its target).
 */
opnd_t 
instr_get_target(instr_t *cti_instr);

DR_API
/**
 * Assumes that \p cti_instr is a control transfer instruction.
 * Sets the first source operand of \p cti_instr to be \p target.
 * Also calls instr_set_raw_bits_valid(\p instr, false) and
 * instr_set_operands_valid(\p instr, true).
 */
void 
instr_set_target(instr_t *cti_instr, opnd_t target);

#ifdef AVOID_API_EXPORT
INSTR_INLINE  /* hot internally */
#endif
DR_API
/** Returns true iff \p instr's operands are up to date. */
bool 
instr_operands_valid(instr_t *instr);

DR_API
/** Sets \p instr's operands to be valid if \p valid is true, invalid otherwise. */
void 
instr_set_operands_valid(instr_t *instr, bool valid);

DR_API
/**
 * Returns true iff \p instr's opcode is valid.
 * If the opcode is ever set to other than OP_INVALID or OP_UNDECODED it is assumed
 * to be valid.  However, calling instr_get_opcode() will attempt to
 * decode a valid opcode, hence the purpose of this routine.
 */
bool 
instr_opcode_valid(instr_t *instr);

/******************************************************************
 * Eflags validity is not exported!  It's hidden.  Calling get_eflags or
 * get_arith_flags will make them valid if they're not.
 */

bool 
instr_arith_flags_valid(instr_t *instr);

/* Returns true iff instr's eflags are up to date. */
bool 
instr_eflags_valid(instr_t *instr);

/* Sets instr's eflags to be valid if valid is true, invalid otherwise. */
void 
instr_set_eflags_valid(instr_t *instr, bool valid);

DR_API
/** Returns \p instr's eflags use as EFLAGS_ constants or'ed together. */
uint 
instr_get_cpsr(instr_t *instr);

DR_API
/** Returns the eflags usage of instructions with opcode \p opcode,
 * as EFLAGS_ constants or'ed together.
 */
uint 
instr_get_opcode_eflags(int opcode);

DR_API
bool
opcode_is_relative_load( int opc );

bool
opcode_is_possible_pc_read( int opc );

DR_API
bool
opcode_is_other_relative( int opc );


DR_API
/**
 * Returns \p instr's arithmetic flags (bottom 6 eflags) use 
 * as EFLAGS_ constants or'ed together.
 * If \p instr's eflags behavior has not been calculated yet or is
 * invalid, the entire eflags use is calculated and returned (not
 * just the arithmetic flags).
 */
uint 
instr_get_arith_flags(instr_t *instr);

/*
 ******************************************************************/

DR_API
/**
 * Assumes that \p instr does not currently have any raw bits allocated.
 * Sets \p instr's raw bits to be \p length bytes starting at \p addr.
 * Does not set the operands invalid.
 */
void 
instr_set_raw_bits(instr_t *instr, byte * addr, uint length);

DR_API
/** Sets \p instr's raw bits to be valid if \p valid is true, invalid otherwise. */
void 
instr_set_raw_bits_valid(instr_t *instr, bool valid);

#ifdef AVOID_API_EXPORT
INSTR_INLINE  /* internal inline */
#endif
DR_API
/** Returns true iff \p instr's raw bits are a valid encoding of instr. */
bool 
instr_raw_bits_valid(instr_t *instr);

#ifdef AVOID_API_EXPORT
INSTR_INLINE  /* internal inline */
#endif
DR_API
/** Returns true iff \p instr has its own allocated memory for raw bits. */
bool 
instr_has_allocated_bits(instr_t *instr);

#ifdef AVOID_API_EXPORT
INSTR_INLINE  /* internal inline */
#endif
DR_API
/** Returns true iff \p instr's raw bits are not a valid encoding of \p instr. */
bool 
instr_needs_encoding(instr_t *instr);

DR_API
/**
 * Return true iff \p instr is not a meta-instruction that can fault
 * (see instr_set_meta_may_fault() for more information).
 *
 * \deprecated Any meta instruction can fault if it has a non-NULL
 * translation field and the client fully handles all of its faults,
 * so this routine is no longer needed.
 */
bool
instr_is_meta_may_fault(instr_t *instr);

DR_API
/**
 * \deprecated Any meta instruction can fault if it has a non-NULL
 * translation field and the client fully handles all of its faults,
 * so this routine is no longer needed.
 */
void
instr_set_meta_may_fault(instr_t *instr, bool val);

DR_API
/**
 * Allocates \p num_bytes of memory for \p instr's raw bits.
 * If \p instr currently points to raw bits, the allocated memory is
 * initialized with the bytes pointed to.
 * \p instr is then set to point to the allocated memory.
 */
void 
instr_allocate_raw_bits(dcontext_t *dcontext, instr_t *instr, uint num_bytes);

DR_API
/**
 * Sets the translation pointer for \p instr, used to recreate the
 * application address corresponding to this instruction.  When adding
 * or modifying instructions that are to be considered application
 * instructions (i.e., non meta-instructions: see
 * #instr_ok_to_mangle), the translation should always be set.  Pick
 * the application address that if executed will be equivalent to
 * restarting \p instr.  Currently the translation address must lie
 * within the existing bounds of the containing code block.
 * Returns the supplied \p instr (for easy chaining).  Use
 * #instr_get_app_pc to see the current value of the translation.
 */
instr_t * 
instr_set_translation(instr_t *instr, app_pc addr);

DR_UNS_API
/**
 * If the translation pointer is set for \p instr, returns that
 * else returns NULL.
 * \note The translation pointer is not automatically set when
 * decoding instructions from raw bytes (via decode(), e.g.); it is
 * set for instructions in instruction lists generated by DR (see
 * dr_register_bb_event()).
 * 
 */
app_pc 
instr_get_translation(instr_t *instr);

DR_API
/**
 * Calling this function with \p instr makes it safe to keep the
 * instruction around indefinitely when its raw bits point into the
 * cache.  The function allocates memory local to \p instr to hold a
 * copy of the raw bits. If this was not done, the original raw bits
 * could be deleted at some point.  Making an instruction persistent
 * is necessary if you want to keep it beyond returning from the call
 * that produced the instruction.
 */
void
instr_make_persistent(dcontext_t *dcontext, instr_t *instr);

DR_API
/**
 * Assumes that \p instr's raw bits are valid.
 * Returns a pointer to \p instr's raw bits.
 * \note A freshly-decoded instruction has valid raw bits that point to the
 * address from which it was decoded.
 */
byte *
instr_get_raw_bits(instr_t *instr);

DR_API
/** If \p instr has raw bits allocated, frees them. */
void
instr_free_raw_bits(dcontext_t *dcontext, instr_t *instr);

DR_API
/**
 * Assumes that \p instr's raw bits are valid and have > \p pos bytes.
 * Returns a pointer to \p instr's raw byte at position \p pos (beginning with 0).
 */
byte 
instr_get_raw_byte(instr_t *instr, uint pos);

DR_API
/**
 * Assumes that \p instr's raw bits are valid and allocated by \p instr
 * and have > \p pos bytes.
 * Sets instr's raw byte at position \p pos (beginning with 0) to the value \p byte.
 */
void 
instr_set_raw_byte(instr_t *instr, uint pos, byte byte);

DR_API
/**
 * Assumes that \p instr's raw bits are valid and allocated by \p instr
 * and have >= num_bytes bytes.
 * Copies the \p num_bytes beginning at start to \p instr's raw bits.
 */
void 
instr_set_raw_bytes(instr_t *instr, byte *start, uint num_bytes);

DR_API
/**
 * Assumes that \p instr's raw bits are valid and allocated by \p instr
 * and have > pos+3 bytes.
 * Sets the 4 bytes beginning at position \p pos (0-based) to the value word.
 */
void 
instr_set_raw_word(instr_t *instr, uint pos, uint word);

DR_API
/**
 * Assumes that \p instr's raw bits are valid and have > \p pos + 3 bytes.
 * Returns the 4 bytes beginning at position \p pos (0-based).
 */
uint 
instr_get_raw_word(instr_t *instr, uint pos);

DR_API
/**
 * Assumes that \p prefix is a PREFIX_ constant.
 * Ors \p instr's prefixes with \p prefix.
 * Returns the supplied instr (for easy chaining).
 */
instr_t *
instr_set_prefix_flag(instr_t *instr, uint prefix);

DR_API
/**
 * Assumes that \p prefix is a PREFIX_ constant.
 * Returns true if \p instr's prefixes contain the flag \p prefix.
 */
bool 
instr_get_prefix_flag(instr_t *instr, uint prefix);

/* NOT EXPORTED because we want to limit a client to seeing only the
 * handful of PREFIX_ flags we're exporting.
 * Assumes that prefix is a group of PREFIX_ constants or-ed together.
 * Sets instr's prefixes to be exactly those flags in prefixes.
 */
void 
instr_set_prefixes(instr_t *instr, uint prefixes);

/* DR_API EXPORT BEGIN */
#ifdef X64
/* DR_API EXPORT END */
DR_API
/**
 * Each instruction stores whether it should be interpreted in 32-bit
 * (x86) or 64-bit (x64) mode.  This routine sets the mode for \p instr.
 *
 * \note For 64-bit DR builds only.
 */
void
instr_set_x86_mode(instr_t *instr, bool x86);

DR_API
/**
 * Returns true if \p instr is an x86 instruction (32-bit) and false
 * if \p instr is an x64 instruction (64-bit).
 *
 * \note For 64-bit DR builds only.
 */
bool 
instr_get_x86_mode(instr_t *instr);
/* DR_API EXPORT BEGIN */
#endif
/* DR_API EXPORT END */

/***********************************************************************/
/* decoding routines */

DR_UNS_API
/**
 * If instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands instr into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.
 * Returns the replacement of instr, if any expansion is performed
 * (in which case the old instr is destroyed); otherwise returns
 * instr unchanged.
 */
instr_t *
instr_expand(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr);

DR_UNS_API
/**
 * Returns true if instr is at Level 0 (i.e. a bundled group of instrs
 * as raw bits).
 */
bool
instr_is_level_0(instr_t *inst);

DR_UNS_API
/**
 * If the next instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands it into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.  Then returns the new next instr.
 */
instr_t *
instr_get_next_expanded(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr);

DR_UNS_API
/**
 * If the prev instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands it into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.  Then returns the new prev instr.
 */
instr_t *
instr_get_prev_expanded(dcontext_t *dcontext, instrlist_t *ilist, instr_t *instr);

DR_UNS_API
/**
 * If instr is not already at the level of decode_cti, decodes enough
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
instr_decode_cti(dcontext_t *dcontext, instr_t *instr);

DR_UNS_API
/**
 * If instr is not already at the level of decode_opcode, decodes enough
 * from the raw bits pointed to by instr to bring it to that level.
 * Assumes that instr is a single instr (i.e., NOT Level 0).
 *
 * decode_opcode decodes the opcode and eflags usage of the instruction.
 * This corresponds to a Level 2 decoding.
 */
void
instr_decode_opcode(dcontext_t *dcontext, instr_t *instr);

DR_UNS_API
/**
 * If instr is not already fully decoded, decodes enough
 * from the raw bits pointed to by instr to bring it Level 3.
 * Assumes that instr is a single instr (i.e., NOT Level 0).
 */
void
instr_decode(dcontext_t *dcontext, instr_t *instr);

/* Calls instr_decode() with the current dcontext.  *Not* exported.  Mostly
 * useful as the slow path for IR routines that get inlined.
 */
instr_t *
instr_decode_with_current_dcontext(instr_t *instr);

/* DR_API EXPORT TOFILE dr_ir_instrlist.h */
DR_UNS_API
/**
 * If the first instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands it into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.  Then returns the new first instr.
 */
instr_t*
instrlist_first_expanded(dcontext_t *dcontext, instrlist_t *ilist);

DR_UNS_API
/**
 * If the last instr is at Level 0 (i.e., a bundled group of instrs as raw bits),
 * expands it into a sequence of Level 1 instrs using decode_raw() which
 * are added in place to ilist.  Then returns the new last instr.
 */
instr_t*
instrlist_last_expanded(dcontext_t *dcontext, instrlist_t *ilist);

DR_UNS_API
/**
 * Brings all instrs in ilist up to the decode_cti level, and
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
instrlist_decode_cti(dcontext_t *dcontext, instrlist_t *ilist);
/* DR_API EXPORT TOFILE dr_ir_instr.h */

/***********************************************************************/
/* utility functions */

DR_API
/**
 * Shrinks all registers not used as addresses, and all immed integer and
 * address sizes, to 16 bits.
 * Does not shrink DR_REG_ESI or DR_REG_EDI used in string instructions.
 */
void 
instr_shrink_to_16_bits(instr_t *instr);

/* DR_API EXPORT BEGIN */
#ifdef X64
/* DR_API EXPORT END */
DR_API
/**
 * Shrinks all registers, including addresses, and all immed integer and
 * address sizes, to 32 bits.
 *
 * \note For 64-bit DR builds only.
 */
void 
instr_shrink_to_32_bits(instr_t *instr);
/* DR_API EXPORT BEGIN */
#endif
/* DR_API EXPORT END */

DR_API
/**
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff at least one of \p instr's operands references a
 * register that overlaps \p reg.
 *
 * Returns false for multi-byte nops with an operand using reg.
 */
bool
instr_uses_reg(instr_t *instr, reg_id_t reg);

DR_API
/**
 * Returns true iff at least one of \p instr's operands references a floating
 * point register.
 */
bool 
instr_uses_fp_reg(instr_t *instr);

DR_API
/**
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff at least one of \p instr's source operands references \p reg.
 *
 * Returns false for multi-byte nops with a source operand using reg.
 *
 * \note Use instr_reads_from_reg() to also consider addressing
 * registers in destination operands.
 */
bool
instr_reg_in_src(instr_t *instr, reg_id_t reg);

DR_API
/**
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff at least one of \p instr's destination operands references \p reg.
 */
bool 
instr_reg_in_dst(instr_t *instr, reg_id_t reg);

DR_API
/**
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff at least one of \p instr's destination operands is
 * a register operand for a register that overlaps \p reg.
 */
bool 
instr_writes_to_reg(instr_t *instr, reg_id_t reg);

DR_API
/**
 * Assumes that reg is a DR_REG_ constant.
 * Returns true iff at least one of instr's operands reads
 * from a register that overlaps reg (checks both source operands
 * and addressing registers used in destination operands).
 *
 * Returns false for multi-byte nops with an operand using reg.
 */
bool 
instr_reads_from_reg(instr_t *instr, reg_id_t reg);

DR_API 
/**
 * Assumes that \p reg is a DR_REG_ constant.
 * Returns true iff at least one of \p instr's destination operands is
 * the same register (not enough to just overlap) as \p reg.
 */
bool
instr_writes_to_exact_reg(instr_t *instr, reg_id_t reg);

DR_API
/**
 * Replaces all instances of \p old_opnd in \p instr's source operands with
 * \p new_opnd (uses opnd_same() to detect sameness).
 */
bool 
instr_replace_src_opnd(instr_t *instr, opnd_t old_opnd, opnd_t new_opnd);

DR_API
/**
 * Returns true iff \p instr1 and \p instr2 have the same opcode, prefixes,
 * and source and destination operands (uses opnd_same() to compare the operands).
 */
bool 
instr_same(instr_t *instr1, instr_t *instr2);

DR_API
/**
 * Returns true iff any of \p instr's source operands is a memory reference.
 *
 * Returns false for multi-byte nops with a memory operand.
 */
bool
instr_reads_memory(instr_t *instr);

DR_API
/** Returns true iff any of \p instr's destination operands is a memory reference. */
bool 
instr_writes_memory(instr_t *instr);

/* DR_API EXPORT BEGIN */
#ifdef X64
/* DR_API EXPORT END */
DR_API
/**
 * Returns true iff any of \p instr's operands is a rip-relative memory reference. 
 *
 * \note For 64-bit DR builds only.
 */
bool 
instr_has_rel_addr_reference(instr_t *instr);

DR_API
/**
 * If any of \p instr's operands is a rip-relative memory reference, returns the
 * address that reference targets.  Else returns false.
 *
 * \note For 64-bit DR builds only.
 */
bool
instr_get_rel_addr_target(instr_t *instr, /*OUT*/ app_pc *target);

DR_API
/**
 * If any of \p instr's destination operands is a rip-relative memory
 * reference, returns the operand position.  If there is no such
 * destination operand, returns -1.
 *
 * \note For 64-bit DR builds only.
 */
int
instr_get_rel_addr_dst_idx(instr_t *instr);

DR_API
/**
 * If any of \p instr's source operands is a rip-relative memory
 * reference, returns the operand position.  If there is no such
 * source operand, returns -1.
 *
 * \note For 64-bit DR builds only.
 */
int
instr_get_rel_addr_src_idx(instr_t *instr);

/* We're not exposing the low-level rip_rel_pos routines directly to clients,
 * who should only use this level 1-3 feature via decode_cti + encode.
 */

/* Returns true iff instr's raw bits are valid and the offset within
 * those raw bits of a rip-relative displacement is set (to 0 if there
 * is no such displacement).
 */
bool
instr_rip_rel_valid(instr_t *instr);

/* Sets whether instr's rip-relative displacement offset is valid. */
void
instr_set_rip_rel_valid(instr_t *instr, bool valid);

/* Assumes that instr_rip_rel_valid() is true.
 * Returns the offset within the encoded bytes of instr of the
 * displacement used for rip-relative addressing; returns 0
 * if instr has no rip-relative operand.
 * There can be at most one rip-relative operand in one instruction.
 */
uint
instr_get_rip_rel_pos(instr_t *instr);

/* Sets the offset within instr's encoded bytes of instr's
 * rip-relative displacement (the offset should be 0 if there is no
 * rip-relative operand) and marks it valid.  \p pos must be less
 * than 256.
 */
void
instr_set_rip_rel_pos(instr_t *instr, uint pos);
/* DR_API EXPORT BEGIN */
#endif /* X64 */
/* DR_API EXPORT END */

/* not exported: for PR 267260 */
bool
instr_is_our_mangling(instr_t *instr);

/* Sets whether instr came from our mangling. */
void
instr_set_our_mangling(instr_t *instr, bool ours);


DR_API
/**
 * Returns NULL if none of \p instr's operands is a memory reference.
 * Otherwise, returns the effective address of the first memory operand
 * when the operands are considered in this order: destinations and then
 * sources.  The address is computed using the passed-in registers.
 * \p mc->flags must include DR_MC_CONTROL and DR_MC_INTEGER.
 */
app_pc
instr_compute_address(instr_t *instr, dr_mcontext_t *mc);

app_pc
instr_compute_address_priv(instr_t *instr, priv_mcontext_t *mc);

DR_API
/**
 * Performs address calculation in the same manner as
 * instr_compute_address() but handles multiple memory operands.  The
 * \p index parameter should be initially set to 0 and then
 * incremented with each successive call until this routine returns
 * false, which indicates that there are no more memory operands.  The
 * address of each is computed in the same manner as
 * instr_compute_address() and returned in \p addr; whether it is a
 * write is returned in \p is_write.  Either or both OUT variables can
 * be NULL.
 * \p mc->flags must include DR_MC_CONTROL and DR_MC_INTEGER.
 */
bool
instr_compute_address_ex(instr_t *instr, dr_mcontext_t *mc, uint index,
                         OUT app_pc *addr, OUT bool *write);

DR_API
/**
 * Performs address calculation in the same manner as
 * instr_compute_address_ex() with additional information
 * of which opnd is used for address computation returned
 * in \p pos. If \p pos is NULL, it is the same as 
 * instr_compute_address_ex().
 */
bool
instr_compute_address_ex_pos(instr_t *instr, dr_mcontext_t *mc, uint index,
                             OUT app_pc *addr, OUT bool *is_write,
                             OUT uint *pos);

bool
instr_compute_address_ex_priv(instr_t *instr, priv_mcontext_t *mc, uint index,
                              OUT app_pc *addr, OUT bool *write, OUT uint *pos);

DR_API
/**
 * Calculates the size, in bytes, of the memory read or write of \p instr.
 * If \p instr does not reference memory, or is invalid, returns 0.
 * If \p instr is a repeated string instruction, considers only one iteration.
 */
uint
instr_memory_reference_size(instr_t *instr);

DR_API
/** 
 * \return a pointer to user-controlled data fields in a label instruction.
 * These fields are available for use by clients for their own purposes.
 * Returns NULL if \p instr is not a label instruction.
 * \note These data fields are copied (shallowly) across instr_clone().
 */
dr_instr_label_data_t *
instr_get_label_data_area(instr_t *instr);

/* DR_API EXPORT TOFILE dr_ir_utils.h */
/* DR_API EXPORT BEGIN */

/***************************************************************************
 * DECODE / DISASSEMBLY ROUTINES
 */
/* DR_API EXPORT END */

DR_API
/**
 * Calculates the size, in bytes, of the memory read or write of
 * the instr at \p pc.  If the instruction is a repeating string instruction,
 * considers only one iteration.
 * Returns the pc of the following instruction.
 * If the instruction at \p pc does not reference memory, or is invalid, 
 * returns NULL.
 */
app_pc
decode_memory_reference_size(dcontext_t *dcontext, app_pc pc, uint *size_in_bytes);

/* DR_API EXPORT TOFILE dr_ir_instr.h */
DR_API
/**
 * Returns true iff \p instr is an IA-32/AMD64 "mov" instruction: either OP_mov_st,
 * OP_mov_ld, OP_mov_imm, OP_mov_seg, or OP_mov_priv.
 */
bool 
instr_is_mov(instr_t *instr);

DR_API
/**
 * Returns true iff \p instr's opcode is OP_call, OP_call_far, OP_call_ind,
 * or OP_call_far_ind.
 */
bool 
instr_is_call(instr_t *instr);

DR_API
/** Returns true iff \p instr's opcode is OP_call or OP_call_far. */
bool 
instr_is_call_direct(instr_t *instr);

DR_API
/** Returns true iff \p instr's opcode is OP_ret, OP_ret_far, or OP_iret. */
bool 
instr_is_return(instr_t *instr);

DR_API
/**
 * Returns true iff \p instr is a control transfer instruction of any kind
 * This includes OP_jcc, OP_jcc_short, OP_loop*, OP_jecxz, OP_call*, and OP_jmp*.
 */
bool 
instr_is_cti(instr_t *instr);

DR_API
/**
 * Returns true iff \p instr is a control transfer instruction that takes an
 * 8-bit offset: OP_loop*, OP_jecxz, OP_jmp_short, or OP_jcc_short
 */
#ifdef UNSUPPORTED_API
/**
 * This routine does NOT try to decode an opcode in a Level 1 or Level
 * 0 routine, and can thus be called on Level 0 routines.  
 */
#endif
bool 
instr_is_cti_short(instr_t *instr);

DR_API
/** Returns true iff \p instr is one of OP_loop* or OP_jecxz. */
bool 
instr_is_cti_loop(instr_t *instr);

DR_API
/**
 * Returns true iff \p instr's opcode is OP_loop* or OP_jecxz and instr has
 * been transformed to a sequence of instruction that will allow a 32-bit
 * offset.
 * If \p pc != NULL, \p pc is expected to point the the beginning of the encoding of
 * \p instr, and the following instructions are assumed to be encoded in sequence
 * after \p instr.
 * Otherwise, the encoding is expected to be found in \p instr's allocated bits.
 */
#ifdef UNSUPPORTED_API
/**
 * This routine does NOT try to decode an opcode in a Level 1 or Level
 * 0 routine, and can thus be called on Level 0 routines.  
 */
#endif
bool 
instr_is_cti_short_rewrite(instr_t *instr, byte *pc);

byte *
remangle_short_rewrite(dcontext_t *dcontext, instr_t *instr, byte *pc, app_pc target);

DR_API
/**
 * Returns true iff \p instr is a conditional branch
 */
bool 
instr_is_cbr(instr_t *instr);

DR_API
/**
 * Returns true iff \p instr is a multi-way (indirect) branch: OP_jmp_ind,
 * OP_call_ind, OP_ret, OP_jmp_far_ind, OP_call_far_ind, OP_ret_far, or
 * OP_iret.
 */
bool 
instr_is_mbr(instr_t *instr);

DR_API
/**
 * Returns true iff \p instr is an unconditional direct branch: OP_jmp,
 * OP_jmp_short, or OP_jmp_far.
 */
bool 
instr_is_ubr(instr_t *instr);

DR_API
/**
 * Returns true iff \p instr is a near unconditional direct branch: OP_jmp,
 * or OP_jmp_short.
 */
bool 
instr_is_near_ubr(instr_t *instr);

DR_API
/**
 * Returns true iff \p instr is a far control transfer instruction: OP_jmp_far,
 * OP_call_far, OP_jmp_far_ind, OP_call_far_ind, OP_ret_far, or OP_iret.
 */
bool 
instr_is_far_cti(instr_t *instr);

DR_API
/** Returns true if \p instr is an absolute call or jmp that is far. */
bool 
instr_is_far_abs_cti(instr_t *instr);

DR_API
/**
 * Returns true iff \p instr is used to implement system calls: OP_int with a
 * source operand of 0x80 on linux or 0x2e on windows, or OP_sysenter,
 * or OP_syscall, or #instr_is_wow64_syscall() for WOW64.
 */
bool 
instr_is_syscall(instr_t *instr);

/* DR_API EXPORT BEGIN */
#ifdef WINDOWS 
/* DR_API EXPORT END */
DR_API
/**
 * Returns true iff \p instr is the indirect transfer from the 32-bit
 * ntdll.dll to the wow64 system call emulation layer.  This
 * instruction will also return true for instr_is_syscall, as well as
 * appear as an indirect call, so clients modifying indirect calls may
 * want to avoid modifying this type.
 *
 * \note Windows-only
 */
bool
instr_is_wow64_syscall(instr_t *instr);
/* DR_API EXPORT BEGIN */
#endif
/* DR_API EXPORT END */

DR_API
/**
 * Returns true iff \p instr is a prefetch instruction: OP_prefetchnta,
 * OP_prefetchnt0, OP_prefetchnt1, OP_prefetchnt2, OP_prefetch, or
 * OP_prefetchw.
 */
bool 
instr_is_prefetch(instr_t *instr);

DR_API
/**
 * Tries to identify common cases of moving a constant into either a
 * register or a memory address.
 * Returns true and sets \p *value to the constant being moved for the following
 * cases: mov_imm, mov_st, and xor where the source equals the destination.
 */
bool 
instr_is_mov_constant(instr_t *instr, ptr_int_t *value);

DR_API
/** Returns true iff \p instr is a floating point instruction. */
bool 
instr_is_floating(instr_t *instr);

/* DR_API EXPORT BEGIN */
/**
 * Indicates which type of floating-point operation and instruction performs.
 */
typedef enum {
    DR_FP_STATE,   /**< Loads, stores, or queries general floating point state. */
    DR_FP_MOVE,    /**< Moves floating point values from one location to another. */
    DR_FP_CONVERT, /**< Converts to or from floating point values. */
    DR_FP_MATH,    /**< Performs arithmetic or conditional operations. */
} dr_fp_type_t;
/* DR_API EXPORT END */

DR_API
/**
 * Returns true iff \p instr is a floating point instruction.
 * @param[in] instr  The instruction to query
 * @param[out] type  If the return value is true and \p type is
 *   non-NULL, the type of the floating point operation is written to \p type.
 */
bool 
instr_is_floating_ex(instr_t *instr, dr_fp_type_t *type);

DR_API
/** Returns true iff \p instr is part of Intel's MMX instructions. */
bool 
instr_is_mmx(instr_t *instr);

DR_API
/** Returns true iff \p instr is part of Intel's SSE or SSE2 instructions. */
bool 
instr_is_sse_or_sse2(instr_t *instr);

DR_API
/** Returns true iff \p instr is a "mov $imm -> (%esp)". */
bool 
instr_is_mov_imm_to_tos(instr_t *instr);

DR_API
/** Returns true iff \p instr is a label meta-instruction. */
bool 
instr_is_label(instr_t *instr);

DR_API
/** Returns true iff \p instr is an "undefined" instruction (ud2) */
bool 
instr_is_undefined(instr_t *instr);

DR_API
/**
 * Assumes that \p instr's opcode is OP_int and that either \p instr's
 * operands or its raw bits are valid.
 * Returns the first source operand if \p instr's operands are valid,
 * else if \p instr's raw bits are valid returns the first raw byte.
 */
int 
instr_get_interrupt_number(instr_t *instr);

DR_API
/**
 * Assumes that \p instr is a conditional branch instruction
 * Reverses the logic of \p instr's conditional
 * e.g., changes OP_jb to OP_jnb.
 * Works on cti_short_rewrite as well.
 */
void 
instr_invert_cbr(instr_t *instr);

/* PR 266292 */
DR_API
/**
 * Assumes that instr is a meta instruction (!instr_ok_to_mangle())
 * and an instr_is_cti_short() (8-bit reach).  Converts instr's opcode
 * to a long form (32-bit reach).  If instr's opcode is OP_loop* or
 * OP_jecxz, converts it to a sequence of multiple instructions (which
 * is different from instr_is_cti_short_rewrite()).  Each added instruction
 * is marked !instr_ok_to_mangle().
 * Returns the long form of the instruction, which is identical to \p instr
 * unless \p instr is OP_loop* or OP_jecxz, in which case the return value
 * is the final instruction in the sequence, the one that has long reach.
 * \note DR automatically converts non-meta short ctis to long form.
 */
instr_t *
instr_convert_short_meta_jmp_to_long(dcontext_t *dcontext, instrlist_t *ilist,
                                     instr_t *instr);

DR_API
/** 
 * Given \p eflags, returns whether or not the conditional branch, \p
 * instr, would be taken.
 */
bool
instr_jcc_taken(instr_t *instr, reg_t eflags);

/* Given a machine state, returns whether or not the cbr instr would be taken
 * if the state is before execution (pre == true) or after (pre == false).
 * (not exported since machine state isn't)
 */
bool
instr_cbr_taken(instr_t *instr, priv_mcontext_t *mcontext, bool pre);

DR_API
/**
 * Converts a cmovcc opcode \p cmovcc_opcode to the OP_jcc opcode that
 * tests the same bits in eflags.
 */
int
instr_cmovcc_to_jcc(int cmovcc_opcode);

DR_API
/**
 * Given \p eflags, returns whether or not the conditional move
 * instruction \p instr would execute the move.  The conditional move
 * can be an OP_cmovcc or an OP_fcmovcc instruction.
 */
bool
instr_cmovcc_triggered(instr_t *instr, reg_t eflags);

/* utility routines that are in optimize.c */
opnd_t 
instr_get_src_mem_access(instr_t *instr);

void 
loginst(dcontext_t *dcontext, uint level, instr_t *instr, const char *string);

void 
logopnd(dcontext_t *dcontext, uint level, opnd_t opnd, const char *string);

DR_API
/**
 * Returns true if \p instr is one of a class of common nops.
 * currently checks:
 * - nop
 * - nop reg/mem
 * - xchg reg, reg
 * - mov reg, reg
 * - lea reg, (reg)
 */
bool 
instr_is_nop(instr_t *instr);

DR_UNS_API
/**
 * Convenience routine to create a nop of a certain size.  If \p raw
 * is true, sets raw bytes rather than filling in the operands or opcode.
 */
instr_t *
instr_create_nbyte_nop(dcontext_t *dcontext, uint num_bytes, bool raw);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode and no sources or destinations.
 */
instr_t *
instr_create_0dst_0src(dcontext_t *dcontext, int opcode, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode and a single source (\p src).
 */
instr_t *
instr_create_0dst_1src(dcontext_t *dcontext, int opcode,
                       opnd_t src, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode and two sources (\p src1, \p src2).
 */
instr_t *
instr_create_0dst_2src(dcontext_t *dcontext, int opcode,
                       opnd_t src1, opnd_t src2, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated
 * on the thread-local heap with opcode \p opcode and three sources
 * (\p src1, \p src2, \p src3).
 */
instr_t * 
instr_create_0dst_3src(dcontext_t *dcontext, int opcode,
                       opnd_t src1, opnd_t src2, opnd_t src3, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode and one destination (\p dst).
 */
instr_t *
instr_create_1dst_0src(dcontext_t *dcontext, int opcode,
                       opnd_t dst, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode, one destination(\p dst),
 * and one source (\p src).
 */
instr_t *
instr_create_1dst_1src(dcontext_t *dcontext, int opcode,
                       opnd_t dst, opnd_t src, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode, one destination (\p dst),
 * and two sources (\p src1, \p src2).
 */
instr_t *
instr_create_1dst_2src(dcontext_t *dcontext, int opcode,
                       opnd_t dst, opnd_t src1, opnd_t src2, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode, one destination (\p dst),
 * and three sources (\p src1, \p src2, \p src3).
 */
instr_t *
instr_create_1dst_3src(dcontext_t *dcontext, int opcode,
                       opnd_t dst, opnd_t src1, opnd_t src2, opnd_t src3, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode, one destination (\p dst),
 * and five sources (\p src1, \p src2, \p src3, \p src4, \p src5).
 */
instr_t * 
instr_create_1dst_5src(dcontext_t *dcontext, int opcode,
                       opnd_t dst, opnd_t src1, opnd_t src2, opnd_t src3,
                       opnd_t src4, opnd_t src5, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode, two destinations (\p dst1, \p dst2)
 * and no sources.
 */
instr_t *
instr_create_2dst_0src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode, two destinations (\p dst1, \p dst2)
 * and one source (\p src).
 */
instr_t *
instr_create_2dst_1src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t src, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode, two destinations (\p dst1, \p dst2)
 * and two sources (\p src1, \p src2).
 */
instr_t *
instr_create_2dst_2src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t src1, opnd_t src2, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode, two destinations (\p dst1, \p dst2)
 * and three sources (\p src1, \p src2, \p src3).
 */
instr_t *
instr_create_2dst_3src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2,
                       opnd_t src1, opnd_t src2, opnd_t src3, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated on the
 * thread-local heap with opcode \p opcode, two destinations (\p dst1, \p dst2)
 * and four sources (\p src1, \p src2, \p src3, \p src4).
 */
instr_t *
instr_create_2dst_4src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2,
                       opnd_t src1, opnd_t src2, opnd_t src3, opnd_t src4, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated
 * on the thread-local heap with opcode \p opcode, three destinations
 * (\p dst1, \p dst2, \p dst3) and no sources.
 */
instr_t *
instr_create_3dst_0src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated
 * on the thread-local heap with opcode \p opcode, three destinations
 * (\p dst1, \p dst2, \p dst3) and three sources 
 * (\p src1, \p src2, \p src3).
 */
instr_t *
instr_create_3dst_3src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3,
                       opnd_t src1, opnd_t src2, opnd_t src3, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated
 * on the thread-local heap with opcode \p opcode, three destinations
 * (\p dst1, \p dst2, \p dst3) and four sources 
 * (\p src1, \p src2, \p src3, \p src4).
 */
instr_t *
instr_create_3dst_4src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3,
                       opnd_t src1, opnd_t src2, opnd_t src3, opnd_t src4, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated
 * on the thread-local heap with opcode \p opcode, three destinations
 * (\p dst1, \p dst2, \p dst3) and five sources
 * (\p src1, \p src2, \p src3, \p src4, \p src5).
 */
instr_t *
instr_create_3dst_5src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3,
                       opnd_t src1, opnd_t src2, opnd_t src3,
                       opnd_t src4, opnd_t src5, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated
 * on the thread-local heap with opcode \p opcode, four destinations
 * (\p dst1, \p dst2, \p dst3, \p dst4) and 1 source (\p src).
 */
instr_t *
instr_create_4dst_1src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3, opnd_t dst4,
                       opnd_t src, int cond);

DR_API
/**
 * Convenience routine that returns an initialized instr_t allocated
 * on the thread-local heap with opcode \p opcode, four destinations
 * (\p dst1, \p dst2, \p dst3, \p dst4) and four sources
 * (\p src1, \p src2, \p src3, \p src4).
 */
instr_t *
instr_create_4dst_4src(dcontext_t *dcontext, int opcode,
                       opnd_t dst1, opnd_t dst2, opnd_t dst3, opnd_t dst4,
                       opnd_t src1, opnd_t src2, opnd_t src3, opnd_t src4, int cond);

DR_API
/** Convenience routine that returns an initialized instr_t for OP_popa. */
instr_t *
instr_create_popa(dcontext_t *dcontext);

DR_API
/** Convenience routine that returns an initialized instr_t for OP_pusha. */
instr_t *
instr_create_pusha(dcontext_t *dcontext);

/* build instructions from raw bits */

DR_UNS_API
/**
 * Convenience routine that returns an initialized instr_t with invalid operands
 * and allocated raw bits with 1 byte (byte).
 */
instr_t *
instr_create_raw_1byte(dcontext_t *dcontext, byte byte);

DR_UNS_API
/**
 * Convenience routine that returns an initialized instr_t with invalid operands
 * and allocated raw bits with 2 bytes (byte1, byte2).
 */
instr_t *
instr_create_raw_2bytes(dcontext_t *dcontext, byte byte1, byte byte2);

DR_UNS_API
/**
 * Convenience routine that returns an initialized instr_t with invalid operands
 * and allocated raw bits with 3 bytes (byte1, byte2, byte3).
 */
instr_t *
instr_create_raw_3bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2, byte byte3);

DR_UNS_API
/**
 * Convenience routine that returns an initialized instr_t with invalid operands
 * and allocated raw bits with 4 bytes (byte1, byte2, byte3, byte4).
 */
instr_t *
instr_create_raw_4bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2, byte byte3, byte byte4);

DR_UNS_API
/**
 * Convenience routine that returns an initialized instr_t with invalid operands
 * and allocated raw bits with 5 bytes (byte1, byte2, byte3, byte4, byte5).
 */
instr_t *
instr_create_raw_5bytes(dcontext_t *dcontext, byte byte1,
                        byte byte2, byte byte3, byte byte4, byte byte5);

DR_UNS_API
/**
 * Convenience routine that returns an initialized instr_t with invalid operands
 * and allocated raw bits with 6 bytes (byte1, byte2, byte3, byte4, byte5, byte6).
 */
instr_t *
instr_create_raw_6bytes(dcontext_t *dcontext, byte byte1, byte byte2,
                        byte byte3, byte byte4, byte byte5, byte byte6);

DR_UNS_API
/**
 * Convenience routine that returns an initialized instr_t with invalid operands
 * and allocated raw bits with 7 bytes (byte1, byte2, byte3, byte4, byte5, byte6,
 * byte7).
 */
instr_t *
instr_create_raw_7bytes(dcontext_t *dcontext, byte byte1, byte byte2,
                        byte byte3, byte byte4, byte byte5,
                        byte byte6, byte byte7);

DR_UNS_API
/**
 * Convenience routine that returns an initialized instr_t with invalid operands
 * and allocated raw bits with 7 bytes (byte1, byte2, byte3, byte4, byte5, byte6,
 * byte7, byte8).
 */
instr_t *
instr_create_raw_8bytes(dcontext_t *dcontext, byte byte1, byte byte2,
                        byte byte3, byte byte4, byte byte5,
                        byte byte6, byte byte7, byte byte8);

opnd_t opnd_create_dcontext_field(dcontext_t *dcontext, int offs);
opnd_t opnd_create_dcontext_field_byte(dcontext_t *dcontext, int offs);
opnd_t opnd_create_dcontext_field_sz(dcontext_t *dcontext, int offs, opnd_size_t sz);
instr_t * instr_create_save_to_dcontext(instrlist_t *ilist, dcontext_t *dcontext, 
                                        reg_id_t reg, int offs, int where, instr_t* rel_instr, bool absolute);
instr_t * instr_create_save_immed_to_dcontext(dcontext_t *dcontext, int immed, int offs);
void
instr_create_restore_from_dcontext(instrlist_t *ilist, dcontext_t *dcontext, reg_id_t reg,
                                   int offs, int where, instr_t* rel_instr, bool absolute);


/* basereg, if left as REG_NULL, is assumed to be xdi (xsi for upcontext) */
opnd_t
opnd_create_dcontext_field_via_reg_sz(dcontext_t *dcontext, reg_id_t basereg,
                                      int offs, opnd_size_t sz);
opnd_t opnd_create_dcontext_field_via_reg(dcontext_t *dcontext, reg_id_t basereg,
                                        int offs);

instr_t * instr_create_save_to_dc_via_reg(dcontext_t *dcontext, reg_id_t basereg,
                                        reg_id_t reg, int offs);
instr_t * instr_create_restore_from_dc_via_reg(dcontext_t *dcontext, reg_id_t basereg,
                                             reg_id_t reg, int offs);

instr_t * instr_create_jump_via_dcontext(dcontext_t *dcontext, int offs);
void
instr_create_save_dynamo_stack(instrlist_t *ilist, dcontext_t *dcontext, int where, instr_t* rel_instr);
void
instr_create_restore_dynamo_stack(instrlist_t *ilist, dcontext_t *dcontext, int where, instr_t* rel_instr, bool absolute);
#ifdef RETURN_STACK
instr_t * instr_create_restore_dynamo_return_stack(dcontext_t *dcontext);
instr_t * instr_create_save_dynamo_return_stack(dcontext_t *dcontext);
#endif
opnd_t update_dcontext_address(opnd_t op, dcontext_t *old_dcontext,
                             dcontext_t *new_dcontext);
opnd_t opnd_create_tls_slot(int offs);
/* For size, use a OPSZ_ value from decode.h, typically OPSZ_1 or OPSZ_4 */
opnd_t opnd_create_sized_tls_slot(int offs, opnd_size_t size);
bool instr_raw_is_tls_spill(byte *pc, reg_id_t reg, ushort offs);
bool instr_is_tls_spill(instr_t *instr, reg_id_t reg, ushort offs);
bool instr_is_tls_xcx_spill(instr_t *instr);
/* Pass REG_NULL to not care about the reg */
bool
instr_is_tls_restore(instr_t *instr, reg_id_t reg, ushort offs);
bool
instr_is_reg_spill_or_restore(dcontext_t *dcontext, instr_t *instr,
                              bool *tls, bool *spill, reg_id_t *reg);

/* N.B. : client meta routines (dr_insert_* etc.) should never use anything other
 * then TLS_XAX_SLOT unless the client has specified a slot to use as we let the
 * client use the rest. */
instr_t * instr_create_save_to_tls(dcontext_t *dcontext, reg_id_t reg, ushort offs);
instr_t * instr_create_restore_from_tls(dcontext_t *dcontext, reg_id_t reg, ushort offs);
/* For -x86_to_x64, we can spill to 64-bit extra registers (xref i#751). */
instr_t * instr_create_save_to_reg(dcontext_t *dcontext, reg_id_t reg1, reg_id_t reg2);
instr_t * instr_create_restore_from_reg(dcontext_t *dcontext,
                                        reg_id_t reg1, reg_id_t reg2);

#ifdef X64
byte *
instr_raw_is_rip_rel_lea(byte *pc, byte *read_end);
#endif

/* DR_API EXPORT TOFILE dr_ir_instr.h */
/* DR_API EXPORT BEGIN */


/****************************************************************************
 * CPSR 
 */
#define CPSR_READ_N   0x00000001 /**< Reads CF (Carry Flag). */             
#define CPSR_READ_Z   0x00000010 /**< Reads CF (Carry Flag). */             
#define CPSR_READ_C   0x00000100 /**< Reads CF (Carry Flag). */             
#define CPSR_READ_V   0x00001000 /**< Reads CF (Carry Flag). */             
#define CPSR_READ_Q   0x00010000 /**< Reads CF (Carry Flag). */             
#define CPSR_WRITE_N  0x00000002 /**< Writes CF (Carry Flag). */             
#define CPSR_WRITE_Z  0x00000020 /**< Writes CF (Carry Flag). */             
#define CPSR_WRITE_C  0x00000200 /**< Writes CF (Carry Flag). */             
#define CPSR_WRITE_V  0x00002000 /**< Writes CF (Carry Flag). */             
#define CPSR_WRITE_Q  0x00020000 /**< Writes CF (Carry Flag). */             

#define CPSR_READ_ALL  0x000007ff /**< Reads all flags. */    
#define CPSR_WRITE_ALL 0x003ff800 /**< Writes all flags. */   
/* 5 most common flags ("arithmetic flags"): N, Z, C, V, Q  */
/** Reads all 5 arithmetic flags (N, Z, C, V, Q). */ 
#define CPSR_READ_5    0x0000011f
/** Writes all 5 arithmetic flags (N, Z, C, V, Q). */ 
#define CPSR_WRITE_5   0x0008f800

//TODO SJF Check these work. Prob wont
/** Converts an CPSR_WRITE_* value to the corresponding CPSR_READ_* value. */
#define CPSR_WRITE_TO_READ(x) ((x) >> 11)
/** Converts an CPSR_READ_* value to the corresponding CPSR_WRITE_* value. */
#define CPSR_READ_TO_WRITE(x) ((x) << 11)

/**
 * SJF: CPSR flags
 *
 * 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0
 * N  Z  C  V  Q  IT IT J  | Reserved || GE[3:0] | |    IT[7:2]    | E A I F T | M[4:0]|
 */
enum {
    CPSR_N = 0x80000000, /** The bit in the cpsr of N(negative flag) */
    CPSR_Z = 0x40000000, /** The bit in the cpsr of Z(zero flag) */
    CPSR_C = 0x20000000, /** The bit in the cpsr of C(carry flag) */
    CPSR_V = 0x08000000, /** The bit in the cpsr of V(overflow flag) */
    CPSR_Q = 0x04000000, /** The bit in the cpsr of Q(cumulative saturation flag) */
    CPSR_E = 0x200,      /** The bit in the cpsr of E(endianess flag) */
    CPSR_T = 0x20,       /** The bit in the cpsr of T(thumb flag) */
};

/* DR_API EXPORT END */

/* even on x64, displacements are 32 bits, so we keep the "int" type and 4-byte size */
#define PC_RELATIVE_TARGET(addr) ( *((int *)(addr)) + (addr) + 4 )

enum { /* FIXME: vs RAW_OPCODE_* enum */
    FS_SEG_OPCODE        = 0x64,
    GS_SEG_OPCODE        = 0x65,

    /* For Windows, we piggyback on native TLS via gs for x64 and fs for x86.
     * For Linux, we steal a segment register, and so use fs for x86 (where
     * pthreads uses gs) and gs for x64 (where pthreads uses fs) (presumably
     * to avoid conflicts w/ wine).
     */
#ifdef X64
    TLS_SEG_OPCODE       = GS_SEG_OPCODE,
#else
    TLS_SEG_OPCODE       = FS_SEG_OPCODE,
#endif

};

/* length of our mangling of jecxz/loop*, beyond a possible addr prefix byte */
#define CTI_SHORT_REWRITE_LENGTH 9

/* This should be kept in sync w/ the defines in x86/x86.asm */
enum {
#ifdef X64
# ifdef LINUX
    /* SysV ABI calling convention */
    NUM_REGPARM          = 6,
    REGPARM_0            = REG_RDI,
    REGPARM_1            = REG_RSI,
    REGPARM_2            = REG_RDX,
    REGPARM_3            = REG_RCX,
    REGPARM_4            = REG_R8,
    REGPARM_5            = REG_R9,
    REGPARM_MINSTACK     = 0,
    REDZONE_SIZE         = 128,
# else
    /* Intel/Microsoft calling convention */
    NUM_REGPARM          = 4,
    REGPARM_0            = REG_RCX,
    REGPARM_1            = REG_RDX,
    REGPARM_2            = REG_R8,
    REGPARM_3            = REG_R9,
    REGPARM_MINSTACK     = 4*sizeof(XSP_SZ),
    REDZONE_SIZE         = 0,
# endif
    /* In fact, for Windows the stack pointer is supposed to be
     * 16-byte aligned at all times except in a prologue or epilogue.
     * The prologue will always adjust by 16*n+8 since push of retaddr
     * always makes stack pointer not 16-byte aligned.
     */
    REGPARM_END_ALIGN    = 16,
#else
    NUM_REGPARM          = 0,
    REGPARM_MINSTACK     = 0,
    REDZONE_SIZE         = 0,
    REGPARM_END_ALIGN    = sizeof(XSP_SZ),
#endif
};
extern const reg_id_t regparms[];

/* DR_API EXPORT TOFILE dr_ir_opcodes.h */
/* DR_API EXPORT BEGIN */

/****************************************************************************
 * OPCODES
 */
/**
 * @file dr_ir_opcodes.h
 * @brief Instruction opcode constants.
 */
#ifdef AVOID_API_EXPORT
/*
 * This enum corresponds with the array in decode_table.c
 * IF YOU CHANGE ONE YOU MUST CHANGE THE OTHER
 * The Perl script tools/x86opnums.pl is useful for re-numbering these
 * if you add or delete in the middle (feed it the array from decode_table.c).
 * When adding new instructions, be sure to update all of these places:
 *   1) decode_table op_instr array
 *   2) decode_table decoding table entries
 *   3) OP_ enum (here) via x86opnums.pl
 *   4) update OP_LAST at end of enum here
 *   5) decode_fast tables if necessary (they are conservative)
 *   6) instr_create macros
 *   7) suite/tests/api/ir* tests
 */
#endif
/** Opcode constants for use in the instr_t data structure. */
enum {
/*   0 */     OP_INVALID,  /* NULL, */ /**< INVALID opcode */
/*   1 */     OP_UNDECODED,  /* NULL, */ /**< UNDECODED opcode */
/*   2 */     OP_CONTD,    /* NULL, */ /**< CONTD opcode */
/*   3 */     OP_LABEL,    /* NULL, */ /**< LABEL opcode */

/*   4 */     OP_adc_imm,
/*   5 */     OP_adc_reg,
/*   6 */     OP_adc_rsr,
/*   7 */     OP_add_imm,
/*   8 */     OP_add_reg,
/*   9 */     OP_add_rsr,
/*   10 */     OP_add_sp_imm,
/*   11 */     OP_add_sp_reg,
/*   12 */     OP_adr,
/*   13 */     OP_and_imm,
/*   14 */     OP_and_reg,
/*   15 */     OP_and_rsr,
/*   16 */     OP_asr_imm,
/*   17 */     OP_asr_reg,
/*   18 */     OP_b,
/*   19 */     OP_bfc,
/*   20 */     OP_bfi,
/*   21 */     OP_bic_imm,
/*   22 */     OP_bic_reg,
/*   23 */     OP_bic_rsr,
/*   24 */     OP_bkpt,
/*   25 */     OP_bl,
/*   26 */     OP_blx_imm,
/*   27 */     OP_blx_reg,
/*   28 */     OP_bx,
/*   29 */     OP_bxj,
/*   30 */     OP_cbnz,
/*   31 */     op_cbz,
/*   32 */     OP_cdp,
/*   33 */     OP_cdp2,
/*   34 */     OP_clrex,
/*   35 */     OP_clz,
/*   36 */     OP_cmn_imm,
/*   37 */     OP_cmn_reg,
/*   38 */     OP_cmn_rsr,
/*   39 */     OP_cmp_imm,
/*   40 */     OP_cmp_reg,
/*   41 */     OP_cmp_rsr,
/*   42 */     OP_cps,
/*   43 */     OP_dbg,
/*   44 */     OP_dmb,
/*   45 */     OP_dsb,
/*   46 */     OP_eor_imm,
/*   47 */     OP_eor_reg,
/*   48 */     OP_eor_rsr,
/*   49 */     OP_isb,
/*   50 */     OP_it,
/*   51 */     OP_ldc_imm,
/*   52 */     OP_ldc2_imm,
/*   53 */     OP_ldc_lit,
/*   54 */     OP_ldc2_lit,
/*   55 */     OP_ldm,
/*   56 */     OP_ldmia,
/*   57 */     OP_ldmfd,
/*   58 */     OP_ldmda,
/*   59 */     OP_ldmfa,
/*   60 */     OP_ldmdb,
/*   61 */     OP_ldmea,
/*   62 */     OP_ldmib,
/*   63 */     OP_ldmed,
/*   64 */     OP_ldr_imm,
/*   65 */     OP_ldr_lit,
/*   66 */     OP_ldr_reg,
/*   67 */     OP_ldrb_imm,
/*   68 */     OP_ldrb_lit,
/*   69 */     OP_ldrb_reg,
/*   70 */     OP_ldrbt,
/*   71 */     OP_ldrd_imm,
/*   72 */     OP_ldrd_lit,
/*   73 */     OP_ldrd_reg,
/*   74 */     OP_ldrex,
/*   75 */     OP_ldrexb,
/*   76 */     OP_ldrexd,
/*   77 */     OP_ldrexh,
/*   78 */     OP_ldrh_imm,
/*   79 */     OP_ldrh_lit,
/*   80 */     OP_ldrh_reg,
/*   81 */     OP_ldrht,
/*   82 */     OP_ldrsb_imm,
/*   83 */     OP_ldrsb_lit,
/*   84 */     OP_ldrsb_reg,
/*   85 */     OP_ldrsbt,
/*   86 */     OP_ldrsh_imm,
/*   87 */     OP_ldrsh_lit,
/*   88 */     OP_ldrsh_reg,
/*   89 */     OP_ldrsht,
/*   90 */     OP_ldrt,
/*   91 */     OP_lsl_imm,
/*   92 */     OP_lsl_reg,
/*   93 */     OP_lsr_imm,
/*   94 */     OP_lsr_reg,
/*   95 */     OP_mcr,
/*   96 */     OP_mcr2,
/*   97 */     OP_mcrr,
/*   98 */     OP_mcrr2,
/*   99 */     OP_mla,
/*   100 */     OP_mls,
/*   101 */     OP_mov_imm,
/*   102 */     OP_mov_reg,
/*   103 */     OP_movt,
/*   104 */     OP_mrc,
/*   105 */     OP_mrc2,
/*   106 */     OP_mrrc,
/*   107 */     OP_mrrc2,
/*   108 */     OP_mrs,
/*   109 */     OP_msr_imm,
/*   110 */     OP_msr_reg,
/*   111 */     OP_mul,
/*   112 */     OP_mvn_imm,
/*   113 */     OP_mvn_reg,
/*   114 */     OP_mvn_rsr,
/*   115 */     OP_nop,
/*   116 */     OP_orn_imm,
/*   117 */     OP_orn_reg,
/*   118 */     OP_orr_imm,
/*   119 */     OP_orr_reg,
/*   120 */     OP_orr_rsr,
/*   121 */     OP_pkh,
/*   122 */     OP_pld_imm,
/*   123 */     OP_pldw_imm,
/*   124 */     OP_pld_lit,
/*   125 */     OP_pldw_lit,
/*   126 */     OP_pld_reg,
/*   127 */     OP_pldw_reg,
/*   128 */     OP_pli_imm,
/*   129 */     OP_pli_lit,
/*   130 */     OP_pli_reg,
/*   131 */     OP_pop,
/*   132 */     OP_push,
/*   133 */     OP_qadd,
/*   134 */     OP_qadd16,
/*   135 */     OP_qadd8,
/*   136 */     OP_qasx,
/*   137 */     OP_qdadd,
/*   138 */     OP_qdsub,
/*   139 */     OP_qsax,
/*   140 */     OP_qsub,
/*   141 */     OP_qsub16,
/*   142 */     OP_qsub8,
/*   143 */     OP_rbit,
/*   144 */     OP_rev,
/*   145 */     OP_rev16,
/*   146 */     OP_revsh,
/*   147 */     OP_rfe,
/*   148 */     OP_ror_imm,
/*   149 */     OP_ror_reg,
/*   150 */     OP_rrx,
/*   151 */     OP_rsb_imm,
/*   152 */     OP_rsb_reg,
/*   153 */     OP_rsb_rsr,
/*   154 */     OP_rsc_imm,
/*   155 */     OP_rsc_reg,
/*   156 */     OP_rsc_rsr,
/*   157 */     OP_sadd16,
/*   158 */     OP_sadd8,
/*   159 */     OP_sasx,
/*   160 */     OP_sbc_imm,
/*   161 */     OP_sbc_reg,
/*   162 */     OP_sbc_rsr,
/*   163 */     OP_sbfx,
/*   164 */     OP_sdiv,
/*   165 */     OP_sel,
/*   166 */     OP_setend,
/*   167 */     OP_sev,
/*   168 */     OP_shadd16,
/*   169 */     OP_shadd8,
/*   170 */     OP_shsax,
/*   171 */     OP_shsub16,
/*   172 */     OP_shsub8,
/*   173 */     OP_smlabb,
/*   174 */     OP_smlabt,
/*   175 */     OP_smlatb,
/*   176 */     OP_smlatt,
/*   177 */     OP_smlad,
/*   178 */     OP_smlal,
/*   179 */     OP_smlalbb,
/*   180 */     OP_smlalbt,
/*   181 */     OP_smlaltb,
/*   182 */     OP_smlaltt,
/*   183 */     OP_smlald,
/*   184 */     OP_smlawb,
/*   185 */     OP_smlawt,
/*   186 */     OP_smlsd,
/*   187 */     OP_smlsld,
/*   188 */     OP_smmla,
/*   189 */     OP_smmls,
/*   190 */     OP_smmul,
/*   191 */     OP_smuad,
/*   192 */     OP_smulbb,
/*   193 */     OP_smulbt,
/*   194 */     OP_smultb,
/*   195 */     OP_smultt,
/*   196 */     OP_smull,
/*   197 */     OP_smulwb,
/*   198 */     OP_smulwt,
/*   199 */     OP_smusd,
/*   200 */     OP_srs,
/*   201 */     OP_ssat,
/*   202 */     OP_ssat16,
/*   203 */     OP_ssax,
/*   204 */     OP_ssub16,
/*   205 */     OP_ssub8,
/*   206 */     OP_stc,
/*   207 */     OP_stc2,
/*   208 */     OP_stm,
/*   209 */     OP_stmia,
/*   210 */     OP_stmea,
/*   211 */     OP_stmda,
/*   212 */     OP_stmed,
/*   213 */     OP_stmdb,
/*   214 */     OP_stmfd,
/*   215 */     OP_stmib,
/*   216 */     OP_stmfa,
/*   217 */     OP_str_imm,
/*   218 */     OP_str_reg,
/*   219 */     OP_strb_imm,
/*   220 */     OP_strb_reg,
/*   221 */     OP_strbt,
/*   222 */     OP_strd_imm,
/*   223 */     OP_strd_reg,
/*   224 */     OP_strex,
/*   225 */     OP_strexb,
/*   226 */     OP_strexd,
/*   227 */     OP_strexh,
/*   228 */     OP_strh_imm,
/*   229 */     OP_strh_reg,
/*   230 */     OP_strht,
/*   231 */     OP_strt,
/*   232 */     OP_sub_imm,
/*   233 */     OP_sub_reg,
/*   234 */     OP_sub_rsr,
/*   235 */     OP_sub_sp_imm,
/*   236 */     OP_sub_sp_reg,
/*   237 */     OP_subs,
/*   238 */     OP_svc,
/*   239 */     OP_swp,
/*   240 */     OP_swpb,
/*   241 */     OP_sxtab,
/*   242 */     OP_sxtab16,
/*   243 */     OP_sxtah,
/*   244 */     OP_tbb,
/*   245 */     OP_tbh,
/*   246 */     OP_teq_imm,
/*   247 */     OP_teq_reg,
/*   248 */     OP_teq_rsr,
/*   249 */     OP_tst_imm,
/*   250 */     OP_tst_reg,
/*   251 */     OP_tst_rsr,
/*   252 */     OP_uadd16,
/*   253 */     OP_uadd8,
/*   254 */     OP_uasx,
/*   255 */     OP_ubfx,
/*   256 */     OP_udiv,
/*   257 */     OP_uhadd16,
/*   258 */     OP_uhadd8,
/*   259 */     OP_uhsax,
/*   260 */     OP_uhsub16,
/*   261 */     OP_uhsub8,
/*   262 */     OP_umaal,
/*   263 */     OP_umlal,
/*   264 */     OP_umull,
/*   265 */     OP_uqadd16,
/*   266 */     OP_uqadd8,
/*   267 */     OP_uqasx,
/*   268 */     OP_uqsax,
/*   269 */     OP_usub16,
/*   270 */     OP_usub8,
/*   271 */     OP_usad8,
/*   272 */     OP_usada8,
/*   273 */     OP_usat,
/*   274 */     OP_usat16,
/*   275 */     OP_usax,
/*   276 */     OP_uxtab,
/*   277 */     OP_uxtab16,
/*   278 */     OP_uxtah,
/*   279 */     OP_uxtb,
/*   280 */     OP_uxtb16,
/*   281 */     OP_uxth,
/*   282 */     OP_vaba,
/*   283 */     OP_vabal_int,
/*   284 */     OP_vabd_int,
/*   285 */     OP_vabd_flt,
/*   286 */     OP_vabs,
/*   287 */     OP_vacge,
/*   288 */     OP_vacgt,
/*   289 */     OP_vacle,
/*   290 */     OP_vaclt,
/*   291 */     OP_vadd_int,
/*   292 */     OP_vadd_flt,
/*   293 */     OP_vaddhn,
/*   294 */     OP_vaddl,
/*   295 */     OP_vaddw,
/*   296 */     OP_vand_imm,
/*   297 */     OP_vand_reg,
/*   298 */     OP_vbic_imm,
/*   299 */     OP_vbic_reg,
/*   300 */     OP_vbif,
/*   301 */     OP_vbsl,
/*   302 */     OP_vceq_reg,
/*   303 */     OP_vceq_imm,
/*   304 */     OP_vcge_reg,
/*   305 */     OP_vcge_imm,
/*   306 */     OP_vcgt_reg,
/*   307 */     OP_vcgt_imm,
/*   308 */     OP_vcle_reg,
/*   309 */     OP_vcle_imm,
/*   310 */     OP_vcls,
/*   311 */     OP_vclt_reg,
/*   312 */     OP_vclt_imm,
/*   313 */     OP_vclz,
/*   314 */     OP_vcmp,
/*   315 */     OP_vcmpe,
/*   316 */     OP_vcnt,
/*   317 */     OP_vcvt_flt_int_simd,
/*   318 */     OP_vcvt_flt_int_vfp,
/*   319 */     OP_vcvtr_flt_int_vfp,
/*   320 */     OP_vcvt_flt_fip_simd,
/*   321 */     OP_vcvt_dp_sp,
/*   322 */     OP_vcvt_hp_sp_simd,
/*   323 */     OP_vcvtb_hp_sp_vfp,
/*   324 */     OP_vcvtt_hp_sp_vfp,
/*   325 */     OP_vdiv,
/*   326 */     OP_vdup_scl,
/*   327 */     OP_vdup_reg,
/*   328 */     OP_veor,
/*   329 */     OP_vext,
/*   330 */     OP_vhadd,
/*   331 */     OP_vhsub,
/*   332 */     OP_vld1_mse,
/*   333 */     OP_vld1_se1,
/*   334 */     OP_vld1_sea,
/*   335 */     OP_vld2_m2es,
/*   336 */     OP_vld2_s2e1,
/*   337 */     OP_vld2_s2ea,
/*   338 */     OP_vld3_m3s,
/*   339 */     OP_vld3_se1,
/*   340 */     OP_vld3_sea,
/*   341 */     OP_vld4_m4es,
/*   342 */     OP_vld4_se1,
/*   343 */     OP_vld4_s4ea,
/*   344 */     OP_vldm,
/*   345 */     OP_vldr,
/*   346 */     OP_vmax_int,
/*   347 */     OP_vmin_int,
/*   348 */     OP_vmax_flt,
/*   349 */     OP_vmin_flt,
/*   350 */     OP_vmla_int,
/*   351 */     OP_vmlal_int,
/*   352 */     OP_vmls_int,
/*   353 */     OP_vmlsl_int,
/*   354 */     OP_vmla_flt,
/*   355 */     OP_vmls_flt,
/*   356 */     OP_vmla_scl,
/*   357 */     OP_vmlal_scl,
/*   358 */     OP_vmls_scl,
/*   359 */     OP_vmlsl_scl,
/*   360 */     OP_vmov_imm,
/*   361 */     OP_vmov_reg,
/*   362 */     OP_vmov_reg_scl,
/*   363 */     OP_vmov_scl_reg,
/*   364 */     OP_vmov_reg_sp,
/*   365 */     OP_vmov_2reg_2sp,
/*   366 */     OP_vmov_2reg_2dp,
/*   367 */     OP_vmovl,
/*   368 */     OP_vmovn,
/*   369 */     OP_vmrs,
/*   370 */     OP_vmsr,
/*   371 */     OP_vmul_int,
/*   372 */     OP_vmull_int,
/*   373 */     OP_vmul_flp,
/*   374 */     OP_vmul_scl,
/*   375 */     OP_vmull_scl,
/*   376 */     OP_vmvn_imm,
/*   377 */     OP_vmvn_reg,
/*   378 */     OP_vneg,
/*   379 */     OP_vnmla,
/*   380 */     OP_vnmls,
/*   381 */     OP_vnmul,
/*   382 */     OP_vorn_imm,
/*   383 */     OP_vorn_reg,
/*   384 */     OP_vorr_imm,
/*   385 */     OP_vorr_reg,
/*   386 */     OP_vpadal,
/*   387 */     OP_vpadd_int,
/*   388 */     OP_vpadd_flp,
/*   389 */     OP_vpaddl,
/*   390 */     OP_vpmax_int,
/*   391 */     OP_vpmin_int,
/*   392 */     OP_vpmax_flp,
/*   393 */     OP_vpmin_flp,
/*   394 */     OP_vpop,
/*   395 */     OP_vpush,
/*   396 */     OP_vqabs,
/*   397 */     OP_vqadd,
/*   398 */     OP_vqdmlal,
/*   399 */     OP_vqdmlsl,
/*   400 */     OP_vqdmulh,
/*   401 */     OP_vqdmull,
/*   402 */     OP_vqdmovn,
/*   403 */     OP_vqdmovun,
/*   404 */     OP_vqneq,
/*   405 */     OP_vqrdmulh,
/*   406 */     OP_vqrshl,
/*   407 */     OP_vqrshrn,
/*   408 */     OP_vqrshrun,
/*   409 */     OP_vqshl_reg,
/*   410 */     OP_vqshl_imm,
/*   411 */     OP_vqshlu_imm,
/*   412 */     OP_vqshrn,
/*   413 */     OP_vqshrun,
/*   414 */     OP_vqsub,
/*   415 */     OP_vqraddhn,
/*   416 */     OP_vqrecpe,
/*   417 */     OP_vqrecps,
/*   418 */     OP_vrev16,
/*   419 */     OP_vrev32,
/*   420 */     OP_vrev64,
/*   421 */     OP_vrhadd,
/*   422 */     OP_vrshl,
/*   423 */     OP_vrshr,
/*   424 */     OP_vrshrn,
/*   425 */     OP_vrsqrte,
/*   426 */     OP_vrsqrts,
/*   427 */     OP_vrsra,
/*   428 */     OP_vrsubhn,
/*   429 */     OP_vshl_imm,
/*   430 */     OP_vshl_reg,
/*   431 */     OP_vshll,
/*   432 */     OP_vshr,
/*   433 */     OP_vshrn,
/*   434 */     OP_vsli,
/*   435 */     OP_vsqrt,
/*   436 */     OP_vsra,
/*   437 */     OP_vsri,
/*   438 */     OP_vst1_mse,
/*   439 */     OP_vst1_se1,
/*   440 */     OP_vst2_m2e,
/*   441 */     OP_vst2_s2e1,
/*   442 */     OP_vst3_m3es,
/*   443 */     OP_vst3_s3e1,
/*   444 */     OP_vst4_m4es,
/*   445 */     OP_vst4_s4e1,
/*   446 */     OP_vstm,
/*   447 */     OP_vstr,
/*   448 */     OP_vsub_int,
/*   449 */     OP_vsub_flp,
/*   450 */     OP_vsubhn,
/*   451 */     OP_vsubl,
/*   452 */     OP_vsubw,
/*   453 */     OP_vswp,
/*   454 */     OP_vtbl,
/*   455 */     OP_vtbx,
/*   456 */     OP_vtrn,
/*   457 */     OP_vtst,
/*   458 */     OP_vuzp,
/*   459 */     OP_vzip,
/*   460 */     OP_wfe,
/*   461 */     OP_wfi,
/*   462 */     OP_yield,

/*   463 */     OP_AFTER_LAST_ARM, //SJF Sentinel value to border ARM opcodes

//SJF Add the thumb instrs here. Just duplicate the ARM equivs

/*   464 */     OP_T_add_reg,
/*   465 */     OP_T_adc_reg,
/*   466 */     OP_T_add_low_reg,
/*   467 */     OP_T_add_high_reg,
/*   468 */     OP_T_add_sp_imm,
/*   469 */     OP_T_add_imm_3,
/*   470 */     OP_T_add_imm_8,
/*   471 */     OP_T_and_reg,
/*   472 */     OP_T_asr_imm,
/*   473 */     OP_T_asr_reg,
/*   474 */     OP_T_b,
/*   475 */     OP_T_bic_reg,
/*   476 */     OP_T_bkpt,
/*   477 */     OP_T_blx_ref,
/*   478 */     OP_T_bx,
/*   479 */     OP_T_cbnz,
/*   480 */     OP_T_cbnz_2,
/*   481 */     OP_T_cbz,
/*   482 */     OP_T_cbz_2,
/*   483 */     OP_T_cmn_reg,
/*   484 */     OP_T_cmp_high_reg,
/*   485 */     OP_T_cmp_imm,
/*   486 */     OP_T_cmp_reg,
/*   487 */     OP_T_cps,
/*   488 */     OP_T_eor_reg,
/*   489 */     OP_T_it,
/*   490 */     OP_T_ldrb_imm,
/*   491 */     OP_T_ldrb_reg,
/*   492 */     OP_T_ldrh_imm,
/*   493 */     OP_T_ldrh_reg,
/*   494 */     OP_T_ldrsb_reg,
/*   495 */     OP_T_ldrsh_reg,
/*   496 */     OP_T_ldr_imm,
/*   497 */     OP_T_ldr_reg,
/*   498 */     OP_T_lsl_imm,
/*   499 */     OP_T_lsl_reg,
/*   500 */     OP_T_lsr_imm,
/*   501 */     OP_T_lsr_reg,
/*   502 */     OP_T_mov_imm,
/*   503 */     OP_T_mov_high_reg,
/*   504 */     OP_T_mov_low_reg,
/*   505 */     OP_T_mvn_reg,
/*   506 */     OP_T_mul,
/*   507 */     OP_T_nop,
/*   508 */     OP_T_orr_reg,
/*   509 */     OP_T_pop,
/*   510 */     OP_T_push,
/*   511 */     OP_T_rev,
/*   512 */     OP_T_rev16,
/*   513 */     OP_T_revsh,
/*   514 */     OP_T_ror_reg,
/*   515 */     OP_T_rsb_imm,
/*   516 */     OP_T_sbc_reg,
/*   517 */     OP_T_setend,
/*   518 */     OP_T_sev,
/*   519 */     OP_T_str_imm,
/*   520 */     OP_T_str_reg,
/*   521 */     OP_T_str_sp,
/*   522 */     OP_T_strb_imm,
/*   523 */     OP_T_strb_reg,
/*   524 */     OP_T_strh_imm,
/*   525 */     OP_T_strh_reg,
/*   526 */     OP_T_sub_sp_imm,
/*   527 */     OP_T_sub_imm_8,
/*   528 */     OP_T_sub_reg,
/*   529 */     OP_T_sub_imm_3,
/*   530 */     OP_T_svc,
/*   531 */     OP_T_sxth,
/*   532 */     OP_T_sxtb,
/*   533 */     OP_T_tst_reg,
/*   534 */     OP_T_uxtb,
/*   535 */     OP_T_uxth,
/*   536 */     OP_T_wfe,
/*   537 */     OP_T_wfi,
/*   538 */     OP_T_yield,
/*   539 */     OP_T_32_and_imm,
/*   540 */     OP_T_32_tst_imm,
/*   541 */     OP_T_32_bic_imm,
/*   542 */     OP_T_32_orr_imm,
/*   543 */     OP_T_32_mov_imm,
/*   544 */     OP_T_32_orn_imm,
/*   545 */     OP_T_32_mvn_imm,
/*   546 */     OP_T_32_eor_imm,
/*   547 */     OP_T_32_teq_imm,
/*   548 */     OP_T_32_add_imm,
/*   549 */     OP_T_32_cmn_imm,
/*   550 */     OP_T_32_adc_imm,
/*   551 */     OP_T_32_sbc_imm,
/*   552 */     OP_T_32_sub_imm,
/*   553 */     OP_T_32_cmp_imm,
/*   554 */     OP_T_32_rsb_imm,
/*   555 */     OP_T_32_add_wide,
/*   556 */     OP_T_32_adr,
/*   557 */     OP_T_32_mov_wide,
/*   558 */     OP_T_32_adr_2,
/*   559 */     OP_T_32_movt_top,
/*   560 */     OP_T_32_ssat,
/*   561 */     OP_T_32_ssat16,
/*   562 */     OP_T_32_sbfx,
/*   563 */     OP_T_32_bfi,
/*   564 */     OP_T_32_bfc,
/*   565 */     OP_T_32_usat16,
/*   566 */     OP_T_32_ubfx,
/*   567 */     OP_T_32_b,
/*   568 */     OP_T_32_msr_reg_app,
/*   569 */     OP_T_32_msr_reg_sys,
/*   570 */     OP_T_32_bxj,
/*   571 */     OP_T_32_subs,
/*   572 */     OP_T_32_mrs,
/*   573 */     OP_T_32_smc,
/*   574 */     OP_T_32_b_2,
/*   575 */     OP_T_32_blx_imm,
/*   576 */     OP_T_32_bl,
/*   577 */     OP_T_32_cps,
/*   578 */     OP_T_32_nop,
/*   579 */     OP_T_32_yield,
/*   580 */     OP_T_32_wfe,
/*   581 */     OP_T_32_wfi,
/*   582 */     OP_T_32_sev,
/*   583 */     OP_T_32_dbg,
/*   584 */     OP_T_32_enterx,
/*   585 */     OP_T_32_leavex,
/*   586 */     OP_T_32_clrex,
/*   587 */     OP_T_32_dsb,
/*   588 */     OP_T_32_dmb,
/*   589 */     OP_T_32_isb,
/*   590 */     OP_T_32_srs,
/*   591 */     OP_T_32_rfe,
/*   592 */     OP_T_32_stm,
/*   593 */     OP_T_32_stmia,
/*   594 */     OP_T_32_stmea,
/*   595 */     OP_T_32_ldm,
/*   596 */     OP_T_32_ldmia,
/*   597 */     OP_T_32_ldmfd,
/*   598 */     OP_T_32_pop,
/*   599 */     OP_T_32_stmdb,
/*   600 */     OP_T_32_stmfd,
/*   601 */     OP_T_32_push,
/*   602 */     OP_T_32_ldmdb,
/*   603 */     OP_T_32_ldmea,
/*   604 */     OP_T_32_strex,
/*   605 */     OP_T_32_ldrex,
/*   606 */     OP_T_32_strd_imm,
/*   607 */     OP_T_32_ldrd_imm,
/*   608 */     OP_T_32_ldrd_lit,
/*   609 */     OP_T_32_strexb,
/*   610 */     OP_T_32_strexh,
/*   611 */     OP_T_32_strexd,
/*   612 */     OP_T_32_tbb,
/*   613 */     OP_T_32_tbh,
/*   614 */     OP_T_32_ldrexb,
/*   615 */     OP_T_32_ldrexh,
/*   616 */     OP_T_32_ldrexd,
/*   617 */     OP_T_32_ldr_imm,
/*   618 */     OP_T_32_ldrt,
/*   619 */     OP_T_32_ldr_reg,
/*   620 */     OP_T_32_ldr_lit,
/*   621 */     OP_T_32_ldrh_lit,
/*   622 */     OP_T_32_ldrh_imm,
/*   623 */     OP_T_32_ldrht,
/*   624 */     OP_T_32_ldrh_reg,
/*   625 */     OP_T_32_ldrsh_imm,
/*   626 */     OP_T_32_ldrsht,
/*   627 */     OP_T_32_ldrsh_reg,
/*   628 */     OP_T_32_ldrb_lit,
/*   629 */     OP_T_32_ldrb_imm,
/*   630 */     OP_T_32_ldrbt,
/*   631 */     OP_T_32_ldrb_reg,
/*   632 */     OP_T_32_ldrsb_lit,
/*   633 */     OP_T_32_ldrsb_imm,
/*   634 */     OP_T_32_ldrsbt,
/*   635 */     OP_T_32_ldrsb,
/*   636 */     OP_T_32_pld_imm,
/*   637 */     OP_T_32_pld_lit,
/*   638 */     OP_T_32_pld_reg,
/*   639 */     OP_T_32_pli_imm,
/*   640 */     OP_T_32_pli_lit,
/*   641 */     OP_T_32_pli_reg,
/*   642 */     OP_T_32_strb_imm,
/*   643 */     OP_T_32_strbt,
/*   644 */     OP_T_32_strb_reg,
/*   645 */     OP_T_32_strh_imm,
/*   646 */     OP_T_32_strht,
/*   647 */     OP_T_32_strh_reg,
/*   648 */     OP_T_32_str_imm,
/*   649 */     OP_T_32_strt,
/*   650 */     OP_T_32_str_reg,
/*   651 */     OP_T_32_and_reg,
/*   652 */     OP_T_32_tst_reg,
/*   653 */     OP_T_32_bic_reg,
/*   654 */     OP_T_32_orr_reg,
/*   655 */     OP_T_32_mov_reg,
/*   656 */     OP_T_32_orn_reg,
/*   657 */     OP_T_32_mvn_reg,
/*   658 */     OP_T_32_eor_reg,
/*   659 */     OP_T_32_teq_reg,
/*   660 */     OP_T_32_pkh,
/*   661 */     OP_T_32_add_reg,
/*   662 */     OP_T_32_cmn_reg,
/*   663 */     OP_T_32_adc_reg,
/*   664 */     OP_T_32_sbc_reg,
/*   665 */     OP_T_32_sub_reg,
/*   666 */     OP_T_32_cmp_reg,
/*   667 */     OP_T_32_rsb_reg,
/*   668 */     OP_T_32_lsl_reg,
/*   669 */     OP_T_32_lsr_reg,
/*   670 */     OP_T_32_asr_reg,
/*   671 */     OP_T_32_ror_reg,
/*   672 */     OP_T_32_sxtah,
/*   673 */     OP_T_32_sxth,
/*   674 */     OP_T_32_uxtah,
/*   675 */     OP_T_32_uxth,
/*   676 */     OP_T_32_sxtab16,
/*   677 */     OP_T_32_sxtb16,
/*   678 */     OP_T_32_uxtab16,
/*   679 */     OP_T_32_uxtb16,
/*   680 */     OP_T_32_sxtab,
/*   681 */     OP_T_32_sxtb,
/*   682 */     OP_T_32_uxtab,
/*   683 */     OP_T_32_uxtb,
/*   684 */     OP_T_32_sadd16,
/*   685 */     OP_T_32_sasx,
/*   686 */     OP_T_32_ssax,
/*   687 */     OP_T_32_ssub16,
/*   688 */     OP_T_32_sadd8,
/*   689 */     OP_T_32_ssub8,
/*   690 */     OP_T_32_qadd16,
/*   691 */     OP_T_32_qasx,
/*   692 */     OP_T_32_qsax,
/*   693 */     OP_T_32_qsub16,
/*   694 */     OP_T_32_qadd8,
/*   695 */     OP_T_32_qsub8,
/*   696 */     OP_T_32_shadd16,
/*   697 */     OP_T_32_shasx,
/*   698 */     OP_T_32_shsax,
/*   699 */     OP_T_32_shsub16,
/*   700 */     OP_T_32_shadd8,
/*   701 */     OP_T_32_shsub8,
/*   702 */     OP_T_32_uadd16,
/*   703 */     OP_T_32_uasx,
/*   704 */     OP_T_32_usax,
/*   705 */     OP_T_32_usub16,
/*   706 */     OP_T_32_uadd8,
/*   707 */     OP_T_32_usub8,
/*   708 */     OP_T_32_uqadd16,
/*   709 */     OP_T_32_uqasx,
/*   710 */     OP_T_32_uqsax,
/*   711 */     OP_T_32_uqsub16,
/*   712 */     OP_T_32_uqadd8,
/*   713 */     OP_T_32_uqsub8,
/*   714 */     OP_T_32_uhadd16,
/*   715 */     OP_T_32_uhasx,
/*   716 */     OP_T_32_uhsax,
/*   717 */     OP_T_32_uhsub16,
/*   718 */     OP_T_32_uhadd8,
/*   719 */     OP_T_32_uhsub8,
/*   720 */     OP_T_32_qadd,
/*   721 */     OP_T_32_qdadd,
/*   722 */     OP_T_32_qsub,
/*   723 */     OP_T_32_qdsub,
/*   724 */     OP_T_32_rev,
/*   725 */     OP_T_32_rev16,
/*   726 */     OP_T_32_rbit,
/*   727 */     OP_T_32_revsh,
/*   728 */     OP_T_32_sel,
/*   729 */     OP_T_32_clz,
/*   730 */     OP_T_32_mla,
/*   731 */     OP_T_32_mul,
/*   732 */     OP_T_32_mls,
/*   733 */     OP_T_32_smlabb,
/*   734 */     OP_T_32_smlabt,
/*   735 */     OP_T_32_smlatb,
/*   736 */     OP_T_32_smlatt,
/*   737 */     OP_T_32_smulbb,
/*   738 */     OP_T_32_smulbt,
/*   739 */     OP_T_32_smultb,
/*   740 */     OP_T_32_smultt,
/*   741 */     OP_T_32_smlad,
/*   742 */     OP_T_32_smuad,
/*   743 */     OP_T_32_smlawb,
/*   744 */     OP_T_32_smlawt,
/*   745 */     OP_T_32_smulwb,
/*   746 */     OP_T_32_smulwt,
/*   747 */     OP_T_32_smlsd,
/*   748 */     OP_T_32_smusd,
/*   749 */     OP_T_32_smmla,
/*   750 */     OP_T_32_smmul,
/*   751 */     OP_T_32_smmls,
/*   752 */     OP_T_32_usad8,
/*   753 */     OP_T_32_usada8,
/*   754 */     OP_T_32_smull,
/*   755 */     OP_T_32_sdiv,
/*   756 */     OP_T_32_umull,
/*   757 */     OP_T_32_udiv,
/*   758 */     OP_T_32_smlal,
/*   759 */     OP_T_32_smlalbb,
/*   760 */     OP_T_32_smlalbt,
/*   761 */     OP_T_32_smlaltb,
/*   762 */     OP_T_32_smlaltt,
/*   763 */     OP_T_32_smlald,
/*   764 */     OP_T_32_smlsld,
/*   765 */     OP_T_32_umlal,
/*   766 */     OP_T_32_umaal,
/*   767 */     OP_T_32_stc,
/*   768 */     OP_T_32_stc2,
/*   769 */     OP_T_32_ldc_imm,
/*   770 */     OP_T_32_ldc_lit,
/*   771 */     OP_T_32_ldc2_imm,
/*   772 */     OP_T_32_ldc2_lit,
/*   773 */     OP_T_32_mcrr,
/*   774 */     OP_T_32_mcrr2,
/*   775 */     OP_T_32_mrrc,
/*   776 */     OP_T_32_mrrc2,
/*   777 */     OP_T_32_cdp,
/*   778 */     OP_T_32_cdp2,
/*   779 */     OP_T_32_mcr,
/*   780 */     OP_T_32_mcr2,
/*   781 */     OP_T_32_mrc,
/*   782 */     OP_T_32_mrc2,


//TODO add the Adv SIMD/VFP instructions for Thumb

    OP_AFTER_LAST,
    OP_FIRST = OP_adc_imm,            /**< First real opcode. */
    OP_LAST  = OP_AFTER_LAST - 1, /**< Last real opcode. */
};

/* alternative names */

/* undocumented opcodes */

/****************************************************************************/
/* DR_API EXPORT END */

#include "instr_inline.h"

#endif /* _INSTR_H_ */
