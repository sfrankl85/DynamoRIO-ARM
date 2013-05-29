/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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

/* configure.cmake.h
 * processed by cmake to contain all configuration defines
 */
#ifndef _CONFIGURE_H_
#define _CONFIGURE_H_ 1

/* exposed options */
#define INTERNAL
-DINTERNAL
#define DEBUG
-DDEBUG
#define DRGUI_DEMO
-DDRGUI_DEMO
/* #undef STATIC_LIBRARY */

/* target */
/* #undef X64 */
/* Need both an ARM and X86 define */
#define ARM 
-DARM
/* #undef X86 */
/* #undef WINDOWS */
#define LINUX
-DLINUX
/* #undef VMKERNEL */
/* #undef MACOS */

/* set by high-level VMAP/VMSAFE/VPS configurations */
/* #undef PROGRAM_SHEPHERDING */
#define CLIENT_INTERFACE
-DCLIENT_INTERFACE
#define APP_EXPORTS
-DAPP_EXPORTS
/* #undef STRACE_CLIENT */
/* #undef HOT_PATCHING_INTERFACE */
/* #undef PROCESS_CONTROL */
/* #undef GBOP */

/* for use by developers */
#define KSTATS
-DKSTATS
/* #undef CALLPROF */
#ifdef CALLPROF
/* XXX: perhaps should rename CALLPROF cmake var to CALL_PROFILE */
# define CALL_PROFILE
-DCALL_PROFILE
#endif
/* #undef LINKCOUNT */
/* #undef PARAMS_IN_REGISTRY */

/* when packaging */
#define VERSION_NUMBER 4.0.
#define VERSION_COMMA_DELIMITED 4,0,
#define VERSION_NUMBER_INTEGER 400
#define OLDEST_COMPATIBLE_VERSION 400
/* #undef BUILD_NUMBER */
/* #undef UNIQUE_BUILD_NUMBER */
/* #undef CUSTOM_PRODUCT_NAME */

/* features */
/* #undef HAVE_FVISIBILITY */

/* typedef conflicts */
/* #undef DR_DO_NOT_DEFINE_bool */
/* #undef DR_DO_NOT_DEFINE_byte */
/* #undef DR_DO_NOT_DEFINE_int64 */
/* #undef DR_DO_NOT_DEFINE_MAX_MIN */
/* #undef DR_DO_NOT_DEFINE_sbyte */
#define DR_DO_NOT_DEFINE_uint
-DDR_DO_NOT_DEFINE_uint
/* #undef DR_DO_NOT_DEFINE_uint32 */
/* #undef DR_DO_NOT_DEFINE_uint64 */
#define DR_DO_NOT_DEFINE_ushort
-DDR_DO_NOT_DEFINE_ushort
#define DR__Bool_EXISTS
-DDR__Bool_EXISTS

/* Issue 20: we need to know lib dirs for cross-arch execve */
#define LIBDIR_X64 lib64
#define LIBDIR_X86 lib32

/* i#955: private loader search paths */
#define DR_RPATH_SUFFIX "drpath"

/* dependent defines */
/*
###################################
# definitions for conditional compilation
#
# Linux variants
#    $(D)HAVE_PROC_MAPS - set if /proc/self/maps is available
#      if not set: issues w/ mem queries from signal handler (PR 287309)
#    $(D)HAVE_TLS       - set if any form of ldt or gdt entry can be claimed
#      if not set: client reg spill slots won't work, and may hit asserts
#      after fork.
#    $(D)HAVE_SIGALTSTACK - set if SYS_sigaltstack is available
#    $(D)INIT_TAKE_OVER - libdynamorio.so init() takes over so no preload needed
# not supported but still in code because may be useful later
#    $(D)STEAL_REGISTER
#    $(D)DCONTEXT_IN_EDI
#    $(D)ASSUME_NORMAL_EFLAGS - (NEVER ON) (causes errors w/ Microsoft-compiled apps)
# internal studies, not for general use
#    $(D)SHARING_STUDY
#    $(D)FRAGMENT_SIZES_STUDY
#    $(D)FOOL_CPUID
#    $(D)NATIVE_RETURN - should clean this up, as well
#	NATIVE_RETURN_CALLDEPTH, NATIVE_RETURN_RET_IN_TRACES, 
#	NATIVE_RETURN_TRY_TO_PUT_APP_RETURN_PC_ON_STACK
#    $(D)LOAD_DYNAMO_DEBUGBREAK
# profiling
#    $(D)PROFILE_LINKCOUNT $(D)LINKCOUNT_64_BITS 
#    $(D)PROFILE_RDTSC 
#    $(D)PAPI - now deprecated
#    $(D)WINDOWS_PC_SAMPLE - on for all Windows builds
#    $(D)KSTATS - on for INTERNAL, DEBUG, and PROFILE builds, use KSTATS=1 for
# release builds
#    $(D)PROGRAM_SHEPHERDING -  (always ON)
#         currently turns on code origins checks and diagnostics, eventually will also turn
#         on return-after-call and other restricted control transfer features
#    $(D)RETURN_AFTER_CALL  - (always ON) return only to instructions after seen calls
#    $(D)RCT_IND_BRANCH     - (experimental) indirect branch only to address taken entry points
#    $(D)DGC_DIAGNOSTICS
#    $(D)CHECK_RETURNS_SSE2 (experimental security feature)
#    $(D)CHECK_RETURNS_SSE2_EMIT (experimental unfinished)
#    $(D)DIRECT_CALL_CHECK  (experimental unfinished)
#    $(D)SIMULATE_ATTACK    - simulate security violations
#    $(D)GBOP - generic buffer overflow prevention via hooking APIs
# optimization of application
#    $(D)SIDELINE
#    $(D)SIDELINE_COUNT_STUDY
#    $(D)LOAD_TO_CONST - around loadtoconst.c, $(D)LTC_STATS 

# optimization of dynamo
#    $(D)AVOID_EFLAGS  (uses instructions that don't modify flags) (defines ASSUME_NORMAL_EFLAGS)
#    $(D)RETURN_STACK
#    $(D)TRACE_HEAD_CACHE_INCR   (incompatible with security FIXME:?)
#    $(D)DISALLOW_CACHE_RESIZING (use as temporary hack when developing)
# transparency
#    $(D)NOLIBC = doesn't link libc on windows, currently uses ntdll.dll libc
#      functions, NOLIBC=0 causes the core to be linked against libc and kernel32.dll
# external interface
#    $(D)CLIENT_INTERFACE
#    $(D)DR_APP_EXPORTS
#    $(D)CUSTOM_EXIT_STUBS -- optional part of CLIENT_INTERFACE
#      we may want it for our own internal use too, though
#    $(D)CUSTOM_TRACES -- optional part of CLIENT_INTERFACE
#      has some sub-features that are aggressive and not supported by default:
#      $(D)CUSTOM_TRACES_RET_REMOVAL = support for removing inlined rets
#      $(D)CLIENT_SIDELINE = allows adaptive interface methods to be called 
#                            from other threads safetly, performance hit
#                            requires CLIENT_INTERFACE
#    $(D)UNSUPPORTED_API -- part of 0.9.4 MIT API but not supported in current API
#    $(D)NOT_DYNAMORIO_CORE - should be defined by non core components sharing our code

#    $(D)FANCY_COUNTDOWN - (NOT IMPLEMENTED) countdown messagebox

# debugging
#    $(D)DEBUG for debug builds
#    $(D)DEBUG_MEMORY (on for DEBUG)
#    $(D)STACK_GUARD_PAGE (on for DEBUG)
#    $(D)DEADLOCK_AVOIDANCE (on for DEBUG) - enforce total rank order on locks
#    $(D)MUTEX_CALLSTACK - enable collecting callstack info, requires DEADLOCK_AVOIDANCE
#    $(D)HEAP_ACCOUNTING (on for DEBUG)

#    $(D)INTERNAL for features that are not intended to reach customer hands
#    $(D)VERBOSE=1 for verbose debugging or in situations where normal DEBUG 

# statistics
#    $(D)HASHTABLE_STATISTICS - IBL table statistics

# target platforms
#    $(D)WINDOWS (avoid using _WIN32 used by cl)
#    $(D)LINUX 
#    note that in many cases we use the else of WINDOWS to mean LINUX and vice versa
#    we're just starting to add VMKERNEL and MACOS support
#    $(D)X86
#    $(D)X64

# support for running in x86 emulator on IA-64
#    $(D)IA32_ON_IA64

# build script provides these
#    $(D)BUILD_NUMBER (<64K == vmware's PRODUCT_BUILD_NUMBER)
#    $(D)UNIQUE_BUILD_NUMBER (== vmware's BUILD_NUMBER)
#    $(D)VERSION_NUMBER
#    $(D)VERSION_COMMA_DELIMITED

###################################
*/

/* only architecture we support (this is set for X64 as well) */
#define X86
-DX86

#ifdef WINDOWS
   /* we do not support linking to libc.  we should probably remove
    * this define from the code and eliminate it altogether.
    */
#  define NOLIBC
-DNOLIBC
#endif

#ifdef LINUX
#  define ASSEMBLE_WITH_GAS
-DASSEMBLE_WITH_GAS
#else
#  define ASSEMBLE_WITH_MASM
-DASSEMBLE_WITH_MASM
#endif

/* operating system */
#ifdef LINUX

#  ifdef VMKERNEL
#    define VMX86_SERVER
-DVMX86_SERVER
#    define USERLEVEL
-DUSERLEVEL
     /* PR 361894/388563: only on ESX4.1+ */
#    define HAVE_TLS
-DHAVE_TLS
#  else
#    ifdef MACOS
       /* FIXME NYI */
#      define MACOS
-DMACOS
#    else
       /* Linux */
       /* FIXME: use cmake to discover whether these are available */
#      define HAVE_PROC_MAPS
-DHAVE_PROC_MAPS
#      define HAVE_TLS
-DHAVE_TLS
#      define HAVE_SIGALTSTACK
-DHAVE_SIGALTSTACK
#    endif
#  endif

#  ifdef HAVE_FVISIBILITY
#    define USE_VISIBILITY_ATTRIBUTES
-DUSE_VISIBILITY_ATTRIBUTES
#  endif
#endif

#ifdef WINDOWS
#  define WINDOWS_PC_SAMPLE
-DWINDOWS_PC_SAMPLE
#endif

#ifdef PROGRAM_SHEPHERDING
#  define RETURN_AFTER_CALL
-DRETURN_AFTER_CALL
#  define RCT_IND_BRANCH
-DRCT_IND_BRANCH
#endif

#ifdef CLIENT_INTERFACE
   /* standard client interface features */
#  define DYNAMORIO_IR_EXPORTS
-DDYNAMORIO_IR_EXPORTS
#  define CUSTOM_TRACES
-DCUSTOM_TRACES
#  define CLIENT_SIDELINE
-DCLIENT_SIDELINE
   /* PR 200409: not part of our current API, xref PR 215179 on -pad_jmps
    * issues with CUSTOM_EXIT_STUBS
#  define CUSTOM_EXIT_STUBS
-DCUSTOM_EXIT_STUBS
#  define UNSUPPORTED_API
-DUNSUPPORTED_API
    */
#endif

#if defined(HOT_PATCHING_INTERFACE) && defined(CLIENT_INTERFACE)
#  define PROBE_API
-DPROBE_API
#endif

#if defined(PROGRAM_SHEPHERDING) && defined(CLIENT_INTERFACE)
/* used by libutil and tools */
#  define MF_API
-DMF_API
#  define PROBE_API
-DPROBE_API
#endif

#ifdef APP_EXPORTS
#  define DR_APP_EXPORTS
-DDR_APP_EXPORTS
#endif

/* FIXME: some GBOP hooks depend on hotp_only HOT_PATCHING_INTERFACE */

#ifdef DEBUG
   /* for bug fixing this is useful so we turn on for all debug builds */
#  define DEBUG_MEMORY
-DDEBUG_MEMORY
#  define STACK_GUARD_PAGE
-DSTACK_GUARD_PAGE
#  define HEAP_ACCOUNTING
-DHEAP_ACCOUNTING
#  define DEADLOCK_AVOIDANCE
-DDEADLOCK_AVOIDANCE
#  define MUTEX_CALLSTACK /* requires DEADLOCK_AVOIDANCE */
   /* even though only usable in all-private config useful in default builds */
#  define SHARING_STUDY
-DSHARING_STUDY
#  define HASHTABLE_STATISTICS
-DHASHTABLE_STATISTICS
#endif

#ifdef LINKCOUNT
#  define PROFILE_LINKCOUNT
-DPROFILE_LINKCOUNT
/* not bothering to support 32-bit: only if we start using it again */
#  define LINKCOUNT_64_BITS
-DLINKCOUNT_64_BITS
#endif

#endif /* _CONFIGURE_H_ */
