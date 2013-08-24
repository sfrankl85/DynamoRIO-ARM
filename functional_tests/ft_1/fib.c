/******************************************************************************

   MSc Adv. Computer Science: Computer Systems Engineering,
   Steven Frankl: 7247890,
   Functional Test 1: ft_1

   Test program based on Bruening fib.c program. Removed recursion and
   put fib function into a loop. Should test program loading and execution.

******************************************************************************/
   
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

//#include "tools.h"
#include <stdio.h>

int fib(int n) 
{
  double prev = -1;
  double result = 1;
  double sum;
  int i;
        
  for(i = 0;i <= n;++ i)
  {
    sum = result + prev;
    prev = result;
    result = sum;
  }
        
  return result;
}

int
main(int argc, char** argv) 
{
    int i, t;
    
//    INIT();
//    USE_USER32();

  printf( "%d\n" , fib(5));

/*
  printf( "%d\n" , fib(15));

  printf( "%d\n" , fib(25));
*/

// Do not print the values as want to avoid using shared libraries or syscalls.
//    printf("fib(%d)=%d\n", 5, fib(5));
//    printf("fib(%d)=%d\n", 15, fib(15));
//    printf("fib(%d)=%d\n", 25, fib(25));
}

/* 
It is amazing that with default options native=13s dr=12s

only when optimized differences show up in the other direction
$ cl /O2 -I.. fib.c
native=8s dr=11s   ITER=? DEPTH=?
 
$ cl /O2  /Zi fib.c -I.. /link /incremental:no user32.lib
*/
