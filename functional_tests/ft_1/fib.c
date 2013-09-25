/******************************************************************************

   MSc Adv. Computer Science: Computer Systems Engineering,
   Steven Frankl: 7247890,
   Functional Test 1: ft_1

   Test program based on Bruening fib.c program. Removed recursion and
   put fib function into a loop. Should test program loading and execution.

******************************************************************************/
   
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
    
  printf( "%d\n" , fib(5));

}

