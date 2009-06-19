//  Test program for grader
//  Compile as gcc test.c -o test -DtestN -static, where N is the test number
//  and run as ./sandbox -t 1000 -m 8192 test (or whatever)
//  
//  Tests:
//  1 - Too much memory (large global)
//  2 - Too much memory (large single stack, will probably give SIGSEGV rather than memlimit)
//  3 - Too much memory (stack overflow from unbounded recursion)
//  4 - General silliness (try to dereference NULL)
//  5 - Divide by 0
//  6 - Timeout (infinite loop)
//  7 - Hangs waiting for input (please don't type anything to standard input)
//  8 - Tries to execute disallowed system call
//  No test enabled - Actually works, and returns 42
//
//  To run all the test cases as a batch, try this script: (assuming the sandbox is already compiled in the current dir)
//  for i in $(seq 1 9); do echo; echo $i; gcc test.c -Dtest$i -o test -static && ./sandbox -t 300 -m 4096 ./test; done
//
//  On my machine, it produces the following output:
//  1
//  M: Memory limit exceeded
//  t: 0 milliseconds of CPU time used
//  m: 4096 KB used (peak)
//  
//  2
//  S: SIGSEGV Segmentation fault
//  t: 0 milliseconds of CPU time used
//  m: 644 KB used (peak)
//  
//  3
//  M: Memory limit exceeded
//  t: 0 milliseconds of CPU time used
//  m: 4096 KB used (peak)
//  
//  4
//  S: SIGSEGV Segmentation fault
//  t: 0 milliseconds of CPU time used
//  m: 644 KB used (peak)
//  
//  5
//  S: SIGFPE Floating point exception
//  t: 0 milliseconds of CPU time used
//  m: 648 KB used (peak)
//  
//  6
//  T: Program timed out
//  t: 300 milliseconds of CPU time used
//  m: 644 KB used (peak)
//  
//  7
//  H: Program hung waiting for input
//  t: 0 milliseconds of CPU time used
//  m: 648 KB used (peak)
//  
//  8
//  X: fork (syscall #2) was called by the program (disallowed syscall)
//  t: 0 milliseconds of CPU time used
//  m: 648 KB used (peak)
//  
//  9
//  O: 42 was exit code
//  t: 0 milliseconds of CPU time used
//  m: 648 KB used (peak)


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
int na=1, nb=2;
void nop(){
  //This silly function is to prevent gcc optimising the stack overflow into an empty function
  if (na==nb)printf("fsda");
}
void stack_overflow(){
  stack_overflow();
  nop();
}
#ifdef test1
int bigarray[10000000];
#endif
int main(){
#ifdef test2
  int bofsd[10000000];
  bofsd[na]=nb;
  return bofsd[1000];
#endif
#ifdef test3
  stack_overflow();
#endif
#ifdef test4
  int* x = NULL;
  printf("Look what I found!!! %d", *x);
#endif
#ifdef test5
  //silly expression involving globals to defeat optimiser
  printf("Look at this!! %d", nb / (nb - 2 * na));
#endif
#ifdef test6
  for (;;)nop();
#endif
#ifdef test7
  int x;
  scanf("%d", x);
#endif
#ifdef test8
  fork();
#endif

  return 42; 
}
