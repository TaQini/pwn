# 动态调试

## pwngdb常用命令

`b *$rebase(0xabc) `

bins - chunk回收信息

heap - chunk信息

canary - TLS

search -8 0x12345678

cyclic 1000

dump memory



## 重载libc

 `LD_RELOAD` (挖坑，日后整理)



## 调试指定进程

```shell
$ gdb attach <pid>
```

若失败，可能是权限不够，试试用`sudo`



## PIE下断点

调试开启PIE保护的程序时，下断点可以使用`$rebase`

```shell
pwndbg> b *$rebase(0xAAAA)
```



## Pwntools.gdb执行多条指令

若想执行多条指令，可以使用`\n`连接多条指令：

```python
gdb.attach(p, "b *$rebase(0xAAAA)\n" + "c\n" + "si")
```



## pwngdb 堆相关指令

查看堆结构 [Ref.](https://github.com/SignorMercurio/MetasequoiaCTF/tree/master/Pwn/Summoner)

```shell
pwndbg> heapls
           ADDR             SIZE            STATUS
sbrk_base  0x56476bb24000
chunk      0x56476bb24000   0x1010          (inuse)
chunk      0x56476bb25010   0x20            (inuse)
chunk      0x56476bb25030   0x20            (inuse)
chunk      0x56476bb25050   0x20fb0         (top)
sbrk_end   0x56476bb46000
pwndbg> x/8gx 0x56476bb25010
0x56476bb25010:	0x0000000000000000	0x0000000000000021
0x56476bb25020:	0x000056476bb25040	0x0000000000000000
0x56476bb25030:	0x0000000000000000	0x0000000000000021
0x56476bb25040:	0x6161616161616161	0x0000000000000005
```

相关指令

> heap (查看堆详细内容) 
>
> bins  (查看bins)



## gdb不跟进新进程

遇到system, dup等创建新进程的函数时，不跟进

```
set follow-fork-mode parent
```

继续调试当前进程。