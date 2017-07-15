# 题目分析
根据题目提示，程序是一个`BrainF**k`的解释器，用IDA Pro静态分析程序，如下图：
[IDA1](!)
[IDA2](!)
在`do_brainfuck`中可以看到程序一共支持6种操作`>`,`<`,`+`,`-`,`.`,`,`，具体含义如下表：

| 操作|     含义     |
|----|--------------|
| >  | p += 1		|
| <  | p -= 1		|
| +  | (*p) += 1	|
| -  | (*p) -= 1	|
| .  | putchar(*p) 	|
| ,  | getchar(p)  	|
注：`p`是指向堆空间的一个指针

既然这个指针在堆中，那么它距离got表很近。
而上述的操作中正好有移动指针的操作，利用`>`,`<`前后移动指针就可以到达内存中任意区域，再利用`.`,`,`操作就可以实现对内存的读取与改写。
如下图：
[heap](!)
指针p距离GOT表中最后一个函数只有112字节，我们很容易实现对GOT表的覆写。

所以这道题目主要考察GOT覆写技术

# 解题思路
最终是要拿到一个shell，所以要想办法构造并执行`system("/bin/sh\0")`，`system`函数可以通过泄露内存得到，而`"/bin/sh"`只能从标准输入中得到，程序中有一个`fgets`函数，但是`fgets`到的数组用于在`do_brainfuck`中的buf用于覆写GOT表了，只能想别的办法在main函数中构造一个`gets`函数
[func](!)
这里挑选memset和fgets两个函数作为覆写对象正合适，原因如下：
 - puts函数不好控制参数，第一个参数为固定的字符串
 - memset的第一个参数正好可以存放我们输入的字符串`"/bin/sh"`
 - fgets紧随memset，并且第一个参数与memset相同

所以大致的思路为：

 - 将menset覆写为gets，从stdin中读入`"/bin/sh\0"`
 - 将fgets覆写为system，执行`system("/bin/sh\0")`获取shell

# 解题过程
 - 泄露putchar函数真实地址
 - 根据题目给的libc计算其他函数真实地址
 - 覆写GOT表中putchar函数为main函数地址
 - 覆写GOT表中fgets函数为system函数地址
 - 覆写GOT表中memset函数为gets函数地址
 - 返回main函数，getshell

# 解题脚本
```python

```