# Heap

系统申请的内存一般在heap中，申请到的内存块称作`chunk`。

申请不同大小的`chunk`有着不同的分配机制。

以下根据大小进行分类，分别介绍分配机制及相关漏洞。

## 钩子函数 hook

申请或释放内存时会调用钩子函数(hook)
申请时调用`__malloc_hook`，释放时调用`__free_hook`
这俩`hook`一般位于`libc`中，默认值是`0x0`，并且可写
因此可以修改hook，然后等到程序调用malloc或是free时触发钩子函数从而劫持程序控制流

除了`malloc`以外，很多函数的内部实现也会申请/释放内存，比如：
`printf`的格式化字符串为`%100000`时会调用`malloc`申请内存(栈中空间不足)
`seccomp`添加沙盒规则时也会申请一堆chunk

## 很小-fastbin
...to learn

## large ..
..to learn

## ...


## 很大-超多MMAP阈值

使用`malloc`申请内存超过`MMAP_THRESHOLD`时就会调用`mmap`申请内存

> Normally, malloc() allocates memory from the heap, and adjusts the size of the heap as required, using sbrk(2). When allocating blocks of memory larger than MMAP_THRESHOLD bytes, the glibc malloc() implementation allocates the memory as a private anonymous mapping using mmap(2). MMAP_THRESHOLD is 128 kB by default, but is adjustable using mallopt(3). Allocations performed using mmap(2) are unaffected by the RLIMIT_DATA resource limit (see getrlimit(2)).

申请到的`chunk`地址在`libc`和`ld`附近

这是比较常见的利用点

如果chunk中存在溢出或者越界读写漏洞的话，可以泄漏或修改libc或者ld中的值


