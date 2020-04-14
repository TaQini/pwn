# 栈迁移

辅助攻击手段

将程序的栈转移到我们可控制的区域，便于后续攻击

## setcontext
libc中的一段代码，可以设置全部寄存器的值
栗子: [TG:Hack2020-carp](http://taqini.space/2020/04/08/TG-Hack-CTF-Pwn-writeup/#Solution-2)

## leave-ret
控制ebp/rbp，利用gadget: `leave;ret` 修改esp/rsp

leave相当于:
```nasm
mov rsp, rbp
pop rbp
```

因此可以改变rsp

## jmp rsp
比较少见...
