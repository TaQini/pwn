# 辅助攻击手段
实用的gadget

## 栈迁移gadget

将程序的栈转移到我们可控制的区域，便于后续攻击

### setcontext
libc中的一段代码，可以设置全部寄存器的值
栗子: [TG:Hack2020-carp](http://taqini.space/2020/04/08/TG-Hack-CTF-Pwn-writeup/#Solution-2)

### leave-ret
控制ebp/rbp，利用gadget: `leave;ret` 修改esp/rsp

leave相当于:
```nasm
mov rsp, rbp
pop rbp
```

因此可以改变rsp

### jmp rsp
比较少见...



## gadget in resolver

动态解析函数，解析前将目标函数的参数保存到栈中

![](http://image.taqini.space/img/20200422040216.png)

解析成功后会，恢复参数，并调用被解析的函数

可以利用这个恢复参数的代码段，在栈中伪造参数、栈迁移+执行任意函数

> 跳转地址(被解析的函数地址)保存在rax中，因此需要设置好rax

gadget定位：不同环境位置不同，直接找动态解析成功后的返回地址

```nasm
   0x7ffff7fe9200:  push   rbx
   0x7ffff7fe9201:  mov    rbx,rsp
   0x7ffff7fe9204:  and    rsp,0xffffffffffffffc0
   0x7ffff7fe9208:  sub    rsp,QWORD PTR [rip+0x13579]
   0x7ffff7fe920f:  mov    QWORD PTR [rsp],rax                   ; save args
   0x7ffff7fe9213:  mov    QWORD PTR [rsp+0x8],rcx
   0x7ffff7fe9218:  mov    QWORD PTR [rsp+0x10],rdx
   0x7ffff7fe921d:  mov    QWORD PTR [rsp+0x18],rsi
   0x7ffff7fe9222:  mov    QWORD PTR [rsp+0x20],rdi
   0x7ffff7fe9227:  mov    QWORD PTR [rsp+0x28],r8
   0x7ffff7fe922c:  mov    QWORD PTR [rsp+0x30],r9
   0x7ffff7fe9231:  mov    eax,0xee
   0x7ffff7fe9236:  xor    edx,edx
   0x7ffff7fe9238:  mov    QWORD PTR [rsp+0x250],rdx
   0x7ffff7fe9240:  mov    QWORD PTR [rsp+0x258],rdx
   0x7ffff7fe9248:  mov    QWORD PTR [rsp+0x260],rdx
   0x7ffff7fe9250:  mov    QWORD PTR [rsp+0x268],rdx
   0x7ffff7fe9258:  mov    QWORD PTR [rsp+0x270],rdx
   0x7ffff7fe9260:  mov    QWORD PTR [rsp+0x278],rdx
   0x7ffff7fe9268:  xsavec [rsp+0x40]
   0x7ffff7fe926d:  mov    rsi,QWORD PTR [rbx+0x10]
   0x7ffff7fe9271:  mov    rdi,QWORD PTR [rbx+0x8]
   0x7ffff7fe9275:  call   0x7ffff7fe1ff0                      ; resolve 
=> 0x7ffff7fe927a:  mov    r11,rax                             ; gadget here
   0x7ffff7fe927d:  mov    eax,0xee
   0x7ffff7fe9282:  xor    edx,edx
   0x7ffff7fe9284:  xrstor [rsp+0x40]
   0x7ffff7fe9289:  mov    r9,QWORD PTR [rsp+0x30]             ; restore args
   0x7ffff7fe928e:  mov    r8,QWORD PTR [rsp+0x28]
   0x7ffff7fe9293:  mov    rdi,QWORD PTR [rsp+0x20]
   0x7ffff7fe9298:  mov    rsi,QWORD PTR [rsp+0x18]
   0x7ffff7fe929d:  mov    rdx,QWORD PTR [rsp+0x10]
   0x7ffff7fe92a2:  mov    rcx,QWORD PTR [rsp+0x8]
   0x7ffff7fe92a7:  mov    rax,QWORD PTR [rsp]
   0x7ffff7fe92ab:  mov    rsp,rbx
   0x7ffff7fe92ae:  mov    rbx,QWORD PTR [rsp]
   0x7ffff7fe92b2:  add    rsp,0x18
   0x7ffff7fe92b6:  bnd jmp r11                                ; jmp to r11 (rax)
```

