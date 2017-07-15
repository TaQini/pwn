#!/usr/bin/python
from sys import *
f1 = 0x000000000000116E
f2 = 0x000000000000117C
f3 = 0x000000000000118A
f4 = 0x0000000000001198
l = [f1,f2,f3,f4]
l.append(0x0000000000000DCC)
base = eval(argv[1])

def p(f):
    print 'b *' + hex(base+f)

for f in l:
    p(f)

