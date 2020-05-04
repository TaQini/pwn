>  A 12 hour CTF event 

Here are some tasks I have solved in sarcon CTF, not hard. 

# Reversing

## Crack_Em_Up (100pt)

### Description

> Hello crew members !!
>
> This is your captain .Are you ready to get deployed to the land of Cracks ? Fasten your seat belts and sharpen your debugging skills . Best of luck .
>
> Flag Format :- secarmy{flag}
>
> Author : Elemental X

### Attachment

[Cracks](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SARCON-CTF2020/Cracks/Cracks)

### Analysis

I am not good at re, but this challenge is not very hard. This program is written by C++, and we can see two part of flag directly as follows

the first part of flag:
![](http://image.taqini.space/img/re1_0.png)

the second part of flag:
![](http://image.taqini.space/img/re1_1.png)

> flag: secarmy{th3_k3y_t0_fl4g}



# Beginner Malware Analysis

## The Game Of PDFs (0pt)
### Description

> Congratulations for solving the first step!
> Let's move on to the next one now! Here is a pdf i want you to look into.This file contains the flag script which i want you to discover!
> We recommend you to stick to command line! This one is very easy!
>
> Author:Umair9747
>

### Attachment

[notsoevil.pdf](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SARCON-CTF2020/notsoevil/notsoevil.pdf)

### Analysis

As the description say:

> We recommend you to stick to command line! This one is very easy!

I try `cat notsoevil.pdf` and find that:

```
/Type /Action
/S /JavaScript
/JS <69662028313C3029207B0A20206170702E616C657274282273656361726D797B315F7740246E375F337870336337316E675F7930755F37305F66316E645F6D337D22293B0A7D0A0A>
>>
```

Obviously, it is a string of hex encode.

### Solution

Decode then get the flag

```python
In [1]: a='69662028313C3029207B0A20206170702E616C657274282273656361726D797B315F7
   ...: 740246E375F337870336337316E675F7930755F37305F66316E645F6D337D22293B0A7D0
   ...: A0A'

In [2]: a.decode('hex')
Out[2]: 'if (1<0) {\n  app.alert("secarmy{1_w@$n7_3xp3c71ng_y0u_70_f1nd_m3}");\n}\n\n'
```

> flag: secarmy{1_w@$n7_3xp3c71ng_y0u_70_f1nd_m3}

## The Endgame (500pt)

### Description

> Ok hackers it's time to wear your capes and get ready for the endgame. We will be analyzing a real malware now.This malware is being spread worldwide through COVID-19 related campaigns.
> Your task is to get us the name of the harmful executable file located in its strings and save the humanity from the malware. Your flag format is: secarmy{filename.exe}
> Warning:Although this is a static analysis, this is a real malware.You are advised to play this challenge in a virtual environment in order to avoid any damage/loss.
>
> Author:Umair9747
>

### Attachment

[12.exe](https://cdn.jsdelivr.net/gh/TaQini/ctf@master/SARCON-CTF2020/endgame/12.exe)

### Analysis

As the description say, our task is to get the **file name** of the harmful executable file located in its strings.

So, check what string in the executable file first. I use `radare2` cmd as follows:

```bash
rabin2 -zz 12.exe
```

In the end of its output, I saw the file named `tcgcQZrjffyIAPzmPfcQNoEQSJxlP.exe`

![](http://image.taqini.space/img/20200425001832.png)

I try to submit it and it is the real flag

> secarmy{tcgcQZrjffyIAPzmPfcQNoEQSJxlP.exe}