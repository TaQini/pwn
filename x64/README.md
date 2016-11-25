## x86 x64 区别
x86 参数保存在栈中
x64 参数保存在RDI,RSI,RDX,RCX,R8,R9中，超出6个参数存在栈中

x86 构造payload方法，参数直接在栈中覆写
```
payload = "A" * N + p32(write_plt) + p32(ret) + p32(1) + p32(address) + p32(4)
```

x64 构造payload方法，通过pop rdi; ret等gadgets
```
$ ROPgadgets --binary ./target --only "pop|ret"
```

