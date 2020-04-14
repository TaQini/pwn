# 劫持控制流

程序执行的当前指令保存在`eip/rip`中，劫持控制流就是修改`eip/rip`

控制流转移通常发生在函数的调用/返回过程中

能够转移控制流的指令有仨

 * ret
 * call
 * jmp

攻击就是针对这三条指令的利用

## return 

被调用的函数执行完毕后，通常是使用`ret`指令，根据栈中保存的返回地址来还原`eip/rip`

`ret`相当于`pop eip`

### stack overflow
栈中变量溢出，导致返回地址被覆盖


### rop

返回导向编程攻击

## call

function ptr

### call [ptr]

## jmp

