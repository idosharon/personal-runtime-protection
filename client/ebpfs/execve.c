/*
    File: execve.c
    Description: This file contains the code for the execve syscall hook, which is used to capture the arguments passed to the execve syscall.
    Author: Ido Sharon
*/
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE 50

// Define the data structure that will be sent to user space.
struct data_t {
    // timestamp
    u64 ts;

    // process info
    u32 pid;
    u32 ppid;
    u32 uid;

    // event info
    char process[TASK_COMM_LEN];
    char value[ARGSIZE];
};
BPF_PERF_OUTPUT(execve);

int syscall__kretprobe_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    if(uid < 1000 || uid > 60000)
        goto out;
    
    data.ts = bpf_ktime_get_ns() / 1000;
    data.uid = uid;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.process, sizeof(data.process));

    // submit data to user space
    execve.perf_submit(ctx, &data, sizeof(data));

out:
    return 0;
}