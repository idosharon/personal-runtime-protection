#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE 50

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
BPF_PERF_OUTPUT(openat);


int syscall__kprobe_openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u32 uid = task->cred->uid.val;

    if(uid < 1000 || uid > 60000)
        goto out;
    
    data.ts = bpf_ktime_get_ns();
    data.uid = uid;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.process, sizeof(data.process));
    bpf_probe_read_user(data.value, sizeof(data.value), filename);

    openat.perf_submit(ctx, &data, sizeof(data));

out:
    return 0;
}
