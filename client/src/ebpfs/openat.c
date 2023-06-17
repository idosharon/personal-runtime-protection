#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define MAXARG  20
#define ARGSIZE 128

enum event_type {
    EVENT_ARG = 0,
    EVENT_RET = 1,
};

struct data_t {
    // timestamp
    u64 ts;

    // process info
    u32 pid;
    u32 ppid;
    u32 uid;

    // event type
    enum event_type type;
    int return_value;

    // event info
    char comm[TASK_COMM_LEN];
    char value[ARGSIZE];
    char argv[ARGSIZE];
};
BPF_PERF_OUTPUT(openat);


int syscall__kprobe_openat(struct pt_regs *ctx,
                    int dfd,
                    const char __user *filename,
                    int flags)
{
    struct data_t data = {};
    struct task_struct *task;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = uid;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.return_value = 0;


    bpf_probe_read_user(data.value, sizeof(data.value), filename);

    openat.perf_submit(ctx, &data, sizeof(data));

//    bpf_trace_printk("filename: %s\n", filename);

    return 0;
}
