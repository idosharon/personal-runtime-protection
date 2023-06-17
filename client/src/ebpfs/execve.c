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
BPF_PERF_OUTPUT(execve);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    execve.perf_submit(ctx, data, sizeof(*data));
    return 1;
}
static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall__kprobe_execve(struct pt_regs *ctx,
                       const char __user *filename,
                       const char __user *const __user *__argv,
                       const char __user *const __user *__envp)
{
    struct data_t data = {};

    // get timestamp
    data.ts = bpf_ktime_get_ns();

    // get process info
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    data.ppid = task->real_parent->pid;
    data.uid = task->cred->uid.val;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;

    // get file name
    bpf_probe_read_user(data.value, sizeof(data.value), filename);

    // skip first arg, as we submitted filename
     #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }

    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);

out:
    return 0;
}


int syscall__kretprobe_execve(struct pt_regs *ctx)
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
    data.return_value = PT_REGS_RC(ctx);
    execve.perf_submit(ctx, &data, sizeof(data));

    return 0;
}