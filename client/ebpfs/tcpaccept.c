#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct data_t {
    // timestamp
    u64 ts;

    // process info
    u32 pid;
    u32 ppid;
    u32 uid;

    // event info
    char process[TASK_COMM_LEN];
    u32 value;
};
BPF_PERF_OUTPUT(inet_csk_accept);

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u32 uid = task->cred->uid.val;

    if (uid < 1000 || uid > 60000)
        goto out;

    data.ts = bpf_ktime_get_ns();
    data.uid = uid;
    data.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.process, sizeof(data.process));
    data.value = newsk->__sk_common.skc_rcv_saddr;

    inet_csk_accept.perf_submit(ctx, &data, sizeof(data));  

out:
    return 0;
}
