#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define MAXARG  20
#define ARGSIZE 128

enum event_type {
    EVENT_ARG = 0,
    EVENT_RET = 1,
};

struct ipv4_data_t {
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
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

    // struct ipv4_data_t value;
    char argv[ARGSIZE];
};
BPF_PERF_OUTPUT(inet_csk_accept);


int syscall__kretprobe_inet_csk_accept(struct pt_regs *ctx)
{
    bpf_trace_printk("Hello, World!\n");

    /*
    struct data_t data = {};
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);

     // get timestamp
    data.ts = bpf_ktime_get_ns();

    // get process info
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    data.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    data.ppid = task->real_parent->pid;
    data.uid = task->cred->uid.val;

    u16 protocol = 0;

    int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
    int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);

    if (sk_lingertime_offset - gso_max_segs_offset == 2)
        protocol = newsk->sk_protocol;
    else if (sk_lingertime_offset - gso_max_segs_offset == 4)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 3);
    else
        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 3);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 1);
    else
        protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 1);
#else
    # error "Fix your compiler's __BYTE_ORDER__?!"
#endif

    if (protocol != IPPROTO_TCP)
        return 0;

    // pull in details
    u16 family = 0, lport = 0, dport;
    family = newsk->__sk_common.skc_family;
    lport = newsk->__sk_common.skc_num;
    dport = newsk->__sk_common.skc_dport;
    dport = ntohs(dport);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.ip = 4};
        data4.saddr = newsk->__sk_common.skc_rcv_saddr;
        data4.daddr = newsk->__sk_common.skc_daddr;
        data4.lport = lport;
        data4.dport = dport;

        data.value = data4;

        inet_csk_accept.perf_submit(ctx, &data, sizeof(data));
    }*/
    

    return 0;
}