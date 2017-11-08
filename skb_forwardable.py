from bcc import BPF
import ctypes as ct

# Check if hitting http://lxr.free-electrons.com/source/net/core/dev.c#L1748

# define BPF program
prog = """
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <bcc/proto.h>
#include <uapi/linux/ptrace.h>


// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    unsigned int mtu;
    unsigned int skb_len;
    unsigned int hard_header_len;
    unsigned int len;
    char comm[TASK_COMM_LEN];
    char dev_name[IFNAMSIZ];
};
BPF_PERF_OUTPUT(events);

int trace_is_skb_forwardable(struct pt_regs *ctx, const struct net_device *dev, const struct sk_buff *skb) {
    unsigned int len;
    struct data_t data = {};

    len = dev->mtu + dev->hard_header_len + VLAN_HLEN;

    if (skb->len > len) {
        data.len = len;
        data.skb_len = skb->len;
        data.hard_header_len = dev->hard_header_len;
        data.mtu = dev->mtu;
        bpf_probe_read(&data.dev_name, sizeof(data.dev_name), (void*)dev->name);

        data.pid = bpf_get_current_pid_tgid();
        data.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event="is_skb_forwardable", fn_name="trace_is_skb_forwardable")

TASK_COMM_LEN = 16    # linux/sched.h
IFNAMSIZ = 16 # uapi/linux/if.h

class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("mtu", ct.c_uint),
                ("slen", ct.c_uint),
                ("hrhl", ct.c_uint),
                ("len", ct.c_uint),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("dev", ct.c_char * IFNAMSIZ)
                ]

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    time_s = float(event.ts) / 1000000000
    print("%-18.9f %-6d %-6d %-6d %-6d %-6d %-16s %-16s" % (time_s, event.pid,
        event.mtu, event.slen, event.hrhl, event.len, event.comm, event.dev))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
