from bcc import BPF
import ctypes as ct

# Track chmod calls

# define BPF program
prog = """
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/dcache.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    unsigned short mode;
    char name[NAME_MAX];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int trace_chmod_common(struct pt_regs *ctx, struct path *path, umode_t mode) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.mode = mode;

    bpf_probe_read(&data.name, sizeof(data.name), (void*)path->dentry->d_name.name);
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=prog, debug=4)
b.attach_kprobe(event="chmod_common", fn_name="trace_chmod_common")

TASK_COMM_LEN = 16    # linux/sched.h
NAME_MAX = 255 # linux/limits.h

class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("mode", ct.c_ushort),
                ("name", ct.c_char * NAME_MAX),
                ("comm", ct.c_char * TASK_COMM_LEN)
                ]

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    time_s = float(event.ts) / 1000000000
    print("%-18.9f %-6d %-6d %-16s %-16s" % (time_s, event.pid, event.mode, event.name, event.comm))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
