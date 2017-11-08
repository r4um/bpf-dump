from bcc import BPF
import ctypes as ct

# Track chmod calls

# define BPF program
prog = """
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/fdtable.h>

struct data_t {
    u32 pid;
    u64 ts;
    u32 uid;
    umode_t mode;
    char fname[NAME_MAX];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int trace_sys_fchmod(struct pt_regs *ctx, unsigned int fd, umode_t mode)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.mode = mode;

    // https://github.com/iovisor/bcc/issues/237
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    struct file *f = NULL;
    struct dentry *de = NULL;
    struct qstr dn = {};
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&files, sizeof(files), &curr->files);
    bpf_probe_read(&fdt, sizeof(fdt), &files->fdt);
    bpf_probe_read(&f, sizeof(f), &fdt[fd]);
    bpf_probe_read(&de, sizeof(de), &f->f_path.dentry);
    bpf_probe_read(&dn, sizeof(dn), &de->d_name);

    if(f) {
        bpf_probe_read(&data.fname, sizeof(data.fname), (void*) dn.name);
    }

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int trace_sys_fchmodat(struct pt_regs *ctx, int dfd, const char __user *filename, umode_t mode) 
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    data.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.mode = mode;

    bpf_probe_read(&data.fname, sizeof(data.fname), (void*) filename);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BPF(text=prog, debug=0)
b.attach_kprobe(event="sys_fchmodat", fn_name="trace_sys_fchmodat")
b.attach_kprobe(event="sys_fchmod", fn_name="trace_sys_fchmod")

TASK_COMM_LEN = 16    # linux/sched.h
NAME_MAX = 255 # linux/limits.h

class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("uid", ct.c_uint),
                ("mode", ct.c_ushort),
                ("fname", ct.c_char * NAME_MAX),
                ("comm", ct.c_char * TASK_COMM_LEN)
                ]

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    time_s = float(event.ts) / 1000000000
    print("%-18.9f %-6d %-6d %-6d %-16s %-16s" % (time_s, event.pid, event.uid, event.mode, event.fname, event.comm))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
