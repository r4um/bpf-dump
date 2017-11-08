#!/usr/bin/python

# Why drop? http://elixir.free-electrons.com/linux/latest/source/drivers/net/veth.c#L106

from __future__ import print_function
from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

int kretprobe__dev_forward_skb(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);

    if(ret != NET_RX_SUCCESS) {
        bpf_trace_printk("ret_dev_forward_skb %d\\n", ret);
    }
    return 0;
}

int kretprobe__is_skb_forwardable(struct pt_regs *ctx)
{
    bool ret = PT_REGS_RC(ctx);

    if(!ret) {
        bpf_trace_printk("ret_is_skb_forwardable FALSE %d\\n", ret);
    }
    return 0;
}

// watch for -ENOMEM
// http://elixir.free-electrons.com/linux/latest/source/include/uapi/asm-generic/errno-base.h#L15
int kretprobe__skb_copy_ubufs(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);

    if(ret != 0) {
        bpf_trace_printk("ret_skb_copy_ubufs %d\\n", ret);
    }
    return 0;
}

// via http://elixir.free-electrons.com/linux/latest/source/net/core/dev.c#L3781
int kretprobe__enqueue_to_backlog(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);

    if(ret == NET_RX_DROP) {
        bpf_trace_printk("ret_enqueue_to_backlog NET_RX_DROP %d\\n", ret);
    }
    return 0;
}
"""

b = BPF(text=bpf_text)

while 1:
   (task, pid, cpu, flags, ts, msg) = b.trace_fields()
   print("%-6d %-12.12s %16s" % (pid, task, msg))
