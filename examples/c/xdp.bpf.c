#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define DEBUG 1

#ifdef  DEBUG
/* Only use this for debug output. Notice output from  bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                     \
        ({                          \
            char ____fmt[] = fmt;               \
            bpf_trace_printk(____fmt, sizeof(____fmt),  \
                     ##__VA_ARGS__);            \
        })
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif
static bool parse_eth(struct ethhdr *eth, void *data_end, u16 *eth_type)
{
    u64 offset;

    offset = sizeof(*eth);
    if ((void *)eth + offset > data_end)
        return false;
	*eth_type = eth->h_proto;
	return true;
}

static bool parse_ip(struct iphdr *ip, void *data_end, __be32 *ip_saddr)
{
    u64 offset;

    offset = sizeof(*ip);
    if ((void *)ip + offset > data_end)
        return false;
	*ip_saddr = ip->saddr;
	return true;
}

static int ntohs(u32 num)
{
    char temp1 =  num        & 0xff;
    char temp2 = (num >>  8) & 0xff;
    char temp3 = (num >> 16) & 0xff;
    char temp4 = (num >> 24) & 0xff;
    return (temp1 << 24) & (temp2 << 16) & (temp3 << 8) & (temp4 );

}
SEC("prog")
int xdp_ipv6_filter_program(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
	u16 eth_type = 0;
    __be32 ip_saddr = 0;
	if (!(parse_eth(eth, data_end, &eth_type))) {
        bpf_debug("Debug: Cannot parse L2\n");
        return XDP_PASS;
    }

    bpf_debug("Debug: eth_type:0x%x\n", ntohs(eth_type));
	if (eth_type == ntohs(0x0800) ) {
		struct iphdr *ip = data + sizeof(*eth);
        if(!parse_ip(ip,data_end,&ip_saddr))
        {
            bpf_debug("Debug: Cannot parse L2\n");
            return XDP_PASS;
        }
            
        if(ip_saddr == 0x640105c1)
            return XDP_DROP;

	} else {
        bpf_debug("here\n");
		return XDP_PASS;
	}
}
