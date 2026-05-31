// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * firewall.bpf.c — XDP 统一黑名单（IPv4/IPv6，OR 匹配，分片策略见 FIREWALL.md）
 */
#define __FIREWALL_BPF__
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "firewall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//黑名单实际有几条规则
const volatile __u32 blacklist_count;

//是否需要l4匹配(是否一律丢弃ip层非首片)
const volatile __u8 need_l4_match;

//注意:volatite:告知编译器，它所修饰的变量是“易变的”.每次都从内存读取

//黑名单表,最多256条规则
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FIREWALL_BLACKLIST_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct firewall_blacklist_rule);
} blacklist SEC(".maps");

//统计表,最多8个计数器
//0:FW_STAT_PASS 放行（规则都没命中）
//1:FW_STAT_DROP 丢弃（某条规则命中）
//2:FW_STAT_EARLY_PASS 早期放行（不是 IP 包、解析失败等，不处理直接过）
//3:FW_STAT_DROP_FRAG 因分片策略丢弃
//其余未用到
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FIREWALL_STATS_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

//按规则统计表:统计各规则命中数
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FIREWALL_RULE_HITS_MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} rule_hits SEC(".maps");

//注意:__always_inline强制内联,编译时把函数体展开到调用处，减少函数调用开销

//stats[idx]++
static __always_inline void stats_inc(__u32 idx)
{
	__u64 *v;

	if (idx >= FIREWALL_STATS_MAX_ENTRIES)
		return;
	v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

//rule_hits[rid]++
static __always_inline void rule_hit_inc(__u8 rid)
{
	__u32 idx = (__u32)rid;
	__u64 *v;

	if (idx >= FIREWALL_RULE_HITS_MAX_ENTRIES)
		idx = FIREWALL_RULE_HITS_MAX_ENTRIES - 1;
	v = bpf_map_lookup_elem(&rule_hits, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

//处理链路层,处理vlan
//1->IPv4, 2->IPv6, 0->不处理, -1->太短
static __always_inline int parse_eth_vlan_ip(void **pdata, void *data_end)
{
	struct ethhdr *eth;
	//双字节指针
	__be16 *inner;
	void *data = *pdata;

	if (data + sizeof(struct ethhdr) > data_end)
		return -1;

	eth = data;

	if (eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto == bpf_htons(ETH_P_8021AD)) {
		if (data + sizeof(struct ethhdr) + 4 > data_end)
			return -1;
		inner = (void *)eth + sizeof(struct ethhdr) + 2;
		if (*inner == bpf_htons(ETH_P_IP)) {
			*pdata = (void *)eth + sizeof(struct ethhdr) + 4;
			return 1;
		}
		if (*inner == bpf_htons(ETH_P_IPV6)) {
			*pdata = (void *)eth + sizeof(struct ethhdr) + 4;
			return 2;
		}
		if (*inner == bpf_htons(ETH_P_8021Q)) {
			if (data + sizeof(struct ethhdr) + 8 > data_end)
				return -1;
			inner = (void *)eth + sizeof(struct ethhdr) + 6;
			if (*inner == bpf_htons(ETH_P_IP)) {
				*pdata = (void *)eth + sizeof(struct ethhdr) + 8;
				return 1;
			}
			if (*inner == bpf_htons(ETH_P_IPV6)) {
				*pdata = (void *)eth + sizeof(struct ethhdr) + 8;
				return 2;
			}
		}
		return 0;
	}
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		*pdata = (void *)eth + sizeof(struct ethhdr);
		return 1;
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		*pdata = (void *)eth + sizeof(struct ethhdr);
		return 2;
	}
	return 0;
}

//是否非首片
static __always_inline bool ipv4_frag_non_first(struct iphdr *iph)
{
	__u16 fo = bpf_ntohs(iph->frag_off);
	//只取出偏移量
	return (fo & 0x1FFF) != 0;
}

//是否非首片
static __always_inline bool ipv6_frag_non_first(struct ipv6hdr *ip6h, void *data_end)
{
	struct firewall_ipv6_frag_hdr *fh;

	if (ip6h->nexthdr != IPPROTO_FRAGMENT)
		return false;
	if ((void *)(ip6h + 1) + sizeof(*fh) > data_end)
		return false;
	fh = (void *)(ip6h + 1);
	if (bpf_ntohs(fh->frag_off) & 0xFFF8)
		return true;
	return false;
}

//ip是否命中
static __always_inline bool match_src_v4(__be32 saddr, __u32 plen, __u32 net)
{
	__u32 mask;
	//任意源都匹配
	if (plen == 0)
		return true;
	//精确ip
	if (plen >= 32)
		return saddr == net;
	//移位运算需要无符号数
	mask = bpf_htonl(0xffffffffu << (32 - plen));
	return (saddr & mask) == (net & mask);
}

//ip是否命中
static __always_inline bool match_src_v6(struct in6_addr *addr, __u32 plen,
					 const __u32 net[4])
{
	__u32 i, mask, aw, nw;

	if (plen == 0)
		return true;
#pragma unroll
	for (i = 0; i < 4; i++) {
		if (plen <= i * 32)
			break;
		aw = addr->in6_u.u6_addr32[i];
		nw = net[i];
		if (plen >= (i + 1) * 32) {
			if (aw != nw)
				return false;
		} else {
			mask = bpf_htonl(0xffffffffu << (32 - (plen - i * 32)));
			if ((aw & mask) != (nw & mask))
				return false;
		}
	}
	return true;
}

//包与规则是否匹配
static __always_inline bool rule_match(const struct firewall_blacklist_rule *r,
				       __u8 pkt_af, __be32 saddr_v4,
				       struct in6_addr *saddr_v6, __u8 ip_proto,
				       bool have_l4, bool is_tcp, bool is_udp,
				       __be16 sport, __be16 dport)
{
	//是否端口相关
	bool need_ports = !!(r->flags & (FW_RULE_F_SPORT | FW_RULE_F_DPORT));
	//是不是只封源
	bool pure_src;

	//如果源字段有效,对比源:源未命中:false;源命中:对比网段是否匹配,不匹配:false;匹配:下一步
	//源字段无效:跳过
	if (r->flags & FW_RULE_F_SRC) {
		if (r->af == FW_AF_INET) {
			if (pkt_af != FW_AF_INET)
				return false;
			if (!match_src_v4(saddr_v4, r->src_plen, r->src_v4))
				return false;
		} else if (r->af == FW_AF_INET6) {
			if (pkt_af != FW_AF_INET6)
				return false;
			if (!match_src_v6(saddr_v6, r->src_plen, r->src_v6))
				return false;
		} else {
			return false;
		}
	}

	//只封源
	pure_src = (r->proto == FW_PROTO_ANY) && !need_ports &&
		   (r->flags & FW_RULE_F_SRC);
	if (pure_src)
		return true;

	//1.写了src,网段匹配,且写了协议或端口至少其一 2.无src
	//匹配协议,无协议无端口则跳过,无协议有端口满足特定条件则进入下一步
	if (r->proto == FW_PROTO_TCP) {
		if (!is_tcp)
			return false;
	} else if (r->proto == FW_PROTO_UDP) {
		if (!is_udp)
			return false;
	} else if (r->proto == FW_PROTO_ICMP) {
		if (pkt_af != FW_AF_INET || ip_proto != IPPROTO_ICMP)
			return false;
	} else if (r->proto == FW_PROTO_ICMPV6) {
		if (pkt_af != FW_AF_INET6 || ip_proto != IPPROTO_ICMPV6)
			return false;
	} 
	else if (r->proto == FW_PROTO_ANY) {
		//没写协议写了端口:未成功解析L4头:false;既不是tcp也不是udp:false
		if (need_ports) {
			if (!have_l4 || (!is_tcp && !is_udp))
				return false;
		}
	}

	//1.src/协议都匹配 2.无src,协议匹配 3.无src,无协议,无端口
	//端口匹配,无端口则跳过
	//未成功解析L4头:false;端口不匹配:false
	if (r->flags & FW_RULE_F_SPORT) {
		if (!have_l4 || sport != r->sport)
			return false;
	}
	if (r->flags & FW_RULE_F_DPORT) {
		if (!have_l4 || dport != r->dport)
			return false;
	}

	//1.完全匹配 2.无src,无端口,无协议
	return true;
}

//逐条匹配规则
static __always_inline int process_packet(struct xdp_md *ctx, __u8 pkt_af,
					  __be32 saddr_v4, struct in6_addr *saddr_v6,
					  __u8 ip_proto, bool have_l4, bool is_tcp,
					  bool is_udp, __be16 sport, __be16 dport)
{
	__u32 i, n = blacklist_count;
	struct firewall_blacklist_rule *r;

	if (n > FIREWALL_BLACKLIST_MAX_ENTRIES)
		n = FIREWALL_BLACKLIST_MAX_ENTRIES;
	{
		__u32 c, j;
//循环展开
#pragma unroll
		for (c = 0; c < FIREWALL_BLACKLIST_MAX_ENTRIES / 16; c++) {
#pragma unroll
			for (j = 0; j < 16; j++) {
				i = c * 16 + j;
				if (i >= n)
					goto rule_scan_done;
				r = bpf_map_lookup_elem(&blacklist, &i);
				if (!r)
					continue;
				if (rule_match(r, pkt_af, saddr_v4, saddr_v6,
					       ip_proto, have_l4, is_tcp, is_udp,
					       sport, dport)) {
					stats_inc(FW_STAT_DROP);
					rule_hit_inc(r->rule_id);
					return XDP_DROP;
				}
			}
		}
rule_scan_done:
		;
	}

	stats_inc(FW_STAT_PASS);
	return XDP_PASS;
}

SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int pr;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	__u8 ip_hdr_len;
	__be16 sport = 0, dport = 0;
	bool have_l4 = false, is_tcp = false, is_udp = false;
	__u8 pkt_af;
	__be32 saddr_v4 = 0;
	struct in6_addr saddr_v6 = {};

	//处理链路层.
	pr = parse_eth_vlan_ip(&data, data_end);
	if (pr < 0) {
		stats_inc(FW_STAT_EARLY_PASS);
		return XDP_PASS;
	}
	if (pr == 0) {
		stats_inc(FW_STAT_EARLY_PASS);
		return XDP_PASS;
	}

	//处理网络层
	//ipv4
	if (pr == 1) {
		iph = data;
		pkt_af = FW_AF_INET;
		//长度检查
		if (data + sizeof(struct iphdr) > data_end) {
			stats_inc(FW_STAT_EARLY_PASS);
			return XDP_PASS;
		}
		if (iph->ihl < 5) {
			stats_inc(FW_STAT_EARLY_PASS);
			return XDP_PASS;
		}
		ip_hdr_len = iph->ihl * 4;
		if (data + ip_hdr_len > data_end) {
			stats_inc(FW_STAT_EARLY_PASS);
			return XDP_PASS;
		}
		//非首片&需要端口:drop
		if (need_l4_match && ipv4_frag_non_first(iph)) {
			stats_inc(FW_STAT_DROP_FRAG);
			return XDP_DROP;
		}
		saddr_v4 = iph->saddr;

		//处理传输层
		if (iph->protocol == IPPROTO_TCP) {
			if (data + ip_hdr_len + sizeof(struct tcphdr) <= data_end) {
				struct tcphdr *t = (void *)((__u8 *)data + ip_hdr_len);

				sport = t->source;
				dport = t->dest;
				have_l4 = true;
				is_tcp = true;
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			if (data + ip_hdr_len + sizeof(struct udphdr) <= data_end) {
				struct udphdr *u = (void *)((__u8 *)data + ip_hdr_len);

				sport = u->source;
				dport = u->dest;
				have_l4 = true;
				is_udp = true;
			}
		}

		//返回
		return process_packet(ctx, pkt_af, saddr_v4, &saddr_v6,
				    iph->protocol, have_l4, is_tcp, is_udp,
				    sport, dport);
	}

	//ipv6
	ip6h = data;
	pkt_af = FW_AF_INET6;
	if (data + sizeof(struct ipv6hdr) > data_end) {
		stats_inc(FW_STAT_EARLY_PASS);
		return XDP_PASS;
	}
	if (need_l4_match && ipv6_frag_non_first(ip6h, data_end)) {
		stats_inc(FW_STAT_DROP_FRAG);
		return XDP_DROP;
	}
	saddr_v6 = ip6h->saddr;

	if (ip6h->nexthdr == IPPROTO_TCP) {
		if (data + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) <=
		    data_end) {
			struct tcphdr *t =
				(void *)((__u8 *)data + sizeof(struct ipv6hdr));

			sport = t->source;
			dport = t->dest;
			have_l4 = true;
			is_tcp = true;
		}
	} else if (ip6h->nexthdr == IPPROTO_UDP) {
		if (data + sizeof(struct ipv6hdr) + sizeof(struct udphdr) <=
		    data_end) {
			struct udphdr *u =
				(void *)((__u8 *)data + sizeof(struct ipv6hdr));

			sport = u->source;
			dport = u->dest;
			have_l4 = true;
			is_udp = true;
		}
	}

	return process_packet(ctx, pkt_af, saddr_v4, &saddr_v6, ip6h->nexthdr,
			      have_l4, is_tcp, is_udp, sport, dport);
}
