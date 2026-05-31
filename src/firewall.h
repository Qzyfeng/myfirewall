#ifndef __FIREWALL_H
#define __FIREWALL_H

#ifndef __FIREWALL_BPF__
#include <linux/types.h>
#endif

/*
 * firewall.h — 用户态与 eBPF 共享契约
 */

#ifndef FIREWALL_BLACKLIST_MAX_ENTRIES
#define FIREWALL_BLACKLIST_MAX_ENTRIES 512
#endif

#ifndef FIREWALL_STATS_MAX_ENTRIES
#define FIREWALL_STATS_MAX_ENTRIES 8
#endif

#ifndef FIREWALL_RULE_HITS_MAX_ENTRIES
#define FIREWALL_RULE_HITS_MAX_ENTRIES 256
#endif

/* 规则地址族（与源字段一致） */
enum firewall_af {
	FW_AF_UNSPEC = 0,
	FW_AF_INET   = 2,
	FW_AF_INET6  = 10,
};

/* 规则协议；空= ANY（语义见 FIREWALL.md） */
enum firewall_proto {
	FW_PROTO_ANY     = 0,
	FW_PROTO_TCP     = 1,
	FW_PROTO_UDP     = 2,
	FW_PROTO_ICMP    = 3,
	FW_PROTO_ICMPV6  = 4,
};

#define FW_RULE_F_SRC   (1 << 0)
#define FW_RULE_F_SPORT (1 << 1)
#define FW_RULE_F_DPORT (1 << 2)

/*
 * 单条黑名单；blacklist map 的 value。
 * src_v4 / src_v6[4] 为网络序；源前缀长度 src_plen（v4:0-32，v6:0-128）。
 */
struct firewall_blacklist_rule {
	//哪些字段生效
	__u8  flags;
	//ipv4还是ipv6
	__u8  af;
	//协议类型:tcp/udp/icmp/icmpv6/任意协议
	__u8  proto;
	//规则命中时加一
	__u8  rule_id;
	//源端口 //注意:__be16:网络字节序,即大端序.端口在网络包里就是大端序存的,不用反复转换
	__be16 sport;
	//目的端口
	__be16 dport;
	//源地址前缀长度
	__u32 src_plen;
	//ipv4源地址
	__u32 src_v4;
	//ipv6源地址
	__u32 src_v6[4];
};

enum firewall_stat_idx {
	FW_STAT_PASS       = 0,
	FW_STAT_DROP       = 1,
	FW_STAT_EARLY_PASS = 2,
	FW_STAT_DROP_FRAG  = 3,
};

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT 44
#endif

/* IPv6 分片扩展头（RFC 8200） */
struct firewall_ipv6_frag_hdr {
	__u8   nexthdr;
	__u8   reserved;
	__be16 frag_off;
	__be32 identification;
};

#endif /* __FIREWALL_H */
