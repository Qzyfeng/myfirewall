// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * firewall.c — XDP 统一黑名单用户态加载器
 */

#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/stat.h>

#include <linux/types.h>
#include <netinet/in.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "firewall.h"
#include ".output/firewall.skel.h"

enum {
	OPT_PIN_DIR = 300,
	OPT_REUSE_DIR,
	OPT_REFILL,
	OPT_LEAVE_PINNED,
};

static const char *const map_names[] = { "blacklist", "stats", "rule_hits" };
#define N_MAPS (sizeof(map_names) / sizeof(map_names[0]))

static struct {
	//网卡名
	const char *ifname;
	//黑名单
	struct firewall_blacklist_rule rules[FIREWALL_BLACKLIST_MAX_ENTRIES];
	//规则数
	int n_rules;
	//是否打印日志
	bool verbose;
	//map持久化路径
	const char *pin_path;
	//复用已存在的 map
	const char *reuse_path;
	//复用时重新写入规则
	bool refill_on_reuse;
	//退出不删除map
	bool leave_pinned;
} env;

//标记 map 是否被持久化到磁盘
static bool maps_were_pinned;
//ctrl+c时为true
static volatile bool exiting;
//标识XDP程序与网卡的挂载关联
static struct bpf_link *xdp_link;
//给信号处理函数用
static struct firewall_bpf *skel_for_signals;



/* =================================================================
 * libbpf 日志
 * 作用：接管 libbpf 的 stderr 输出；非 verbose 时屏蔽 LIBBPF_DEBUG。
 * 流程：main 中 libbpf_set_print() 注册 → 后续 bpf 加载/attach 的
 *       诊断信息经此函数过滤后输出。
 * ================================================================= */

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

 //遍历打印两个map
static void print_stats(struct firewall_bpf *skel)
{
	static const struct {
		__u32 idx;
		const char *label;
	} rows[] = {
		{ FW_STAT_PASS,       "pass (policy):" },
		{ FW_STAT_DROP,       "drop:" },
		{ FW_STAT_DROP_FRAG,  "drop (分片):" },
		{ FW_STAT_EARLY_PASS, "pass (early/跳过):" },
	};
	int stats_fd = bpf_map__fd(skel->maps.stats);
	int hits_fd = bpf_map__fd(skel->maps.rule_hits);
	__u32 k;
	__u64 v;
	unsigned int i;
	int any_hits = 0;

	if (stats_fd >= 0) {
		for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
			k = rows[i].idx;
			v = 0;
			(void)bpf_map_lookup_elem(stats_fd, &k, &v);
			printf("  %-22s%llu\n", rows[i].label,
			       (unsigned long long)v);
		}
	}
	if (hits_fd < 0)
		return;
	printf("  rule_hits (按 id):\n");
	for (k = 0; k < FIREWALL_RULE_HITS_MAX_ENTRIES; k++) {
		v = 0;
		if (bpf_map_lookup_elem(hits_fd, &k, &v) != 0 || v == 0)
			continue;
		any_hits = 1;
		printf("    id %" PRIu32 ": %llu\n", k, (unsigned long long)v);
	}
	if (!any_hits)
		printf("    (无非零计数)\n");
}

//信号处理函数
//kill -USR1 进程PID 打印统计
//ctrl+c退出
static void on_signal(int sig)
{
	if (sig == SIGUSR1) {
		if (skel_for_signals)
			print_stats(skel_for_signals);
		return;
	}
	exiting = true;
}

 //创建文件夹
static int mkpath(const char *path)
{
	char buf[512];
	size_t i, len;
	int err;

	strncpy(buf, path, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';
	len = strlen(buf);
	while (len > 0 && buf[len - 1] == '/')
		buf[--len] = '\0';
	for (i = 1; i < len; i++) {
		if (buf[i] != '/')
			continue;
		buf[i] = '\0';
		err = mkdir(buf, 0755);
		if (err != 0 && errno != EEXIST)
			return -1;
		buf[i] = '/';
	}
	err = mkdir(buf, 0755);
	if (err != 0 && errno != EEXIST)
		return -1;
	return 0;
}

enum map_path_op { 
	//复用map
	MAP_OP_REUSE, 
	//持久化map
	MAP_OP_PIN, 
	//清除磁盘上的map
	MAP_OP_UNPIN };

static int map_path_op(struct firewall_bpf *skel, const char *dir, enum map_path_op op)
{
	struct bpf_map *maps[] = {
		skel->maps.blacklist,
		skel->maps.stats,
		skel->maps.rule_hits,
	};
	char path[512];
	unsigned int i;
	int fd, err;

	for (i = 0; i < N_MAPS; i++) {
		snprintf(path, sizeof(path), "%s/%s", dir, map_names[i]);
		if (op == MAP_OP_UNPIN) {
			if (unlink(path) != 0 && errno != ENOENT)
				fprintf(stderr, "unlink %s: %s\n", path,
					strerror(errno));
			continue;
		}
		if (op == MAP_OP_REUSE) {
			//打开文件
			fd = bpf_obj_get(path);
			if (fd < 0) {
				fprintf(stderr, "bpf_obj_get %s: %s\n", path,
					strerror(errno));
				return -1;
			}
			//复用
			err = bpf_map__reuse_fd(maps[i], fd);
			if (err) {
				fprintf(stderr, "bpf_map__reuse_fd %s: %s\n",
					path, strerror(-err));
				close(fd);
				return err;
			}
			continue;
		}
		//持久化到path
		err = bpf_map__pin(maps[i], path);
		if (err) {
			fprintf(stderr, "bpf_map__pin %s: %s\n", path,
				strerror(-err));
			return err;
		}
	}
	return 0;
}


//黑名单规则解析

//前缀长度->子网掩码
static __u32 ipv4_host_mask(unsigned plen)
{
	if (plen == 0)
		return 0;
	if (plen >= 32)
		return 0xffffffffu;
	return 0xffffffffu << (32 - plen);
}

//ipv4源地址+子网掩码->填入黑名单规则表
static int parse_src_v4(const char *addr, unsigned long plen,
			struct firewall_blacklist_rule *r)
{
	struct in_addr in4;

	if (inet_pton(AF_INET, addr, &in4) != 1)
		return -1;
	r->src_plen = (__u32)plen;
	//ipv4网段基地址
	r->src_v4 = htonl(ntohl(in4.s_addr) & ipv4_host_mask((unsigned)plen));
	r->flags |= FW_RULE_F_SRC;
	r->af = FW_AF_INET;
	return 0;
}

//获取ipv6网段基地址
static void apply_v6_mask(__u32 addr[4], unsigned plen)
{
	__u32 i, mask, host;

	if (plen >= 128)
		return;
	for (i = 0; i < 4; i++) {
		if (plen <= i * 32)
			addr[i] = 0;
		else if (plen >= (i + 1) * 32)
			continue;
		else {
			mask = 0xffffffffu << (32 - (unsigned)(plen - i * 32));
			host = ntohl(addr[i]);
			addr[i] = htonl(host & mask);
		}
	}
}

//ipv6源地址+子网掩码->填入黑名单规则表
static int parse_src_v6(const char *addr, unsigned long plen,
			struct firewall_blacklist_rule *r)
{
	struct in6_addr in6;

	if (inet_pton(AF_INET6, addr, &in6) != 1)
		return -1;
	if (plen > 128)
		return -1;
	memcpy(r->src_v6, in6.s6_addr, sizeof(r->src_v6));
	apply_v6_mask(r->src_v6, (unsigned)plen);
	r->src_plen = (__u32)plen;
	r->flags |= FW_RULE_F_SRC;
	r->af = FW_AF_INET6;
	return 0;
}

//解析ip字符串,写入黑名单
static int parse_src_cidr(const char *cidr, struct firewall_blacklist_rule *r)
{
	const char *slash = strchr(cidr, '/');
	char addr[128];
	unsigned long plen;
	char *end;

	if (!slash || (size_t)(slash - cidr) >= sizeof(addr))
		return -1;
	memcpy(addr, cidr, (size_t)(slash - cidr));
	addr[slash - cidr] = '\0';
	errno = 0;
	plen = strtoul(slash + 1, &end, 10);
	if (errno || *end != '\0')
		return -1;
	if (strchr(addr, ':'))
		return parse_src_v6(addr, plen, r);
	if (plen > 32)
		return -1;
	return parse_src_v4(addr, plen, r);
}


//解析协议名字符串
static int parse_proto(const char *s, __u8 *out)
{
	static const struct {
		const char *name;
		__u8 proto;
	} table[] = {
		{ "tcp", FW_PROTO_TCP },
		{ "udp", FW_PROTO_UDP },
		{ "icmp", FW_PROTO_ICMP },
		{ "icmpv6", FW_PROTO_ICMPV6 },
	};
	unsigned int i;

	for (i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
		if (!strcasecmp(s, table[i].name)) {
			*out = table[i].proto;
			return 0;
		}
	}
	return -1;
}

//解析端口字符串
static int parse_port(const char *s, __be16 *out)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno || end == s || *end != '\0' || v <= 0 || v > 65535)
		return -1;
	*out = htons((unsigned short)v);
	return 0;
}

//端口写入黑名单
static int parse_rule_port(const char *val, __be16 *port, __u8 flag,
			   struct firewall_blacklist_rule *r)
{
	if (parse_port(val, port) != 0)
		return -1;
	r->flags |= flag;
	return 0;
}

//黑名单合法性检查
static int validate_rule(struct firewall_blacklist_rule *r)
{
	bool need_ports = !!(r->flags & (FW_RULE_F_SPORT | FW_RULE_F_DPORT));

	if (!r->flags && r->proto == FW_PROTO_ANY)
		return -1;
	if ((r->proto == FW_PROTO_ICMP || r->proto == FW_PROTO_ICMPV6) &&
	    need_ports)
		return -1;
	if ((r->proto == FW_PROTO_ICMP && r->af == FW_AF_INET6) ||
	    (r->proto == FW_PROTO_ICMPV6 && r->af == FW_AF_INET))
		return -1;
	return 0;
}


//字符串写入黑名单
static int parse_block_rule(const char *spec, struct firewall_blacklist_rule *r)
{
	char buf[512];
	char *save = NULL, *tok, *eq, *key, *val;

	memset(r, 0, sizeof(*r));
	strncpy(buf, spec, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		while (*tok == ' ' || *tok == '\t')
			tok++;
		eq = strchr(tok, '=');
		if (!eq)
			return -1;
		*eq = '\0';
		key = tok;
		val = eq + 1;
		if (!strcmp(key, "src")) {
			if (parse_src_cidr(val, r) != 0)
				return -1;
		} else if (!strcmp(key, "proto")) {
			if (parse_proto(val, &r->proto) != 0)
				return -1;
		} else if (!strcmp(key, "sport")) {
			if (parse_rule_port(val, &r->sport, FW_RULE_F_SPORT, r) != 0)
				return -1;
		} else if (!strcmp(key, "dport")) {
			if (parse_rule_port(val, &r->dport, FW_RULE_F_DPORT, r) != 0)
				return -1;
		} else if (!strcmp(key, "id")) {
			char *e;
			unsigned long id;

			errno = 0;
			id = strtoul(val, &e, 10);
			if (errno || e == val || *e != '\0' ||
			    id >= FIREWALL_RULE_HITS_MAX_ENTRIES)
				return -1;
			r->rule_id = (__u8)id;
		} else {
			return -1;
		}
	}
	return validate_rule(r);
}

//黑名单写入内核map黑名单
static int fill_blacklist(struct firewall_bpf *skel)
{
	int fd = bpf_map__fd(skel->maps.blacklist);
	__u32 i, key;
	int err;

	for (i = 0; i < (unsigned)env.n_rules; i++) {
		key = i;
		err = bpf_map_update_elem(fd, &key, &env.rules[i], BPF_ANY);
		if (err) {
			fprintf(stderr, "blacklist update #%u: %s\n", i,
				strerror(errno));
			return -errno;
		}
	}
	return 0;
}

//是否空规则
static bool rule_is_empty(const struct firewall_blacklist_rule *r)
{
	const __u8 *p = (const __u8 *)r;
	unsigned int i;

	for (i = 0; i < sizeof(*r); i++) {
		if (p[i] != 0)
			return false;
	}
	return true;
}

/* pure --reuse 且无 -b：从已 pin 的 blacklist map 推断 rodata */
static int scan_blacklist_rodata(struct firewall_bpf *skel, __u32 *count,
				 __u8 *need_l4)
{
	int fd = bpf_map__fd(skel->maps.blacklist);
	struct firewall_blacklist_rule r;
	__u32 key, n = 0;
	__u8 l4 = 0;

	if (fd < 0)
		return -1;
	for (key = 0; key < FIREWALL_BLACKLIST_MAX_ENTRIES; key++) {
		if (bpf_map_lookup_elem(fd, &key, &r) != 0)
			break;
		if (rule_is_empty(&r))
			break;
		n++;
		if ((r.flags & (FW_RULE_F_SPORT | FW_RULE_F_DPORT)) ||
		    r.proto == FW_PROTO_TCP || r.proto == FW_PROTO_UDP)
			l4 = 1;
	}
	*count = n;
	*need_l4 = l4;
	return 0;
}

 //命令行参数解析
const char *argp_program_version = "firewall 0.4";

static const char argp_doc[] =
	"XDP 防火墙：统一黑名单（IPv4/IPv6，-b 可重复，OR 匹配）。\n"
	"示例: sudo ./firewall -i eth0 -b dport=8080\n"
	"      sudo ./firewall -i eth0 -b src=10.0.0.0/8,proto=tcp,dport=8080\n"
	"SIGUSR1 打印统计；详见 FIREWALL.md。\n\v";

static struct argp_option options[] = {
	{ "interface", 'i', "IFNAME", 0, "网卡名（必填）" },
	{ "block", 'b', "RULE", 0,
	  "黑名单（可重复）：src=CIDR,proto=tcp|udp|icmp|icmpv6,sport=N,dport=N,id=N" },
	{ "verbose", 'v', NULL, 0, "libbpf 调试输出" },
	{ "pin", OPT_PIN_DIR, "DIR", 0, "attach 后 pin map 到 DIR" },
	{ "reuse", OPT_REUSE_DIR, "DIR", 0, "load 前复用 DIR 下已 pin 的 map" },
	{ "refill", OPT_REFILL, NULL, 0, "与 --reuse 合用：重写规则" },
	{ "leave-pinned", OPT_LEAVE_PINNED, NULL, 0, "退出时不 unlink pin" },
	{ 0 },
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct firewall_blacklist_rule r;

	switch (key) {
	case 'i':
		env.ifname = arg;
		break;
	case 'b':
		if (env.n_rules >= FIREWALL_BLACKLIST_MAX_ENTRIES) {
			fprintf(stderr, "规则数超过上限 %d\n",
				FIREWALL_BLACKLIST_MAX_ENTRIES);
			argp_usage(state);
		}
		if (parse_block_rule(arg, &r) != 0) {
			fprintf(stderr, "无效规则: %s\n", arg);
			argp_usage(state);
		}
		env.rules[env.n_rules++] = r;
		break;
	case OPT_PIN_DIR:
		env.pin_path = arg;
		break;
	case OPT_REUSE_DIR:
		env.reuse_path = arg;
		break;
	case OPT_REFILL:
		env.refill_on_reuse = true;
		break;
	case OPT_LEAVE_PINNED:
		env.leave_pinned = true;
		break;
	case 'v':
		env.verbose = true;
		break;
	case ARGP_KEY_END:
		if (!env.ifname)
			argp_error(state, "必须指定网卡: -i IFNAME");
		if (env.n_rules == 0 &&
		    (!env.reuse_path || env.refill_on_reuse))
			argp_error(state, "至少一条黑名单: -b RULE");
		if (env.refill_on_reuse && !env.reuse_path)
			argp_error(state, "--refill 需与 --reuse 合用");
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, 0, argp_doc };


int main(int argc, char **argv)
{
	//初始化参数
	struct firewall_bpf *skel = NULL;
	int ifindex, i, err = 0;
	__u32 blacklist_count;
	__u8 need_l4 = 0;
	memset(&env, 0, sizeof(env));

	//调用parse_opt(),解析命令行参数,存入env
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	//注册打印函数
	libbpf_set_print(libbpf_print_fn);
	//网卡名转ifindex
	ifindex = if_nametoindex(env.ifname);
	if (!ifindex) {
		fprintf(stderr, "找不到网卡: %s\n", env.ifname);
		return 1;
	}
	//注册信号处理函数
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGUSR1, on_signal);

	//打开BPFskeleton
	skel = firewall_bpf__open();
	if (!skel) {
		fprintf(stderr, "firewall_bpf__open 失败\n");
		return 1;
	}

	//复用map
	if (env.reuse_path) {
		err = map_path_op(skel, env.reuse_path, MAP_OP_REUSE);
		if (err) {
			fprintf(stderr, "复用 pin map 失败\n");
			goto cleanup;
		}
	}

	blacklist_count = (__u32)env.n_rules;
	//判断是否需要L4
	for (i = 0; i < env.n_rules; i++) {
		const struct firewall_blacklist_rule *r = &env.rules[i];

		if ((r->flags & (FW_RULE_F_SPORT | FW_RULE_F_DPORT)) ||
		    r->proto == FW_PROTO_TCP || r->proto == FW_PROTO_UDP) {
			need_l4 = 1;
			break;
		}
	}
	if (env.reuse_path && !env.refill_on_reuse && env.n_rules == 0) {
		err = scan_blacklist_rodata(skel, &blacklist_count, &need_l4);
		if (err) {
			fprintf(stderr, "扫描复用 blacklist map 失败\n");
			goto cleanup;
		}
	}
	//初始化内核常量
	skel->rodata->blacklist_count = blacklist_count;
	skel->rodata->need_l4_match = need_l4;

	//加载bpf程序到内核
	err = firewall_bpf__load(skel);
	if (err) {
		fprintf(stderr, "firewall_bpf__load: %s\n", strerror(-err));
		goto cleanup;
	}

	//写入黑名单规则到内核map
	if (!env.reuse_path || env.refill_on_reuse) {
		err = fill_blacklist(skel);
		if (err)
			goto cleanup;
	}

	//挂载xdp程序到网卡
	xdp_link = bpf_program__attach_xdp(skel->progs.xdp_firewall_prog, ifindex);
	err = libbpf_get_error(xdp_link);
	if (err) {
		fprintf(stderr, "bpf_program__attach_xdp: %s\n", strerror(-err));
		xdp_link = NULL;
		goto cleanup;
	}

	//持久化map
	if (env.pin_path) {
		if (mkpath(env.pin_path) != 0) {
			fprintf(stderr, "创建 pin 目录 %s: %s\n", env.pin_path,
				strerror(errno));
			err = -1;
			goto cleanup;
		}
		err = map_path_op(skel, env.pin_path, MAP_OP_PIN);
		if (err) {
			map_path_op(skel, env.pin_path, MAP_OP_UNPIN);
			goto cleanup;
		}
		maps_were_pinned = true;
	}

	skel_for_signals = skel;
	printf("XDP 已附加到 %s (ifindex=%d)，黑名单 %u 条，分片策略: %s。",
	       env.ifname, ifindex, blacklist_count, need_l4 ? "非首片 DROP" : "关");
	if (env.pin_path)
		printf(" pin: %s。", env.pin_path);
	if (env.reuse_path)
		printf(" reuse: %s%s。", env.reuse_path,
		       env.refill_on_reuse ? "+refill" : "");
	printf(" Ctrl-C 退出；SIGUSR1 打印统计。\n");
	
	//休眠
	while (!exiting) {
		if (pause() < 0 && errno != EINTR)
			break;
	}

cleanup:
	skel_for_signals = NULL;
	//卸载防火墙
	if (xdp_link) {
		bpf_link__destroy(xdp_link);
		xdp_link = NULL;
	}
	//如果需要,清理map
	if (maps_were_pinned && env.pin_path && !env.leave_pinned)
		map_path_op(skel, env.pin_path, MAP_OP_UNPIN);
	//打印最终统计;销毁 BPF 程序
	if (skel) {
		printf("--- 统计（退出） ---\n");
		print_stats(skel);
		firewall_bpf__destroy(skel);
	}
	return err ? 1 : 0;
}
