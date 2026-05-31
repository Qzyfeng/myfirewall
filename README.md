# myfirewall

基于 **eBPF / XDP** 的 Linux 网卡防火墙：在数据面用统一黑名单做 IPv4/IPv6 过滤，用户态负责加载规则、挂载 XDP 与统计。

## 特性

- 在指定网卡上挂载 XDP 程序，命中黑名单的包直接 **DROP**，否则 **PASS**
- 支持 **IPv4 / IPv6**，单条或双层 **VLAN** 封装
- 黑名单最多 **512** 条；多条规则之间为 **OR**（任意一条命中即丢弃）
- 规则字段：`src`（CIDR）、`proto`、`sport`、`dport`、`id`（按规则统计命中）
- 需要 L4 匹配时，对 **非首片 IP 分片** 执行丢弃策略，降低分片绕过风险
- BPF map 支持 **pin / reuse**，便于无中断换程序或保留计数
- 运行中发送 **SIGUSR1** 可打印统计；**Ctrl+C** 退出并输出最终计数

## 环境要求

| 依赖 | 说明 |
|------|------|
| Linux | 内核需支持 XDP 与 BPF（建议 5.x+） |
| `clang` | 编译 BPF 目标 |
| `bpftool` | 生成 skeleton（`bpftool gen skeleton`） |
| `libbpf` | 用户态加载（`pkg-config libbpf` 或 `-lbpf -lelf -lz`） |
| `vmlinux.h` | 位于项目根目录，供 BPF 程序包含内核类型 |
| 权限 | 加载 XDP、写 map 通常需要 **root**（`sudo`） |

> 本项目面向 Linux 构建与运行；在 Windows 上仅适合阅读代码，需在 Linux 虚拟机或物理机上编译测试。

## 构建

```bash
make              # 生成 src/.output/firewall
make check-deps   # 检查 clang / bpftool 是否在 PATH
make clean        # 删除 src/.output/
```

产物路径：`src/.output/firewall`

## 快速开始

```bash
# 丢弃目的端口 8080 的流量
sudo ./src/.output/firewall -i eth0 -b dport=8080

# 源网段 + TCP + 目的端口
sudo ./src/.output/firewall -i eth0 \
  -b src=10.0.0.0/8,proto=tcp,dport=8080

# 多条规则（OR）
sudo ./src/.output/firewall -i eth0 \
  -b dport=443 \
  -b src=192.0.2.0/24,proto=udp,sport=53

# 运行中查看统计（另开终端）
sudo kill -USR1 $(pgrep -x firewall)
```

程序附加到网卡后会阻塞；**Ctrl+C** 卸载 XDP 并打印 `pass` / `drop` / `drop (分片)` / `pass (early)` 及按 `id` 的 `rule_hits`。

## 命令行参数

| 选项 | 说明 |
|------|------|
| `-i IFNAME` | **必填**，网卡名（如 `eth0`） |
| `-b RULE` | 黑名单规则，可重复；格式见下文 |
| `-v` | 输出 libbpf 调试日志 |
| `--pin DIR` | attach 后将 `blacklist` / `stats` / `rule_hits` pin 到目录 |
| `--reuse DIR` | 加载前复用 DIR 下已 pin 的 map |
| `--refill` | 与 `--reuse` 合用：复用后重新写入 `-b` 规则 |
| `--leave-pinned` | 退出时不删除 pin 文件 |

**注意：**

- 未使用 `--reuse` 时，至少提供一条 `-b` 规则。
- 仅 `--reuse` 且不带 `--refill`、不带 `-b` 时，从已 pin 的 `blacklist` map 推断规则数量与 L4 需求。

## 规则语法

每条 `-b` 规则为逗号分隔的 `key=value`：

| 字段 | 示例 | 说明 |
|------|------|------|
| `src` | `src=10.0.0.0/8`、`src=2001:db8::/32` | 源地址 CIDR（IPv4 前缀 0–32，IPv6 0–128） |
| `proto` | `proto=tcp` | `tcp` / `udp` / `icmp` / `icmpv6`；省略表示 ANY（语义见下） |
| `sport` | `sport=53` | 源端口 1–65535 |
| `dport` | `dport=8080` | 目的端口 1–65535 |
| `id` | `id=1` | 规则 ID（0–255），用于 `rule_hits` 计数 |

**匹配语义（简要）：**

- 各字段在规则内为 **AND**；配置了 `src` 则必须先匹配源地址。
- 仅配置 `src`、且 `proto` 为 ANY、无端口时：源匹配即丢弃（“只封源”）。
- 配置了 `proto` 或端口时，按协议与 L4 信息继续匹配；`icmp` / `icmpv6` 不能与端口字段合用。
- 未写 `proto` 但写了端口：仅对能解析出 TCP/UDP 的包做端口匹配。
- 多条 `-b` 之间为 **OR**：遍历黑名单，**先命中先 DROP**。

**分片：** 当任意规则涉及 TCP/UDP 协议或源/目的端口时，内核会开启 `need_l4_match`，对 **非首片分片** 直接丢弃（`FW_STAT_DROP_FRAG`）。

## 项目结构

```
myfirewall/
├── Makefile           # 编译 BPF + 用户态
├── vmlinux.h          # BPF 所需内核类型（需自行准备或 bpftool 生成）
├── README.md
└── src/
    ├── firewall.h     # 用户态与 eBPF 共享的数据结构
    ├── firewall.bpf.c # XDP 黑名单逻辑
    └── firewall.c     # 加载器、CLI、map pin/reuse、统计
```

## Map 持久化示例

```bash
# 首次运行并 pin
sudo ./src/.output/firewall -i eth0 -b dport=8080 --pin /sys/fs/bpf/myfw

# 换程序实例：复用 map，保留 stats / rule_hits
sudo ./src/.output/firewall -i eth0 --reuse /sys/fs/bpf/myfw

# 复用 map 并更新规则
sudo ./src/.output/firewall -i eth0 -b dport=8443 \
  --reuse /sys/fs/bpf/myfw --refill
```

退出时默认会 **unlink** pin 路径下的 map 文件；若需保留，加 `--leave-pinned`。

## 统计项

| 索引 | 含义 |
|------|------|
| `pass (policy)` | 未命中任何黑名单，放行 |
| `drop` | 命中黑名单，丢弃 |
| `drop (分片)` | 因分片策略丢弃 |
| `pass (early/跳过)` | 非 IP、解析失败等，不处理直接放行 |

`rule_hits` 按规则 `id` 累计命中次数（未设置 `id` 时 id 为 0）。

## 许可证

源码头文件标注：**GPL-2.0 OR BSD-3-Clause**（Dual BSD/GPL）。