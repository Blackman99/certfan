---
title: "证书续期了，每台节点都换上了吗？"
description: 证书有效期越来越短，"某台负载均衡节点还在发旧证书"会变成常态。只探测一个地址的检查发现不了它；certfan 对域名背后的每个地址做 TLS 握手，比对各自返回的证书。
---

# 证书续期了，每台节点都换上了吗？

*2026 年 10 月 · [English](every-node-same-cert.md)*

凌晨三点，ACME 客户端把证书续好了。部署钩子把新证书分发出去，挨个 reload。监控是绿的。可 `shop.example.com` 背后的四台节点里，有一台还在发上个月的旧证书：可能它的 reload 失败了，可能部署时它正好被摘流量，也可能它是另一个地域的副本，压根没接进钩子。

眼下什么都不会坏，旧证书还没过期。等它真的过期，大约四分之一的请求会报证书错误，而且只影响一部分用户，取决于他们的解析器或负载均衡把他们分到了哪个地址。

## 为什么这种事会越来越常见

公网 TLS 证书的最长有效期正按既定时间表缩短。根据 CA/Browser Forum 的
[SC-081 投票](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)：

| 签发时间（含当天及之后） | 最长有效期 |
|---|---|
| 2026 年 3 月 15 日 | 200 天 |
| 2027 年 3 月 15 日 | 100 天 |
| 2029 年 3 月 15 日 | **47 天** |

Let's Encrypt 从 2026 年 1 月起正式提供可选的 [6 天证书](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability)，并计划把默认有效期从 90 天逐步降到 45 天。

续期本身早就自动化了，没解决的是**分发**。每续一次，就要把新文件再部署一遍，送到所有替这个域名终结 TLS 的地方：负载均衡节点、Ingress 副本、边缘服务器、第二条 A 记录背后那台大家都忘了的虚拟机。证书一年一换时，某台节点漏了一次 reload，要好几个月才会出事；换成 47 天证书、几周续一次，同样的疏漏一年要发生很多回，从"已续期"到"旧副本过期"之间的时间窗口也越来越短。

## 为什么现有的检查一直是绿的

大多数证书检查是这样做的：解析域名，取一个地址，握手，读 `notAfter`。`openssl s_client -connect shop.example.com:443` 是这样，常见的 blackbox_exporter、Uptime Kuma、Gatus 探测也是这样，除非你手工为每个 IP 各配一个探测。

如果域名解析出四个地址、只有一个是旧的，单地址检查四次里有三次打到健康节点；就算打到那台旧的，看到的证书也还在有效期内。在旧证书真正过期之前，什么告警都不会有。

真正该问的是另一个问题：**这个域名背后的所有地址，返回的是不是同一张有效、且不快过期的证书？**

## certfan 做了什么

[certfan](https://github.com/Blackman99/certfan) 是一个小命令行工具（纯 Python 3.9+，零依赖），专门回答这个问题：

1. 解析每个目标的**全部** A 和 AAAA 记录（也可以用 `--connect` 直接给出后端列表）。
2. 对**每个**地址发起 TLS 连接，带上正确的 SNI，校验证书链和主机名。
3. 比较各地址的证书指纹。不一致时，发少数派证书的节点判为失败（票数相同时，没在用最新签发证书的那一方失败）。
4. 证书剩余天数少于 `--warn-days`（默认 7 天），**或**剩余寿命不到总有效期的 `--warn-pct`（默认 33%）时告警。百分比对短期证书很重要：一张 6 天证书只剩 1.5 天时，寿命只剩 25%，本该早就续了，可"1.5 天"能通过很多按天数设的阈值。
5. 退出码 `0`（通过）、`1`（告警）、`2`（失败），可选输出 JSON 或 Prometheus 指标。

它只做 TLS 握手，不发任何 HTTP 请求。

## 上手试试

```bash
pipx install "git+https://github.com/Blackman99/certfan@v0.1.0"
certfan demo
```

`certfan demo` 会在本地为同一个域名起三个 TLS 服务，其中一个用的是另一张证书，然后检查它们。下面是 2026 年 10 月 9 日实际运行的输出：

```text
shop.example.test  3 address(es), 2 distinct certificate(s)
  PASS  127.0.0.1:38255                         cert A  serial 51fe63574478  expires 2126-09-15  TLSv1.3  7ms
  PASS  127.0.0.1:42175                         cert A  serial 51fe63574478  expires 2126-09-15  TLSv1.3  6ms
  FAIL  127.0.0.1:43293                         cert B  serial 61c4ec55df4c  expires 2126-09-15  TLSv1.3  6ms
    - 127.0.0.1:43293: serves a different certificate (serial 61c4ec55df4cf8bb, issued 2026-10-09) than the other nodes
  verdict: FAIL
(demo: exit code would be 2; returning 0)
```

两张证书都有效，离过期还远，单地址的过期检查会认为一切正常。certfan 判失败，是因为节点之间不一致。

### 一个真实域名

在一台没有 IPv6 出网的机器上检查 `example.com`：

```text
$ certfan check example.com
example.com  4 address(es), 1 distinct certificate(s)
  PASS  104.20.23.154                           cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  36ms
  PASS  172.66.147.243                          cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  31ms
  FAIL  2606:4700:10::6814:179a                 OSError: [Errno 101] Network is unreachable
  FAIL  2606:4700:10::ac42:93f3                 OSError: [Errno 101] Network is unreachable
    - 2606:4700:10::6814:179a: unreachable: OSError: [Errno 101] Network is unreachable
    - 2606:4700:10::ac42:93f3: unreachable: OSError: [Errno 101] Network is unreachable
  verdict: FAIL
$ echo $?
2
```

这个域名有两条 A 记录、两条 AAAA 记录，certfan 四个都试了。两台 IPv4 节点证书一致；IPv6 地址失败，是因为**这台机器**没有 IPv6 路由。certfan 默认把连不上的地址当作失败：DNS 里公布了、却检查不了的地址，不能算健康。如果你清楚探测机没有 IPv6，可以限定地址族，或者把连不上降级为告警：

```text
$ certfan check -4 example.com
example.com  2 address(es), 1 distinct certificate(s)
  PASS  172.66.147.243                          cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  31ms
  PASS  104.20.23.154                           cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  32ms
  verdict: PASS

$ certfan check example.com --allow-unreachable      # 同样 4 个地址；IPv6 两行变成 WARN，退出码 1
```

### 剩余寿命百分比

上面这张证书 9 月 26 日签发，有效期 90 天。把阈值调高，就能看到百分比规则生效：

```text
$ certfan check -4 example.com --warn-pct 90
example.com  2 address(es), 1 distinct certificate(s)
  WARN  104.20.23.154                           cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  30ms
  WARN  172.66.147.243                          cert A  serial 01eee6aabb52  expires 2026-12-25  TLSv1.3  30ms
    - 104.20.23.154: 77.6 days left (86% of a 90-day lifetime)
    - 172.66.147.243: 77.6 days left (86% of a 90-day lifetime)
  verdict: WARN
```

默认的 33% 对应 ACME 客户端的常见做法：一般在寿命剩下约三分之一时续期，所以低于这个比例的证书，本该已经被新证书替换掉了。

### 一个 VIP 背后的后端

如果节点都挂在同一个负载均衡地址后面，DNS 只能看到 VIP。这时自己列出后端，SNI 和主机名校验仍然用对外的域名：

```bash
certfan check shop.example.com --connect 10.0.0.7 --connect 10.0.0.8 --connect 10.0.0.9:8443
```

私有 CA 加 `--cafile corp-root.pem`；只关心一致性和过期时间，用 `--no-verify`。

## 定时运行

退出码就是接口，所以凡是能跑 shell 命令的地方都能用 certfan。

**cron**，只在出问题时发邮件：

```cron
*/15 * * * * certfan check shop.example.com api.example.com > /var/log/certfan.log || mail -s "certfan" ops@example.com < /var/log/certfan.log
```

**Prometheus**，走 node_exporter 的 textfile 收集器。`--prom-file` 以原子方式写文件，同时照常把文本报告打到标准输出。下面是 `--format prom` 的真实输出：

```text
$ certfan check -4 example.com --format prom
# HELP certfan_node_cert_expiry_seconds Unix time the served certificate expires.
# TYPE certfan_node_cert_expiry_seconds gauge
# HELP certfan_node_status 0=pass 1=warn 2=fail per address.
# TYPE certfan_node_status gauge
# HELP certfan_distinct_certs Distinct certificates served across all addresses.
# TYPE certfan_distinct_certs gauge
certfan_node_cert_expiry_seconds{host="example.com",ip="172.66.147.243",serial="01eee6aabb521d5e14fc315fd9985690"} 1798239395
certfan_node_status{host="example.com",ip="172.66.147.243",serial="01eee6aabb521d5e14fc315fd9985690"} 0
certfan_node_cert_expiry_seconds{host="example.com",ip="104.20.23.154",serial="01eee6aabb521d5e14fc315fd9985690"} 1798239395
certfan_node_status{host="example.com",ip="104.20.23.154",serial="01eee6aabb521d5e14fc315fd9985690"} 0
certfan_distinct_certs{host="example.com"} 1
```

```bash
certfan check shop.example.com --prom-file /var/lib/node_exporter/textfile/certfan.prom
```

```yaml
- alert: CertFanOut
  expr: certfan_distinct_certs > 1
  for: 15m
- alert: CertNodeFailing
  expr: certfan_node_status == 2
  for: 15m
```

**CI：部署之后或定时跑。** 下面这个 GitHub Actions 任务每小时跑一次，并在部署工作流结束后再跑一次（把工作流名字换成你自己的）。退出码非零会让任务失败，JSON 报告作为 artifact 保留：

```yaml
name: certs
on:
  schedule: [{cron: "17 * * * *"}]
  workflow_run: {workflows: ["deploy"], types: [completed]}
  workflow_dispatch:
jobs:
  certfan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v7
        with: {python-version: "3.12"}
      - run: pip install "git+https://github.com/Blackman99/certfan@v0.1.0"
      - run: certfan check -4 shop.example.com api.example.com --format json > certfan.json
      - if: always()
        uses: actions/upload-artifact@v4
        with: {name: certfan, path: certfan.json}
```

GitHub 托管的 runner 没有 IPv6 连通性，所以示例里加了 `-4`。CI runner 还能提供第二个观察点，对 anycast 和 GeoDNS 有帮助，因为不同位置看到的地址可能不一样。

## 目前的局限

- **一个观察点只看到一种视图。** 用了 anycast 或 GeoDNS 时，certfan 检查的是**它自己**的解析器和路由给出的结果。可以从几个地方分别跑，或用 `--connect` 指向源站地址。单次运行对比多个解析器（`--resolver`）已列入 v0.2 [路线图](https://github.com/Blackman99/certfan/blob/main/ROADMAP.md)。
- **目前只比较叶子证书。** 某台节点叶子证书对、中间证书链不同，暂时不会被标出来。逐节点比较证书链计划在 v0.2 加入。
- **只支持直接 TLS。** STARTTLS（SMTP、IMAP、Postgres）计划在 v0.3 支持。
- **它不负责续期。** 那是 ACME 客户端的事；certfan 负责确认续好的证书真的到了每一台节点。

## 链接

- 代码和 issue：[github.com/Blackman99/certfan](https://github.com/Blackman99/certfan)（MIT）
- 文档：[用法](../usage.md)、[监控接入](../monitoring.md)、[命令参考](../reference.md)
