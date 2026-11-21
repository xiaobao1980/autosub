# autosub — 只放实测活着的免费节点

订阅地址（Clash Meta / mihomo 内核，OpenClash 可直接添加为在线订阅）：

```
https://raw.githubusercontent.com/xiaobao1980/autosub/main/sub/autosub.yaml
```

## 和别家聚合订阅的区别

只发布**测过还活着**的节点。上游吃 [dongchengjie/airport](https://github.com/dongchengjie/airport) 的
`subs/merged/tested_within.yaml`（1600+ 节点），然后在本机用 mihomo 临时实例（不开 tun、不干扰正在跑的
OpenClash）做端到端 delay 测试，连续两轮全过才进订阅。

公开聚合站通常不做这一步，或者在 GitHub 自己的机房里做——机房里测出的存活率对家用宽带没有参考价值，
这是同一份节点池在两种网络下能差出一个数量级的原因。

## 用之前需要知道的四件事

**测速线路**：存活一半取决于节点服务器活着（可迁移），一半取决于你到那台服务器的通路（不可迁移）。
本文件按订阅发布时所在线路测得，换运营商、换城市后命中率会下降，这是链路属性不是文件坏了。
即便如此仍显著优于直接吃原始池——原始里约九成节点是彻底连不上的。

**这是完整配置，不只是节点表**：包含 `dns`（fake-ip）、`sniffer`、5 个策略分组、10 条分流规则、
`allow-lan: true`。结构与上游 airport 的输出同构。当 OpenClash / mihomo 的配置档加载时，这些字段
会被你自己的覆写设置接管；但用 clash-verge、v2rayN 这类独立客户端直接导入时会被照单采纳，导入前确认一下。

**分组与规则**：分组名为 `🚀 节点选择` / `♻️ 自动选择` / `🚑 故障转移` / `🎯 全局直连` / `🐟 漏网之鱼`，
末条规则是 `MATCH,🐟 漏网之鱼`，即未命中规则默认走代理。需要分流自己加规则。

**新鲜度**：每 6 小时重新测速发布一次。本轮候选数、存活数、协议分布看 `sub/latest.json`，
逐个节点的延迟与失败原因看 `sub/stats.csv`，YAML 头部注释里也写了生成时间和存活数。

## 安全性

不含任何付费机场凭据。全部节点来自公开仓库，其中的 UUID 与密码本来就是公开共享的。
发布脚本在推送前会校验目标仓库可见性：配置中一旦出现标记为 `private: true` 的上游而目标仓库是公开的，
立即中止，不会发布。

## 自部署

管线是单文件 Ruby（无 gem 依赖，Ruby 2.6 即可运行），设计目标是跑在 iStoreOS / OpenWrt 上，
通过 GitHub Contents API 发布，目标设备不需要装 git。
