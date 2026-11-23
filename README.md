# autosub — 四家免费源聚合成一份 OpenClash 订阅

订阅地址（Clash Meta / mihomo 内核，OpenClash 直接添加为在线订阅即可）：

```
https://raw.githubusercontent.com/xiaobao1980/autosub/sub/autosub.yaml
https://fastly.jsdelivr.net/gh/xiaobao1980/autosub@sub/autosub.yaml
```

两条任选。`raw.` 那条最实时但国内经常连不上；jsDelivr 那条国内可达，代价是它的缓存 key 里
只有文件大小没有内容 hash，yaml 大小恰好没变时能给你 7 天前的旧版。真卡住了就在 OpenClash 里
手动刷新或临时换成带 commit SHA 的地址：`https://raw.githubusercontent.com/xiaobao1980/autosub/<sha>/sub`。

产出提交在 **`sub` 分支**（只有一个文件的历史），代码在 `main`。

## 这个流水线做什么、不做什么

**做**：抓 4 个还在更新的公开源 → 解 base64/明文/clash yaml 三种格式 → 按 server:port:uuid 去重 →
协议白名单 → 修 mihomo 会整份拒绝的非法 REALITY 字段 → 按「同一节点出现在几个独立源里」降序取 300 个
→ 拼上 dns / sniffer / 5 个策略分组 / 分流规则 → 每 6 小时提交一次。

**不做**：**不测速**。这一步在 GitHub 上做不了——runner 在美国机房，而 GFW 的阻断是方向性的，
它连得通的节点你家宽可能根本连不上，反过来也一样。所以这份订阅里 300 个节点是「多个独立采集仓
都认为它存在」，不是「实测可用」。

真正的挑选交给订阅里的两个组，它们跑在你自己的 OpenClash 上，用的就是你自己的线路：

- `♻️ 自动选择`（url-test）：每 600 秒探一次 `cp.cloudflare.com/generate_204`，谁快用谁，容差 30ms；
- `🚑 故障转移`（fallback）：按顺序挑第一个连得上的。

所以**别把节点直接放进 `🚀 节点选择` 长期使用**，让 `🚀` 指向 `♻️` 或 `🚑` 才有自动换节点的效果。

靶子为什么是 `cp.cloudflare.com` 而不是 `www.gstatic.com`：mihomo 是本地解析靶子域名再把 IP 交给
远端节点去连，国内 DNS 解 `gstatic` 得到的是 Google 北京机房地址（`120.253.253.226`），境外节点连它
必超时——实测 1052 个节点 883 个报 Timeout，存活被压到 0.9%。`cp.cloudflare.com` 是任播地址
（`104.16.132.229`），国内外解析答案一致，谁都连得到。订阅里的 `dns.fake-ip-filter` 也把它排除了，
否则 fake-ip 会把这个靶子解成 `198.18.x`，mihomo 自己拨号打的是假地址，全组一起超时。

## 用之前需要知道的四件事

**免费节点的真实命中率**：原始池里约九成彻底连不上。经过多源共现筛选的 300 个会好一些，但仍然
要在 `♻️ 自动选择` 里靠 url-test 自己捞出来，不要指望列表里每个都能用。

**这是完整配置，不只是节点表**：含 `dns`（fake-ip）、`sniffer`、5 个分组、10 条分流规则、
`allow-lan: true`。OpenClash / mihomo 加载时这些字段会被你自己的覆写设置接管；但 clash-verge、
v2rayN 这类独立客户端直接导入会照单采纳，导入前看一眼。

**分组与规则**：`🚀 节点选择` / `♻️ 自动选择` / `🚑 故障转移` / `🎯 全局直连` / `🐟 漏网之鱼`，
末条规则 `MATCH,🐟 漏网之鱼`，未命中默认走代理。要分流自己加规则。

**新鲜度**：每 6 小时一次（`0 */6 * * *`）。本轮候选数、发布数、协议分布看 `sub/latest.json`；
本轮跑了什么、为什么没更新，看仓库 Actions 页的运行记录。
每轮发布前会拿真 mihomo 跑一遍 `-t`：内核解析代理是全有全无的，一个非法字段就让它拒绝加载
整份配置（OpenClash 表现为「下载成功但配置文件测试失败」），所以自检不过宁可不提交，也绝不发一份
加载不了的文件。
注意 GitHub 的规矩：仓库 60 天没有任何活动，`schedule` 会被自动停用，重新 push 代码或在
Actions 页手动 Run 一次就恢复。

## 安全性

不含任何付费机场凭据，全部节点来自公开仓库，其中的 UUID 与密码本来就是公开共享的。
加私有源必须在 `sources.yaml` 里写 `private: true`——脚本推送前会校验目标仓库可见性，
公开仓库直接中止；地址里带 `target=`/`token=`/`/sub/<长串>` 这类凭据特征又没标 private 的，
脚本拒绝启动。

## 自部署（fork 后三步）

1. Fork 本仓库，改 `sources.yaml` 里的仓库不用改，`sub` 分支会由 workflow 自己建。
2. 仓库 Settings → Actions → General → Workflows permissions 选 **Read and write**
   （或直接信任代码里写的 `permissions: contents: write`）。
3. Actions 页手动 Run workflow 验证一次，成功后 `sub` 分支出现 `autosub.yaml`，
   把上面的地址里的仓库名换成你自己的。

不需要配 PAT，产出是用 workflow 里的 git 提交推的。管线是单文件 Ruby，只用 stdlib（Ruby 3.3 /
GitHub runner 自带的版本都行）；`run.sh` 是早先打算跑在 iStoreOS 路由器上的 cron 包装，
走 Actions 路线用不到它。想在本地先看产出：`ruby autosub.rb -c sources.yaml --stage all`，
文件落在 `./work/`。
