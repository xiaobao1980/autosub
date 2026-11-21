# autosub

路由器上自跑的免费节点订阅管线：拉上游 -> 本机 mihomo 临时实例测速 -> 只发布存活节点。

产出由 `/root/autosub/autosub.rb` 通过 Contents API 推到本仓库 `sub/` 目录，
`run.sh` 每 6 小时跑一次。订阅地址用 commit SHA 固定，避开 CDN 弱 ETag 缓存。

- `sub/autosub.yaml`  存活节点订阅（Clash Meta / mihomo 格式）
- `sub/stats.csv`     每个节点的测速明细
- `sub/latest.json`   本轮统计摘要（候选数、存活率、协议分布）

上游全部来自公开仓库，不含任何付费订阅源。
