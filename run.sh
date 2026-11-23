#!/bin/sh
# 自动订阅流水线包装脚本：加锁、导出 token、跑一轮、留日志
# cron（每 6 小时，错开上游 airport 的 0/6 整点抓取）：
#   30 */6 * * * /root/autosub/run.sh >> /root/autosub/run.log 2>&1

BASE=/root/autosub
CONF=$BASE/sources.yaml
LOCK=$BASE/.lock

# busybox 不一定有 flock，用 mkdir 原子锁 + 陈旧锁清理（超过 2 小时视为上次异常退出）
if [ -d "$LOCK" ]; then
  if [ "$(find "$LOCK" -maxdepth 0 -mmin +120 2>/dev/null)" ]; then
    echo "$(date) 清理陈旧锁"
    rmdir "$LOCK"
  else
    echo "$(date) 已有任务在跑，跳过"
    exit 0
  fi
fi
mkdir "$LOCK" || exit 0
trap 'rmdir "$LOCK"' EXIT INT TERM

# token 只放这里（文件权限 600），不要写进 sources.yaml
if [ -f "$BASE/.env" ]; then
  . "$BASE/.env"
fi

ruby "$BASE/autosub.rb" -c "$CONF"
rc=$?
case $rc in
  0) echo "$(date) 完成" ;;
  2) echo "$(date) 存活节点不足，保留上一版（退出码 2）" ;;
  *) echo "$(date) 失败，退出码 $rc" ;;
esac

# 日志只留最近 2000 行
if [ -f "$BASE/run.log" ]; then
  tail -n 2000 "$BASE/run.log" > "$BASE/run.log.tmp" && mv "$BASE/run.log.tmp" "$BASE/run.log"
fi
exit $rc
