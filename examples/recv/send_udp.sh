#!/bin/bash

# --- 配置参数 ---
TARGET_IP="192.168.8.100"  # 目标 IP 地址
TARGET_PORT="9891"        # 目标 UDP 端口
MESSAGE_PREFIX="Hello, UDP " # 消息前缀
DELAY_SECONDS="1"         # 延迟时间 (秒)
# ----------------

echo "--- UDP 时间戳发送脚本启动 ---"
echo "目标: ${TARGET_IP}:${TARGET_PORT} (每 ${DELAY_SECONDS} 秒发送一次)"
echo "按 Ctrl+C 停止"
echo "-----------------------------------"

# 循环发送消息
while true; do
    # 获取当前的 Unix 时间
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    # 构建完整的消息
    MESSAGE="${MESSAGE_PREFIX}${TIMESTAMP} ${TARGET_IP}:${TARGET_PORT}"

    # 使用 nc (Netcat) 命令发送 UDP 消息
    # -u: 使用 UDP 协议
    # -w1: 发送后等待 1 秒 (但由于我们使用 sleep，可以省略，这里保留以确保连接立即关闭)
    # echo "$MESSAGE" | nc -u -w1 $TARGET_IP $TARGET_PORT
    echo "发送: ${MESSAGE}"
    echo "$MESSAGE" | nc -u -w0 $TARGET_IP $TARGET_PORT

    # 暂停指定时间
    sleep $DELAY_SECONDS
done

echo "-----------------------------------"
echo "脚本已停止."
