# DPDK 数据包接收和解析示例程序

## 概述

这是一个基于 DPDK 的数据包接收和解析示例程序，支持：

- ✅ 解析以太网头（MAC 地址）
- ✅ 解析 IP 层（IPv4/IPv6 地址）
- ✅ 解析传输层（UDP/TCP 端口号）
- ✅ 显示 UDP/TCP 负载内容预览（前 32 字节）
- ✅ 支持单端口和多端口模式
- ✅ 自动过滤不支持的协议类型

## 目录

- [编译和运行](#编译和运行)
- [测试](#测试)
- [其他用法](#其他用法)

---

## 编译和运行

### 概述

DPDK 工作在数据链路层（L2），不直接管理 IP 地址。当网卡被 DPDK 接管后，Linux 内核不再管理该网卡，因此无法使用传统的 `ifconfig` 或 `ip addr` 命令设置 IP。

如果只需要**接收和解析数据包**，通常不需要设置 IP 地址，因为：

- 程序已启用混杂模式（`rte_eth_promiscuous_enable`）
- 可以接收所有经过网卡的数据包
- 只需要解析数据包中的源/目的 IP 即可

### 总结

- **仅接收数据包**：不需要设置 IP，使用混杂模式即可
- **需要发送数据包**：使用应用层处理
- **高性能场景**：推荐完全在用户空间处理

### 编译程序

```bash
cd examples/recv && make
```

### 运行程序

```bash
# 使用sudo运行（DPDK需要root权限）
sudo ./build/recv -- -t  # -t 可选，启用硬件时间戳
```

---

## 测试

### 使用 nc 命令

```bash
# 设置 arp 表信息
sudo arp -s 192.168.8.100 84:47:09:32:5f:3f

# 查看 arp 信息
sudo arp -n -a

# 单次发送
echo "Hello, UDP 123456····" | nc -u -w1 192.168.8.100 9891

# 循环发送（每1秒）
while true; do
  echo "Hello, UDP $(date +%H:%M:%S) ····" | nc -u -w1 192.168.8.100 9891
  sleep 1
done
```

### 输出示例

程序运行时会显示类似以下的信息：

```
[Port 0] 数据包信息: 长度=92, 源MAC=c8:a3:62:7d:b2:62, 目的MAC=84:47:09:32:5f:3f, 源IP=192.168.8.24, 目的IP=192.168.8.100, 协议=UDP, 源端口=52170, 目的端口=9891, 负载长度=50, 负载预览="Hello, UDP 2025-11-18 11:20:53 1"
[Port 0] 数据包信息: 长度=92, 源MAC=c8:a3:62:7d:b2:62, 目的MAC=84:47:09:32:5f:3f, 源IP=192.168.8.24, 目的IP=192.168.8.100, 协议=UDP, 源端口=57327, 目的端口=9891, 负载长度=50, 负载预览="Hello, UDP 2025-11-18 11:20:55 1"
```

---

## 其他用法

### 修改负载预览长度

在 `main.c` 的 `parse_and_print_packet` 函数中，可以修改：

```c
uint16_t preview_len = payload_len < 32 ? payload_len : 32;  // 改为你想要的长度
```

### 过滤特定端口的数据包

可以在 `add_timestamps` 回调函数中添加过滤逻辑：

```c
// 只处理目标端口为9891的UDP包
if (dst_port == 9891 && proto_str == "UDP") {
    parse_and_print_packet(pkts[i], port);
}
```

### 配置 DPDK 网卡 IP

在 `main.c` 的 `main` 函数中，可以配置 DPDK 网卡的 IP 信息：

```c
/* 配置端口的IP地址、子网掩码和网关 */
RTE_ETH_FOREACH_DEV(portid) {
    if (configure_port_ip(portid, "192.168.8.100", "255.255.255.0", "192.168.8.1") != 0) {
        printf("Warning: Failed to configure IP for port %u\n", portid);
    }
}
```

### 支持的协议类型

程序目前支持并会打印以下协议的数据包：

- IPv4 TCP
- IPv4 UDP
- IPv4 ICMP
- IPv6 TCP
- IPv6 UDP
- IPv6 ICMPv6

其他协议类型会被自动跳过，不打印任何信息。

---

## 注意事项

1. **权限要求**：DPDK 程序需要 root 权限运行
2. **网卡绑定**：确保目标网卡已绑定到 DPDK 驱动

      ```shell
      ../../usertools/dpdk-devbind.py -s

      # Network devices using DPDK-compatible driver
      # ============================================
      # 0000:2d:00.0 'Ethernet Controller I225-V 15f3' drv=vfio-pci unused=igc,uio_pci_generic
      #
      # Network devices using kernel driver
      # ===================================
      # 0000:00:14.3 'Alder Lake-P PCH CNVi WiFi 51f0' if=wlo1 drv=iwlwifi unused=vfio-pci,uio_pci_generic *Active*
      # 0000:2c:00.0 'Ethernet Controller I225-V 15f3' if=enp44s0 drv=igc unused=vfio-pci,uio_pci_generic *Active*
      #
      # No 'Baseband' devices detected
      # ==============================
      #
      # No 'Crypto' devices detected
      # ============================
      #
      # No 'DMA' devices detected
      # =========================
      #
      # No 'Eventdev' devices detected
      # ==============================
      #
      # No 'Mempool' devices detected
      # =============================
      #
      # No 'Compress' devices detected
      # ==============================
      #
      # No 'Misc (rawdev)' devices detected
      # ===================================
      #
      # No 'Regex' devices detected
      # ===========================
      #
      # No 'ML' devices detected
      # ========================
      ```

3. **IP 地址**：程序使用混杂模式，可以接收所有数据包，但配置 IP 地址有助于网络通信
4. **网络连接**：确保发送端和接收端在同一网络或可以路由
5. **ARP 配置**：从远程机器发送时，必须手动配置 ARP 表

---

## 总结

1. **基本命令**：`echo "message" | nc -u 192.168.8.100 9891`
2. **关键配置**：手动添加 ARP 条目（远程测试时）
3. **验证方法**：查看 DPDK 程序输出
4. **故障排查**：检查 ARP、路由、防火墙

由于 DPDK 工作在用户空间，网络配置需要手动处理，但一旦配置正确，就可以正常接收和解析 UDP/TCP 数据包了。
