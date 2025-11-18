#include <arpa/inet.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static int hwts_dynfield_offset = -1;

static inline rte_mbuf_timestamp_t *hwts_field(struct rte_mbuf *mbuf) {
  return RTE_MBUF_DYNFIELD(mbuf, hwts_dynfield_offset, rte_mbuf_timestamp_t *);
}

typedef uint64_t tsc_t;
static int tsc_dynfield_offset = -1;

static inline tsc_t *tsc_field(struct rte_mbuf *mbuf) {
  return RTE_MBUF_DYNFIELD(mbuf, tsc_dynfield_offset, tsc_t *);
}

static const char usage[] = "%s EAL_ARGS -- [-t]\n";

static struct {
  uint64_t total_cycles;
  uint64_t total_queue_cycles;
  uint64_t total_pkts;
} latency_numbers;

int hw_timestamping;

#define TICKS_PER_CYCLE_SHIFT 16
static uint64_t ticks_per_cycle_mult;

/* 端口IP配置结构（可选，用于需要发送数据包或响应ARP的场景） */
struct port_ip_config {
  uint32_t ip_addr;          /* 本机IP地址（网络字节序） */
  uint32_t netmask;          /* 子网掩码（网络字节序） */
  uint32_t gateway;          /* 网关地址（网络字节序，可选） */
  struct rte_ether_addr mac; /* MAC地址 */
  int configured;            /* 是否已配置 */
};

static struct port_ip_config port_configs[RTE_MAX_ETHPORTS];

/* 配置端口的IP地址（可选功能） */
static int configure_port_ip(uint16_t port, const char *ip_str,
                             const char *netmask_str, const char *gateway_str) {
  struct in_addr ip, mask, gateway;

  if (port >= RTE_MAX_ETHPORTS) {
    printf("Error: Invalid port number %u\n", port);
    return -1;
  }

  if (inet_aton(ip_str, &ip) == 0) {
    printf("Error: Invalid IP address format: %s\n", ip_str);
    return -1;
  }

  if (netmask_str != NULL) {
    if (inet_aton(netmask_str, &mask) == 0) {
      printf("Error: Invalid netmask format: %s\n", netmask_str);
      return -1;
    }
    port_configs[port].netmask = mask.s_addr;
  } else {
    /* 默认使用 /24 子网掩码 */
    port_configs[port].netmask = htonl(0xFFFFFF00);
  }

  if (gateway_str != NULL) {
    if (inet_aton(gateway_str, &gateway) == 0) {
      printf("Error: Invalid gateway format: %s\n", gateway_str);
      return -1;
    }
    port_configs[port].gateway = gateway.s_addr;
  } else {
    port_configs[port].gateway = 0; /* 网关可选 */
  }

  port_configs[port].ip_addr = ip.s_addr;
  port_configs[port].configured = 1;

  /* 获取端口的MAC地址 */
  if (rte_eth_macaddr_get(port, &port_configs[port].mac) != 0) {
    printf("Error: Failed to get MAC address for port %u\n", port);
    return -1;
  }

  printf("Port %u IP configured: IP=%s, Netmask=%s, Gateway=%s, MAC: "
         "%02x:%02x:%02x:%02x:%02x:%02x\n",
         port, ip_str, netmask_str ? netmask_str : "255.255.255.0",
         gateway_str ? gateway_str : "N/A",
         RTE_ETHER_ADDR_BYTES(&port_configs[port].mac));

  return 0;
}

/* 获取端口的IP地址（网络字节序） */
static inline uint32_t get_port_ip(uint16_t port) {
  if (port >= RTE_MAX_ETHPORTS || !port_configs[port].configured)
    return 0;
  return port_configs[port].ip_addr;
}

/* 检查IP地址是否属于本端口的子网 */
static inline int is_ip_in_subnet(uint16_t port, uint32_t ip) {
  if (port >= RTE_MAX_ETHPORTS || !port_configs[port].configured)
    return 0;
  return (ip & port_configs[port].netmask) ==
         (port_configs[port].ip_addr & port_configs[port].netmask);
}

/* 解析并打印数据包信息（源和目的地址） */
static inline void parse_and_print_packet(struct rte_mbuf *mbuf,
                                          uint16_t port) {
  struct rte_ether_hdr *eth_hdr;
  uint16_t pkt_len;
  char src_mac[18], dst_mac[18];
  char src_ip[INET6_ADDRSTRLEN] = "N/A";
  char dst_ip[INET6_ADDRSTRLEN] = "N/A";
  uint16_t ether_type = 0;
  const char *proto_str = "Unknown";

  /* 检查数据包长度是否足够包含以太网头 */
  pkt_len = rte_pktmbuf_pkt_len(mbuf);
  if (pkt_len < sizeof(struct rte_ether_hdr)) {
    /* 数据包太短，直接跳过 */
    return;
  }

  /* 获取以太网头指针，使用安全的宏 */
  eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
  if (eth_hdr == NULL) {
    /* 无法获取以太网头指针，直接跳过 */
    return;
  }

  /* 格式化MAC地址 */
  snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
           eth_hdr->src_addr.addr_bytes[0], eth_hdr->src_addr.addr_bytes[1],
           eth_hdr->src_addr.addr_bytes[2], eth_hdr->src_addr.addr_bytes[3],
           eth_hdr->src_addr.addr_bytes[4], eth_hdr->src_addr.addr_bytes[5]);

  snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
           eth_hdr->dst_addr.addr_bytes[0], eth_hdr->dst_addr.addr_bytes[1],
           eth_hdr->dst_addr.addr_bytes[2], eth_hdr->dst_addr.addr_bytes[3],
           eth_hdr->dst_addr.addr_bytes[4], eth_hdr->dst_addr.addr_bytes[5]);

  /* 获取以太网类型（网络字节序） */
  ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

  /* 解析IP层（仅支持IPv4和IPv6） */
  if (ether_type == RTE_ETHER_TYPE_IPV4) {
    struct rte_ipv4_hdr *ipv4_hdr;
    uint16_t ipv4_hdr_len;

    /* 检查数据包长度是否足够包含IPv4头 */
    if (pkt_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)) {
      /* 数据包太短，无法解析IPv4头，直接跳过 */
      return;
    }

    /* 获取IPv4头指针 */
    ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *,
                                       sizeof(struct rte_ether_hdr));
    if (ipv4_hdr == NULL) {
      /* 无法获取IPv4头指针，直接跳过 */
      return;
    }

    /* 获取IPv4头长度（以4字节为单位） */
    ipv4_hdr_len = (ipv4_hdr->version_ihl & 0x0F) * 4;
    if (ipv4_hdr_len < sizeof(struct rte_ipv4_hdr)) {
      /* IPv4头长度无效，直接跳过 */
      return;
    }

    /* 检查数据包总长度 */
    uint16_t total_len = rte_be_to_cpu_16(ipv4_hdr->total_length);
    if (total_len < ipv4_hdr_len) {
      /* IPv4总长度无效，直接跳过 */
      return;
    }

    /* 转换IP地址为字符串 */
    if (inet_ntop(AF_INET, &ipv4_hdr->src_addr, src_ip, sizeof(src_ip)) ==
        NULL) {
      strncpy(src_ip, "Invalid", sizeof(src_ip) - 1);
      src_ip[sizeof(src_ip) - 1] = '\0';
    }
    if (inet_ntop(AF_INET, &ipv4_hdr->dst_addr, dst_ip, sizeof(dst_ip)) ==
        NULL) {
      strncpy(dst_ip, "Invalid", sizeof(dst_ip) - 1);
      dst_ip[sizeof(dst_ip) - 1] = '\0';
    }

    /* 确定协议类型 */
    switch (ipv4_hdr->next_proto_id) {
    case IPPROTO_TCP:
      proto_str = "TCP";
      break;
    case IPPROTO_UDP:
      proto_str = "UDP";
      break;
    case IPPROTO_ICMP:
      proto_str = "ICMP";
      break;
    default:
      /* 协议类型为Other时不打印 */
      return;
    }

  } else if (ether_type == RTE_ETHER_TYPE_IPV6) {
    struct rte_ipv6_hdr *ipv6_hdr;

    /* 检查数据包长度是否足够包含IPv6头 */
    if (pkt_len < sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)) {
      /* 数据包太短，无法解析IPv6头，直接跳过 */
      return;
    }

    /* 获取IPv6头指针 */
    ipv6_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv6_hdr *,
                                       sizeof(struct rte_ether_hdr));
    if (ipv6_hdr == NULL) {
      /* 无法获取IPv6头指针，直接跳过 */
      return;
    }

    /* 转换IPv6地址为字符串 */
    if (inet_ntop(AF_INET6, &ipv6_hdr->src_addr, src_ip, sizeof(src_ip)) ==
        NULL) {
      strncpy(src_ip, "Invalid", sizeof(src_ip) - 1);
      src_ip[sizeof(src_ip) - 1] = '\0';
    }
    if (inet_ntop(AF_INET6, &ipv6_hdr->dst_addr, dst_ip, sizeof(dst_ip)) ==
        NULL) {
      strncpy(dst_ip, "Invalid", sizeof(dst_ip) - 1);
      dst_ip[sizeof(dst_ip) - 1] = '\0';
    }

    /* 确定协议类型 */
    switch (ipv6_hdr->proto) {
    case IPPROTO_TCP:
      proto_str = "TCP";
      break;
    case IPPROTO_UDP:
      proto_str = "UDP";
      break;
    case IPPROTO_ICMPV6:
      proto_str = "ICMPv6";
      break;
    default:
      /* 协议类型为Other时不打印 */
      return;
    }
  } else {
    /* 不是IPv4或IPv6，直接跳过 */
    return;
  }

  /* 打印数据包信息 */
  printf("[Port %u] 数据包信息: 长度=%u, 源MAC=%s, 目的MAC=%s", port, pkt_len,
         src_mac, dst_mac);
  printf(", 源IP=%s, 目的IP=%s, 协议=%s", src_ip, dst_ip, proto_str);

  /* 如果有端口信息，添加端口 */
  if (ether_type == RTE_ETHER_TYPE_IPV4) {
    struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    uint16_t src_port = 0, dst_port = 0;
    uint16_t payload_len = 0;
    char payload_str[64] = {0};

    if (ipv4_hdr && (ipv4_hdr->next_proto_id == IPPROTO_TCP ||
                     ipv4_hdr->next_proto_id == IPPROTO_UDP)) {
      uint16_t ipv4_hdr_len = (ipv4_hdr->version_ihl & 0x0F) * 4;
      uint16_t trans_offset = sizeof(struct rte_ether_hdr) + ipv4_hdr_len;

      if (ipv4_hdr->next_proto_id == IPPROTO_UDP &&
          pkt_len >= trans_offset + sizeof(struct rte_udp_hdr)) {
        struct rte_udp_hdr *udp_hdr =
            rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *, trans_offset);
        src_port = rte_be_to_cpu_16(udp_hdr->src_port);
        dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
        uint16_t udp_len = rte_be_to_cpu_16(udp_hdr->dgram_len);
        if (udp_len >= sizeof(struct rte_udp_hdr)) {
          payload_len = udp_len - sizeof(struct rte_udp_hdr);
          if (payload_len > 0 &&
              pkt_len > trans_offset + sizeof(struct rte_udp_hdr)) {
            const char *payload = (const char *)(udp_hdr + 1);
            uint16_t preview_len = payload_len < 32 ? payload_len : 32;
            memcpy(payload_str, payload, preview_len);
            payload_str[preview_len] = '\0';
            for (int i = 0; i < preview_len; i++) {
              if (payload_str[i] < 32 || payload_str[i] > 126)
                payload_str[i] = '.';
            }
          }
        }
      } else if (ipv4_hdr->next_proto_id == IPPROTO_TCP &&
                 pkt_len >= trans_offset + sizeof(struct rte_tcp_hdr)) {
        struct rte_tcp_hdr *tcp_hdr =
            rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *, trans_offset);
        src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
        dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        uint16_t tcp_hdr_len = (tcp_hdr->data_off >> 4) * 4;
        if (tcp_hdr_len >= sizeof(struct rte_tcp_hdr) &&
            pkt_len > trans_offset + tcp_hdr_len) {
          payload_len = pkt_len - trans_offset - tcp_hdr_len;
          if (payload_len > 0) {
            const char *payload =
                (const char *)((uint8_t *)tcp_hdr + tcp_hdr_len);
            uint16_t preview_len = payload_len < 32 ? payload_len : 32;
            memcpy(payload_str, payload, preview_len);
            payload_str[preview_len] = '\0';
            for (int i = 0; i < preview_len; i++) {
              if (payload_str[i] < 32 || payload_str[i] > 126)
                payload_str[i] = '.';
            }
          }
        }
      }

      if (src_port > 0 || dst_port > 0) {
        printf(", 源端口=%u, 目的端口=%u", src_port, dst_port);
      }
      if (payload_len > 0) {
        printf(", 负载长度=%u, 负载预览=\"%.32s\"", payload_len, payload_str);
      }
    }
  }
  printf("\n");
}

/* 添加到RX端口的回调函数，应用于数据包。8< */
static uint16_t add_timestamps(uint16_t port __rte_unused,
                               uint16_t qidx __rte_unused,
                               struct rte_mbuf **pkts, uint16_t nb_pkts,
                               uint16_t max_pkts __rte_unused,
                               void *_ __rte_unused) {
  unsigned i;
  uint64_t now = rte_rdtsc();

  for (i = 0; i < nb_pkts; i++) {
    /* 检查mbuf指针有效性 */
    if (pkts[i] == NULL) {
      printf("[Port %u] 警告: 收到NULL mbuf指针\n", port);
      continue;
    }

    /* 解析并打印数据包信息 */
    parse_and_print_packet(pkts[i], port);

    /* 添加时间戳 */
    *tsc_field(pkts[i]) = now;
  }
  return nb_pkts;
}
/* >8 回调函数添加和应用结束。 */

/* 添加到TX端口的回调函数。8< */
static uint16_t calc_latency(uint16_t port, uint16_t qidx __rte_unused,
                             struct rte_mbuf **pkts, uint16_t nb_pkts,
                             void *_ __rte_unused) {
  uint64_t cycles = 0;
  uint64_t queue_ticks = 0;
  uint64_t now = rte_rdtsc();
  uint64_t ticks;
  unsigned i;

  if (hw_timestamping)
    rte_eth_read_clock(port, &ticks);

  for (i = 0; i < nb_pkts; i++) {
    cycles += now - *tsc_field(pkts[i]);
    if (hw_timestamping)
      queue_ticks += ticks - *hwts_field(pkts[i]);
  }

  latency_numbers.total_cycles += cycles;
  if (hw_timestamping)
    latency_numbers.total_queue_cycles +=
        (queue_ticks * ticks_per_cycle_mult) >> TICKS_PER_CYCLE_SHIFT;

  latency_numbers.total_pkts += nb_pkts;

  if (latency_numbers.total_pkts > (100 * 1000 * 1000ULL)) {
    printf("Latency = %" PRIu64 " cycles\n",
           latency_numbers.total_cycles / latency_numbers.total_pkts);
    if (hw_timestamping) {
      printf("Latency from HW = %" PRIu64 " cycles\n",
             latency_numbers.total_queue_cycles / latency_numbers.total_pkts);
    }
    latency_numbers.total_cycles = 0;
    latency_numbers.total_queue_cycles = 0;
    latency_numbers.total_pkts = 0;
  }
  return nb_pkts;
}
/* >8 回调函数添加结束。 */

/*
 * 使用全局设置初始化给定端口，接收缓冲区来自作为参数传递的mbuf_pool
 */

/* 端口初始化。8< */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
  struct rte_eth_conf port_conf;
  const uint16_t rx_rings = 1, tx_rings = 1;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  int retval;
  uint16_t q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_rxconf rxconf;
  struct rte_eth_txconf txconf;

  if (!rte_eth_dev_is_valid_port(port))
    return -1;

  memset(&port_conf, 0, sizeof(struct rte_eth_conf));

  retval = rte_eth_dev_info_get(port, &dev_info);
  if (retval != 0) {
    printf("Error during getting device (port %u) info: %s\n", port,
           strerror(-retval));

    return retval;
  }

  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

  if (hw_timestamping) {
    if (!(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP)) {
      printf("\nERROR: Port %u does not support hardware timestamping\n", port);
      return -1;
    }
    port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
    rte_mbuf_dyn_rx_timestamp_register(&hwts_dynfield_offset, NULL);
    if (hwts_dynfield_offset < 0) {
      printf("ERROR: Failed to register timestamp field\n");
      return -rte_errno;
    }
  }

  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0)
    return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0)
    return retval;

  rxconf = dev_info.default_rxconf;

  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port, q, nb_rxd, rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
    if (retval < 0)
      return retval;
  }

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                    rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0)
      return retval;
  }

  retval = rte_eth_dev_start(port);
  if (retval < 0)
    return retval;

  if (hw_timestamping && ticks_per_cycle_mult == 0) {
    uint64_t cycles_base = rte_rdtsc();
    uint64_t ticks_base;
    retval = rte_eth_read_clock(port, &ticks_base);
    if (retval != 0)
      return retval;
    rte_delay_ms(100);
    uint64_t cycles = rte_rdtsc();
    uint64_t ticks;
    rte_eth_read_clock(port, &ticks);
    uint64_t c_freq = cycles - cycles_base;
    uint64_t t_freq = ticks - ticks_base;
    double freq_mult = (double)c_freq / t_freq;
    printf("TSC Freq ~= %" PRIu64 "\nHW Freq ~= %" PRIu64 "\nRatio : %f\n",
           c_freq * 10, t_freq * 10, freq_mult);
    /* TSC将比内部时钟周期更快，所以freq_mult > 0
     * 我们将乘法转换为整数移位和乘法运算
     */
    ticks_per_cycle_mult = (1 << TICKS_PER_CYCLE_SHIFT) / freq_mult;
  }

  struct rte_ether_addr addr;

  retval = rte_eth_macaddr_get(port, &addr);
  if (retval < 0) {
    printf("Failed to get MAC address on port %u: %s\n", port,
           rte_strerror(-retval));
    return retval;
  }
  printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
         " %02" PRIx8 " %02" PRIx8 "\n",
         (unsigned)port, RTE_ETHER_ADDR_BYTES(&addr));

  retval = rte_eth_promiscuous_enable(port);
  if (retval != 0)
    return retval;

  /* 将RX和TX回调函数添加到端口。8< */
  rte_eth_add_rx_callback(port, 0, add_timestamps, NULL);
  rte_eth_add_tx_callback(port, 0, calc_latency, NULL);
  /* >8 RX和TX回调函数添加结束。 */

  return 0;
}
/* >8 端口初始化结束。 */

/*
 * 执行工作的主线程，从INPUT_PORT读取数据
 * 并写入到OUTPUT_PORT
 */
static __rte_noreturn void lcore_main(void) {
  uint16_t port;

  RTE_ETH_FOREACH_DEV(port)
  if (rte_eth_dev_socket_id(port) >= 0 &&
      rte_eth_dev_socket_id(port) != (int)rte_socket_id())
    printf("WARNING, port %u is on remote NUMA node to "
           "polling thread.\n\tPerformance will "
           "not be optimal.\n",
           port);

  uint16_t nb_ports = rte_eth_dev_count_avail();
  if (nb_ports == 1) {
    printf("\nCore %u receiving and parsing packets (single port mode). "
           "[Ctrl+C to quit]\n",
           rte_lcore_id());
  } else {
    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());
  }

  for (;;) {
    RTE_ETH_FOREACH_DEV(port) {
      struct rte_mbuf *bufs[BURST_SIZE];
      const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
      if (unlikely(nb_rx == 0))
        continue;

      /* 如果只有一个端口，或者当前是最后一个端口（奇数个端口的情况），只接收不转发
       */
      if (nb_ports == 1) {
        /* 单端口模式：接收并解析后释放数据包 */
        uint16_t buf;
        for (buf = 0; buf < nb_rx; buf++)
          rte_pktmbuf_free(bufs[buf]);
      } else {
        /* 多端口模式：转发到相邻端口 */
        uint16_t dst_port = port ^ 1;

        /* 检查目标端口是否有效（处理奇数个端口的情况） */
        if (dst_port >= nb_ports) {
          /* 最后一个端口，只接收不转发 */
          uint16_t buf;
          for (buf = 0; buf < nb_rx; buf++)
            rte_pktmbuf_free(bufs[buf]);
        } else {
          /* 转发到相邻端口 */
          const uint16_t nb_tx = rte_eth_tx_burst(dst_port, 0, bufs, nb_rx);
          if (unlikely(nb_tx < nb_rx)) {
            uint16_t buf;
            for (buf = nb_tx; buf < nb_rx; buf++)
              rte_pktmbuf_free(bufs[buf]);
          }
        }
      }
    }
  }
}

/* 主函数，执行初始化并调用每个lcore的函数 */
int main(int argc, char *argv[]) {
  struct rte_mempool *mbuf_pool;
  uint16_t nb_ports;
  uint16_t portid;
  struct option lgopts[] = {{NULL, 0, 0, 0}};
  int opt, option_index;

  static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
      .name = "example_bbdev_dynfield_tsc",
      .size = sizeof(tsc_t),
      .align = alignof(tsc_t),
  };

  /* 初始化EAL */
  int ret = rte_eal_init(argc, argv);

  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  argc -= ret;
  argv += ret;

  while ((opt = getopt_long(argc, argv, "t", lgopts, &option_index)) != EOF)
    switch (opt) {
    case 't':
      hw_timestamping = 1;
      break;
    default:
      printf(usage, argv[0]);
      return -1;
    }
  optind = 1; /* 重置getopt库 */

  nb_ports = rte_eth_dev_count_avail();
  if (nb_ports < 1)
    rte_exit(EXIT_FAILURE, "Error: no available ports\n");

  if (nb_ports == 1)
    printf("Warning: Only 1 port available. Will receive and parse packets "
           "only (no forwarding).\n");
  else if (nb_ports & 1)
    printf("Warning: Odd number of ports (%u). Last port will only receive "
           "packets.\n",
           nb_ports);

  mbuf_pool = rte_pktmbuf_pool_create(
      "MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
      RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL)
    rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

  tsc_dynfield_offset = rte_mbuf_dynfield_register(&tsc_dynfield_desc);
  if (tsc_dynfield_offset < 0)
    rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");

  /* 初始化所有端口 */
  RTE_ETH_FOREACH_DEV(portid)
  if (port_init(portid, mbuf_pool) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

  /* 配置端口的IP地址、子网掩码和网关 */
//   RTE_ETH_FOREACH_DEV(portid) {
//     if (configure_port_ip(portid, "192.168.8.100", "255.255.255.0",
//                           "192.168.8.1") != 0) {
//       printf("Warning: Failed to configure IP for port %u\n", portid);
//     }
//   }

  if (rte_lcore_count() > 1)
    printf("\nWARNING: Too much enabled lcores - "
           "App uses only 1 lcore\n");

  /* 仅在主核心上调用lcore_main */
  lcore_main();

  /* 清理EAL */
  rte_eal_cleanup();

  return 0;
}
