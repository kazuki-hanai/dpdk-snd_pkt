/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64

#define QUEUE_NUM_PER_PORT 2

static const struct rte_eth_conf port_conf_default = {
  .rxmode = {
    .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
  },
};

struct flow_info {
  unsigned int packet_size; /* byte */
  struct rte_ether_addr eth_dst;
  struct rte_ether_addr eth_src;
  uint8_t ip_dst[4];
  uint8_t ip_src[4];
};

struct tx_main_info {
  uint16_t port;
  uint16_t queue_id;
  struct rte_mempool *mbuf_pool;
  unsigned int tx_rate; /* Mbps */
  unsigned int tx_duration; /* sec */
  struct flow_info flow;
};

#define SEC_TO_USEC(x) ((x) * 1000 * 1000)

static void
set_tx0(struct tx_main_info *tx0, struct rte_mempool *mbuf_pool)
{
  const uint8_t eth_dst[6] = { 0x22, 0x3c, 0x94, 0x68, 0x41, 0xe0 };
  const uint8_t eth_src[6] = { 0x3c, 0xfd, 0xfe, 0xa2, 0x1e, 0x3a };
  const uint8_t ip_dst[4] = { 10, 1, 20, 20 };
  const uint8_t ip_src[4] = { 10, 1, 20, 10 };

  tx0->port = 0;
  tx0->queue_id = 0;
  tx0->mbuf_pool = mbuf_pool;

  tx0->tx_rate = 3000;
  tx0->tx_duration = 70;
  tx0->flow.packet_size = 64;

  rte_memcpy(&tx0->flow.eth_dst, eth_dst, sizeof(eth_dst) / sizeof(eth_dst[0]));
  rte_memcpy(&tx0->flow.eth_src, eth_src, sizeof(eth_src) / sizeof(eth_src[0]));
  rte_memcpy(tx0->flow.ip_dst, ip_dst, sizeof(ip_dst) / sizeof(ip_dst[0]));
  rte_memcpy(tx0->flow.ip_src, ip_src, sizeof(ip_src) / sizeof(ip_src[0]));
}

static void
set_tx1(struct tx_main_info *tx1, struct rte_mempool *mbuf_pool)
{
  const uint8_t eth_dst[6] = { 0x06, 0xec, 0xbe, 0x1d, 0x9a, 0x44 };
  const uint8_t eth_src[6] = { 0x3c, 0xfd, 0xfe, 0xa2, 0x1e, 0x3a };
  const uint8_t ip_dst[4] = { 10, 1, 20, 21 };
  const uint8_t ip_src[4] = { 10, 1, 20, 10 };

  tx1->port = 0;
  tx1->queue_id = 1;
  tx1->mbuf_pool = mbuf_pool;

  tx1->tx_rate = 10000;
  tx1->tx_duration = 70;
  tx1->flow.packet_size = 64;

  rte_memcpy(&tx1->flow.eth_dst, eth_dst, sizeof(eth_dst) / sizeof(eth_dst[0]));
  rte_memcpy(&tx1->flow.eth_src, eth_src, sizeof(eth_src) / sizeof(eth_src[0]));
  rte_memcpy(tx1->flow.ip_dst, ip_dst, sizeof(ip_dst) / sizeof(ip_dst[0]));
  rte_memcpy(tx1->flow.ip_src, ip_src, sizeof(ip_src) / sizeof(ip_src[0]));
}

static struct rte_mbuf *
construct_udp_pkt(struct rte_mempool *mbuf_pool, struct flow_info flow)
{
  struct rte_mbuf *buf;
  struct rte_ether_hdr *eth;
  struct rte_ipv4_hdr *ip;
  struct rte_udp_hdr *udp;
  char *data;
  int i, data_size;
  unsigned int packet_size = flow.packet_size - RTE_ETHER_CRC_LEN;

  /* allocation */
  buf = rte_pktmbuf_alloc(mbuf_pool);
  if (buf == NULL)
    rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc() failed\n");

  if (rte_pktmbuf_append(buf, packet_size) == NULL)
    rte_exit(EXIT_FAILURE, "rte_pktmbuf_append() failed\n");

  /* ether */
  eth = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
  rte_ether_addr_copy(&flow.eth_dst, &eth->d_addr);
  rte_ether_addr_copy(&flow.eth_src, &eth->s_addr);
  eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

  /* ip */
  ip = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *, sizeof(*eth));
  ip->version_ihl = 0x45;
  ip->type_of_service = 0;
  ip->total_length = rte_cpu_to_be_16(packet_size - sizeof(*eth));
  ip->packet_id = 0;
  ip->fragment_offset = 0;
  ip->time_to_live = 64;
  ip->next_proto_id = 0x11;
  ip->dst_addr = rte_cpu_to_be_32(
      RTE_IPV4(flow.ip_dst[0], flow.ip_dst[1], flow.ip_dst[2], flow.ip_dst[3]));
  ip->src_addr = rte_cpu_to_be_32(
      RTE_IPV4(flow.ip_src[0], flow.ip_src[1], flow.ip_src[2], flow.ip_src[3]));
  ip->hdr_checksum = 0;
  ip->hdr_checksum = rte_ipv4_cksum(ip);

  /* udp */
  udp = rte_pktmbuf_mtod_offset(buf, struct rte_udp_hdr *,
      sizeof(*eth) + sizeof(*ip));
  udp->src_port = rte_cpu_to_be_16(20000);
  udp->dst_port = rte_cpu_to_be_16(20000);
  udp->dgram_len = rte_cpu_to_be_16(
      packet_size - sizeof(*eth) - sizeof(*ip));
  udp->dgram_cksum = 0;

  /* data */
  data = rte_pktmbuf_mtod_offset(buf, char *,
      sizeof(*eth) + sizeof(*ip) + sizeof(*udp));
  data_size = packet_size - sizeof(*eth) - sizeof(*ip) - sizeof(*udp);
  for (i = 0; i < data_size; i++)
    data[i] = 0;

  return buf;
}

static void
set_mbufs(struct rte_mbuf *bufs[], struct tx_main_info *tx_info)
{
  int i;
 
  for (i = 0; i < BURST_SIZE; i++) {
    bufs[i] = construct_udp_pkt(tx_info->mbuf_pool, tx_info->flow);
    /* rte_pktmbuf_dump(stdout, bufs[i], rte_pktmbuf_data_len(bufs[i])); */
    /* printf("\n"); */
  }
}

static inline double
calc_elapsed_sec(uint64_t end, uint64_t start, uint64_t tsc_hz)
{
  return (double)(end - start) / tsc_hz;
}

static int
tx_main(void *arg)
{
  struct tx_main_info *tx_info = (struct tx_main_info *)arg;
  uint16_t port = tx_info->port;
  uint16_t queue_id = tx_info->queue_id;

  /*
   * Check that the port is on the same NUMA node as the polling thread
   * for best performance.
   */
  if (rte_eth_dev_socket_id(port) > 0 &&
      rte_eth_dev_socket_id(port) != (int)rte_socket_id())
    printf("WARNING, port %u is on remote NUMA node to "
        "polling thread.\n\tPerformance will "
        "not be optimal.\n", port);

  /* main */
  struct rte_mbuf *bufs[BURST_SIZE];
  uint16_t nb_tx;

  uint64_t start, end, now;
  double elapsed_time;
  const uint64_t tsc_hz = rte_get_tsc_hz();
  unsigned int tx_count = 0;

  unsigned int tx_rate, packet_size, tx_duration;
  /* unsigned int tx_count_limit; */
  double pps, tx_interval;

  /* Initialization */
  // tx_rate
  tx_rate = tx_info->tx_rate;
  packet_size = tx_info->flow.packet_size;
  tx_duration = tx_info->tx_duration;

  pps = (double)(tx_rate) / (packet_size * 8) * SEC_TO_USEC(1);
  tx_interval = 1.0 / (pps / BURST_SIZE) * SEC_TO_USEC(1); /* us */
  /* tx_count_limit = pps * tx_duration; */

  // mbuf
  set_mbufs(bufs, tx_info);

  /* tx_loop */
  printf("\n");
  printf(">> start TX on Core %u.\n", rte_lcore_id());
  printf("   tx_rate: %u Mbps, packet_size: %u byte, duration: %u s on Core %u\n",
      tx_rate, packet_size, tx_duration, rte_lcore_id());

  start = rte_rdtsc();

  if (tx_rate == 0)
    goto log;
 
  for (;;) {
    nb_tx = rte_eth_tx_burst(port, queue_id, bufs, BURST_SIZE);
    tx_count += nb_tx;

    now = rte_rdtsc();
    if (unlikely(calc_elapsed_sec(now, start, tsc_hz) > tx_duration))
      break;
    /* if (unlikely(tx_count > tx_count_limit)) */
      /* break; */

    rte_delay_us(tx_interval);
  }

log:
  end = rte_rdtsc();
  elapsed_time = calc_elapsed_sec(end, start, tsc_hz);

  printf("\n");
  printf(">> finish TX on Core %u.\n", rte_lcore_id());
  printf("   tx_count: %u, elapsed_time: %f s, throughput: %f Mbps on Core %u\n",
      tx_count, elapsed_time, 
      (double)(tx_count / SEC_TO_USEC(1) * packet_size * 8) / elapsed_time,
      rte_lcore_id());

  return 0;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pools[])
{
  struct rte_eth_conf port_conf = port_conf_default;
  const uint16_t rx_rings = QUEUE_NUM_PER_PORT, tx_rings = QUEUE_NUM_PER_PORT;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  int retval;
  uint16_t q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf txconf;

  if (!rte_eth_dev_is_valid_port(port))
    return -1;

  rte_eth_dev_info_get(port, &dev_info);
  if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
    port_conf.txmode.offloads |=
      DEV_TX_OFFLOAD_MBUF_FAST_FREE;

  /* Configure the Ethernet device. */
  retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
  if (retval != 0)
    return retval;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
  if (retval != 0)
    return retval;

  /* Allocate and set up RX queue per Ethernet port. */
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
        rte_eth_dev_socket_id(port), NULL, mbuf_pools[q]);
    if (retval < 0)
      return retval;
  }

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up TX queue per Ethernet port. */
  for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd,
        rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0)
      return retval;
  }

  /* Start the Ethernet port. */
  retval = rte_eth_dev_start(port);
  if (retval < 0)
    return retval;

  /* Display the port MAC address. */
  struct rte_ether_addr addr;
  rte_eth_macaddr_get(port, &addr);
  printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
         " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
      port,
      addr.addr_bytes[0], addr.addr_bytes[1],
      addr.addr_bytes[2], addr.addr_bytes[3],
      addr.addr_bytes[4], addr.addr_bytes[5]);

  /* Enable RX in promiscuous mode for the Ethernet device. */
  rte_eth_promiscuous_enable(port);

  return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
  uint16_t portid;
  struct rte_mempool *mbuf_pools[QUEUE_NUM_PER_PORT];
  struct tx_main_info tx0, tx1;
  int i;

  /* Initialize the Environment Abstraction Layer (EAL). */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

  argc -= ret;
  argv += ret;

  /* Check that there is two lcores. */
  if (rte_lcore_count() != QUEUE_NUM_PER_PORT)
    rte_exit(EXIT_FAILURE, "%u lcores needed\n", QUEUE_NUM_PER_PORT);

  /* Creates a new mempool in memory to hold the mbufs. */
  mbuf_pools[0] = rte_pktmbuf_pool_create("MBUF_POOL0", NUM_MBUFS,
    MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_lcore_to_socket_id(4));
  mbuf_pools[1] = rte_pktmbuf_pool_create("MBUF_POOL1", NUM_MBUFS,
    MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_lcore_to_socket_id(5));

  for (i = 0; i < QUEUE_NUM_PER_PORT; i++) {
    if (mbuf_pools[i] == NULL)
      rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
  }

  /* Initialize a port. */
  portid = 0;
  if (port_init(portid, mbuf_pools) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

  /* set tx_main_info */
  set_tx0(&tx0, mbuf_pools[0]);
  set_tx1(&tx1, mbuf_pools[1]);

  /* launch tx_main on Core 5 */
  rte_eal_remote_launch(tx_main, &tx0, 5);

  /* launch tx_main thread on Master Core. */
  tx_main(&tx1);

  /* wait thread on Core 5 */
  rte_eal_wait_lcore(5);

  return 0;
}
