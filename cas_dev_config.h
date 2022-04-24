#ifndef __CAS_DEV_CONFIG_H
#define __CAS_DEV_CONFIG_H
#endif

#pragma once        // 防止重复编译头文件

#include <rte_config.h>
#include <rte_byteorder.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <rte_string_fns.h>
#include <rte_log.h>


/* linux kernel */
#ifdef RTE_EXEC_ENV_FREEBSD
#include <sys/endian.h>
#elif defined RTE_EXEC_ENV_LINUX
#include <endian.h>
#endif    

#define INLINE inline __attribute__((always_inline))
#define UNUSED __attribute__((unused))
#define RTE_LOGTYPE_LSI RTE_LOGTYPE_USER1

#define DIE(msg, ...)                                       \
    do {                                                    \
        RTE_LOG(ERR, LSI, msg , ## __VA_ARGS__ );         \
        exit(EXIT_FAILURE);                                 \
    } while (0)

#define PKT_BURST               128
#define MAX_PKT_BURST           32
#define MAX_TX_BURST            32
#define RX_RING_SIZE            256
#define TX_RING_SIZE            512
#define MEMPOOL_CACHE_SIZE      256
#define MBUF_SIZE               (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NUM_BUFS                (4096-1)
#define MAX_RX_QUEUE_PER_LCORE  16
#define MAX_TX_QUEUE_PER_PORT   128         // 待定**********
#define MAX_RX_QUEUE_PER_PORT   128
#define NUM_SOCKETS             8
#define RX_DESC_DEFAULT         128
#define TX_DESC_DEFAULT         512
#define MAX_LCORE_PARAMS        1024
#define BURST_TX_DRAIN_US       100


#define NUM_MBUF(ports, rx, tx, lcores)                 \
    RTE_MAX((ports * rx * RX_DESC_DEFAULT +             \
             ports * lcores * MAX_PKT_BURST +           \
             ports * tx * TX_DESC_DEFAULT +             \
             lcores * MEMPOOL_CACHE_SIZE),              \
            (unsigned) 8192)

struct lcore_params{
    uint8_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;      // cache line对齐

struct mbuf_table{
    uint16_t            len;
    struct rte_mbuf     *m_table[MAX_PKT_BURST];
} __rte_cache_aligned;

struct lcore_rx_queue{
    uint8_t port_id;
    uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_conf{
    uint16_t                n_rx_queue;
    struct lcore_rx_queue   rx_queues[MAX_RX_QUEUE_PER_LCORE];
    uint16_t                tx_queue_ids[MAX_TX_QUEUE_PER_PORT];
    struct mbuf_table       tx_mbufs[MAX_TX_QUEUE_PER_PORT];
} __rte_cache_aligned;

struct psd_hdr{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
}  __rte_packed;         //不对齐

static uint8_t intel_rss_key[40] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};

/* 
 * XXX: The below rte_eth_conf values are optimized for VMXNET3
 * support up to 4 rx/tx queue
 * using the DPDK igb_uio PMD
 */
static const struct rte_eth_conf dev_conf = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        .mq_mode = ETH_MQ_RX_RSS,           // Receive Side Scaling 根据端口的接收队列进行报文分发的。 例如我们在一个端口上配置了3个接收队列(0,1,2)并开启了RSS，那么(redirection table)就是这样的:{0,1,2,0,1,2,0.........}
        .split_hdr_size = 0,
        .offloads = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = intel_rss_key,
            /* rss_hf 要根据网卡支持的卸载协议进行配置 */
            .rss_hf = ETH_RSS_NONFRAG_IPV6_TCP | ETH_RSS_IPV6 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_IPV4 ,
        }
    }
};

static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = 8,
        .hthresh = 8,
        .wthresh = 4,
    },
    .rx_free_thresh = 32,
};

/* 
 * XXX: The below tx_thresh values are optimized for Intel 82599 10GigE NICs
 * using the DPDK ixgbe PMD
 */
static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = 36,
        .hthresh = 0,
        .wthresh = 0,
    },
    .tx_free_thresh = 0,
    .tx_rs_thresh   = 0,
};


extern uint32_t              enabled_ports_mask;
extern bool                  numa_on;
extern uint16_t              nb_rxd;
extern uint16_t              nb_txd;
extern struct lcore_conf     lcore_conf[RTE_MAX_LCORE];                   /*there may be a problem !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
extern struct lcore_params   lcore_params_array[MAX_LCORE_PARAMS];
extern struct lcore_params   lcore_params_array_default[];
extern struct lcore_params  *lcore_params;
extern uint16_t              n_lcore_parms;

extern struct rte_mempool   *pktmbuf_pool[NUM_SOCKETS];

extern struct rte_ether_addr local_mac;

uint8_t socket_for_lcore(unsigned lcore_id);
void check_lcore_params(void);
void init_lcores(void);
void init_tx_queue_for_port(uint8_t port);
void configure_ports(unsigned n_ports, uint32_t port_mask, uint16_t n_lcores);
void init_packet_buffer(unsigned num_mbuf);
void init_rx_queues(void);
void start_ports(unsigned n_ports, uint32_t port_mask);
void check_port_link_status(uint8_t n_ports, uint32_t port_mask);
void init_nics(void);
