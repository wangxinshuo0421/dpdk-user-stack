#include <stdio.h>

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
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <rte_string_fns.h>
#include <rte_log.h>
#include <rte_mempool.h>

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
// #define MAX_TX_QUEUE_PER_PORT   RTE_MAX_ETHPORTS
#define MAX_TX_QUEUE_PER_PORT   128         // 待定**********
#define MAX_RX_QUEUE_PER_PORT   128
#define NUM_SOCKETS             8
#define RX_DESC_DEFAULT         128
#define TX_DESC_DEFAULT         512
#define MAX_LCORE_PARAMS        1024
#define BURST_TX_DRAIN_US       100

/* protocol enable */
#define ARP_IS_ENABLE 0
#define UDP_IS_ENABLE 1
#define TCP_IS_ENABLE 0


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

struct lcore_conf
{
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


static uint32_t              enabled_ports_mask = 0;
static bool                  numa_on = false;
static uint16_t              nb_rxd = RX_DESC_DEFAULT;
static uint16_t              nb_txd = TX_DESC_DEFAULT;
static struct lcore_conf     lcore_conf[RTE_MAX_LCORE];                   /*there may be a problem !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
static struct rte_mempool   *pktmbuf_pool[NUM_SOCKETS];
static struct lcore_params   lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params   lcore_params_array_default[] = {{0, 0, 0},
                                                             {0, 1, 1},
                                                             {0, 2, 2},
                                                             {0, 3, 3}};
static struct lcore_params  *lcore_params = lcore_params_array_default;
static uint16_t              n_lcore_parms;
static uint32_t              local_ip = 0x802FA8C0;     // LOCAL IP : 192.168.47.128 big-endian
static uint32_t              host_ip = 0x012FA8C0;      // LOCAL IP : 192.168.47.1 big-endian
static struct rte_ether_addr local_mac;

/* ========================= ETHERNET LAYER ========================================= */
/* =========================  ARP PROTOCOL  ========================================= */

#if ARP_IS_ENABLE
/*
 * build a arp packet for broadcast
 */
static struct rte_mbuf *build_arp_pkt(uint8_t port_id, struct rte_mbuf *mbuf, 
                                     uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);    	
    /* 1 ethhdr */
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)pkt_data;
    struct rte_ether_hdr *eth_s_addr;
    rte_eth_macaddr_get(port_id, &eth_s_addr);
    uint8_t *src_mac = eth_s_addr->s_addr.addr_bytes; 
	rte_memcpy(eth->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	/* 2 arp */ 
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(2);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	
	return mbuf;
}
#endif

/*
 * Return the CPU socket on which the given logical core resides.
 */
static INLINE uint8_t socket_for_lcore(unsigned lcore_id){
    return (numa_on) ? (uint8_t)rte_lcore_to_socket_id(lcore_id) : 0;
}

/*
 * Print a packet information
 */
static void print_pkt(uint8_t src_ip, int dst_ip, 
                      uint16_t src_port, uint16_t dst_port, 
                      struct rte_udp_hdr * udp_hdr,
                      int len, int lcore_id)
{
    uint8_t     b[12];
    uint16_t    sp,
                dp;

    b[0] = src_ip & 0xFF;
    b[1] = (src_ip >> 8) & 0xFF;
    b[2] = (src_ip >> 16) & 0xFF;
    b[3] = (src_ip >> 24) & 0xFF;
    b[4] = src_port & 0xFF;
    b[5] = (src_port >> 8) & 0xFF;
    sp = ((b[4] << 8) & 0xFF00) | (b[5] & 0x00FF);
    b[6] = dst_ip & 0xFF;
    b[7] = (dst_ip >> 8) & 0xFF;
    b[8] = (dst_ip >> 16) & 0xFF;
    b[9] = (dst_ip >> 24) & 0xFF;
    b[10] = dst_port & 0xFF;
    b[11] = (dst_port >> 8) & 0xFF;
    dp = ((b[10] << 8) & 0xFF00) | (b[11] & 0x00FF);
    *(char *)(udp_hdr + rte_be_to_cpu_16(udp_hdr->dgram_len)) = '\0';
    if((sp == 10000 || sp == 60000))
        RTE_LOG(INFO, LSI,
            "CAS: lcore_id = %d rx udp packet: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (%d bytes) data: %s\n",
            lcore_id,
            b[0], b[1], b[2], b[3], sp,
            b[6], b[7], b[8], b[9], dp,
            len, (char *)(udp_hdr + 1));
}
/*
* function: calculate a udp packet checksum.
* input:    packet src ip and dst ip big end (network order) ;
*           need to be calculated udp head.
* output:   a right checksum (16bit, cpu order)
*/
rte_le16_t calculate_udp_checksum(rte_be32_t src_ip, rte_be32_t dst_ip, struct rte_udp_hdr *udp_hdr){
    unsigned int    cksum = 0;
    rte_be16_t      udp_len = udp_hdr -> dgram_len;
    unsigned short *tmp = (unsigned short *) (udp_hdr + 1);                   // extract data section
    uint16_t        data_len = rte_be_to_cpu_16(udp_hdr -> dgram_len) - 8;    // 8 is udp head length

    /* calculate pseudo-ip-head sum */
    cksum = ((src_ip >> 16) & 0xffff) + (src_ip & 0xffff);          // src ip
    cksum = ((dst_ip >> 16) & 0xffff) + (dst_ip & 0xffff) + cksum;  // dst ip
    cksum += 0x0011;                 // 0 complement ;  11 -> udp protocol number
    cksum += udp_len;                // udp length

    /* calculate udp head sum */
    cksum += udp_hdr -> src_port;    // src port
    cksum += udp_hdr -> dst_port;    // dst port
    cksum += 0x0000;                 // check sum
    cksum += udp_len;                // udp length  ps: twice udp length is right

    printf("tmp : ");
    /* calculate udp data sum */
    while (data_len > 1) {
        printf("%u ", *tmp);
        cksum += *tmp++;
        data_len -= 2;
    }
    printf("%u\n",(*tmp));
    if (data_len)
        cksum += (*tmp) & 0xff00;
    while (cksum >> 16)
        cksum = (cksum >> 16) + (cksum & 0xffff);
    
    return (rte_le16_t)(~cksum);
}
/*
 * Send a number of packets out the specified port (Ethernet device).
 */
static inline int send_burst(struct lcore_conf *conf, uint16_t n, uint8_t port, int socket){
    uint16_t           rsv, 
                       queueid;
    struct rte_mbuf  **m_table;

    queueid = conf->tx_queue_ids[port];
    //printf("send queue id = %d\n", queueid);
    m_table = (struct rte_mbuf **) conf->tx_mbufs[port].m_table;
    rsv = rte_eth_tx_burst(port, queueid, m_table, n);
    if(unlikely(rsv < n)){                      // unlikely for compiler acceleration
        do{ 
            RTE_LOG(INFO, LSI, "something wrong in send queue\n");
            rte_pktmbuf_free(m_table[rsv]);
        }while(++rsv < n);
    }
    for(uint8_t i = 0; i < n; i++)
        rte_pktmbuf_free(conf->tx_mbufs[port].m_table[i]);
    // RTE_LOG(DEBUG, LSI, 
    //         "CAS: free count mempool socket %u: %u\n", 
    //         socket, rte_mempool_free_count(pktmbuf_pool[socket]));
    return 0;
}

/*
 * Build and queue a single packet for transmit through a given port (Ethernet device).
 * This will send a burst of packets out if the TX buffer is full.
 */
static inline int build_one_udp(struct lcore_conf *conf, uint8_t port, int socket,
                                uint16_t src_port, uint16_t dst_port, const char *data, uint16_t data_len,
                                uint32_t dst_ip, struct rte_ether_addr next_mac){
    uint16_t                len;
    struct rte_ether_hdr   *eth_hdr;
    struct rte_ipv4_hdr    *ip_hdr;
    struct rte_udp_hdr     *udp_hdr;
    struct rte_mbuf        *buf;

    buf = rte_pktmbuf_alloc(pktmbuf_pool[0]);
    if(buf == NULL)
        RTE_LOG(INFO, LSI, "send pktmbufs alloc failed\n");
    
    char *pkt_addr = rte_pktmbuf_append(buf, data_len);
    if (pkt_addr == NULL)
        return -1;
    rte_memcpy(pkt_addr, data, data_len);

    /* add udp head */
    udp_hdr = (struct rte_udp_hdr *)rte_pktmbuf_prepend(buf, sizeof(struct rte_udp_hdr));
    udp_hdr->src_port = rte_cpu_to_be_16(src_port);
    udp_hdr->dst_port = rte_cpu_to_be_16(dst_port);
    udp_hdr->dgram_len = rte_cpu_to_be_16(data_len + sizeof(struct rte_udp_hdr));
    udp_hdr->dgram_cksum = 0;               

    /* add the ip head */
    ip_hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(buf, sizeof(struct rte_ipv4_hdr));
    ip_hdr->version_ihl = 0x45;             // ip version
    ip_hdr->total_length = rte_cpu_to_be_16(data_len + 8 + sizeof(struct rte_ipv4_hdr));
    ip_hdr->next_proto_id = 0x11;           // next protocol is udp = 17
    ip_hdr->dst_addr = rte_cpu_to_be_32(dst_ip);
    ip_hdr->src_addr = local_ip;
    ip_hdr->time_to_live = 128;
    ip_hdr->hdr_checksum = 0;

    /* add check sum */
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);

    /* add the ether head , the ether frame has no CRC*/
    eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(buf, sizeof(struct rte_ether_hdr));
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    rte_ether_addr_copy(&local_mac, &eth_hdr->s_addr);
    rte_ether_addr_copy(&next_mac, &eth_hdr->d_addr);
    
    len = conf->tx_mbufs[port].len;
    conf->tx_mbufs[port].m_table[len] = buf;
    len++;
    if(unlikely(len == MAX_TX_BURST)){
        RTE_LOG(INFO, LSI, "send queue has full, auto transport now\n");
        send_burst(conf, MAX_TX_BURST, port, socket);
        len = 0;
    }else{
        send_burst(conf, len, port, socket);
        len = 0;
    }
    conf->tx_mbufs[port].len = len;
    return 0;
}

/*
 *  handle a arp packet 
 */
static INLINE void arp_pkt_handle(uint8_t port_id, int socket, struct rte_mbuf *pkt, int lcore_id){
    /* the pkt is arp protocol, transport arp head (big endian) */       
    struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ether_hdr *, sizeof(struct rte_ether_hdr));
    struct lcore_conf *conf;    
    conf = &lcore_conf[lcore_id];
    /* print arp msg */
    printf("arp ---> dst: %u; \n", arp_hdr->arp_data.arp_tip);
    if (arp_hdr->arp_data.arp_tip == local_ip){
        printf("i am in now!\n");
        /* make and give a arp response */
        struct rte_mbuf   *arp_pkt;
        arp_pkt = rte_pktmbuf_alloc(pktmbuf_pool[socket]);
        if (!arp_pkt)   rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc \n");
        struct rte_mbuf *arpbuf = build_arp_pkt(port_id, arp_pkt, arp_hdr->arp_data.arp_sha.addr_bytes,
                                                arp_hdr->arp_data.arp_tip, arp_hdr->arp_data.arp_sip); 
        printf("already build alloc\n");
        // send_one(conf, arp_pkt, port_id, socket);
        // send_burst(conf, conf->tx_mbufs[port_id].len, port_id, socket);
        // rte_pktmbuf_free(arp_pkt);
    }
    return;
}

/*
 * Echoes back a single packet to its origin.
 */
static INLINE int echo_single_packet(uint8_t port_id, int socket, struct rte_mbuf *pkt, int lcore_id){
    int                    l2_len;
    uint16_t               eth_type,
                           udp_port,
                           checksum = 99;
    uint32_t               ip_addr;
    struct rte_udp_hdr    *udp_h;
    struct rte_ipv4_hdr   *ip_h;
    struct rte_vlan_hdr   *vlan_h;
    struct rte_ether_hdr  *eth_h;
    struct rte_ether_addr  eth_addr;

    eth_h = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    eth_type = rte_be_to_cpu_16(eth_h->ether_type);
    l2_len = sizeof(*eth_h);
   
    /* ARP */
#if ARP_IS_ENABLE
    if (eth_type == RTE_ETHER_TYPE_ARP){
        arp_pkt_handle(port_id, socket, pkt, lcore_id);
        return 1;
    }
#endif
    /* frames in VPC come in with ethertype 0x8100, i.e. they are 802.1q VLAN tagged */
    /* VLAN */
    if(eth_type == RTE_ETHER_TYPE_VLAN){
        vlan_h = (struct rte_vlan_hdr *) ((char *) eth_h + l2_len);
        eth_type = rte_be_to_cpu_16(vlan_h->eth_proto);
        l2_len += sizeof(*vlan_h); 
    }
    /* not support ipv6*/
    if(eth_type != RTE_ETHER_TYPE_IPV4){
        RTE_LOG(DEBUG, LSI, 
                "CAS: receive ipv6 packet, can't handle it\n");
        return 0;
    }
    ip_h = (struct rte_ipv4_hdr *) ((char *) eth_h + l2_len);
    /* only support udp !!!!*/
    if(ip_h -> next_proto_id != IPPROTO_UDP){
        RTE_LOG(DEBUG, LSI, 
                "CAS: receive tcp packet, can't handle it\n");
        return 0;
    }else{
        udp_h = (struct rte_udp_hdr *) ((char *) ip_h + sizeof(*ip_h));
        // RTE_LOG(INFO, LSI, "recv cksum = %u ; calculate cksum = %u\n", 
        //                     rte_be_to_cpu_16(udp_h->dgram_cksum),
        //                     rte_ipv4_udptcp_cksum(ip_h, udp_h));
        print_pkt(ip_h->src_addr, ip_h->dst_addr, udp_h->src_port, udp_h->dst_port, 
                udp_h, pkt->data_len, lcore_id);
    }
    
    return 1;
}

/*
 * Main per-lcore worker routine.
 */
//static int main_loop(UNUSED void *junk){
static int main_loop(void){

    int                socket;
    uint8_t            port,
                       queue;
    uint16_t           i,
                       n_rx,
                       n_reply;
    unsigned           lcore_id;
    struct rte_mbuf   *pkt,
                      *pkts_burst[PKT_BURST];
    struct lcore_conf *conf;

    lcore_id = rte_lcore_id();
    conf = &lcore_conf[lcore_id];
    socket = socket_for_lcore(lcore_id);
    if(conf->n_rx_queue == 0){
        RTE_LOG(INFO, LSI, 
                "CAS: lcore %u not mapped into service\n", lcore_id);
        return 0;
    }
    RTE_LOG(INFO, LSI, 
            "CAS: starting service on lcore %u\n", lcore_id);
    for(i = 0; i < conf->n_rx_queue; i++){
        port = conf->rx_queues[i].port_id;
        queue = conf->rx_queues[i].queue_id;
        RTE_LOG(INFO, LSI, 
                "CAS: --- lcore = %u port = %u rx_queue = %u ---\n", 
                lcore_id, port, queue);
    }  

    /* cyclic processing port receive information */
    while (1){
        for(i = 0; i < conf->n_rx_queue; i++){
            port = conf->rx_queues[i].port_id;
            queue = conf->rx_queues[i].queue_id;
            n_reply = 0;
            n_rx = rte_eth_rx_burst(port, queue, pkts_burst, PKT_BURST);
            if(n_rx == 0)
                continue;
            for(i = 0; i < n_rx; i++){
                pkt = pkts_burst[i];
                if(echo_single_packet(port, socket, pkt, lcore_id)){
                    //send_one(conf, pkt, port, socket);
                    struct rte_ether_addr next_mac_addr;
                    next_mac_addr.addr_bytes[0] = 0x00;
                    next_mac_addr.addr_bytes[1] = 0x50;
                    next_mac_addr.addr_bytes[2] = 0x56;
                    next_mac_addr.addr_bytes[3] = 0xc0;
                    next_mac_addr.addr_bytes[4] = 0x00;
                    next_mac_addr.addr_bytes[5] = 0x01;
                    build_one_udp(conf, port, socket,
                                  60000, 10000, "recv!", 5,
                                  0xc0a82f01, next_mac_addr);
                }
                rte_pktmbuf_free(pkt);
            }
        }
    }
    return 0;
}

/*
 * Return how many RX queues were specified on a given port (Ethernet device).
 */
static uint8_t rx_queue_for_port(const uint8_t port){
    int      queue = -1;
    uint16_t i;

    for(i = 0; i < n_lcore_parms; i++){
        if(lcore_params[i].port_id == port && lcore_params[i].queue_id > queue){
            queue = lcore_params[i].port_id;
        }
    }
    return (uint8_t) (++queue);
}

/*
* Initialize a section of RAM for packet buffers per logical core
*/
static void init_packet_buffer(unsigned num_mbuf){
    int         socketid;
    char        s[64];
    unsigned    lcore_id;

    for(lcore_id = 0; lcore_id < n_lcore_parms; lcore_id++){
        if(!rte_lcore_is_enabled(lcore_id)){
            continue;
        }
        socketid = socket_for_lcore(lcore_id);
        if(pktmbuf_pool[socketid] == NULL){
            pktmbuf_pool[socketid] = rte_pktmbuf_pool_create("mbuf pool", MBUF_SIZE,MEMPOOL_CACHE_SIZE, 
                                                             0, RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());
            
            if(pktmbuf_pool[socketid] == NULL){
                DIE("CAS: failed to allocate mbuf pool on socket %d\n", socketid);
            }
        }
    }
}

/*
 * Initialize a TX queue for each (lcore,port) pair.
 */
static void init_tx_queue_for_port(uint8_t port){
    uint8_t             socket_id;
    uint16_t            queue;
    unsigned            lcore_id;
    struct lcore_conf  *queue_conf;

    queue = 0;
    for(lcore_id = 0; lcore_id < n_lcore_parms; lcore_id++){
        if(!rte_lcore_is_enabled(lcore_id)){
            continue;
        }
        socket_id = socket_for_lcore(lcore_id);
        RTE_LOG(INFO, LSI, 
                "CAS: initializing TX queue: (lcore %u, queue %u, socket %u)\n",
                lcore_id, queue, socket_id);
        if(rte_eth_tx_queue_setup(port, queue, nb_txd, socket_id, &tx_conf)){
            DIE("CAS: in function init_tx_queue_for_port(cas_udp.c) rte_eth_tx_queue_setup(%u) failed: port=%d queue=%d\n", lcore_id, port, queue);
        }
        queue_conf = &lcore_conf[lcore_id];
        queue_conf->tx_queue_ids[port] = queue;
        queue++;
    }
}

/*
 * Ensure the configured (port,queue,lcore) mappings are valid.
 */
static void check_lcore_params(void){
    int         socket_id;
    uint8_t     queue,
                lcore;
    uint16_t    i;

    for(i = 0; i < n_lcore_parms; i++){
        queue = lcore_params[i].queue_id;
        if(queue >= MAX_RX_QUEUE_PER_PORT){
            DIE("CAS: invalid queue number: %hhu\n", queue);
        }
        lcore = lcore_params[i].lcore_id;
        if(!rte_lcore_is_enabled(lcore)){
            DIE("CAS: lcore %hhu is not enabled in lcore mask\n", lcore);
        }
        socket_id = rte_lcore_to_socket_id(lcore);
        if(socket_id != 0 && !numa_on){
            RTE_LOG(WARNING, LSI, 
            "CAS: lcore %hhu is on socket %d with NUMA off \n", lcore, socket_id);
        }
    }
}

/*
 * RX queues and logical cores.
 */
static void init_lcores(void){
    uint8_t     lcore;
    uint16_t    i,
                n_rx_queue;
    printf("init lcores ing lcore = %d\n", rte_lcore_count());
    for(i = 0; i < n_lcore_parms; i++){
        lcore = lcore_params[i].lcore_id;
        n_rx_queue = lcore_conf[lcore].n_rx_queue;
        if(n_rx_queue >= MAX_RX_QUEUE_PER_LCORE){
            DIE("CAS: too man RX queues (%u) for lcore %u\n", (unsigned) n_rx_queue + 1, (unsigned) lcore);
        }
        /* there are some problems may be !!!!!!!!!!!!*/
        lcore_conf[lcore].rx_queues[n_rx_queue].port_id = lcore_params[i].port_id;
        lcore_conf[lcore].rx_queues[n_rx_queue].queue_id = lcore_params[i].queue_id;
        lcore_conf[lcore].n_rx_queue = 1;
        printf("DEBUG: lcore id = %d ; n_rx_queue = %d \n", lcore, lcore_conf[lcore].n_rx_queue);
    }
}

/*
 * Configure all specified Ethernet devices, including allocating packet buffer
 * memory and TX queue rings.
 */
static void configure_ports(unsigned n_ports, uint32_t port_mask, uint32_t n_lcores){
    int                     rsv;
    uint8_t                 port_id,
                            n_rx_queue;
    uint32_t                n_tx_queue;
    struct rte_ether_addr   eth_addr;

    for(port_id = 0; port_id < n_ports; port_id++){
        n_rx_queue = 4;
        n_tx_queue = 4;         // change there: n_tx_queue = n_lcore;
        if(n_tx_queue > MAX_TX_QUEUE_PER_PORT){
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        }
        RTE_LOG(INFO, LSI,
                "CAS: initializing port %u: %u rx, %u tx\n",
                port_id, (uint16_t)n_rx_queue, n_tx_queue);
        if((rsv = rte_eth_dev_configure(port_id, n_rx_queue, (uint16_t) n_tx_queue, &dev_conf)) < 0){
            DIE("CAS: failed to configure Ethernet port %u\n", port_id);
        }
        rte_eth_macaddr_get(port_id, &eth_addr);
        RTE_LOG(INFO, LSI,
                "port %u MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                port_id,
                eth_addr.addr_bytes[0], eth_addr.addr_bytes[1], 
                eth_addr.addr_bytes[2], eth_addr.addr_bytes[3], 
                eth_addr.addr_bytes[4], eth_addr.addr_bytes[5]);
        init_packet_buffer(NUM_MBUF(n_ports, n_rx_queue, n_tx_queue, n_lcores));

        init_tx_queue_for_port(port_id);
    }
    RTE_LOG(INFO, LSI, "CAS: function configure_ports have excuted, n_port = %d, port_id = %u\n", n_ports, port_id);
}

/*
 * Initialize all RX queues rings assigned for each logical core.
 */
static void init_rx_queues(void){
    int                 rsv;
    uint8_t             port_id,
                        queue_id,
                        socket_id;
    uint16_t            queue;
    unsigned            lcore_id;
    struct lcore_conf  *lconf;

    for(lcore_id = 0; lcore_id < n_lcore_parms; lcore_id++){
        if(!rte_lcore_is_enabled(lcore_id)){
            printf("rte_lcore_is_disabled, lcore_id = %d\n",lcore_id);
            continue;
        }
        socket_id = socket_for_lcore(lcore_id);
        lconf = &lcore_conf[lcore_id];
        RTE_LOG(INFO, LSI,
                "CAS: initializing RX queue on lcore %u, n_rx_queue = % d\n",
                lcore_id, lconf->n_rx_queue);
        for(queue = 0; queue < lconf->n_rx_queue; queue++){
            port_id = lconf->rx_queues[queue].port_id;
            queue_id = lconf->rx_queues[queue].queue_id;
            RTE_LOG(INFO, LSI,
                    "CAS: -- rx_queue: port = %u; queue = %u; socket = %u;\n", 
                    port_id, queue_id, socket_id);
            if((rsv = rte_eth_rx_queue_setup(port_id, queue_id, nb_rxd, socket_id, &rx_conf, pktmbuf_pool[socket_id]))){
                DIE("CAS: rte_eth_rx_queue_setup failed: err = %d; port = %d; queue = %d; lcore = %d;\n",
                    rsv, port_id, queue_id, lcore_id);
            }
        }
    }
}

/*
 * Start DPDK on all configured ports (Ethernet devices).
 */
static void start_ports(unsigned n_ports, uint32_t port_mask){
    int     rsv;
    uint8_t port_id;

    for(port_id = 0; port_id < n_ports; port_id++){
        // if(!(port_mask & (1 << port_id))){
        //     continue;
        // }
        rte_eth_promiscuous_enable(port_id);
        if((rsv = rte_eth_dev_start(port_id)) < 0){
            DIE("CAS: RTE eth dev start failed: err = %d; port = %d\n", rsv, port_id);
        }
    }
}

/*
 * Wait for all specified ports to show link UP.
 */
static void check_port_link_status(uint8_t n_ports, uint32_t port_mask){
    uint8_t             port,
                        count,
                        all_ports_up;
    struct rte_eth_link link;

#define CHECK_INTERVAL  100 /* milliseconds */
#define MAX_CHECK_TIME  90  /* 90 * 100ms = 9s */

    for(count = 0; count <= MAX_CHECK_TIME; count++){
        all_ports_up = 1;
        for(port = 0; port < n_ports; port++){
            if(!(port_mask & (1 << port))){
                continue;
            }
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(port, &link);
            if(link.link_status == 0){
                all_ports_up = 0;
                break;
            }
        }
        if(all_ports_up) break;
        rte_delay_ms(CHECK_INTERVAL);
    }

#undef CHECK_INTERVAL
#undef MAX_CHECK_TIME
}

/*
 * Parse enabled ports bitmask (to specify which Ethernet devices to use). On
 * failure to parse the bitmask it will return -1, which, when interpreted as
 * unsigned, will result in all bits on.
 */
static int parse_portmask(const char *arg){
    char           *end = NULL;
    unsigned long   mask;

    mask = strtoul(arg, &end, 16);
    if(!*arg || !end || !*end){
        return -1;
    }
    return (!mask) ? -1 : mask;
}

/*
 * Initialize
 */
static void init_nics(void){
    unsigned n_ports;

    check_lcore_params();
    init_lcores();
    if((n_ports = rte_eth_dev_count_avail()) == 0){
        DIE("CAS: no Ethernet ports detected\n");
    }
    RTE_LOG(INFO, LSI,
            "%u Ethernet ports detected\n", n_ports);
    configure_ports(n_ports, enabled_ports_mask, rte_lcore_count());
    rte_eth_macaddr_get(0, &local_mac);     // nic only have port 0, so write port 0;
    init_rx_queues();
    start_ports(n_ports, enabled_ports_mask);
    check_port_link_status(n_ports, enabled_ports_mask);
}

int main(int argc, char **argv){
    /* code */
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "init eal failed\n");
    }
    n_lcore_parms = rte_lcore_count();
    init_nics();
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);
    rte_eal_mp_wait_lcore();
    return 0;
}
