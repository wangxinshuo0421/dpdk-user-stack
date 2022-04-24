#include <stdio.h>

#include "cas_dev_config.h"


/* protocol enable */
#define ARP_IS_ENABLE 0
#define UDP_IS_ENABLE 1
#define TCP_IS_ENABLE 0

rte_be32_t            local_ip = 0x802FA8C0;     // LOCAL IP : 192.168.47.128 big-endian
rte_be32_t            host_ip = 0x012FA8C0;      // LOCAL IP : 192.168.47.1 big-endian
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
 * Print a packet information
 */
static void print_pkt(uint32_t src_ip, uint32_t dst_ip, 
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

int main(int argc, char **argv){
    /* code */
    struct lcore_conf *conf;

    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "init eal failed\n");
    }
    init_nics();
    rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);
    rte_eal_mp_wait_lcore();
    return 0;
}
