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
#include <rte_mempool.h>

#include <stdio.h>
#include <arpa/inet.h>      // 字节顺序转换

#define NUM_BUFS        (4096-1)
#define BURST_SIZE      128

/**
 * IPv4 Header
 */
struct rte_ipv4_h6dr {
	uint8_t  version_ihl;		/**< version and header length */
	uint8_t  type_of_service;	/**< type of service */
	rte_be16_t total_length;	/**< length of packet */
	rte_be16_t packet_id;		/**< packet ID */
	rte_be16_t fragment_offset;	/**< fragmentation offset */
	uint8_t  time_to_live;		/**< time to live */
	uint8_t  next_proto_id;		/**< protocol ID */
	rte_be16_t hdr_checksum;	/**< header checksum */
	rte_be32_t src_addr;		/**< source address */
	rte_be32_t dst_addr;		/**< destination address */
} __rte_packed;

int dpdk_port_id = 0;
static const struct rte_eth_conf dev_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

void init_port(struct rte_mempool *mbuf_pool){
    uint16_t num_sys_ports = rte_eth_dev_count_avail();
    if (num_sys_ports == 0){
        rte_exit(EXIT_FAILURE, "No Support eth found\n");
    }
#if 1
    struct rte_eth_dev_info devinfo;
    rte_eth_dev_info_get(dpdk_port_id, &devinfo);
#endif  
    const int num_rx_queues = 1;
    const int num_tx_queues = 0;
    rte_eth_dev_configure(dpdk_port_id, num_rx_queues, num_tx_queues, &dev_conf_default);
    if (rte_eth_rx_queue_setup(dpdk_port_id, 0, 128, rte_eth_dev_socket_id(dpdk_port_id), NULL, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup failed\n");
    }
    printf("rte_eth_dev_socket_id(dpdk_port_id) = %d\n", rte_eth_dev_socket_id(dpdk_port_id));
    if (rte_eth_dev_start(dpdk_port_id) < 0){
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start failed\n");
    }

}

int main(int argc, char **argv){
    if (rte_eal_init(argc, argv) < 0) {           // init dpdk environmentn
        rte_exit(EXIT_FAILURE, "Error with eal init\n");
    }
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_BUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "mempool create failed\n");
    }
    init_port(mbuf_pool);
    while (1){
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(dpdk_port_id, 0, mbufs, BURST_SIZE);
        if(num_recvd > BURST_SIZE){
            rte_exit(EXIT_FAILURE, "rte_eth_rx_burst failed\n");
        }
        unsigned i = 0;
        for (i = 0; i < num_recvd; i++) {
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
           // printf("eth here now \n");
            if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_h6dr *ip_hdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ether_hdr *, sizeof(struct rte_ether_hdr));

                if (ip_hdr->next_proto_id == IPPROTO_UDP) {
                    struct rte_udp_hdr *upd_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
                    uint16_t length = ntohs(upd_hdr->dgram_len);
                    *(char *)(upd_hdr + length) = '\0';
                    struct in_addr addr;
                    addr.s_addr = ip_hdr->src_addr;
                    printf("src: %s : %d; ", inet_ntoa(addr), ntohs(upd_hdr->src_port));
                    addr.s_addr = ip_hdr->dst_addr;
                    printf("dst: %s : %d;  ", inet_ntoa(addr), ntohs(upd_hdr->dst_port));
                    printf("mbuf: **; udp packet: %s \n", (char *)(upd_hdr + 1));
                }
            }
            rte_pktmbuf_free(mbufs[i]);
        }
    }
}
