#include "cas_dev_config.h"

uint32_t                enabled_ports_mask = 0;
bool                    numa_on = false;
uint16_t                nb_rxd = RX_DESC_DEFAULT;
uint16_t                nb_txd = TX_DESC_DEFAULT;
struct lcore_conf       lcore_conf[RTE_MAX_LCORE];                   
struct lcore_params     lcore_params_array[MAX_LCORE_PARAMS];
struct lcore_params     lcore_params_array_default[] = {{0, 0, 0},
                                                        {0, 1, 1},
                                                        {0, 2, 2},
                                                        {0, 3, 3}};
struct lcore_params    *lcore_params = lcore_params_array_default;
uint16_t                n_lcore_parms;

struct rte_mempool     *pktmbuf_pool[NUM_SOCKETS];

struct rte_ether_addr   local_mac;


/*
 * Return the CPU socket on which the given logical core resides.
 */
uint8_t socket_for_lcore(unsigned lcore_id){
    return (numa_on) ? (uint8_t)rte_lcore_to_socket_id(lcore_id) : 0;
}

/*
 * Ensure the configured (port,queue,lcore) mappings are valid.
 */
void check_lcore_params(void){
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
void init_lcores(void){
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
        lcore_conf[lcore].rx_queues[n_rx_queue].port_id = lcore_params[i].port_id;
        lcore_conf[lcore].rx_queues[n_rx_queue].queue_id = lcore_params[i].queue_id;
        lcore_conf[lcore].n_rx_queue = 1;
        RTE_LOG(INFO, LSI,
                "CAS: lcore id = %d ; n_rx_queue = %d ; port_id = %d ; queue_id = %d ;\n",
                lcore, lcore_conf[lcore].n_rx_queue, lcore_conf[lcore].rx_queues[n_rx_queue].port_id, lcore_conf[lcore].rx_queues[n_rx_queue].queue_id);
    }
}

/*
* Initialize a section of RAM for packet buffers per logical core
*/
void init_packet_buffer(unsigned num_mbuf){
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
void init_tx_queue_for_port(uint8_t port){
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
 * Configure all specified Ethernet devices, including allocating packet buffer
 * memory and TX queue rings.
 */
void configure_ports(unsigned n_ports, uint32_t port_mask, uint16_t n_lcores){
    int                     rsv;
    uint8_t                 port_id,
                            n_rx_queue;
    uint32_t                n_tx_queue;
    struct rte_ether_addr   eth_addr;

    for(port_id = 0; port_id < n_ports; port_id++){
        n_rx_queue = n_lcores;
        n_tx_queue = n_lcores;         
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
void init_rx_queues(void){
    int                 rsv;
    uint8_t             port_id,
                        queue_id,
                        socket_id;
    uint16_t            queue;
    unsigned            lcore_id;
    struct lcore_conf  *lconf;

    for(lcore_id = 0; lcore_id < n_lcore_parms; lcore_id ++){
        if(!rte_lcore_is_enabled(lcore_id)){
            RTE_LOG(INFO, LSI,
                    "rte_lcore_is_disabled, lcore_id = %d\n",lcore_id);
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
void start_ports(unsigned n_ports, uint32_t port_mask){
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
void check_port_link_status(uint8_t n_ports, uint32_t port_mask){
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
 *  Initialize low layer config, include nic, port, rx queue, tx queue
 */
void init_nics(void){
    unsigned n_ports;
    n_lcore_parms = rte_lcore_count();
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