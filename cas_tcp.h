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
#include <rte_tcp.h>
#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <rte_string_fns.h>
#include <rte_log.h>
#include <rte_mempool.h>

typedef enum _cas_tcp_state {
	CAS_TCP_CLOSED      = 0,
	CAS_TCP_LISTEN      = 1,
	CAS_TCP_SYN_SENT    = 2,
	CAS_TCP_SYN_RCVD    = 3,
	CAS_TCP_ESTABLISHED = 4,
	CAS_TCP_CLOSE_WAIT  = 5,
	CAS_TCP_FIN_WAIT_1  = 6,
	CAS_TCP_CLOSING     = 7,
	CAS_TCP_LAST_ACK    = 8,
	CAS_TCP_FIN_WAIT_2  = 9,
} cas_tcp_state;