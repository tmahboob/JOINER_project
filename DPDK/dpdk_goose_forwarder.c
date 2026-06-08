#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#define BURST_SIZE 32
#define MBUF_COUNT 8192
#define MBUF_CACHE 256

static struct rte_mempool *mbuf_pool;
static uint16_t ports[RTE_MAX_ETHPORTS];
static uint16_t nb_ports = 0;

/* ---------------- GOOSE CHECK (VLAN SAFE) ---------------- */

static inline int is_goose(uint8_t *pkt)
{
    uint16_t ethertype = (pkt[12] << 8) | pkt[13];

    // VLAN tagged frame
    if (ethertype == 0x8100) {
        ethertype = (pkt[16] << 8) | pkt[17];
    }

    return ethertype == 0x88B8;
}

/* ---------------- PORT INIT ---------------- */

static void init_port(uint16_t port_id)
{
    struct rte_eth_conf conf = {0};

    if (rte_eth_dev_configure(port_id, 1, 1, &conf) < 0)
        rte_exit(EXIT_FAILURE, "Port config failed\n");

    if (rte_eth_rx_queue_setup(port_id, 0, 1024,
        rte_eth_dev_socket_id(port_id),
        NULL, mbuf_pool) < 0)
        rte_exit(EXIT_FAILURE, "RX queue setup failed\n");

    if (rte_eth_tx_queue_setup(port_id, 0, 1024,
        rte_eth_dev_socket_id(port_id),
        NULL) < 0)
        rte_exit(EXIT_FAILURE, "TX queue setup failed\n");

    if (rte_eth_dev_start(port_id) < 0)
        rte_exit(EXIT_FAILURE, "Port start failed\n");

    rte_eth_promiscuous_enable(port_id);

    printf("[INIT] Port %u ready\n", port_id);
}

/* ---------------- FORWARD PACKET ---------------- */

static void forward(struct rte_mbuf *m, uint16_t in_port)
{
    uint16_t out_port = (in_port == ports[0]) ? ports[1] : ports[0];

    struct rte_mbuf *out = rte_pktmbuf_alloc(mbuf_pool);
    if (!out) {
        rte_pktmbuf_free(m);
        return;
    }

    uint8_t *in_data = rte_pktmbuf_mtod(m, uint8_t *);
    uint8_t *out_data = rte_pktmbuf_mtod(out, uint8_t *);

    uint16_t len = rte_pktmbuf_pkt_len(m);

    memcpy(out_data, in_data, len);
    rte_pktmbuf_append(out, len);

    uint16_t sent = rte_eth_tx_burst(out_port, 0, &out, 1);

    printf("[FORWARD] %u -> %u | len=%u | TX=%u\n",
           in_port, out_port, len, sent);

    rte_pktmbuf_free(m);
}

/* ---------------- MAIN LOOP ---------------- */

static void loop(void)
{
    struct rte_mbuf *bufs[BURST_SIZE];

    while (1) {

        for (int p = 0; p < nb_ports; p++) {

            uint16_t port = ports[p];

            uint16_t n = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

            if (!n)
                continue;

            printf("[RX] port=%u burst=%u\n", port, n);

            for (int i = 0; i < n; i++) {

                uint8_t *pkt = rte_pktmbuf_mtod(bufs[i], uint8_t *);
                uint16_t ethertype = (pkt[12] << 8) | pkt[13];

                if (ethertype == 0x8100)
                    ethertype = (pkt[16] << 8) | pkt[17];

                printf("[PKT] ethertype=0x%04x len=%u\n",
                       ethertype,
                       rte_pktmbuf_pkt_len(bufs[i]));

                if (is_goose(pkt)) {
                    forward(bufs[i], port);
                } else {
                    printf("[DROP] non-GOOSE\n");
                    rte_pktmbuf_free(bufs[i]);
                }
            }
        }
    }
}

/* ---------------- MAIN ---------------- */

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    nb_ports = rte_eth_dev_count_avail();

    if (nb_ports < 2)
        rte_exit(EXIT_FAILURE, "Need at least 2 DPDK ports\n");

    printf("[INIT] detected %u ports\n", nb_ports);

    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL",
        MBUF_COUNT * nb_ports,
        MBUF_CACHE,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id()
    );

    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "Mempool creation failed\n");

    for (int i = 0; i < nb_ports; i++) {
        ports[i] = i;
        init_port(i);
    }

    printf("[START] GOOSE forwarder running\n");

    loop();

    return 0;
}
