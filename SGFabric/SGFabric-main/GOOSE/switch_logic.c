//
// Created by tm120a on 04/06/2026.
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "../encryption_timings/encryption_config.h"
#include "latency.h"

#define BURST_SIZE 32
#define ETHERNET_HEADER_LEN 14

static uint16_t port_in = 0;
static uint16_t port_out = 1;

static encryption_config_t *chosen_config;
static int packet_count = 0;

/* ---------------- GOOSE FILTER ---------------- */

static inline int is_goose(uint8_t *pkt) {
    uint16_t ethertype = (pkt[12] << 8) | pkt[13];
    return ethertype == 0x88b8;
}

/* ---------------- PACKET PROCESSING ---------------- */

static inline void process_packet(struct rte_mbuf *m) {

    uint8_t *packet = rte_pktmbuf_mtod(m, uint8_t *);
    uint16_t len = rte_pktmbuf_pkt_len(m);

    if (!is_goose(packet)) {
        rte_pktmbuf_free(m);
        return;
    }

    packet_count++;

    long start_time = get_time_ns();
    long elapsed;

    /* ---------------- MODE NONE (timestamp only) ---------------- */
    if (chosen_config->mode == MODE_NONE) {

        int new_len = len + sizeof(struct timestamp_header);

        struct timestamp_header {
            struct timespec ts;
        };

        struct timestamp_header ts_hdr;
        clock_gettime(CLOCK_MONOTONIC, &ts_hdr.ts);

        /* we must create a new mbuf for expanded packet */
        struct rte_mbuf *out =
            rte_pktmbuf_alloc(m->pool);

        if (!out) {
            rte_pktmbuf_free(m);
            return;
        }

        uint8_t *out_data = rte_pktmbuf_mtod(out, uint8_t *);

        memcpy(out_data, packet, ETHERNET_HEADER_LEN);
        memcpy(out_data + ETHERNET_HEADER_LEN,
               &ts_hdr,
               sizeof(ts_hdr));
        memcpy(out_data + ETHERNET_HEADER_LEN + sizeof(ts_hdr),
               packet + ETHERNET_HEADER_LEN,
               len - ETHERNET_HEADER_LEN);

        rte_pktmbuf_append(out, new_len);

        elapsed = get_time_ns() - start_time;

        rte_eth_tx_burst(port_out, 0, &out, 1);
        rte_pktmbuf_free(m);
    }

    /* ---------------- ENCRYPTION MODE (YOUR REAL FUNCTION) ---------------- */
    else {

        int new_len = 0;

        u_char *encrypted =
            build_encrypted_packet(
                packet,
                len,
                ETHERNET_HEADER_LEN,
                &new_len,
                chosen_config
            );

        if (!encrypted) {
            rte_pktmbuf_free(m);
            return;
        }

        elapsed = get_time_ns() - start_time;

        /* allocate new mbuf for encrypted packet */
        struct rte_mbuf *out = rte_pktmbuf_alloc(m->pool);

        if (!out) {
            free(encrypted);
            rte_pktmbuf_free(m);
            return;
        }

        uint8_t *out_data = rte_pktmbuf_mtod(out, uint8_t *);

        memcpy(out_data, encrypted, new_len);
        rte_pktmbuf_append(out, new_len);

        rte_eth_tx_burst(port_out, 0, &out, 1);

        free(encrypted);
        rte_pktmbuf_free(m);
    }

    /* optional logging */
    if (packet_count % 1000 == 0) {
        printf("packet=%d processed\n", packet_count);
    }
}

/* ---------------- RX LOOP ---------------- */

static void main_loop(void) {

    struct rte_mbuf *bufs[BURST_SIZE];

    while (1) {

        uint16_t nb_rx =
            rte_eth_rx_burst(port_in, 0, bufs, BURST_SIZE);

        if (nb_rx == 0)
            continue;

        for (int i = 0; i < nb_rx; i++) {
            process_packet(bufs[i]);
        }
    }
}

/* ---------------- PORT INIT ---------------- */

static struct rte_mempool *init_port(uint16_t port_id) {

    struct rte_eth_conf conf = {0};

    rte_eth_dev_configure(port_id, 1, 1, &conf);

    struct rte_mempool *pool =
        rte_pktmbuf_pool_create(
            "MBUF_POOL",
            8192,
            256,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_socket_id()
        );

    rte_eth_rx_queue_setup(port_id, 0, 1024,
        rte_eth_dev_socket_id(port_id),
        NULL,
        pool);

    rte_eth_tx_queue_setup(port_id, 0, 1024,
        rte_eth_dev_socket_id(port_id),
        NULL);

    rte_eth_dev_start(port_id);

    return pool;
}

/* ---------------- MAIN ---------------- */

int main(int argc, char **argv) {

    rte_eal_init(argc, argv);

    chosen_config = get_chosen_config(argc, argv);

    struct rte_mempool *pool = init_port(port_in);
    init_port(port_out);

    printf("DPDK encrypted forwarding started...\n");

    main_loop();

    return 0;
}