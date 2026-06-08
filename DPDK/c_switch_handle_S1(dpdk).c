#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "encryption_timings/encryption_config.h"
#include "encryption_timings/latency.h"

#define BURST_SIZE 32
#define MBUF_COUNT 8192
#define MBUF_CACHE 256
#define ETHERNET_HEADER_LEN 14

#define CSV_FLUSH_INTERVAL 1000
#define DISPLAY_INTERVAL 100

/* ===================== PORTS ===================== */

static uint16_t port_in = 0;
static uint16_t port_out = 1;

/* ===================== GLOBALS ===================== */

static struct rte_mempool *pool_in;
static struct rte_mempool *pool_out;

static encryption_config_t *chosen_config;
static uint64_t packet_count = 0;

/* ===================== LATENCY FILES ===================== */

static FILE *latency_fp = NULL;
static FILE *latency_e2e_fp = NULL;

/* ===================== GOOSE CHECK ===================== */

static inline int is_goose(uint8_t *pkt)
{
    uint16_t ethertype = ((uint16_t)pkt[12] << 8) | pkt[13];
    return (ethertype == 0x88b8);
}

/* ===================== PACKET PROCESS ===================== */

static inline void process_packet(struct rte_mbuf *m)
{
    uint8_t *packet = rte_pktmbuf_mtod(m, uint8_t *);
    uint16_t len = rte_pktmbuf_pkt_len(m);

    uint64_t start_e2e = get_time_ns();
    uint64_t start_enc = start_e2e;

    packet_count++;

    int new_len = 0;

    /* ===================== ENCRYPTION ===================== */
    uint8_t *encrypted = build_encrypted_packet(
        packet,
        len,
        ETHERNET_HEADER_LEN,
        &new_len,
        chosen_config
    );

    uint64_t enc_ns = get_time_ns() - start_enc;

    if (!encrypted) {
        rte_pktmbuf_free(m);
        return;
    }

    struct rte_mbuf *out = rte_pktmbuf_alloc(pool_out);
    if (!out) {
        free(encrypted);
        rte_pktmbuf_free(m);
        return;
    }

    uint8_t *out_data = rte_pktmbuf_mtod(out, uint8_t *);
    memcpy(out_data, encrypted, new_len);
    rte_pktmbuf_append(out, new_len);

    int sent = rte_eth_tx_burst(port_out, 0, &out, 1);

    uint64_t e2e_ns = get_time_ns() - start_e2e;

    free(encrypted);
    rte_pktmbuf_free(m);

    /* ===================== LOGGING ===================== */

    if (latency_fp) {
        fprintf(latency_fp, "%lu,%lu\n", packet_count, enc_ns);
    }

    if (latency_e2e_fp) {
        fprintf(latency_e2e_fp, "%lu,%lu\n", packet_count, e2e_ns);
    }

    static uint64_t flush_counter = 0;
    if (++flush_counter % CSV_FLUSH_INTERVAL == 0) {
        if (latency_fp) fflush(latency_fp);
        if (latency_e2e_fp) fflush(latency_e2e_fp);
    }

    /* ===================== DISPLAY ===================== */

    if (packet_count % DISPLAY_INTERVAL == 0) {
        printf("[LATENCY] pkt=%lu enc=%lu ns e2e=%lu ns\n",
               packet_count, enc_ns, e2e_ns);
    }

    if (packet_count % 1000 == 0) {
        printf("[STAT] packets processed=%lu sent=%d\n", packet_count, sent);
    }
}

/* ===================== RX LOOP ===================== */

static void main_loop(void)
{
    struct rte_mbuf *bufs[BURST_SIZE];

    printf("[START] forwarding IN=%d OUT=%d\n", port_in, port_out);

    while (1) {
        uint16_t nb_rx = rte_eth_rx_burst(port_in, 0, bufs, BURST_SIZE);

        if (nb_rx == 0)
            continue;

        for (int i = 0; i < nb_rx; i++) {
            process_packet(bufs[i]);
        }
    }
}

/* ===================== PORT INIT ===================== */

static struct rte_mempool *init_port(uint16_t port_id)
{
    struct rte_eth_conf conf = {0};

    char name[32];
    snprintf(name, sizeof(name), "MBUF_POOL_%d", port_id);

    struct rte_mempool *pool = rte_pktmbuf_pool_create(
        name,
        MBUF_COUNT,
        MBUF_CACHE,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id()
    );

    if (!pool)
        rte_exit(EXIT_FAILURE, "mempool create failed\n");

    if (rte_eth_dev_configure(port_id, 1, 1, &conf) < 0)
        rte_exit(EXIT_FAILURE, "dev configure failed\n");

    if (rte_eth_rx_queue_setup(port_id, 0, 1024,
                               rte_eth_dev_socket_id(port_id),
                               NULL, pool) < 0)
        rte_exit(EXIT_FAILURE, "rx queue failed\n");

    if (rte_eth_tx_queue_setup(port_id, 0, 1024,
                               rte_eth_dev_socket_id(port_id),
                               NULL) < 0)
        rte_exit(EXIT_FAILURE, "tx queue failed\n");

    if (rte_eth_dev_start(port_id) < 0)
        rte_exit(EXIT_FAILURE, "port start failed\n");

    rte_eth_promiscuous_enable(port_id);

    printf("[PORT] %d initialized\n", port_id);

    return pool;
}

/* ===================== MAIN ===================== */

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL init failed\n");

    argc -= ret;
    argv += ret;

    chosen_config = get_chosen_config(argc, argv);

    printf("[INIT] starting encryption switch with latency logging\n");

    /* ===================== OPEN CSV ===================== */

    latency_fp = fopen("latency_enc.csv", "w");
    if (!latency_fp)
        rte_exit(EXIT_FAILURE, "Cannot open latency_enc.csv\n");

    latency_e2e_fp = fopen("latency_enc_e2e.csv", "w");
    if (!latency_e2e_fp)
        rte_exit(EXIT_FAILURE, "Cannot open latency_enc_e2e.csv\n");

    fprintf(latency_fp, "packet_id,enc_latency_ns\n");
    fprintf(latency_e2e_fp, "packet_id,e2e_latency_ns\n");

    fflush(latency_fp);
    fflush(latency_e2e_fp);

    pool_in = init_port(port_in);
    pool_out = init_port(port_out);

    main_loop();

    return 0;
}