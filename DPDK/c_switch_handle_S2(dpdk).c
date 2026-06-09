//* ---- Contribution: Dr. Tahira Mahboob, School of Computing, University of Glasgow, UK ------*//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "encryption_timings/encryption_config.h"
#include "encryption_timings/latency.h"

#define BURST_SIZE 32
#define MBUF_COUNT 8192
#define MBUF_CACHE 256
#define ETHERNET_HEADER_LEN 14

static uint16_t port_in = 0;
static uint16_t port_out = 1;

static struct rte_mempool *pool_in;
static struct rte_mempool *pool_out;

static encryption_config_t *chosen_config;
static uint64_t packet_count = 0;

/* ===================== CSV FILES ===================== */
static FILE *latency_fp = NULL;
static FILE *latency_e2e_fp = NULL;   // optional if used

#define CSV_FLUSH_INTERVAL 1000
#define DISPLAY_INTERVAL 100

/* ===================== SIGNAL HANDLER ===================== */
static void handle_exit(int sig)
{
    printf("\n[EXIT] Signal %d received, closing files...\n", sig);

    if (latency_fp) {
        fflush(latency_fp);
        fclose(latency_fp);
    }

    if (latency_e2e_fp) {
        fflush(latency_e2e_fp);
        fclose(latency_e2e_fp);
    }

    exit(0);
}

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

    if (!is_goose(packet)) {
        rte_pktmbuf_free(m);
        return;
    }

    packet_count++;

    struct timestamp_header ts_hdr;
    int new_len = 0;

    long start_decrypt_ns = get_time_ns();
    long start_e2e_ns = start_decrypt_ns;

    uint8_t *decrypted = build_decrypted_packet(
        packet, len, ETHERNET_HEADER_LEN, &new_len, chosen_config, &ts_hdr
    );

    long decrypt_ns = get_time_ns() - start_decrypt_ns;

    if (!decrypted) {
        rte_pktmbuf_free(m);
        return;
    }

    struct rte_mbuf *out = rte_pktmbuf_alloc(pool_out);
    if (!out) {
        free(decrypted);
        rte_pktmbuf_free(m);
        return;
    }

    uint8_t *out_data = rte_pktmbuf_mtod(out, uint8_t *);
    memcpy(out_data, decrypted, new_len);
    rte_pktmbuf_append(out, new_len);

    rte_eth_tx_burst(port_out, 0, &out, 1);

    free(decrypted);
    rte_pktmbuf_free(m);

    /* CSV logging */
    if (latency_fp) {
        fprintf(latency_fp, "%lu,%ld\n", packet_count, decrypt_ns);
        if (packet_count % CSV_FLUSH_INTERVAL == 0)
            fflush(latency_fp);
    }

    if (latency_e2e_fp) {
        long e2e_ns = get_time_ns() - start_e2e_ns;
        fprintf(latency_e2e_fp, "%lu,%ld\n", packet_count, e2e_ns);
        if (packet_count % CSV_FLUSH_INTERVAL == 0)
            fflush(latency_e2e_fp);
    }

    /* Live display */
    if (packet_count % DISPLAY_INTERVAL == 0) {
        printf("[LATENCY] pkt=%lu decrypt=%ld ns\n", packet_count, decrypt_ns);
    }

    if (packet_count % 1000 == 0) {
        printf("[STAT] processed=%lu packets\n", packet_count);
    }
}

/* ===================== RX LOOP ===================== */
static void main_loop(void)
{
    struct rte_mbuf *bufs[BURST_SIZE];

    printf("[START] switch IN=%d OUT=%d\n", port_in, port_out);

    while (1) {
        uint16_t nb_rx = rte_eth_rx_burst(port_in, 0, bufs, BURST_SIZE);
        if (nb_rx == 0) continue;

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
        name, MBUF_COUNT, MBUF_CACHE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()
    );

    if (!pool)
        rte_exit(EXIT_FAILURE, "mempool create failed\n");

    if (rte_eth_dev_configure(port_id, 1, 1, &conf) < 0)
        rte_exit(EXIT_FAILURE, "dev configure failed\n");

    if (rte_eth_rx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id), NULL, pool) < 0)
        rte_exit(EXIT_FAILURE, "rx queue failed\n");

    if (rte_eth_tx_queue_setup(port_id, 0, 1024, rte_eth_dev_socket_id(port_id), NULL) < 0)
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
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL init failed\n");

    argc -= ret;
    argv += ret;

    chosen_config = get_chosen_config(argc, argv);

    printf("[INIT] starting switch with dual latency logging\n");

    /* Open CSV files */
    latency_fp = fopen("latency.csv", "w");
    if (!latency_fp) {
        perror("latency.csv");
        rte_exit(EXIT_FAILURE, "Cannot open latency.csv\n");
    }
    setvbuf(latency_fp, NULL, _IOLBF, 0);
    fprintf(latency_fp, "packet_id,latency_ns\n");

    latency_e2e_fp = fopen("latency_e2e.csv", "w");
    if (!latency_e2e_fp) {
        perror("latency_e2e.csv");
        rte_exit(EXIT_FAILURE, "Cannot open latency_e2e.csv\n");
    }
    setvbuf(latency_e2e_fp, NULL, _IOLBF, 0);
    fprintf(latency_e2e_fp, "packet_id,latency_ns\n");

    fflush(latency_fp);
    fflush(latency_e2e_fp);

    pool_in = init_port(port_in);
    pool_out = init_port(port_out);

    main_loop();

    /* Close CSV files */
    if (latency_fp) { fflush(latency_fp); fclose(latency_fp); }
    if (latency_e2e_fp) { fflush(latency_e2e_fp); fclose(latency_e2e_fp); }

    return 0;
}
