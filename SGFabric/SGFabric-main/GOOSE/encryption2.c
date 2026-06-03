//
// Created by tm120a on 03/06/2026.
//
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <rte_mbuf.h>
#include <rte_ether.h>

#include "../encryption_timings/encryption_config.h"
#include "latency.h"

#define ETHERTYPE_GOOSE 0x88b8
#define ETHERNET_HEADER_LEN 14

extern encryption_config_t *chosen_config;

/* -------------------------------------------------------
 * Timestamp structure (same as your original code)
 * -----------------------------------------------------*/
struct timestamp_header {
    struct timespec ts;
};

/* -------------------------------------------------------
 * Fast timestamp helper
 * -----------------------------------------------------*/
static inline long get_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)(ts.tv_sec * 1000000000LL + ts.tv_nsec);
}

/* -------------------------------------------------------
 * Dummy encryption function (replace with your AES/logic)
 * -----------------------------------------------------*/
static inline void encrypt_payload(uint8_t *data, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        data[i] ^= 0xAA;   // simple XOR encryption placeholder
    }
}

/* -------------------------------------------------------
 * BPFabric / DPDK processing stage
 * -----------------------------------------------------*/
int encrypt_stage(struct rte_mbuf *m)
{
    long start_time = get_ns();

    /* -----------------------------
     * Extract Ethernet header
     * ----------------------------*/
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    uint16_t ethertype =
        rte_be_to_cpu_16(eth->ether_type);

    /* Filter non-GOOSE packets */
    if (ethertype != ETHERTYPE_GOOSE) {
        return 0;  // drop or bypass
    }

    /* -----------------------------
     * Access packet payload
     * ----------------------------*/
    uint8_t *pkt =
        rte_pktmbuf_mtod(m, uint8_t *);

    uint32_t pkt_len =
        rte_pktmbuf_pkt_len(m);

    uint8_t *payload = pkt + ETHERNET_HEADER_LEN;
    uint32_t payload_len = pkt_len - ETHERNET_HEADER_LEN;

    /* -----------------------------
     * MODE NONE: insert timestamp
     * ----------------------------*/
    if (chosen_config->mode == MODE_NONE)
    {
        struct timestamp_header ts;
        clock_gettime(CLOCK_MONOTONIC, &ts.ts);

        /* WARNING:
         * This assumes enough headroom exists.
         * In BPFabric, packets are usually preallocated safely.
         */
        memcpy(payload, &ts, sizeof(ts));
    }
    else
    {
        /* -----------------------------
         * Encrypt payload in-place
         * ----------------------------*/
        encrypt_payload(payload, payload_len);
    }

    long elapsed = get_ns() - start_time;

    /* Optional: export latency counter */
    // update_stats(elapsed);

    return 1;
}