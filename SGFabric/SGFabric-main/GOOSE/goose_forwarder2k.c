//
// Created by tm120a on 03/06/2026.
//
#include <stdint.h>
#include <string.h>
#include <rte_mbuf.h>
#include <rte_ether.h>

#define ETHERTYPE_GOOSE 0x88b8

/* MAC table (replacement for BPF_MAP) */
#define MAX_MAC 256

struct mac_entry {
    uint8_t mac[6];
    uint32_t port;
    int valid;
};

static struct mac_entry mac_table[MAX_MAC];

/* --------------------------------------------------
 * simple MAC hash (replaces BPF hash map)
 * ------------------------------------------------*/
static inline uint32_t mac_hash(uint8_t *mac)
{
    return mac[5] % MAX_MAC;
}

/* --------------------------------------------------
 * lookup MAC
 * ------------------------------------------------*/
static inline int mac_lookup(uint8_t *mac, uint32_t *port)
{
    uint32_t idx = mac_hash(mac);

    if (mac_table[idx].valid &&
        memcmp(mac_table[idx].mac, mac, 6) == 0)
    {
        *port = mac_table[idx].port;
        return 0;
    }

    return -1;
}

/* --------------------------------------------------
 * insert MAC
 * ------------------------------------------------*/
static inline void mac_insert(uint8_t *mac, uint32_t port)
{
    uint32_t idx = mac_hash(mac);

    memcpy(mac_table[idx].mac, mac, 6);
    mac_table[idx].port = port;
    mac_table[idx].valid = 1;
}

/* --------------------------------------------------
 * MAIN PIPELINE STAGE (DPDK replacement of prog())
 * ------------------------------------------------*/
int switch_stage(struct rte_mbuf *m, uint32_t in_port)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    uint16_t ethertype =
        rte_be_to_cpu_16(eth->ether_type);

    uint8_t *src = eth->src_addr.addr_bytes;
    uint8_t *dst = eth->dst_addr.addr_bytes;

    uint32_t out_port = 0;

    /* --------------------------------------------------
     * 1. DROP RULE (virtual port equivalent removed)
     * ------------------------------------------------*/
    if (in_port == 0)
        return -1;

    /* --------------------------------------------------
     * 2. RETURN PATH FOR ENCRYPTED TRAFFIC
     * (replaces: in_port == 1 → PORT + 3)
     * ------------------------------------------------*/
    if (in_port == 1)
    {
        return 1;   // forward to physical output port
    }

    /* --------------------------------------------------
     * 3. FORWARD GOOSE TO ENCRYPTION STAGE
     * (replaces: in_port == 2 && ethertype)
     * ------------------------------------------------*/
    if (in_port == 0 && ethertype == ETHERTYPE_GOOSE)
    {
        return ENCRYPT_STAGE;  // pipeline index, NOT port
    }

    /* --------------------------------------------------
     * 4. MAC LEARNING (replacement of BPF map)
     * ------------------------------------------------*/
    if (!(src[0] & 1))
    {
        mac_insert(src, in_port);
    }

    /* --------------------------------------------------
     * 5. BROADCAST FLOOD
     * ------------------------------------------------*/
    if (dst[0] & 1)
    {
        return FLOOD;
    }

    /* --------------------------------------------------
     * 6. LOOKUP DESTINATION
     * ------------------------------------------------*/
    if (mac_lookup(dst, &out_port) == 0)
    {
        return out_port;
    }

    return FLOOD;
}