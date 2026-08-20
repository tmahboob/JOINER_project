#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#define BURST 32
#define RX_RING 1024
#define TX_RING 1024

#define MODBUS_PORT 1507
#define FLOATS 27
#define PAYLOAD_SIZE (FLOATS * 4)

/* =========================
   FRAME SYNC MAGIC
========================= */
#define MAGIC 0xAABBCCDD

static struct rte_mempool *mbuf_pool;
static uint16_t ports[2];

struct feature_row {
    uint32_t magic;
    double timestamp;
    uint16_t payload_len;
    float features[FLOATS];
};

/* =========================
   CHECK MODBUS PORT
========================= */
static inline int is_target(struct rte_tcp_hdr *tcp)
{
    uint16_t sport = ntohs(tcp->src_port);
    uint16_t dport = ntohs(tcp->dst_port);
    return (sport == MODBUS_PORT || dport == MODBUS_PORT);
}

/* =========================
   EXTRACT FEATURES
========================= */
static void extract_features(uint8_t *pkt,
                             uint16_t len,
                             struct feature_row *out)
{
    struct rte_ether_hdr *eth =
        (struct rte_ether_hdr *)pkt;

    if (ntohs(eth->ether_type) != RTE_ETHER_TYPE_IPV4)
        return;

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(pkt + sizeof(struct rte_ether_hdr));

    int ip_hlen = (ip->version_ihl & 0x0F) * 4;

    struct rte_tcp_hdr *tcp =
        (struct rte_tcp_hdr *)(pkt +
            sizeof(struct rte_ether_hdr) + ip_hlen);

    int tcp_hlen = (tcp->data_off >> 4) * 4;

    uint8_t *payload =
        pkt + sizeof(struct rte_ether_hdr) + ip_hlen + tcp_hlen;

    int pay_len =
        len - (sizeof(struct rte_ether_hdr) + ip_hlen + tcp_hlen);

    out->payload_len = pay_len;

    /* MUST HAVE FULL 108 BYTES */
    if (pay_len < PAYLOAD_SIZE)
        return;

    /* =========================
       READ 27 FLOATS
    ========================= */
    for (int i = 0; i < FLOATS; i++)
    {
        uint32_t raw;
        memcpy(&raw, payload + i * 4, 4);

        raw = ntohl(raw);

        float val;
        memcpy(&val, &raw, 4);

        out->features[i] = val;
    }
}

/* =========================
   STORE TO FILE (SAFE STREAM)
========================= */
static void store_row(struct feature_row *row)
{
    FILE *fp = fopen("/tmp/dpdk_modbus_features.bin", "ab");
    if (!fp) return;

    /* FRAME FORMAT:
       MAGIC + 27 FLOATS
    */

    fwrite(&row->magic, sizeof(uint32_t), 1, fp);
    fwrite(row->features, sizeof(float), FLOATS, fp);

    fflush(fp);
    fclose(fp);
}

/* =========================
   FORWARD
========================= */
static inline void forward(struct rte_mbuf *m, uint16_t in_port)
{
    uint16_t out = (in_port == ports[0]) ? ports[1] : ports[0];

    if (rte_eth_tx_burst(out, 0, &m, 1) == 0)
        rte_pktmbuf_free(m);
}

/* =========================
   MAIN LOOP
========================= */
static void loop(void)
{
    struct rte_mbuf *bufs[BURST];

    while (1)
    {
        for (int p = 0; p < 2; p++)
        {
            uint16_t port = ports[p];

            uint16_t n = rte_eth_rx_burst(port, 0, bufs, BURST);

            for (int i = 0; i < n; i++)
            {
                struct rte_mbuf *m = bufs[i];
                uint8_t *pkt = rte_pktmbuf_mtod(m, uint8_t *);
                uint16_t len = rte_pktmbuf_pkt_len(m);

                forward(m, port);

                struct rte_ipv4_hdr *ip =
                    (struct rte_ipv4_hdr *)(pkt + sizeof(struct rte_ether_hdr));

                if (ip->next_proto_id != IPPROTO_TCP)
                    continue;

                struct rte_tcp_hdr *tcp =
                    (struct rte_tcp_hdr *)(pkt +
                        sizeof(struct rte_ether_hdr) +
                        ((ip->version_ihl & 0x0F) * 4));

                if (!is_target(tcp))
                    continue;

                struct feature_row row;
                memset(&row, 0, sizeof(row));

                row.magic = MAGIC;

                extract_features(pkt, len, &row);

                if (row.payload_len >= PAYLOAD_SIZE)
                    store_row(&row);
            }
        }
    }
}

/* =========================
   INIT PORT
========================= */
static void init_port(uint16_t port)
{
    struct rte_eth_conf conf = {0};

    rte_eth_dev_configure(port, 1, 1, &conf);

    rte_eth_rx_queue_setup(port, 0, RX_RING,
        rte_eth_dev_socket_id(port),
        NULL, mbuf_pool);

    rte_eth_tx_queue_setup(port, 0, TX_RING,
        rte_eth_dev_socket_id(port),
        NULL);

    rte_eth_dev_start(port);
    rte_eth_promiscuous_enable(port);
}

/* =========================
   MAIN
========================= */
int main(int argc, char **argv)
{
    rte_eal_init(argc, argv);

    uint16_t nb_ports = rte_eth_dev_count_avail();
    printf("Ports: %u\n", nb_ports);

    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL",
        8192 * nb_ports,
        256,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id()
    );

    int i = 0;
    uint16_t p;

    RTE_ETH_FOREACH_DEV(p)
    {
        ports[i++] = p;
        if (i == 2) break;
    }

    init_port(ports[0]);
    init_port(ports[1]);

    printf("🚀 Running FIXED DPDK Modbus Float Extractor\n");

    loop();
    return 0;
}
