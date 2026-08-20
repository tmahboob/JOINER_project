#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
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
#define FEATURES 27

static struct rte_mempool *mbuf_pool;
static uint16_t ports[2];

/* =========================
   FEATURE ROW
========================= */
struct feature_row {

    double timestamp;

    uint8_t src_mac[6];
    uint8_t dst_mac[6];

    uint32_t src_ip;
    uint32_t dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

    uint16_t payload_len;
    uint8_t  func_code;

    float features[FEATURES];
};

/* =========================
   SAFE FLOAT
========================= */
static inline float safe(float v)
{
    if (isnan(v) || isinf(v))
        return 0.0f;
    return v;
}

/* =========================
   MODBUS CHECK
========================= */
static inline int is_modbus(struct rte_tcp_hdr *tcp)
{
    uint16_t sport = ntohs(tcp->src_port);
    uint16_t dport = ntohs(tcp->dst_port);

    return (sport == MODBUS_PORT || dport == MODBUS_PORT);
}

/* =========================
   FEATURE EXTRACTION
========================= */
static void extract_features(uint8_t *pkt,
                             uint16_t len,
                             struct feature_row *out)
{
    struct rte_ether_hdr *eth =
        (struct rte_ether_hdr *)pkt;

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(pkt + sizeof(struct rte_ether_hdr));

    int ip_hlen = (ip->version_ihl & 0x0F) * 4;

    struct rte_tcp_hdr *tcp =
        (struct rte_tcp_hdr *)(pkt +
            sizeof(struct rte_ether_hdr) + ip_hlen);

    int header_len =
        sizeof(struct rte_ether_hdr) + ip_hlen + sizeof(struct rte_tcp_hdr);

    if (len <= header_len)
        return;

    uint8_t *payload = pkt + header_len;
    int pay_len = len - header_len;

    /* =========================
       META
    ========================= */
    memcpy(out->src_mac, eth->src_addr.addr_bytes, 6);
    memcpy(out->dst_mac, eth->dst_addr.addr_bytes, 6);

    out->src_ip = ip->src_addr;
    out->dst_ip = ip->dst_addr;

    out->src_port = ntohs(tcp->src_port);
    out->dst_port = ntohs(tcp->dst_port);

    out->payload_len = pay_len;
    out->func_code = (pay_len > 7) ? payload[7] : 0;

    /* =========================
       FEATURE ENGINE (ROBUST)
    ========================= */

    float mean = 0.0f;
    float sq = 0.0f;
    int zero = 0;

    int N = (pay_len > 128) ? 128 : pay_len;

    if (N <= 0) {
        memset(out->features, 0, sizeof(out->features));
        return;
    }

    for (int i = 0; i < N; i++) {
        uint8_t b = payload[i];
        mean += b;
        sq += b * b;
        if (b == 0) zero++;
    }

    mean /= N;
    float var = (sq / N) - (mean * mean);

    out->features[0] = safe(mean);
    out->features[1] = safe(sqrtf(fabsf(var)));
    out->features[2] = safe((float)zero / N);

    /* =========================
       BYTE HISTOGRAM (24 FEATURES)
    ========================= */
    float hist[24] = {0};

    for (int i = 0; i < N; i++) {
        hist[payload[i] % 24] += 1.0f;
    }

    for (int i = 0; i < 24; i++) {
        out->features[3 + i] = safe(hist[i] / N);
    }

    /* =========================
       TIMESTAMP
    ========================= */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    out->timestamp = ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* =========================
   STORE ROW (ENSURE FILE EXISTS)
========================= */
static void store_row(struct feature_row *row)
{
    FILE *fp = fopen("/tmp/dpdk_modbus_features.bin", "ab");

    if (!fp) {
        printf("❌ Cannot open output file\n");
        return;
    }

    fwrite(row, sizeof(struct feature_row), 1, fp);
    fclose(fp);

    printf("✅ row written | func=%u | len=%u\n",
           row->func_code,
           row->payload_len);
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

    while (1) {

        for (int p = 0; p < 2; p++) {

            uint16_t port = ports[p];

            uint16_t n = rte_eth_rx_burst(port, 0, bufs, BURST);

            if (!n) continue;

            for (int i = 0; i < n; i++) {

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

                if (!is_modbus(tcp))
                    continue;

                struct feature_row row;
                memset(&row, 0, sizeof(row));

                extract_features(pkt, len, &row);

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

    RTE_ETH_FOREACH_DEV(p) {
        ports[i++] = p;
        if (i == 2) break;
    }

    init_port(ports[0]);
    init_port(ports[1]);

    printf("🚀 DPDK Modbus feature extractor running\n");

    loop();
    return 0;
}
