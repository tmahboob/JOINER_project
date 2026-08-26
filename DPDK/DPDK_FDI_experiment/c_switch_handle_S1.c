#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <endian.h>
#include <limits.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

/* ============================================================
 * CONFIG
 * ============================================================ */

#define PORT_CLIENT     0
#define PORT_SERVER     1

#define RX_QUEUE        0
#define TX_QUEUE        0

#define RX_RING         1024
#define TX_RING         1024
#define BURST           32

#define NUM_MBUFS       16384
#define MBUF_CACHE      256
#define TX_BUFFER_SIZE  256

#define MODBUS_PORT     1507

#define FLOATS          27
#define REGISTERS       54
#define REGISTER_BYTES  2
#define FLOAT_BYTES     4
#define FEATURE_BYTES   (FLOATS * FLOAT_BYTES)

#define MAGIC           0xAABBCCDD

#define OUTPUT_FILE     "/tmp/dpdk_modbus_features.bin"
#define LATENCY_CSV     "/tmp/dpdk_latency.csv"

/*
 * Ignore short packets.
 *
 * request/other packet ~= 78 bytes
 * desired packet    ~= 187 bytes
 */
#define MIN_PACKET_LEN  150

/*
 * Set to 1 only when debugging.
 *
 * IMPORTANT:
 * Keep this 0 for latency measurements.
 */
#define DEBUG           0

/* ============================================================
 * GLOBALS
 * ============================================================ */

static struct rte_mempool *mbuf_pool;

static struct rte_eth_dev_tx_buffer *tx_buffer[2];

static volatile int force_quit = 0;

static uint64_t rx_packets[2] = {0};
static uint64_t tx_packets[2] = {0};
static uint64_t tx_drops[2] = {0};

static uint64_t ipv4_packets = 0;
static uint64_t tcp_packets = 0;
static uint64_t modbus_candidates = 0;
static uint64_t extraction_success = 0;
static uint64_t extraction_failed = 0;
static uint64_t feature_records = 0;

/*
 * CSV
 */
static FILE *latency_fp = NULL;
static uint64_t latency_packet_id = 0;

/*
 * DPDK timestamp frequency.
 */
static uint64_t tsc_hz = 0;

/* ============================================================
 * LATENCY STRUCTURES
 * ============================================================ */

struct latency_stats
{
    uint64_t count;
    uint64_t total_cycles;
    uint64_t min_cycles;
    uint64_t max_cycles;
};

struct packet_latency
{
    uint16_t payload_len;

    uint64_t parse_cycles;
    uint64_t extraction_cycles;
    uint64_t prediction_cycles;
    uint64_t total_cycles;
};

static struct latency_stats parse_latency = {0};
static struct latency_stats extraction_latency = {0};
static struct latency_stats prediction_latency = {0};
static struct latency_stats total_latency = {0};
static struct latency_stats store_latency = {0};

/* ============================================================
 * DEBUG MACRO
 * ============================================================ */

#if DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

/* ============================================================
 * LATENCY HELPERS
 * ============================================================ */

static inline void
latency_record(
    struct latency_stats *s,
    uint64_t cycles)
{
    s->count++;
    s->total_cycles += cycles;

    if (s->count == 1 ||
        cycles < s->min_cycles)
    {
        s->min_cycles = cycles;
    }

    if (s->count == 1 ||
        cycles > s->max_cycles)
    {
        s->max_cycles = cycles;
    }
}

static inline double
cycles_to_us(uint64_t cycles)
{
    if (tsc_hz == 0)
        return 0.0;

    return ((double)cycles * 1000000.0) /
           (double)tsc_hz;
}

static inline double
average_cycles(
    const struct latency_stats *s)
{
    if (s->count == 0)
        return 0.0;

    return (double)s->total_cycles /
           (double)s->count;
}

/* ============================================================
 * SIGNAL
 * ============================================================ */

static void
signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
        force_quit = 1;
}

/* ============================================================
 * HEX DEBUG
 * ============================================================ */

static void
print_hex(
    const uint8_t *data,
    uint16_t len)
{
    printf(
        "\n---- PAYLOAD HEX (%u bytes) ----\n",
        len);

    uint16_t show = len;

    if (show > 220)
        show = 220;

    for (uint16_t i = 0; i < show; i++)
    {
        printf("%02X ", data[i]);

        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    printf(
        "\n--------------------------------\n");
}

/* ============================================================
 * LATENCY CSV
 * ============================================================ */

static int
init_latency_csv(void)
{
    latency_fp =
        fopen(LATENCY_CSV, "w");

    if (!latency_fp)
    {
        perror("fopen latency CSV");
        return -1;
    }

    fprintf(
        latency_fp,
        "packet_id,"
        "packet_len,"
        "tcp_payload_len,"
        "parse_cycles,"
        "parse_us,"
        "extraction_cycles,"
        "extraction_us,"
        "prediction_cycles,"
        "prediction_us,"
        "total_cycles,"
        "total_us,"
        "prediction\n");

    fflush(latency_fp);

    return 0;
}

/* ============================================================
 * WRITE LATENCY CSV ROW
 * ============================================================ */

static void
write_latency_csv(
    uint64_t packet_id,
    uint16_t packet_len,
    float prediction,
    const struct packet_latency *latency)
{
    if (!latency_fp)
        return;

    fprintf(
        latency_fp,
        "%lu,"
        "%u,"
        "%u,"
        "%lu,"
        "%.6f,"
        "%lu,"
        "%.6f,"
        "%lu,"
        "%.6f,"
        "%lu,"
        "%.6f,"
        "%.9f\n",

        packet_id,

        packet_len,

        latency->payload_len,

        latency->parse_cycles,
        cycles_to_us(
            latency->parse_cycles),

        latency->extraction_cycles,
        cycles_to_us(
            latency->extraction_cycles),

        latency->prediction_cycles,
        cycles_to_us(
            latency->prediction_cycles),

        latency->total_cycles,
        cycles_to_us(
            latency->total_cycles),

        prediction);

    /*
     * Do not flush every packet.
     *
     * This keeps filesystem I/O from dominating the
     * packet-processing benchmark.
     */
    if ((packet_id % 1000ULL) == 0)
        fflush(latency_fp);
}

/* ============================================================
 * CLOSE LATENCY CSV
 * ============================================================ */

static void
close_latency_csv(void)
{
    if (latency_fp)
    {
        fflush(latency_fp);

        fclose(latency_fp);

        latency_fp = NULL;
    }
}

/* ============================================================
 * WRITE FEATURE RECORD
 *
 * File:
 *
 * 4 bytes  MAGIC little endian
 * 27 * 4 bytes little-endian float32
 *
 * total = 112 bytes
 * ============================================================ */

static int
store_row(float features[FLOATS])
{
    uint64_t store_start =
        rte_rdtsc();

    FILE *fp =
        fopen(
            OUTPUT_FILE,
            "ab");

    if (!fp)
    {
        perror("fopen");
        return -1;
    }

    uint32_t magic =
        htole32(MAGIC);

    if (fwrite(
            &magic,
            sizeof(magic),
            1,
            fp) != 1)
    {
        fclose(fp);
        return -1;
    }

    for (int i = 0; i < FLOATS; i++)
    {
        uint32_t raw;

        memcpy(
            &raw,
            &features[i],
            sizeof(raw));

        raw = htole32(raw);

        if (fwrite(
                &raw,
                sizeof(raw),
                1,
                fp) != 1)
        {
            fclose(fp);
            return -1;
        }
    }

    fflush(fp);

    fclose(fp);

    feature_records++;

    uint64_t store_end =
        rte_rdtsc();

    latency_record(
        &store_latency,
        store_end - store_start);

#if DEBUG

    printf(
        "\n========================================\n");

    printf(
        "FEATURE RECORD %lu WRITTEN\n",
        feature_records);

    printf(
        "File size should now be: %lu bytes\n",
        feature_records * 112UL);

    printf(
        "========================================\n");

    for (int i = 0; i < FLOATS; i++)
    {
        printf(
            "F%02d = %.9f\n",
            i,
            features[i]);
    }

#endif

    return 0;
}

/* ============================================================
 * PREDICTION
 *
 * Replace this function with your actual ML inference.
 *
 * Example:
 *
 * static float
 * run_model(float features[FLOATS])
 * {
 *     return your_model_predict(features);
 * }
 *
 * ============================================================ */

static inline float
run_model(
    float features[FLOATS])
{
    /*
     * Placeholder.
     *
     * This currently does almost no work.
     *
     * Replace with your actual prediction function.
     */

    (void)features;

    return 0.0f;
}

/* ============================================================
 * TCP PORT CHECK
 * ============================================================ */

static inline int
is_modbus_tcp(
    struct rte_tcp_hdr *tcp)
{
    uint16_t sport =
        ntohs(tcp->src_port);

    uint16_t dport =
        ntohs(tcp->dst_port);

    return sport == MODBUS_PORT ||
           dport == MODBUS_PORT;
}

/* ============================================================
 * EXTRACT FEATURES
 *
 * Measures:
 *
 *     1. Parsing
 *     2. Feature extraction
 *
 * ============================================================ */

static int
extract_features(
    uint8_t *pkt,
    uint16_t len,
    float features[FLOATS],
    struct packet_latency *latency)
{
    uint64_t parse_start =
        rte_rdtsc();

    const uint16_t ETH_SIZE =
        sizeof(struct rte_ether_hdr);

    /* --------------------------------------------------------
     * Ethernet
     * -------------------------------------------------------- */

    if (len < ETH_SIZE)
        return 0;

    struct rte_ether_hdr *eth =
        (struct rte_ether_hdr *)pkt;

    if (ntohs(eth->ether_type) !=
        RTE_ETHER_TYPE_IPV4)
    {
        return 0;
    }

    ipv4_packets++;

    /* --------------------------------------------------------
     * IPv4
     * -------------------------------------------------------- */

    if (len <
        ETH_SIZE +
        sizeof(struct rte_ipv4_hdr))
    {
        return 0;
    }

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)
        (pkt + ETH_SIZE);

    if ((ip->version_ihl >> 4) != 4)
        return 0;

    uint16_t ip_hlen =
        (ip->version_ihl & 0x0F) * 4;

    if (ip_hlen < 20)
        return 0;

    if (len <
        ETH_SIZE +
        ip_hlen)
    {
        return 0;
    }

    if (ip->next_proto_id !=
        IPPROTO_TCP)
    {
        return 0;
    }

    tcp_packets++;

    /* --------------------------------------------------------
     * TCP
     * -------------------------------------------------------- */

    if (len <
        ETH_SIZE +
        ip_hlen +
        sizeof(struct rte_tcp_hdr))
    {
        return 0;
    }

    struct rte_tcp_hdr *tcp =
        (struct rte_tcp_hdr *)
        (pkt +
         ETH_SIZE +
         ip_hlen);

    uint16_t tcp_hlen =
        ((tcp->data_off >> 4) & 0x0F) * 4;

    if (tcp_hlen < 20)
        return 0;

    uint16_t tcp_offset =
        ETH_SIZE +
        ip_hlen +
        tcp_hlen;

    if (len <= tcp_offset)
        return 0;

    /* --------------------------------------------------------
     * TCP PAYLOAD
     * -------------------------------------------------------- */

    uint8_t *payload =
        pkt + tcp_offset;

    uint16_t payload_len =
        len - tcp_offset;

    /*
     * Ignore short packets.
     */
    if (len < MIN_PACKET_LEN)
        return 0;

    /*
     * Need at least 108 bytes of feature data.
     */
    if (payload_len < FEATURE_BYTES)
    {
        DEBUG_PRINT(
            "\n[EXTRACT FAIL] TCP payload too short: "
            "%u bytes, need %u\n",
            payload_len,
            FEATURE_BYTES);

#if DEBUG
        print_hex(
            payload,
            payload_len);
#endif

        return 0;
    }

    /*
     * Parsing is complete.
     */
    uint64_t parse_end =
        rte_rdtsc();

    latency->parse_cycles =
        parse_end -
        parse_start;

    latency->payload_len =
        payload_len;

    /* --------------------------------------------------------
     * REGISTER DATA
     * -------------------------------------------------------- */

    uint8_t *data =
        payload +
        payload_len -
        FEATURE_BYTES;

    DEBUG_PRINT(
        "\n========================================\n"
        "MODBUS CANDIDATE\n"
        "packet length : %u\n"
        "TCP payload   : %u\n"
        "TCP header    : %u\n"
        "IP header     : %u\n"
        "========================================\n",
        len,
        payload_len,
        tcp_hlen,
        ip_hlen);

#if DEBUG

    uint16_t debug_len =
        payload_len > 32
        ? 32
        : payload_len;

    print_hex(
        payload,
        debug_len);

    printf(
        "[EXTRACT] Using final %u bytes "
        "of TCP payload\n",
        FEATURE_BYTES);

#endif

    /* --------------------------------------------------------
     * FEATURE EXTRACTION
     *
     * 54 registers
     *     ↓
     * 27 float32 values
     *
     * Each register is 16-bit big endian.
     * -------------------------------------------------------- */

    uint64_t extraction_start =
        rte_rdtsc();

    for (int i = 0;
         i < FLOATS;
         i++)
    {
        int byte_offset =
            i * 4;

        uint16_t reg_hi =
            ((uint16_t)data[byte_offset] << 8) |
            data[byte_offset + 1];

        uint16_t reg_lo =
            ((uint16_t)data[byte_offset + 2] << 8) |
            data[byte_offset + 3];

        uint32_t raw =
            ((uint32_t)reg_hi << 16) |
            reg_lo;

        memcpy(
            &features[i],
            &raw,
            sizeof(float));
    }

    uint64_t extraction_end =
        rte_rdtsc();

    latency->extraction_cycles =
        extraction_end -
        extraction_start;

    extraction_success++;

#if DEBUG

    printf(
        "\n******** EXTRACTION SUCCESS ********\n");

    for (int i = 0;
         i < FLOATS;
         i++)
    {
        printf(
            "F%02d = %.9f\n",
            i,
            features[i]);
    }

    printf(
        "************************************\n");

#endif

    return 1;
}

/* ============================================================
 * PROCESS PACKET
 * ============================================================ */

static inline void
process_packet(
    struct rte_mbuf *m,
    uint16_t in_port)
{
    /*
     * Start total processing timer.
     *
     * This measures:
     *
     *     parsing
     *       +
     *     extraction
     *       +
     *     prediction
     *
     * It intentionally does NOT include feature-file
     * storage because storage is measured separately.
     */

    uint64_t total_start =
        rte_rdtsc();

    uint16_t out_port =
        (in_port == PORT_CLIENT)
        ? PORT_SERVER
        : PORT_CLIENT;

    uint8_t *pkt =
        rte_pktmbuf_mtod(
            m,
            uint8_t *);

    uint16_t len =
        rte_pktmbuf_pkt_len(m);

    /*
     * Ignore extremely small packets.
     */
    if (len <
        sizeof(struct rte_ether_hdr))
    {
        rte_eth_tx_buffer(
            out_port,
            TX_QUEUE,
            tx_buffer[out_port],
            m);

        return;
    }

    /* --------------------------------------------------------
     * Ethernet / IPv4 / TCP / Modbus
     * -------------------------------------------------------- */

    struct rte_ether_hdr *eth =
        (struct rte_ether_hdr *)pkt;

    if (ntohs(eth->ether_type) ==
        RTE_ETHER_TYPE_IPV4)
    {
        struct rte_ipv4_hdr *ip =
            (struct rte_ipv4_hdr *)
            (pkt +
             sizeof(struct rte_ether_hdr));

        uint16_t ip_hlen =
            (ip->version_ihl & 0x0F) * 4;

        if ((ip->version_ihl >> 4) == 4 &&
            ip_hlen >= 20 &&
            ip->next_proto_id == IPPROTO_TCP)
        {
            if (len >=
                sizeof(struct rte_ether_hdr) +
                ip_hlen +
                sizeof(struct rte_tcp_hdr))
            {
                struct rte_tcp_hdr *tcp =
                    (struct rte_tcp_hdr *)
                    (pkt +
                     sizeof(struct rte_ether_hdr) +
                     ip_hlen);

                if (is_modbus_tcp(tcp))
                {
                    /*
                     * Count exactly once.
                     */
                    modbus_candidates++;

                    float features[FLOATS];

                    struct packet_latency latency;

                    memset(
                        &latency,
                        0,
                        sizeof(latency));

                    uint64_t packet_id =
                        ++latency_packet_id;

                    /*
                     * ----------------------------------------
                     * PARSING + FEATURE EXTRACTION
                     * ----------------------------------------
                     */

                    if (extract_features(
                            pkt,
                            len,
                            features,
                            &latency))
                    {
                        /*
                         * ------------------------------------
                         * PREDICTION
                         * ------------------------------------
                         */

                        uint64_t prediction_start =
                            rte_rdtsc();

                        float prediction =
                            run_model(features);

                        uint64_t prediction_end =
                            rte_rdtsc();

                        latency.prediction_cycles =
                            prediction_end -
                            prediction_start;

                        /*
                         * ------------------------------------
                         * TOTAL PROCESSING
                         * ------------------------------------
                         */

                        uint64_t total_end =
                            rte_rdtsc();

                        latency.total_cycles =
                            total_end -
                            total_start;

                        /*
                         * ------------------------------------
                         * UPDATE STATISTICS
                         * ------------------------------------
                         */

                        latency_record(
                            &parse_latency,
                            latency.parse_cycles);

                        latency_record(
                            &extraction_latency,
                            latency.extraction_cycles);

                        latency_record(
                            &prediction_latency,
                            latency.prediction_cycles);

                        latency_record(
                            &total_latency,
                            latency.total_cycles);

                        /*
                         * ------------------------------------
                         * WRITE CSV
                         * ------------------------------------
                         */

                        write_latency_csv(
                            packet_id,
                            len,
                            prediction,
                            &latency);

                        /*
                         * ------------------------------------
                         * STORE FEATURES
                         *
                         * Measured separately.
                         * ------------------------------------
                         */

                        store_row(features);
                    }
                    else
                    {
                        extraction_failed++;
                    }
                }
            }
        }
    }

    /*
     * Always forward packet.
     */

    rte_eth_tx_buffer(
        out_port,
        TX_QUEUE,
        tx_buffer[out_port],
        m);
}

/* ============================================================
 * TX CALLBACK
 * ============================================================ */

static void
flush_callback(
    struct rte_mbuf **pkts,
    uint16_t unsent,
    void *userdata)
{
    uint16_t port =
        (uint16_t)(uintptr_t)userdata;

    for (uint16_t i = 0;
         i < unsent;
         i++)
    {
        rte_pktmbuf_free(
            pkts[i]);

        tx_drops[port]++;
    }
}

/* ============================================================
 * INIT PORT
 * ============================================================ */

static int
init_port(uint16_t port)
{
    struct rte_eth_conf conf;

    memset(
        &conf,
        0,
        sizeof(conf));

    int ret =
        rte_eth_dev_configure(
            port,
            1,
            1,
            &conf);

    if (ret < 0)
        return ret;

    ret =
        rte_eth_rx_queue_setup(
            port,
            RX_QUEUE,
            RX_RING,
            rte_eth_dev_socket_id(port),
            NULL,
            mbuf_pool);

    if (ret < 0)
        return ret;

    ret =
        rte_eth_tx_queue_setup(
            port,
            TX_QUEUE,
            TX_RING,
            rte_eth_dev_socket_id(port),
            NULL);

    if (ret < 0)
        return ret;

    ret =
        rte_eth_dev_start(port);

    if (ret < 0)
        return ret;

    rte_eth_promiscuous_enable(port);

    tx_buffer[port] =
        rte_zmalloc_socket(
            "tx_buffer",
            RTE_ETH_TX_BUFFER_SIZE(
                TX_BUFFER_SIZE),
            0,
            rte_eth_dev_socket_id(port));

    if (!tx_buffer[port])
        return -1;

    rte_eth_tx_buffer_init(
        tx_buffer[port],
        TX_BUFFER_SIZE);

    rte_eth_tx_buffer_set_err_callback(
        tx_buffer[port],
        flush_callback,
        (void *)(uintptr_t)port);

    return 0;
}

/* ============================================================
 * FLUSH TX
 * ============================================================ */

static void
flush_tx_buffers(void)
{
    for (int port = 0;
         port < 2;
         port++)
    {
        uint16_t sent =
            rte_eth_tx_buffer_flush(
                port,
                TX_QUEUE,
                tx_buffer[port]);

        tx_packets[port] += sent;
    }
}

/* ============================================================
 * PRINT LATENCY
 * ============================================================ */

static void
print_latency(
    const char *name,
    const struct latency_stats *s)
{
    if (s->count == 0)
    {
        printf(
            "%-22s : no samples\n",
            name);

        return;
    }

    double avg =
        average_cycles(s);

    printf(
        "%-22s : "
        "avg %.3f us | "
        "min %.3f us | "
        "max %.3f us | "
        "samples %lu\n",

        name,

        cycles_to_us(
            (uint64_t)avg),

        cycles_to_us(
            s->min_cycles),

        cycles_to_us(
            s->max_cycles),

        s->count);
}

/* ============================================================
 * STATS
 * ============================================================ */

static void
print_stats(void)
{
    printf(
        "\n"
        "========================================\n"
        "DPDK STATISTICS\n"
        "========================================\n");

    printf(
        "P0 RX              : %lu\n",
        rx_packets[0]);

    printf(
        "P0 TX              : %lu\n",
        tx_packets[0]);

    printf(
        "P0 DROP            : %lu\n",
        tx_drops[0]);

    printf(
        "P1 RX              : %lu\n",
        rx_packets[1]);

    printf(
        "P1 TX              : %lu\n",
        tx_packets[1]);

    printf(
        "P1 DROP            : %lu\n",
        tx_drops[1]);

    printf(
        "IPv4 packets       : %lu\n",
        ipv4_packets);

    printf(
        "TCP packets        : %lu\n",
        tcp_packets);

    printf(
        "Modbus candidates  : %lu\n",
        modbus_candidates);

    printf(
        "Extraction success : %lu\n",
        extraction_success);

    printf(
        "Extraction failed  : %lu\n",
        extraction_failed);

    printf(
        "Feature records    : %lu\n",
        feature_records);

    printf(
        "Expected file size : %lu bytes\n",
        feature_records * 112UL);

    printf(
        "========================================\n");

    printf(
        "\n"
        "LATENCY\n"
        "========================================\n");

    printf(
        "TSC frequency      : %lu Hz\n",
        tsc_hz);

    print_latency(
        "Parsing",
        &parse_latency);

    print_latency(
        "Feature extraction",
        &extraction_latency);

    print_latency(
        "Prediction",
        &prediction_latency);

    print_latency(
        "Total processing",
        &total_latency);

    print_latency(
        "Feature file store",
        &store_latency);

    printf(
        "========================================\n");

    printf(
        "\n"
        "OUTPUT FILES\n"
        "========================================\n");

    printf(
        "Features : %s\n",
        OUTPUT_FILE);

    printf(
        "Latency  : %s\n",
        LATENCY_CSV);

    printf(
        "========================================\n");
}

/* ============================================================
 * SWITCH LOOP
 * ============================================================ */

static void
run_switch(void)
{
    struct rte_mbuf *bufs[BURST];

    uint64_t loops = 0;

    while (!force_quit)
    {
        /*
         * ----------------------------------------
         * PORT 0
         * ----------------------------------------
         */

        uint16_t n =
            rte_eth_rx_burst(
                PORT_CLIENT,
                RX_QUEUE,
                bufs,
                BURST);

        rx_packets[PORT_CLIENT] += n;

        for (uint16_t i = 0;
             i < n;
             i++)
        {
            process_packet(
                bufs[i],
                PORT_CLIENT);
        }

        /*
         * ----------------------------------------
         * PORT 1
         * ----------------------------------------
         */

        n =
            rte_eth_rx_burst(
                PORT_SERVER,
                RX_QUEUE,
                bufs,
                BURST);

        rx_packets[PORT_SERVER] += n;

        for (uint16_t i = 0;
             i < n;
             i++)
        {
            process_packet(
                bufs[i],
                PORT_SERVER);
        }

        /*
         * ----------------------------------------
         * FLUSH TX
         * ----------------------------------------
         */

        flush_tx_buffers();

        loops++;

        /*
         * Print statistics periodically.
         */

        if ((loops % 100000ULL) == 0)
        {
            print_stats();
        }

        /*
         * IMPORTANT:
         *
         * No usleep(1) here.
         *
         * A busy polling loop gives more consistent
         * DPDK latency measurements.
         */
    }

    flush_tx_buffers();
}

/* ============================================================
 * MAIN
 * ============================================================ */

int
main(
    int argc,
    char **argv)
{
    signal(
        SIGINT,
        signal_handler);

    signal(
        SIGTERM,
        signal_handler);

    /*
     * ----------------------------------------
     * DPDK EAL
     * ----------------------------------------
     */

    int ret =
        rte_eal_init(
            argc,
            argv);

    if (ret < 0)
    {
        rte_exit(
            EXIT_FAILURE,
            "EAL initialization failed\n");
    }

    /*
     * ----------------------------------------
     * TSC
     * ----------------------------------------
     */

    tsc_hz =
        rte_get_tsc_hz();

    printf(
        "\n"
        "============================================\n"
        "       DPDK MODBUS FLOAT SWITCH\n"
        "============================================\n");

    printf(
        "TSC frequency: %lu Hz\n",
        tsc_hz);

    /*
     * ----------------------------------------
     * PORT COUNT
     * ----------------------------------------
     */

    uint16_t nb_ports =
        rte_eth_dev_count_avail();

    printf(
        "DPDK ports: %u\n",
        nb_ports);

    if (nb_ports < 2)
    {
        rte_exit(
            EXIT_FAILURE,
            "Need at least 2 ports\n");
    }

    /*
     * ----------------------------------------
     * MBUF
     * ----------------------------------------
     */

    mbuf_pool =
        rte_pktmbuf_pool_create(
            "MBUF_POOL",
            NUM_MBUFS,
            MBUF_CACHE,
            0,
            RTE_MBUF_DEFAULT_BUF_SIZE,
            rte_socket_id());

    if (!mbuf_pool)
    {
        rte_exit(
            EXIT_FAILURE,
            "Cannot create mbuf pool\n");
    }

    /*
     * ----------------------------------------
     * PORT 0
     * ----------------------------------------
     */

    if (init_port(PORT_CLIENT) < 0)
    {
        rte_exit(
            EXIT_FAILURE,
            "Cannot initialize port 0\n");
    }

    /*
     * ----------------------------------------
     * PORT 1
     * ----------------------------------------
     */

    if (init_port(PORT_SERVER) < 0)
    {
        rte_exit(
            EXIT_FAILURE,
            "Cannot initialize port 1\n");
    }

    /*
     * ----------------------------------------
     * CLEAN FEATURE FILE
     * ----------------------------------------
     */

    FILE *fp =
        fopen(
            OUTPUT_FILE,
            "wb");

    if (!fp)
    {
        rte_exit(
            EXIT_FAILURE,
            "Cannot create feature file\n");
    }

    fclose(fp);

    /*
     * ----------------------------------------
     * LATENCY CSV
     * ----------------------------------------
     */

    if (init_latency_csv() < 0)
    {
        rte_exit(
            EXIT_FAILURE,
            "Cannot create latency CSV\n");
    }

    /*
     * ----------------------------------------
     * READY
     * ----------------------------------------
     */

    printf(
        "\n"
        "============================================\n"
        "SWITCH READY\n"
        "============================================\n");

    printf(
        "Modbus TCP port : %d\n",
        MODBUS_PORT);

    printf(
        "Registers       : %d\n",
        REGISTERS);

    printf(
        "Features        : %d\n",
        FLOATS);

    printf(
        "Register bytes  : %d\n",
        REGISTERS * 2);

    printf(
        "Feature bytes   : %d\n",
        FEATURE_BYTES);

    printf(
        "Record size     : %d\n",
        4 + FEATURE_BYTES);

    printf(
        "Output file     : %s\n",
        OUTPUT_FILE);

    printf(
        "Latency CSV     : %s\n",
        LATENCY_CSV);

    printf(
        "Debug           : %s\n",
#if DEBUG
        "ON"
#else
        "OFF"
#endif
    );

    printf(
        "============================================\n\n");

    /*
     * ----------------------------------------
     * RUN
     * ----------------------------------------
     */

    run_switch();

    /*
     * ----------------------------------------
     * FINAL STATS
     * ----------------------------------------
     */

    print_stats();

    /*
     * ----------------------------------------
     * CLOSE FILES
     * ----------------------------------------
     */

    close_latency_csv();

    /*
     * ----------------------------------------
     * STOP PORTS
     * ----------------------------------------
     */

    rte_eth_dev_stop(
        PORT_CLIENT);

    rte_eth_dev_stop(
        PORT_SERVER);

    rte_eth_dev_close(
        PORT_CLIENT);

    rte_eth_dev_close(
        PORT_SERVER);

    return 0;
}
