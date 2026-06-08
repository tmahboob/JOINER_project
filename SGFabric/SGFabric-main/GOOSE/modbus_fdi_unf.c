//
// Created by tm120a on 08/06/2026.
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_malloc.h>

#define BURST 32
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define TIME_STEPS 10
#define FEATURES 27
#define MODBUS_PORT 1505

struct rte_mempool *mbuf_pool;
struct rte_ring *to_python;
struct rte_ring *from_python;

struct modbus_batch {
    float data[TIME_STEPS][FEATURES];
};

static uint16_t ports[RTE_MAX_ETHPORTS];
static uint16_t nb_ports;

/* =========================
   MODBUS CHECK
========================= */
static inline int is_modbus(uint8_t *pkt) {
    uint16_t ethertype = (pkt[12] << 8) | pkt[13];

    if (ethertype == 0x8100)
        ethertype = (pkt[16] << 8) | pkt[17];

    uint16_t ip_proto = pkt[23];
    uint16_t dport = (pkt[36] << 8) | pkt[37];
    uint16_t sport = (pkt[34] << 8) | pkt[35];

    return (ip_proto == 6 && (dport == MODBUS_PORT || sport == MODBUS_PORT));
}

/* =========================
   PARSE FLOATS
========================= */
static void parse_payload(uint8_t *payload, float *out) {
    int offset = 13;

    for (int i = 0; i < FEATURES; i++) {
        float val;
        memcpy(&val, payload + offset + i * 4, 4);
        out[i] = val;
    }
}

/* =========================
   BUILD BATCH
========================= */
static struct modbus_batch batch;
static int batch_count = 0;

/* =========================
   SEND TO PYTHON
========================= */
static void send_to_python() {
    struct modbus_batch *b = rte_malloc(NULL, sizeof(batch), 0);
    memcpy(b, &batch, sizeof(batch));

    rte_ring_enqueue(to_python, b);
}

/* =========================
   RECEIVE FROM PYTHON
========================= */
static int get_decision() {
    int *decision;

    if (rte_ring_dequeue(from_python, (void **)&decision) < 0)
        return 0; // default forward

    int d = *decision;
    rte_free(decision);
    return d;
}

/* =========================
   FORWARD PACKET
========================= */
static void forward(struct rte_mbuf *m, uint16_t port) {
    uint16_t out = (port == ports[0]) ? ports[1] : ports[0];

    rte_eth_tx_burst(out, 0, &m, 1);
}

/* =========================
   MAIN LOOP
========================= */
static void loop() {
    struct rte_mbuf *bufs[BURST];

    while (1) {
        for (int p = 0; p < nb_ports; p++) {

            uint16_t port = ports[p];

            uint16_t n = rte_eth_rx_burst(port, 0, bufs, BURST);

            for (int i = 0; i < n; i++) {

                uint8_t *pkt = rte_pktmbuf_mtod(bufs[i], uint8_t *);

                if (!is_modbus(pkt)) {
                    forward(bufs[i], port);
                    continue;
                }

                float features[FEATURES];
                parse_payload(pkt, features);

                memcpy(batch.data[batch_count], features, sizeof(features));
                batch_count++;

                if (batch_count == TIME_STEPS) {

                    send_to_python();
                    batch_count = 0;

                    int decision = get_decision();

                    if (decision == 0) {
                        forward(bufs[i], port);
                    } else {
                        rte_pktmbuf_free(bufs[i]); // DROP
                        printf("[DROP] anomaly detected\n");
                    }

                } else {
                    forward(bufs[i], port);
                }
            }
        }
    }
}

/* =========================
   INIT PORT
========================= */
static void init_port(uint16_t port) {
    struct rte_eth_conf conf = {0};

    rte_eth_dev_configure(port, 1, 1, &conf);

    rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
        rte_eth_dev_socket_id(port),
        NULL, mbuf_pool);

    rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
        rte_eth_dev_socket_id(port),
        NULL);

    rte_eth_dev_start(port);
}

/* =========================
   MAIN
========================= */
int main(int argc, char **argv) {

    rte_eal_init(argc, argv);

    nb_ports = rte_eth_dev_count_avail();

    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL",
        8192 * nb_ports,
        256,
        0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id()
    );

    /* rings between C <-> Python */
    to_python = rte_ring_create("to_py", 1024, rte_socket_id(), 0);
    from_python = rte_ring_create("from_py", 1024, rte_socket_id(), 0);

    for (int i = 0; i < nb_ports; i++) {
        ports[i] = i;
        init_port(i);
    }

    printf("DPDK Modbus IDS started\n");

    loop();

    return 0;
}