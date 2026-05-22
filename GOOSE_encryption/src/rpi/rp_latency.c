#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "../encryption_timings/encryption_config.h"
#define ETHERNET_HEADER_LEN 14

int packet_count = 0;
encryption_config_t *conf;
const char *TRANSMISSION_LATENCY_LOG = "../src/data/rp_data/transmission_latency_log.csv";
FILE *transmission_latency_file;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    uint16_t ethertype = ntohs(*(uint16_t *)(packet + 12));
    if (ethertype != 0x88b8) {
        return;
    }
    packet_count ++;
    // Verify the packet is long enough
    if (header->len < ETHERNET_HEADER_LEN + 16) {
        fprintf(stderr, "Packet too short.\n");
        return;
    }

    // Extract the timestamp header from the packet
    struct timestamp_header ts_hdr;
    memcpy(&ts_hdr, packet + ETHERNET_HEADER_LEN, sizeof(ts_hdr));

    // Get the current time.
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    // Calculate latency in nanoseconds.
    long delta_sec = now.tv_sec - ts_hdr.ts.tv_sec;
    long delta_nsec = now.tv_nsec - ts_hdr.ts.tv_nsec;
    long total_nsec = delta_sec * 1000000000L + delta_nsec;
    double latency_ms = total_nsec / 1e6;

    if (packet_count > 10 && transmission_latency_file != NULL) {

        if(conf->mode == MODE_NONE){
            fprintf(transmission_latency_file, "%s, %s, %.3f\n", mode_to_string(conf->mode), mode_to_string(conf->mode), latency_ms);
        } else {
            fprintf(transmission_latency_file, "%s, %s, %.3f\n", conf->name, mode_to_string(conf->mode), latency_ms);
            fflush(transmission_latency_file);
        }
    }

    printf("Received GOOSE packet: latency = %.4f ms\n", latency_ms);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <algorithm> <mode>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *iface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    transmission_latency_file = fopen(TRANSMISSION_LATENCY_LOG, "a");
    if (!transmission_latency_file) {
        perror("failed to open latency file");
        exit(EXIT_FAILURE);
    }

    conf = get_chosen_config(argc - 1, argv + 1);

    //pcap setup ...
    pcap_t *handle = pcap_create(iface, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    if (pcap_set_buffer_size(handle, 2 * 1024 * 1024) != 0) {
        fprintf(stderr, "Error setting buffer size: %s\n", pcap_geterr(handle));
    }

    if (pcap_set_immediate_mode(handle, 1) != 0) {
        fprintf(stderr, "Error setting immediate mode: %s\n", pcap_geterr(handle));
    }

    if (pcap_set_timeout(handle, 1000) != 0) {
        fprintf(stderr, "Error setting timeout: %s\n", pcap_geterr(handle));
    }

    if (pcap_setdirection(handle, PCAP_D_IN) != 0) {
        fprintf(stderr, "Error setting capture direction: %s\n", pcap_geterr(handle));
    }

    if (pcap_activate(handle) < 0) {
        fprintf(stderr, "Error activating capture handle: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("Listening for incoming GOOSE packets on %s...\n", iface);
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return EXIT_SUCCESS;
}
