#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "../encryption_timings/encryption.h"
#include "../encryption_timings/encryption_config.h"
#include "../encryption_timings/latency.h"

#define ETHER_TYPE_CUSTOM 0x88b8
#define ETHERNET_HEADER_LEN 14

encryption_config_t *chosen_config = NULL;
FILE *encryption_latency_file = NULL;  //record encryption time
FILE *decryption_latency_file = NULL;  //decryption time
unsigned long packet_count = 0;

typedef struct { //struct to store packets for reading in
    struct pcap_pkthdr header;
    u_char *data;
} packet_record_t;

typedef struct { //struct to store context for creating raw sockets
    int sockfd;
    struct sockaddr_ll socket_address;
} raw_ctx_t;

int init_raw_socket(const char *if_name, const uint8_t *dest_mac, struct sockaddr_ll *socket_address) {
    // create raw socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETHER_TYPE_CUSTOM));
    if (sockfd < 0) {
         perror("socket");
         return -1;
    }

    // get the interface index foe local network
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(if_idx));
    strncpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
         perror("SIOCGIFINDEX");
         close(sockfd);
         return -1;
    }

    // sets the address for the remote device
    memset(socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address->sll_ifindex = if_idx.ifr_ifindex;
    socket_address->sll_halen = ETH_ALEN;
    memcpy(socket_address->sll_addr, dest_mac, ETH_ALEN);
    return sockfd;
}


pcap_t* setup_pcap_handle(const char *iface, char *errbuf) {
    pcap_t *handle = pcap_create(iface, errbuf);
    if (!handle) return NULL;

    pcap_set_buffer_size(handle, 2 * 1024 * 1024);
    pcap_set_immediate_mode(handle, 1);
    pcap_set_timeout(handle, 1000);
    pcap_setdirection(handle, PCAP_D_IN);

    if (pcap_activate(handle) < 0) {
        pcap_close(handle);
        return NULL;
    }

    return handle;
}

// sends packets from pcap file to chosen interface, under given algorithm and mode as required
int send_pcap_encrypted(const char *filename, const char *if_name, const unsigned char *dest_mac,
              encryption_config_t *chosen_config, int packet_limit) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_offline(filename, errbuf);
    if (!pcap_handle) {
         fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
         return -1;
    }

    // load all packets from the file.
    packet_record_t *packets = NULL;
    int num_packets = 0;
    const u_char *packet;
    struct pcap_pkthdr *header;
    int next_pkt;   //loop over packets and stores them in array of packet structs
    while ((next_pkt = pcap_next_ex(pcap_handle, &header, &packet)) >= 0) {
        if (next_pkt == 0) continue;
        packets = realloc(packets, (num_packets + 1) * sizeof(packet_record_t)); //adjust array size
        if (!packets) {
            perror("realloc");
            pcap_close(pcap_handle);
            return -1;
        }
        packets[num_packets].header = *header; // allocate data into struct
        packets[num_packets].data = malloc(header->len);
        if (!packets[num_packets].data) {
            perror("malloc");
            pcap_close(pcap_handle);
            return -1;
        }
        memcpy(packets[num_packets].data, packet, header->len);
        num_packets++;
    }
    pcap_close(pcap_handle); //close after reading in packets
    if (num_packets == 0) {
        fprintf(stderr, "No packets loaded from file.\n");
        return -1;
    }
    //printf("loaded %d packets\n", num_packets);

    // create a raw socket using appropriate local interface and destination mac
    struct sockaddr_ll socket_address;
    int sockfd = init_raw_socket(if_name, dest_mac, &socket_address);
    if (sockfd < 0) {
        return -1;
    }

    // send packets
    int seq = 0;
    for (int i = 0; i < packet_limit; i++) {
        int idx = i % num_packets;  // ensure there are packets to send after  reaching end of file
        packet_record_t *pr = &packets[idx];
        int new_packet_len = 0;
        long start_time, elapsed;
        start_time = get_time_ns();
        //encrypt packet using chosen config (alg and mode)
        uint8_t *new_packet = build_encrypted_packet(pr->data, pr->header.len, ETHERNET_HEADER_LEN,
                                                        &new_packet_len, chosen_config);
        if (!new_packet) {
            fprintf(stderr, "Failed to encrypt packet %d\n", seq);
            continue;
        }
        elapsed = get_time_ns() - start_time;
        if (sendto(sockfd, new_packet, new_packet_len, 0,
                   (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
            perror("sendto");
            free(new_packet);
            break;
        }
        //log_latency_ns("Packet encrypted", elapsed);
        printf("Sent encrypted packet seq %d, original length %d, new length %d\n", seq, pr->header.len, new_packet_len);
        seq++;
        free(new_packet);
        if (seq > 10 && encryption_latency_file != NULL) { //print 'alg, mode, latency' to file (exclude first 10 packets)
            const char *alg_str = (chosen_config->mode == MODE_NONE) ? mode_to_string(chosen_config->mode) : chosen_config->name;
            fprintf(encryption_latency_file, "%s, %s, %ld\n", alg_str, mode_to_string(chosen_config->mode), elapsed);
            fflush(encryption_latency_file);
        }
    }

    // free all loaded packets.
    for (int i = 0; i < num_packets; i++) {
        free(packets[i].data);
    }
    free(packets);
    close(sockfd);
    return 0;
}

// decrypts incoming packets
void packet_handler_decrypt(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    raw_ctx_t *ctx = (raw_ctx_t *)user;
    long start_time = get_time_ns();
    packet_count++;

    // to extract the timestamp header.
    struct timestamp_header ts_hdr;
    int new_len = 0;

    uint8_t *decrypted_packet = build_decrypted_packet_with_timestamp(packet, header->len, ETHERNET_HEADER_LEN,
                                                        &new_len, chosen_config);
    if (!decrypted_packet)return;

    long elapsed = get_time_ns() - start_time;

    if (packet_count > 0 && decryption_latency_file != NULL){ //
        const char *alg_str = (chosen_config->mode == MODE_NONE) ? mode_to_string(chosen_config->mode) : chosen_config->name;
        fprintf(decryption_latency_file, "%s, %s, %ld\n", alg_str, mode_to_string(chosen_config->mode), elapsed);
        fflush(decryption_latency_file);
    }

    // send the decrypted packet using the pre-created raw socket.
    if (sendto(ctx->sockfd, decrypted_packet, new_len, 0,
               (struct sockaddr *)&(ctx->socket_address), sizeof(ctx->socket_address)) < 0) {
        perror("sendto");
    }
    free(decrypted_packet);
}

// sets up a pcap handle on the specified interface and starts the capture loop
int receive_pcap(const char *recv_if, const char *send_if, const uint8_t *dest_mac) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_create(recv_if, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_create failed: %s\n", errbuf);
        return -1;
    }
    if (pcap_set_buffer_size(handle, 2*1024*1024) != 0) {
        fprintf(stderr, "Error setting buffer size: %s\n", pcap_geterr(handle));
    }
    if (pcap_set_immediate_mode(handle, 1) != 0) {
        fprintf(stderr, "Error setting immediate mode: %s\n", pcap_geterr(handle));
    }
    if (pcap_set_timeout(handle, 10) != 0) {
        fprintf(stderr, "Error setting capture timeout: %s\n", pcap_geterr(handle));
    }
    if (pcap_activate(handle) < 0) {
        fprintf(stderr, "Error activating capture handle: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    if (pcap_setdirection(handle, PCAP_D_IN) < 0) {
        fprintf(stderr, "Error setting capture direction: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }

    // Initialize the raw socket context using the sending interface and dest_mac.
    raw_ctx_t ctx;
    ctx.sockfd = init_raw_socket(send_if, dest_mac, &ctx.socket_address);
    if (ctx.sockfd < 0) {
        pcap_close(handle);
        return -1;
    }

    if(pcap_loop(handle, 0, packet_handler_decrypt, (u_char *)&ctx) < 0){
        fprintf(stderr, "Error in capture loop: %s\n", pcap_geterr(handle));
    }

    if (decryption_latency_file) {
        fclose(decryption_latency_file);
    }
    pcap_close(handle);
    close(ctx.sockfd);
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
       printf("Usage:\n");
       printf("  Sender:   %s send <pcap_file> <interface> <dest_mac> <algorithm> <mode> [packet_limit]\n", argv[0]);
       printf("  Receiver: %s recv <recv_interface> <send_interface> <dest_mac> <algorithm> <mode>\n", argv[0]);
       return 1;
    }

    encryption_config_t *conf = NULL;

    if (strcmp(argv[1], "send") == 0) { // Sender mode.
       if (argc < 7 || argc > 8) {
          printf("Usage: %s send <pcap_file> <interface> <dest_mac> <algorithm> <mode> [packet_limit]\n", argv[0]);
          return 1;
       }
       char *config_argv[3];
       config_argv[0] = argv[0];
       config_argv[1] = argv[5];  // algorithm
       config_argv[2] = argv[6];  // mode
       conf = get_chosen_config(3, config_argv);
        // Open latency log files.
        encryption_latency_file = fopen("../src/data/rp_data/encryption_latency_log.csv", "a");
        if (!encryption_latency_file) {
            perror("failed to open encryption latency file");
            return 1;
        }
    } else if (strcmp(argv[1], "recv") == 0) { // Receiver mode.
       printf("reaches here!------");
       // expect 6 arguments: recv_interface, send_interface, dest_mac, algorithm, mode.
       if (argc != 7) {
          printf("Usage: %s recv <recv_interface> <send_interface> <dest_mac> <algorithm> <mode>\n", argv[0]);
          return 1;
       }
       char *config_argv[3];
       config_argv[0] = argv[0];
       config_argv[1] = argv[5];  // algorithm
       config_argv[2] = argv[6];  // mode
       conf = get_chosen_config(3, config_argv);
       decryption_latency_file = fopen("../src/data/rp_data/decryption_latency_log.csv", "a");
        if (!decryption_latency_file) {
            perror("failed to open decryption latency file");
            return 1;
        }
    } else {
       fprintf(stderr, "Unknown command: %s\n", argv[1]);
       return 1;
    }

    chosen_config = conf;

    if (strcmp(argv[1], "send") == 0) {
       unsigned char dest_mac[6]; // parse MAC address for sending.
       if (sscanf(argv[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dest_mac[0], &dest_mac[1], &dest_mac[2], &dest_mac[3], &dest_mac[4], &dest_mac[5]) != 6) {
           fprintf(stderr, "Invalid MAC format\n");
           return 1;
       }
       int packet_limit = 100; // default packet limit.
       if (argc == 8) {
           packet_limit = atoi(argv[7]);
       }
       return send_pcap_encrypted(argv[2], argv[3], dest_mac, chosen_config, packet_limit);

    } else if (strcmp(argv[1], "recv") == 0) {

       unsigned char dest_mac[6];
       if (sscanf(argv[4], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dest_mac[0], &dest_mac[1], &dest_mac[2], &dest_mac[3], &dest_mac[4], &dest_mac[5]) != 6) {
           fprintf(stderr, "Invalid MAC format\n");
           return 1;
       }
       return receive_pcap(argv[2], argv[3], dest_mac);
    }
    return 0;
}


