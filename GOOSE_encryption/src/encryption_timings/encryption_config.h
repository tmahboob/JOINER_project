#ifndef ENCRYPTION_CONFIG_H
#define ENCRYPTION_CONFIG_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "encryption.h"
#include "decryption.h"
#include "latency.h"

#define STNUM_OFFSET 190
#define SQNUM_OFFSET 193
#define ALLDATA_LENGTH 12 // (in bytes)

struct timestamp_header {
    struct timespec ts;
};

// prototype for encrypt and decrypy, defined in encryption.h and ddecryption.h
typedef int (*encrypt_func)(const uint8_t *plaintext, int plaintext_len,
                   const uint8_t *key, const uint8_t *nonce,
                   uint8_t *ciphertext);
typedef int (*decrypt_func)(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *iv,
    uint8_t *plaintext);

typedef enum { //encryption mode enum, to define which fields to encrypt
    MODE_FULL,
    MODE_FIELDS,
    MODE_FIELDS_CONS,
    MODE_ALLDATA,
    MODE_NONE
} encryption_mode_t;

typedef struct { //struct to hold this enum and appropriate functions etc
    const char *name;
    encrypt_func enc;
    decrypt_func dec;
    encryption_mode_t mode;
} encryption_config_t;

static encryption_config_t encrypt_configs[] = { //list is encryption configs, with names and associated algs

    {"aes_128", aes_ctr_encrypt, aes_ctr_decrypt},
    {"aes_192", aes_ctr_encrypt_192, aes_ctr_decrypt_192},
    {"aes_256", aes_ctr_encrypt_256, aes_ctr_decrypt_256},

    //{"chacha", chacha_encrypt, chacha_decrypt},
    //{"aria", aria_encrypt, aria_decrypt},
    //{"camellia", camellia_encrypt, camellia_decrypt},
    {"sm4", sm4_encrypt_128, sm4_decrypt_128},
    {"salsa", salsa20_encrypt, salsa20_decrypt},
    {"chacha", chacha_encrypt_ls, chacha_decrypt_ls},

    {"zuc_128", zuc_128_encrypt, zuc_128_decrypt},
    {"zuc_256", zuc_256_encrypt, zuc_256_decrypt}
    //{"ascon", 16, ascon_encrypt, ascon_decrypt}
};

static const int num_encrypt_configs = sizeof(encrypt_configs) / sizeof(encrypt_configs[0]);

//function to get chosen configs from command line args
static encryption_config_t *get_chosen_config(int argc, char *argv[]){
    encryption_config_t *chosen_config = NULL;
    if (argc > 1){
        for(int i = 0; i < num_encrypt_configs; i++){
            if (strcmp(argv[1], encrypt_configs[i].name) == 0){
                chosen_config = &encrypt_configs[i];
                break;
            }
        }
        if (!chosen_config){
            fprintf(stderr, "invalid option use the following");
            for (int i = 0; i < num_encrypt_configs; i++)
                fprintf(stderr, "%s", encrypt_configs[i].name);
            fprintf(stderr, "\n");
            exit(EXIT_FAILURE);
        }
        printf("using algorithm; %s\n", chosen_config->name);
    } else {
        printf("no alg specified, using chacha as default\n");
        chosen_config = &encrypt_configs[0];
    }
    if (argc > 2) {
        if (strcmp(argv[2], "full") == 0) {
            chosen_config->mode = MODE_FULL;
            printf("Mode set to FULL\n");
        } else if (strcmp(argv[2], "fields") == 0) {
            chosen_config->mode = MODE_FIELDS;
            printf("Mode set to FIELDS\n");
        } else if (strcmp(argv[2], "fields_cons") == 0) {
            chosen_config->mode = MODE_FIELDS_CONS;
            printf("Mode set to FIELDS_COMB\n");
        } else if (strcmp(argv[2], "alldata") == 0) {
            chosen_config->mode = MODE_ALLDATA;
            printf("Mode set to ALLDATA\n");
        } else if (strcmp(argv[2], "none") == 0) {
            chosen_config->mode = MODE_NONE;
            printf("Mode set to NONE\n");
        } else {
            fprintf(stderr, "Invalid mode: %s\n", argv[2]);
            exit(EXIT_FAILURE);
        }
    } else {
            chosen_config->mode = MODE_FULL;
    }
    return chosen_config;
}

const char* mode_to_string(encryption_mode_t mode) {
    switch(mode) {
        case MODE_FULL:
            return "full";
        case MODE_FIELDS:
            return "fields";
        case MODE_FIELDS_CONS:
            return "fields_cons";
        case MODE_ALLDATA:
            return "alldata";
        case MODE_NONE:
            return "none";
        default:
            return "unknown";
    }
}

// function to extract stNum and sqNum from packets, in this instance hardcoded
int extract_st_sq(const uint8_t *payload, int payload_len, uint8_t *stNum_ex, uint8_t *sqNum_ex) {
    *stNum_ex = payload[STNUM_OFFSET - 14];
    *sqNum_ex = payload[SQNUM_OFFSET - 14];
    return 0;
};
//function to replace stNum and sqNum
int replace_st_sq(uint8_t *payload, int payload_len, uint8_t stNum_r, uint8_t sqNum_r) {
    payload[STNUM_OFFSET - 14] = stNum_r;
    payload[SQNUM_OFFSET -14 ] = sqNum_r;
    return 0;
};

int encrypt_payload(encryption_mode_t mode,const uint8_t *payload, int payload_len,
    const uint8_t key[32], const uint8_t nonce[16],encryption_config_t *config, uint8_t **encrypted_out) {
    if (!payload || payload_len <= 0 || !encrypted_out) return -1;

    uint8_t *output = malloc(payload_len);
    if (!output)return -1;

    int ciphertext_len = 0;
    long start_time = get_time_ns();
    long elapsed = 0;

    switch (mode) {
        case MODE_FULL:
        { // encrypt full payload
            ciphertext_len = config->enc(payload, payload_len, key, nonce, output);
            if (ciphertext_len < 0) {
                free(output);
                return -1;
            }
            break;
        }
        case MODE_FIELDS:
        {  //extract the st and sqNum and encrpt as two bytes combined
            memcpy(output, payload, payload_len);
            uint8_t st_val = 0, sq_val = 0;
            if (extract_st_sq(payload, payload_len, &st_val, &sq_val) < 0) {
                fprintf(stderr, "extraction of st and sq failed\n");
                free(output);
                return -1;
            }

            // combine the two single bytes values into a single two-byte variable
            uint16_t combined = ((uint16_t)st_val << 8) | sq_val;
            uint16_t combined_cipher;

            // encrypt the combined value.
            if (config->enc((uint8_t *)&combined, sizeof(combined), key, nonce, (uint8_t *)&combined_cipher) < 0) {
                free(output);
                return -1;
            }

            // split the encrypted store back into its field
            uint8_t st_cipher = (combined_cipher >> 8) & 0xFF;
            uint8_t sq_cipher = combined_cipher & 0xFF;

            if (replace_st_sq(output, payload_len, st_cipher, sq_cipher) < 0) {
                free(output);
                return -1;
            }
            ciphertext_len = payload_len;
            break;

        }
        case MODE_FIELDS_CONS:
        {  //encyrpt 4 bytes consecutively rather than extracting them
            memcpy(output, payload, payload_len);
            if (payload_len < STNUM_OFFSET  + 3) {
                fprintf(stderr, "Payload too short for MODE_FIELDS_CONS encryption\n");
                free(output);
                return -1;
            }
            ciphertext_len = config->enc(payload + (STNUM_OFFSET  - 14), 4, key, nonce, output + (STNUM_OFFSET - 14));
            if (ciphertext_len != 4) {
                fprintf(stderr, "Encryption of consecutive fields failed, incorrect ciphertext length\n");
                free(output);
                return -1;
            }
            ciphertext_len = payload_len;
            break;
        }
        case MODE_ALLDATA:
        {  //encrypt last 12 bytes
            if (payload_len < ALLDATA_LENGTH) {
                fprintf(stderr, "Payload too short for ALLDATA encryption\n");
                free(output);
                return -1;
            }
            memcpy(output, payload, payload_len - ALLDATA_LENGTH);
            ciphertext_len = config->enc(payload + payload_len - ALLDATA_LENGTH, ALLDATA_LENGTH,
                              key, nonce, output + payload_len - ALLDATA_LENGTH);
            if (ciphertext_len != ALLDATA_LENGTH) {
                fprintf(stderr, "Encryption for ALLDATA failed, unexpected ciphertext length\n");
                free(output);
                return -1;
            }
            ciphertext_len = payload_len;
            break;
        }
        case MODE_NONE:
        {
            memcpy(output, payload, payload_len);
            ciphertext_len = payload_len;
            break;
        }
    }
    *encrypted_out = output;
    return ciphertext_len;
}


int decrypt_payload(encryption_mode_t mode, const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t key[32], const uint8_t nonce[16], encryption_config_t *config,
    uint8_t **plaintext_out){
    if (!ciphertext || ciphertext_len <= 0 || !plaintext_out) return -1;

    uint8_t *output = malloc(ciphertext_len);
    if (!output) return -1;

    int plaintext_len = 0;
    long start_time = get_time_ns();
    long elapsed = 0;

    switch (mode) {
    case MODE_FULL:
        {
            plaintext_len = config->dec(ciphertext, ciphertext_len, key, nonce, output);
            if (plaintext_len < 0) {
                free(output);
                return -1;
            }
            break;
        }
        case MODE_FIELDS:
        {  //extract st and sq num and encryt as a two byte store
            memcpy(output, ciphertext, ciphertext_len);
            uint8_t st_enc = 0, sq_enc = 0;
            if (extract_st_sq(ciphertext, ciphertext_len, &st_enc, &sq_enc) < 0) {
                fprintf(stderr, "Extraction of encrypted st and sq failed\n");
                free(output);
                return -1;
            }

            // combine the two encrypted bytes into a single 16-bit variable
            uint16_t combined_cipher = ((uint16_t)st_enc << 8) | sq_enc;
            uint16_t combined_plain;

            // decrypt the two byte combined block
            if (config->dec((uint8_t *)&combined_cipher, sizeof(combined_cipher), key, nonce, (uint8_t *)&combined_plain) < 0) {
                free(output);
                return -1;
            }

            // split back into fields
            uint8_t st_dec = (combined_plain >> 8) & 0xFF;
            uint8_t sq_dec = combined_plain & 0xFF;

            if (replace_st_sq(output, ciphertext_len, st_dec, sq_dec) < 0) {
                free(output);
                return -1;
            }
            plaintext_len = ciphertext_len;
            break;
        }
        case MODE_FIELDS_CONS:
        {  //instead of extracting decrypt 4 consecurive bytes
            memcpy(output, ciphertext, ciphertext_len);
            if (ciphertext_len < (STNUM_OFFSET - 14) + 4) {
                fprintf(stderr, "Ciphertext too short for MODE_FIELDS_CONS decryption\n");
                free(output);
                return -1;
            }

            int fields_pt_len = config->dec(ciphertext + (STNUM_OFFSET - 14), 4, key, nonce, output + (STNUM_OFFSET - 14));
            if (fields_pt_len != 4) {
                fprintf(stderr, "Decryption of consecutive fields failed, incorrect plaintext length\n");
                free(output);
                return -1;
            }
            plaintext_len = ciphertext_len;
            break;
        }
        case MODE_ALLDATA:
        { //decrypt last 12 bytes
            if (ciphertext_len < ALLDATA_LENGTH) {
                fprintf(stderr, "Ciphertext too short for ALLDATA decryption\n");
                free(output);
                return -1;
            }
            memcpy(output, ciphertext, ciphertext_len - ALLDATA_LENGTH);
            int alldata_pt_len = config->dec(ciphertext + ciphertext_len - ALLDATA_LENGTH, ALLDATA_LENGTH,
                              key, nonce, output + ciphertext_len - ALLDATA_LENGTH);
            if (alldata_pt_len != ALLDATA_LENGTH) {
                fprintf(stderr, "Decryption for ALLDATA failed, unexpected plaintext length\n");
                free(output);
                return -1;
            }
            plaintext_len = ciphertext_len;
            break;
        }
        case MODE_NONE:
        {
            memcpy(output, ciphertext, ciphertext_len);
            plaintext_len = ciphertext_len;
            break;
        }
    }

    *plaintext_out = output;
    return plaintext_len;
}

uint8_t *build_encrypted_packet(const uint8_t *packet, int packet_len, int header_len,
                                int *new_len, encryption_config_t *cfg) {

    struct timestamp_header ts_hdr;
    clock_gettime(CLOCK_MONOTONIC, &ts_hdr.ts);


    unsigned char test_nonce[16]; // generate 16 byte nonce to get latency measurment
    if (RAND_bytes(test_nonce, sizeof(test_nonce)) != 1) {
        fprintf(stderr, "CSPRNG generation failed\n");
        return NULL;
    }
    //use static key for demo, use timestamp as unique nonce also
    uint8_t key[32] = {0x01};
    uint8_t nonce[16];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, &ts_hdr, sizeof(ts_hdr));

    int payload_len = packet_len - header_len;
    if (payload_len <= 0) {
        fprintf(stderr, "Invalid payload length: %d\n", payload_len);
        return NULL;
    }
    const uint8_t *payload = packet + header_len; //pointer to actual payload

    uint8_t *encrypted_payload = NULL;
    int ct_len = encrypt_payload(cfg->mode, payload, payload_len, key, nonce, cfg, &encrypted_payload);
    if (ct_len < 0) {
        fprintf(stderr, "Encryption failed\n");
        return NULL;
    }

    *new_len = header_len + sizeof(ts_hdr) + ct_len;
    uint8_t *new_packet = malloc(*new_len);
    if (!new_packet) {
        fprintf(stderr, "Memory allocation failed for new_packet\n");
        free(encrypted_payload);
        return NULL;
    }

    //rebuild packet [header|timestamp|payload]
    int offset = 0;
    memcpy(new_packet, packet, header_len);
    offset += header_len;
    memcpy(new_packet + offset, &ts_hdr, sizeof(ts_hdr));
    offset += sizeof(ts_hdr);
    memcpy(new_packet + offset, encrypted_payload, ct_len);
    free(encrypted_payload);

    return new_packet;
}

uint8_t *build_decrypted_packet(const uint8_t *packet, int packet_len, int header_len,
                                int *new_len, encryption_config_t *cfg,
                                struct timestamp_header *extracted_ts_hdr) {
    // extract timestamp/nonce
    memcpy(extracted_ts_hdr, packet + header_len, sizeof(*extracted_ts_hdr));

    uint8_t key[32] = {0x01}; // use static key for this demo
    uint8_t nonce[16];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, extracted_ts_hdr, sizeof(*extracted_ts_hdr)); //use timestamp as nonce

    int header_offset = header_len + sizeof(*extracted_ts_hdr);
    if (packet_len < header_offset) {
        fprintf(stderr, "Packet too short for header offset\n");
        return NULL;
    }
    int ciphertext_len = packet_len - header_offset;
    const uint8_t *ciphertext = packet + header_offset; //get pointer to actual payload

    uint8_t *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        fprintf(stderr, "Error allocating mem for plaintext\n");
        return NULL;
    }

    int dec_len = decrypt_payload(cfg->mode, ciphertext, ciphertext_len, //decrypt payload
                                  key, nonce, cfg, &plaintext);
    if (dec_len < 0) {
        fprintf(stderr, "Decryption failed\n");
        free(plaintext);
        return NULL;
    }

    *new_len = header_len + dec_len; //build new packet [eth header | payload]
    uint8_t *new_packet = malloc(*new_len);
    if (!new_packet) {
        fprintf(stderr, "Error allocating mem for packet forwarding\n");
        free(plaintext);
        return NULL;
    }
    memcpy(new_packet, packet, header_len);
    memcpy(new_packet + header_len, plaintext, dec_len);
    free(plaintext);
    return new_packet;
}

//exact same as above just keeps timestamp formatted inside the packet
uint8_t *build_decrypted_packet_with_timestamp(const uint8_t *packet, int packet_len, int header_len,
                                                 int *new_len, encryption_config_t *cfg) {
    // extract the timestamp
    struct timestamp_header ts_hdr;
    memcpy(&ts_hdr, packet + header_len, sizeof(ts_hdr));

    uint8_t key[32] = {0x01};  // use static key for this demo
    uint8_t nonce[16];
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, &ts_hdr, sizeof(ts_hdr));  // use timestamp as nonce

    int header_offset = header_len + sizeof(ts_hdr);
    if (packet_len < header_offset) {
        fprintf(stderr, "packet too short for decrypting\n");
        return NULL;
    }
    int ciphertext_len = packet_len - header_offset;
    const uint8_t *ciphertext = packet + header_offset;

    // allocate memory for decrypted payload
    uint8_t *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        fprintf(stderr, "Error allocating mem for plaintext\n");
        return NULL;
    }

    int dec_len = decrypt_payload(cfg->mode, ciphertext, ciphertext_len,
                                  key, nonce, cfg, &plaintext);
    if (dec_len < 0) {
        fprintf(stderr, "Decryption failed\n");
        free(plaintext);
        return NULL;
    }

    // [Ethernet header | timestamp header | decrypted payload]
    *new_len = header_len + sizeof(ts_hdr) + dec_len;
    uint8_t *new_packet = malloc(*new_len);
    if (!new_packet) {
        fprintf(stderr, "Error allocating memory for packet forwarding\n");
        free(plaintext);
        return NULL;
    }

    memcpy(new_packet, packet, header_len);
    memcpy(new_packet + header_len, &ts_hdr, sizeof(ts_hdr));
    memcpy(new_packet + header_len + sizeof(ts_hdr), plaintext, dec_len);

    free(plaintext);
    return new_packet;
}

#endif