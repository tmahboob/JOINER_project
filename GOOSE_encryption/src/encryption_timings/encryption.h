#ifndef ENCRYPTION_H
#define ENCRYPTION_H
#include <stdint.h>


int aes_ctr_encrypt(const uint8_t *plaintext, int plaintext_len,
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *ciphertext);

int chacha_encrypt(const uint8_t *plaintext, int plaintext_len,
                   const uint8_t *key, const uint8_t *nonce,
                   uint8_t *ciphertext);

int aria_encrypt(const uint8_t *plaintext, int plaintext_len,
                 const uint8_t *key, const uint8_t *iv,
                 uint8_t *ciphertext);

int sm4_encrypt(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext);

int camellia_encrypt(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext);

int salsa20_encrypt(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key, const uint8_t *iv,
                uint8_t *ciphertext);

int chacha_encrypt_ls(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key, const uint8_t *nonce,
                uint8_t *ciphertext);

int ascon_encrypt(const uint8_t *plaintext, int plaintext_len,
                        const uint8_t *key, const uint8_t *nonce, uint8_t *ciphertext);

int zuc_128_encrypt(const uint8_t *plaintext, int plaintext_len,
                      const uint8_t *key, const uint8_t *nonce,
                      uint8_t *ciphertext);

int trivium_encrypt(const uint8_t *plaintext, int plaintext_len,
                    const uint8_t *key,
                    const uint8_t *nonce,
                    uint8_t *ciphertext);

int sm4_encrypt_128(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key,
                const uint8_t *nonce,
                uint8_t *ciphertext);

//alternating key sizes

int aes_ctr_encrypt_192(const uint8_t *plaintext, int plaintext_len, //92 size key
                    const uint8_t *key, const uint8_t *nonce,
                    uint8_t *ciphertext);
int aes_ctr_encrypt_256(const uint8_t *plaintext, int plaintext_len, //256 size key
                    const uint8_t *key, const uint8_t *nonce,
                    uint8_t *ciphertext);
int zuc_256_encrypt(const uint8_t *plaintext, int plaintext_len,
                      const uint8_t *key, const uint8_t *nonce,
                      uint8_t *ciphertext);

#endif 