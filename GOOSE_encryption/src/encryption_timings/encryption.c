#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include "cipher/zuc.h"
#include "cipher/sm4.h"
#include "cipher_modes/ctr.h"

int aes_ctr_encrypt(const uint8_t *plaintext, int plaintext_len, //128 size key
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, ciphertext_len = 0; // upadate encryption, encrypt plaintext etc
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len; //finalise encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int chacha_encrypt(const uint8_t *plaintext, int plaintext_len,
                              const uint8_t *key, const uint8_t *nonce,
                              uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int salsa20_encrypt(const uint8_t *plaintext, int plaintext_len,
    const uint8_t *key, const uint8_t *nonce,
    uint8_t *ciphertext) {
    //similar to the encrypt function this only requires this function call
    crypto_stream_salsa20_xor(ciphertext, plaintext, plaintext_len, nonce, key);
    return plaintext_len;
}

int chacha_encrypt_ls(const uint8_t *plaintext, int plaintext_len,
    const uint8_t *key, const uint8_t *nonce,
    uint8_t *ciphertext) {
    crypto_stream_chacha20_xor(ciphertext, plaintext, plaintext_len, nonce, key);
    return plaintext_len;
    }

int zuc_128_encrypt(const uint8_t *plaintext, int plaintext_len,
                      const uint8_t *key, const uint8_t *nonce,
                      uint8_t *ciphertext) {
    ZucContext ctx; //similar structure to OpenSSL
    error_t err;
    err = zucInit(&ctx, key, 16, nonce, 16);
    if(err != NO_ERROR)
        return -1;
    zucCipher(&ctx, plaintext, ciphertext, (size_t)plaintext_len);
    zucDeinit(&ctx);
    return plaintext_len;
}


int sm4_encrypt_128(const uint8_t *plaintext, int plaintext_len,
                const uint8_t *key,
                const uint8_t *nonce,
                uint8_t *ciphertext)
{
    error_t error;
    Sm4Context context;
    uint8_t nonceLocal[16];
    memcpy(nonceLocal, nonce, sizeof(nonceLocal));

    error = sm4Init(&context, key, 16);
    if(error != NO_ERROR)
    {
        return (int)error;
    }

    error = ctrEncrypt(&sm4CipherAlgo, &context, 128, nonceLocal,
                       plaintext, ciphertext, (size_t)plaintext_len);
    if(error != NO_ERROR)
    {
        return (int)error;
    }

    return plaintext_len;
}


//alternating key size
int aes_ctr_encrypt_192(const uint8_t *plaintext, int plaintext_len, //192 size key
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // initialize context for encrypting
    if (EVP_EncryptInit_ex(ctx, EVP_aes_192_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int key_length = EVP_CIPHER_CTX_key_length(ctx);


    int len = 0, ciphertext_len = 0; // upadate encryption, encrypt plaintext etc
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len; //finalise encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int aes_ctr_encrypt_256(const uint8_t *plaintext, int plaintext_len, //256 size key
                    const uint8_t *key, const uint8_t *iv,
                    uint8_t *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    // initialize context for encrypting
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, ciphertext_len = 0; // upadate encryption, encrypt plaintext etc
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len; //finalise encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int zuc_256_encrypt(const uint8_t *plaintext, int plaintext_len,
                      const uint8_t *key, const uint8_t *nonce,
                      uint8_t *ciphertext) {
    ZucContext ctx;
    error_t err;
    err = zucInit(&ctx, key, 32, nonce, 16);
    if(err != NO_ERROR)
        return -1;
    zucCipher(&ctx, plaintext, ciphertext, (size_t)plaintext_len);
    zucDeinit(&ctx);
    return plaintext_len;
}