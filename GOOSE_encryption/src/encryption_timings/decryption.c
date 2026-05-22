#include "decryption.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <string.h>
#include "cipher/zuc.h"
#include "cipher/sm4.h"
#include "cipher_modes/ctr.h"

int aes_ctr_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                    const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //create cipher context
    if (!ctx)return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv)) { //initalize context for given alg
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    //call decrypt update, processes the ciphertext
    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    // this finalised decryption, not as appropriate in ctr mode but still essential
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int sm4_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //same context as above..
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int chacha_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                              const uint8_t *key, const uint8_t *nonce, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int aria_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    const EVP_CIPHER *cipher = EVP_aria_128_ctr();
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int camellia_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_camellia_128_ctr(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int salsa20_decrypt(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *nonce, uint8_t *plaintext) {
    //libsodiums implementation only requires this,
    crypto_stream_salsa20_xor(plaintext, ciphertext, ciphertext_len, nonce, key);
    return ciphertext_len;
}

int chacha_decrypt_ls(const uint8_t *ciphertext, int ciphertext_len,
    const uint8_t *key, const uint8_t *nonce, uint8_t *plaintext) {
    crypto_stream_chacha20_xor(plaintext, ciphertext, ciphertext_len, nonce, key);
    return ciphertext_len;
}

int zuc_128_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                      const uint8_t *key, const uint8_t *iv,
                      uint8_t *plaintext) {
    ZucContext ctx; //simislar to OpenSSL structure
    error_t err;

    // initialize ZUC context
    err = zucInit(&ctx, key, 16, iv, 16);
    if (err != NO_ERROR)
        return -1;

    // decryption is performed exactly as encryption by XORing with the key stream
    zucCipher(&ctx, ciphertext, plaintext, (size_t)ciphertext_len);
    zucDeinit(&ctx);
    return ciphertext_len;
}

int sm4_decrypt_128(const uint8_t *ciphertext, int ciphertext_len,
                    const uint8_t *key,
                    const uint8_t *nonce,
                    uint8_t *plaintext)
{
    error_t error;
    Sm4Context context;
    uint8_t nonceLocal[16];
    memcpy(nonceLocal, nonce, sizeof(nonceLocal));

    // initialize SM4 context with the provided 16 byte key
    error = sm4Init(&context, key, 16);
    if(error != NO_ERROR)
    {
        return (int)error;
    }

    error = ctrEncrypt(&sm4CipherAlgo, &context, 128, nonceLocal,
                       ciphertext, plaintext, (size_t)ciphertext_len);
    if(error != NO_ERROR)
    {
        return (int)error;  // return error code if decryption fails
    }

    return ciphertext_len;
}




//alternating key sizes

int aes_ctr_decrypt_192(const uint8_t *ciphertext, int ciphertext_len,
                    const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //create cipher context
    if (!ctx)return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_ctr(), NULL, key, iv)) { //initalize context for given alg
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    //call decrypt update, processes the ciphertext
    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    // this finalised decryption, not as appropriate in ctr mode but still essential
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int aes_ctr_decrypt_256(const uint8_t *ciphertext, int ciphertext_len,
                    const uint8_t *key, const uint8_t *iv, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //create cipher context
    if (!ctx)return -1;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv)) { //initalize context for given alg
        printf("eror");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    //call decrypt update, processes the ciphertext
    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    // this finalised decryption, not as appropriate in ctr mode but still essential
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int zuc_256_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                      const uint8_t *key, const uint8_t *iv,
                      uint8_t *plaintext) {
    ZucContext ctx;
    error_t err;
    err = zucInit(&ctx, key, 32, iv, 16);
    if (err != NO_ERROR)
        return -1;

    zucCipher(&ctx, ciphertext, plaintext, (size_t)ciphertext_len);

    zucDeinit(&ctx);

    return ciphertext_len;
}