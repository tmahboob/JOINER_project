#!/usr/bin/env python3
import time
from scapy.all import rdpcap
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from Cryptodome.Cipher import Salsa20

def chacha20_poly1305_encrypt(plaintext, key, nonce, associated_data=None):
    aead_cipher = ChaCha20Poly1305(key)
    return aead_cipher.encrypt(nonce, plaintext, associated_data)

def chacha20_poly1305_decrypt(ciphertext, key, nonce, associated_data=None):
    aead_cipher = ChaCha20Poly1305(key)
    return aead_cipher.decrypt(nonce, ciphertext, associated_data)

def salsa20_encrypt(plaintext, key, nonce, associated_data=None):
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.encrypt(plaintext)

def salsa20_decrypt(ciphertext, key, nonce, associated_data=None):
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)

ALGORITHMS = {
    "ChaCha20Poly1305": {
        "encrypt": chacha20_poly1305_encrypt,
        "decrypt": chacha20_poly1305_decrypt,
        "key": b'\x00' * 32,
        "nonce": b'\x00' * 12
    },
    "Salsa20": {
        "encrypt": salsa20_encrypt,
        "decrypt": salsa20_decrypt,
        "key": b'\x00' * 32,
        "nonce": b'\x00' * 8 
    }
}

def main():
    pcap_file = "pcap_test_file.pcap"
    packets = rdpcap(pcap_file)
    iterations = 100

    for algo_name, algo in ALGORITHMS.items():
        total_enc_time = 0.0
        total_dec_time = 0.0
        valid_packet_count = 0
        error_count = 0  

        for pkt in packets:
            raw_data = bytes(pkt)

            goose_payload = raw_data[14:]
            if not goose_payload:
                continue

            valid_packet_count += 1

            for _ in range(iterations):
                start_enc = time.perf_counter()
                ciphertext = algo["encrypt"](goose_payload, algo["key"], algo["nonce"])
                end_enc = time.perf_counter()
                total_enc_time += (end_enc - start_enc)

                start_dec = time.perf_counter()
                decrypted = algo["decrypt"](ciphertext, algo["key"], algo["nonce"])
                end_dec = time.perf_counter()
                total_dec_time += (end_dec - start_dec)

                if decrypted != goose_payload:
                    error_count += 1

        if valid_packet_count > 0:
            total_iterations = valid_packet_count * iterations
            avg_enc_ns = (total_enc_time / total_iterations) * 1e9
            avg_dec_ns = (total_dec_time / total_iterations) * 1e9
            print(f"Algorithm: {algo_name}" + "   -------------------------")
            print(f"Processed {valid_packet_count} packets, each {iterations} times.")
            print(f"Average encryption time per iteration: {avg_enc_ns:.2f} ns")
            print(f"Average decryption time per iteration: {avg_dec_ns:.2f} ns")
            if error_count:
                print(f"Decryption errors detected: {error_count}")
            else:
                print("All packets decrypted correctly.")
        else:
            print(f"No valid GOOSE packets found in the pcap file for {algo_name}.")

if __name__ == "__main__":
    main()
