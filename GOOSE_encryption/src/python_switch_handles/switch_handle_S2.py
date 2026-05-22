from scapy.all import sniff, sendp, Raw
import time
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt(ciphertext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

key = b'\x00' * 32
nonce = b'\x00' * 16

def process_packet(pkt):
    print('------ intercepted packet -----')
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        #timestamp = payload[:8]
        #encrypted_part = payload[8:]
        try:
            start_of_encrypt = time.time()
            decrypted_payload = decrypt(payload[8:], key, nonce)
            end_of_encrypt = (time.time() - start_of_encrypt) * 1000

            print("latency of decrypt - {:.3f}".format(end_of_encrypt))

            finished_total_time = time.perf_counter()
            #print("decryption success:", decrypted_payload)
            latency_total = (finished_total_time - struct.unpack("d", payload[:8])[0]) * 1000
            print("total latency - {:.3f}".format(latency_total))
            pkt[Raw].load = decrypted_payload
        except Exception as e:
            print("failed:", e)
            return

    sendp(pkt, iface="S2-eth2")

def process_packet_without_encryption(pkt):
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        try:
            finished_t = time.perf_counter()
            latency = (finished_t - struct.unpack("d", payload[:8])[0]) * 1000
            print("latency -- {:.3f}".format(latency))
        except Exception as e:
            print("failed:", e)
            return

def main():
    print("------- starting interception on S2 --------")

    sniff(iface="S2-eth1", prn=process_packet_without_encryption, store=0)

if __name__ == "__main__":
    main()



