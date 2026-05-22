from scapy.all import sniff, sendp, Raw, Ether
import time
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(plaintext, key, nonce):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext)

key = b'\x00' * 32
nonce = b'\x00' * 16
no = 0

def process_packet(pkt):
    global no
    no += 1
    print('intercepted packet no: ', no)
    if Raw in pkt and pkt[Ether].type == 0x88b8:
        start_of_encrypt = time.time() #
        pkt[Raw].load = struct.pack("d", time.perf_counter()) + encrypt(pkt[Raw].load, key, nonce)
        end_of_encrypt = (time.time() - start_of_encrypt) * 1000
        print("latency of encrypt - {:.3f}".format(end_of_encrypt))
    sendp(pkt, iface="S1-eth2")

def process_packet_without_encryption(pkt):
    if Raw in pkt and pkt[Ether].type == 0x88b8:
        pkt[Raw].load = struct.pack("d", time.perf_counter()) + pkt[Raw].load
    sendp(pkt, iface="S1-eth2")


def main():
    print("-------- starting interception on S1 ---------")
    sniff(iface="S1-eth1", prn=process_packet_without_encryption, store=0)

if __name__ == "__main__":
    main()