#!/usr/bin/python
from scapy.all import sniff, Ether, Raw, wrpcap, sendp
import argparse
import signal
import sys, time, matplotlib.pyplot as plt, csv
import struct

key = b'\x00' * 32
nonce = b'\x00' * 16
no_packets = 0
no_received = 0
captured_packets = []
pcap_filename = None

# throughput measurement
throughput_start = time.time()
bytes_received = 0
throughput_interval = 0.1
throughput_measurements = []
throughput_timestamps = []
overall_start = None
timeout = None  #  timeout variable
measure_thp = False

def process_packet(pkt):
    global no_packets, no_received, captured_packets

    if pkt.haslayer(Raw) and pkt.haslayer(Ether):
        if pkt[Ether].type == 0x88b8 and "{:02x}".format(pkt[Raw].load[176]) == "01": #stNum always zero in this dataset
            print("----------GOOSE packet received---------")
            raw_payload = pkt[Raw].load
            if b'OperationalValues' in pkt[Raw].load:
                print("decrypted packet no:", no_received, "okay!")
                no_packets += 1
            else:
                print("***  error decrypting  ***")



def start_listen():


    interface = "H2-eth0"
    print("Listening on", interface)


    sniff(iface=interface, prn=process_packet)



def main():
    start_listen()

if __name__ == "__main__":
    main()
