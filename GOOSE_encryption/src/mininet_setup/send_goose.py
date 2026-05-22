from scapy.all import sendp, rdpcap, Ether, Raw
import sys, os
import argparse

script_dir = os.path.dirname(os.path.realpath(__file__))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pfile", default=os.path.join(script_dir, "../data/pcap/pcap_test_file.pcap"))
    parser.add_argument("--count", type=int, default=5000)
    args = parser.parse_args()
    pcap_file = args.pfile
    packets_to_send = args.count

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        sys.exit("error reading from pcap file: " + str(e))

    for i in range(packets_to_send):
        pkt = packets[i % len(packets)]
        pkt[Ether].dst = "00:00:00:00:00:02"
        pkt[Ether].src = "00:00:00:00:00:01"

        #print(f"sending packet {i}")
        sendp(pkt, iface="H1-eth0")
        if i % 100 == 0:
            print(f"sending packet {i}")
        #time.sleep(3)

if __name__ == "__main__":
    main()
