# GOOSE Encryption Timings Project

This project implements encryption/decryption timings for GOOSE messages sent using libpcap, libsodium, and other libraries. It includes support for sending and receiving encrypted packets in different modes.

## Getting Started

***
### Prerequisites
- C compiler with C99 support
- CMake (version 3.10 or later)
- Libraries: libpcap, libsodium, crypto
-
### (IMPORTANT)

This project uses the Orxy-Embedded CycloneCrypto library

- Purpose: 
-- Provides cryptographic functions used for encryption and decryption in the project, including implementations of SM4-CTR and ZUC algorithms.

- Location:
-- The library is to be installed in the /external/CycloneCRYPTO and /external/Common directories.

- License:
-- CycloneCrypto is distributed under the GNU General Public License (GPL) version 2.0 or later. 
-- You can review the complete license details in the following files: /external/CycloneCRYPTO/LICENSE /external/Common/LICENSE
-- Note: Any modifications to CycloneCrypto must comply with these GPL terms. The only additions to these files are os_port_config.h 
     and crypto_config.h, which are configuration files.

***
### Build Instructions
1. Download project file
2. From the root directory run, 'git clone https://github.com/Oryx-Embedded/Common.git external/Common'
3. Then run 'git clone https://github.com/Oryx-Embedded/CycloneCRYPTO.git external/CycloneCRYPTO' this will get the associated files for CycloneCRYPTO, 
4. Once installed okay, from the root directory run "./external/config.sh", this will move configuration files and ensure the correct setup
6. Now from the root directory call "./build.sh", this will call the CMAKE file and build the project
7. The project should now be built and ready for use.

### How to Run
This project is designed for 2 distinct uses:
1. Mininet emulation environment 
Setup
- This can be ran by navigating to the '/mininet_setup', by running 'cd /src/mininet_setup', and running 'sudo python mininet_setup.py',
     sudo privileges are required for mininet
Running the Experiment
- Once in mininet, from the Mininet command line execute 'run_experiment', this will loop over the emulated experiment of looping over the modes and encryption algorithms
- The duration each experiment runs for can be adjusted by changing the 'duration' variable (in seconds) in 'mininet_setup.py'
Output
- Once completed the generated data will be stored in /src/data/mn_data, the plot will be generated automatically for this

2. Creating Raw Sockets and sending packets over Ethernet (this is for the Raspberry Pi setup, but can be used on Mininet too)
- From inside '/build', the send and receive scripts can be used, this is by calling 
Send mode
- Sender:   ./rpswitch send <pcap_file> <interface> <dest_mac> <algorithm> <mode> [packet_limit]
- - The send mode will read in packets from the given .pcap file and send them from the specified local interface to the destination mac address, using the specified encryption modes
Receive mode
- Receiver: ./rpswitch recv <recv_interface> <send_interface> <dest_mac> <algorithm> <mode>
- The recv mode will listen for these packets on a=the given interface, and will send/forward them from the specified send_interface to the destination_mac using the associated algorithm and mode
Latency script
- The ./goose_latency <interface> <algorithm> <mode> script is called with the shown parameters, the interface to listen on, and the chosen algorithm and mose to write to end-to-end latency to the correct csv file
Output
- The generated data will be stored in /src/data/rp_data, due to this being designed to work over multiple devices, no plot is generated automatically

