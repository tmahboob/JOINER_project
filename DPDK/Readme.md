# GOOSE Packet Forwarding Switch using DPDK + Encryption
Author: Dr. Tahira Mahboob, tahira.mahboob@yahoo.com
School of Computing, University of Glasgow, UK
## Overview

This project implements a **high-performance packet processing switch** using **DPDK (Data Plane Development Kit)**.  
It captures Ethernet traffic, filters **IEC 61850 GOOSE packets (Ethertype 0x88B8)**, optionally encrypts payloads, and forwards them between NIC ports.

---

## Key Features

- High-speed packet processing using DPDK Poll Mode Driver (PMD)
- GOOSE protocol detection (IEC 61850)
- Optional encryption pipeline:
  - ChaCha20
  - AES-CTR
  - SM4
  - ZUC
- Burst-based RX/TX processing
- Hugepage-based memory management
- Zero-copy packet forwarding using `rte_mbuf`

---

## System Requirements

### Hardware
- At least 2 DPDK-compatible NICs
- CPU with virtualization support (VT-d / IOMMU recommended)
- Minimum 4 CPU cores (8+ recommended)

### Software
- Ubuntu 20.04 / 22.04 / 24.04
- GCC 11+
- CMake 3.10+
- DPDK 23.11+
- pkg-config

---

## Install DPDK

### Install dependencies

```bash
sudo apt update
sudo apt install -y build-essential meson ninja-build pkg-config \
    libnuma-dev linux-headers-$(uname -r)
    
### Build DPDK
DPDK installation - do not follow the Wiki! 
Just use: 
apt-get install dpdk dpdk-dev 

If manually using the Wiki, issues with meson build fails: 
apt-get install python3-pyelftools libnuma-dev 


https://github.com/UofG-netlab/BPFabric/wiki/Running%20BPFabric

### Configure HugePages
sudo -i
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages


### Verify:
cat /proc/meminfo
grep Huge /proc/meminfo

### Bind NICs to DPDK
Check NIC status:

dpdk-devbind.py --status


### Bind interfaces:

sudo modprobe vfio-pci

sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0
sudo dpdk-devbind.py --bind=vfio-pci 0000:02:00.0

### Verify:

dpdk-devbind.py --status

### create build.sh bash file

set -e

rm -rf build
mkdir build
cd build
cmake ..
make



### Run Switch
Basic execution
sudo -E ./switch1 chacha full

Expected output:

[INIT] starting switch
[PORT] 0 initialized
[PORT] 1 initialized
[START] forwarding IN=0 OUT=1

### Packet Flow Architecture
NIC (Port 0)
    ↓
DPDK RX Burst
    ↓
GOOSE Filter (0x88B8)
    ↓
Encryption Engine
    ↓
DPDK TX Burst
    ↓
NIC (Port 1)


//--- Close DPDK ---
dpdk-devbind.py --unbind 0000:01:00.0
dpdk-devbind.py --unbind 0000:02:00.0


### Fix (clean reset of DPDK runtime state)
Run this exactly:

sudo rm -rf /var/run/dpdk/rte
sudo mkdir -p /var/run/dpdk/rte
sudo chmod 755 /var/run/dpdk/rte
Then also clear hugetlbfs runtime leftovers:

sudo rm -rf /dev/hugepages/dpdk*

===== make changes to huge pages
sudo chmod -R 777 /dev/hugepages

--Need to update CMakeLists.txt as required
