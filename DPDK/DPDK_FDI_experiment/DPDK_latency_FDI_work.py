import pandas as pd
import matplotlib.pyplot as plt

# -----------------------------
# Font settings
# -----------------------------
plt.rcParams["font.family"] = "Times New Roman"
plt.rcParams["font.size"] = 14

# Load data
df = pd.read_csv("dpdk_latency.csv")

# -----------------------------
# Latency data
# -----------------------------
latency_data = [
    df["parse_us"].dropna(),
    df["extraction_us"].dropna(),
    df["prediction_us"].dropna()
]

# -----------------------------
# Create box plot
# -----------------------------
fig, ax = plt.subplots(figsize=(9, 6))

bp = ax.boxplot(
    latency_data,
    labels=["Parsing", "Extraction", "Prediction"],
    patch_artist=True,
    showmeans=True,
    meanline=False,
    widths=0.55,

    # Grayscale styling
    boxprops=dict(facecolor="lightgray", edgecolor="black", linewidth=1.2),
    medianprops=dict(color="black", linewidth=2),
    whiskerprops=dict(color="black", linewidth=1.2),
    capprops=dict(color="black", linewidth=1.2),
    meanprops=dict(
        marker="x",
        markeredgecolor="black",
        markerfacecolor="black",
        markersize=7,
        markeredgewidth=1.5
    ),
    flierprops=dict(
        marker="o",
        markerfacecolor="none",
        markeredgecolor="black",
        markersize=4
    )
)

# -----------------------------
# Labels
# -----------------------------
ax.set_ylabel("Latency (µs)", fontsize=14)
ax.set_xlabel("Processing Stage", fontsize=14)

ax.tick_params(
    axis="both",
    which="major",
    labelsize=14
)

# -----------------------------
# Grayscale grid
# -----------------------------
ax.grid(
    axis="y",
    linestyle="--",
    color="gray",
    alpha=0.4,
    linewidth=0.8
)

# Keep plot background white
ax.set_facecolor("white")
fig.patch.set_facecolor("white")

plt.tight_layout()
plt.show()


import pandas as pd
import matplotlib.pyplot as plt

# Read CSV file
df = pd.read_csv("inference_latency.csv")

# Extract inference time column
inference_ms = df["mse"]

# Create sample numbers for x-axis
samples = range(1, len(inference_ms) + 1)

# Create line graph
plt.figure(figsize=(12, 6))

plt.plot(
    samples,
    inference_ms,
    marker='o',
    linewidth=1.5,
    markersize=4
)

# Labels and title
plt.xlabel("Batch Number", fontsize=12)
plt.ylabel("Inference Time (ms)", fontsize=12)
plt.ylim(0.9,1)
#plt.title("Inference Time per Sample", fontsize=14)

# Add grid
plt.grid(True, alpha=0.3)

# Adjust layout
plt.tight_layout()

# Save graph
plt.savefig("inference_time_line_graph.png", dpi=300, bbox_inches="tight")

# Display graph
plt.show()

from scapy.all import rdpcap, TCP, Raw
import pandas as pd


#===============================================
from scapy.all import rdpcap


PCAPS = [
    "modbus_capture.pcap",
    "modbus_1507.pcap"
]


for pcap_file in PCAPS:

    print("\n" + "=" * 80)
    print(f"PCAP: {pcap_file}")
    print("=" * 80)

    packets = rdpcap(pcap_file)

    tcp_count = 0
    tcp_payload_count = 0
    modbus_count = 0

    for i, pkt in enumerate(packets):

        # ----------------------------------------------------
        # Get TCP layer by name
        # ----------------------------------------------------

        tcp = pkt.getlayer("TCP")

        if tcp is None:
            continue

        tcp_count += 1

        # ----------------------------------------------------
        # Get IP layer by name
        # ----------------------------------------------------

        ip = pkt.getlayer("IP")

        if ip is None:
            continue

        # ----------------------------------------------------
        # Get TCP payload
        # ----------------------------------------------------

        payload = bytes(tcp.payload)

        if len(payload) == 0:
            continue

        tcp_payload_count += 1

        # ----------------------------------------------------
        # Need at least MBAP header + function code
        # ----------------------------------------------------

        if len(payload) < 8:
            continue

        # ----------------------------------------------------
        # Modbus/TCP MBAP header
        # ----------------------------------------------------

        transaction_id = int.from_bytes(
            payload[0:2],
            byteorder="big"
        )

        protocol_id = int.from_bytes(
            payload[2:4],
            byteorder="big"
        )

        length = int.from_bytes(
            payload[4:6],
            byteorder="big"
        )

        unit_id = payload[6]

        function_code = payload[7]

        # ----------------------------------------------------
        # Modbus/TCP protocol ID should be 0
        # ----------------------------------------------------

        if protocol_id != 0:
            continue

        modbus_count += 1

        print(
            f"{i:5d} | "
            f"time={float(pkt.time):.6f} | "
            f"{ip.src}:{tcp.sport} -> "
            f"{ip.dst}:{tcp.dport} | "
            f"payload={len(payload):3d} | "
            f"TID={transaction_id:5d} | "
            f"PID={protocol_id:2d} | "
            f"LEN={length:3d} | "
            f"UNIT={unit_id:3d} | "
            f"FC=0x{function_code:02x}"
        )

    print("\nStatistics")
    print("-" * 50)
    print(f"TCP packets:             {tcp_count}")
    print(f"TCP packets with data:   {tcp_payload_count}")
    print(f"Modbus candidates:       {modbus_count}")
   # print(f"Modbus candidates:       {modbus_candidates}")

    from scapy.all import rdpcap
    import pandas as pd

    # ============================================================
    # CONFIGURATION
    # ============================================================

    PCAP_FILE = "modbus_capture.pcap"

    MODBUS_PORT = 1507

    OUTPUT_CSV = "modbus_latency_results.csv"


    # ============================================================
    # EXTRACT MODBUS/TCP PACKETS
    # ============================================================

    def extract_modbus_packets(pcap_file, port=1507):

        packets = rdpcap(pcap_file)

        records = []

        for index, pkt in enumerate(packets):

            tcp = pkt.getlayer("TCP")
            ip = pkt.getlayer("IP")

            if tcp is None or ip is None:
                continue

            # Only traffic involving Modbus port
            if tcp.sport != port and tcp.dport != port:
                continue

            payload = bytes(tcp.payload)

            # Need MBAP + function code
            if len(payload) < 8:
                continue

            transaction_id = int.from_bytes(
                payload[0:2],
                byteorder="big"
            )

            protocol_id = int.from_bytes(
                payload[2:4],
                byteorder="big"
            )

            length = int.from_bytes(
                payload[4:6],
                byteorder="big"
            )

            unit_id = payload[6]

            function_code = payload[7]

            # Modbus/TCP
            if protocol_id != 0:
                continue

            # Client -> server
            if tcp.dport == port:

                direction = "request"

            # Server -> client
            elif tcp.sport == port:

                direction = "response"

            else:

                continue

            records.append({

                "packet_index": index,

                "timestamp": float(pkt.time),

                "transaction_id": transaction_id,

                "protocol_id": protocol_id,

                "length": length,

                "unit_id": unit_id,

                "function_code": function_code,

                "src_ip": ip.src,

                "dst_ip": ip.dst,

                "src_port": tcp.sport,

                "dst_port": tcp.dport,

                "direction": direction,

                "payload_length": len(payload)

            })

        return pd.DataFrame(records)


    # ============================================================
    # READ PCAP
    # ============================================================

    print("Reading PCAP...")

    df = extract_modbus_packets(
        PCAP_FILE,
        MODBUS_PORT
    )

    print(
        f"Modbus/TCP packets found: {len(df)}"
    )

    # ============================================================
    # SPLIT REQUESTS / RESPONSES
    # ============================================================

    requests = df[
        df["direction"] == "request"
        ].copy()

    responses = df[
        df["direction"] == "response"
        ].copy()

    print(
        f"Requests:  {len(requests)}"
    )

    print(
        f"Responses: {len(responses)}"
    )

    # ============================================================
    # MATCH REQUEST → RESPONSE
    # ============================================================

    results = []

    for _, request in requests.iterrows():

        # Candidate responses:
        # same transaction ID
        # same unit
        # same function code
        # occur after request
        candidates = responses[
            (responses["transaction_id"]
             == request["transaction_id"])
            &
            (responses["unit_id"]
             == request["unit_id"])
            &
            (responses["function_code"]
             == request["function_code"])
            &
            (responses["timestamp"]
             > request["timestamp"])
            ]

        if candidates.empty:
            continue

        # Take the first response after the request
        response = candidates.iloc[0]

        latency_seconds = (
                response["timestamp"]
                -
                request["timestamp"]
        )

        latency_ms = latency_seconds * 1000

        latency_us = latency_seconds * 1_000_000

        results.append({

            "transaction_id":
                request["transaction_id"],

            "function_code":
                request["function_code"],

            "request_timestamp":
                request["timestamp"],

            "response_timestamp":
                response["timestamp"],

            "latency_seconds":
                latency_seconds,

            "latency_ms":
                latency_ms,

            "latency_us":
                latency_us,

            "request_payload_bytes":
                request["payload_length"],

            "response_payload_bytes":
                response["payload_length"],

            "src_ip":
                request["src_ip"],

            "dst_ip":
                request["dst_ip"]

        })

    # ============================================================
    # CREATE RESULTS DATAFRAME
    # ============================================================

    results = pd.DataFrame(results)

    # ============================================================
    # SAVE
    # ============================================================

    results.to_csv(
        OUTPUT_CSV,
        index=False
    )

    # ============================================================
    # RESULTS
    # ============================================================

    print("\n" + "=" * 70)
    print("MODBUS LATENCY CALCULATION COMPLETE")
    print("=" * 70)

    print(
        f"\nMatched request-response pairs: "
        f"{len(results)}"
    )

    if not results.empty:

        print("\nLatency statistics (ms):")

        print(
            results["latency_ms"].describe()
        )

        print("\nLatency statistics (µs):")

        print(
            results["latency_us"].describe()
        )

        print("\nFirst 10 results:")

        print(
            results.head(10).to_string(index=False)
        )

    else:

        print(
            "\nNo request-response pairs were matched."
        )

    print(
        f"\nSaved to: {OUTPUT_CSV}"
    )

import pandas as pd
import matplotlib.pyplot as plt

# ============================================================
# CONFIGURATION
# ============================================================

INPUT_CSV = "modbus_latency_results.csv"
OUTPUT_FIGURE = "modbus_latency_per_packet.pdf"

# ============================================================
# FONT SETTINGS
# ============================================================

plt.rcParams["font.family"] = "Times New Roman"
plt.rcParams["font.size"] = 14

# ============================================================
# READ RESULTS
# ============================================================

df = pd.read_csv(INPUT_CSV)

# Packet number
packet_number = range(1, len(df) + 1)

# ============================================================
# PLOT LATENCY
# ============================================================
import pandas as pd
import matplotlib.pyplot as plt

# ============================================================
# CONFIGURATION
# ============================================================

INPUT_CSV = "modbus_latency_results.csv"
OUTPUT_FIGURE = "modbus_latency_per_packet.pdf"

# ============================================================
# FONT SETTINGS
# ============================================================

plt.rcParams["font.family"] = "Times New Roman"
plt.rcParams["font.size"] = 14

# ============================================================
# READ RESULTS
# ============================================================

df = pd.read_csv(INPUT_CSV)

# Packet number
packet_number = range(1, len(df) + 1)

# ============================================================
# PLOT
# ============================================================

fig, ax = plt.subplots(figsize=(10, 5.5))

ax.plot(
    packet_number,
    df["latency_ms"],
    color="black",
    linewidth=1.2
)

ax.set_xlabel(
    "Packet Number",
    fontsize=14
)

ax.set_ylabel(
    "Latency (ms)",
    fontsize=14
)

ax.tick_params(
    axis="both",
    labelsize=14,
    colors="black"
)

# Grayscale grid
ax.grid(
    True,
    linestyle="--",
    linewidth=0.6,
    color="0.75",
    alpha=0.8
)

# Black axes
for spine in ax.spines.values():
    spine.set_color("black")

plt.tight_layout()

# ============================================================
# SAVE
# ============================================================

plt.savefig(
    OUTPUT_FIGURE,
    format="pdf",
    bbox_inches="tight"
)

plt.show()

print(f"Figure saved to: {OUTPUT_FIGURE}")