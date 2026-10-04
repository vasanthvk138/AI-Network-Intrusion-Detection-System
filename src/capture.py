from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import numpy as np
import sys
from detector import predict

# =========================
# FLOW STORAGE
# =========================
flows = defaultdict(lambda: {
    "start_time": time.time(),
    "timestamps": [],
    "packets": 0,
    "bytes": 0,
    "lengths": [],
    "fwd_packets": 0,
    "bwd_packets": 0,
    "src_ip": None,
    "dst_ip": None,
    "ports": set()
})

FLOW_TIMEOUT = 30

# =========================
# FEATURE BUILDER
# =========================
def extract_features(flow):

    if len(flow["timestamps"]) < 2:
        return [0] * 78

    duration = (
        flow["timestamps"][-1]
        - flow["timestamps"][0]
    )

    total_packets = flow["packets"]
    total_bytes = flow["bytes"]

    lengths = flow["lengths"]

    mean_len = np.mean(lengths)
    std_len = np.std(lengths)
    min_len = np.min(lengths)
    max_len = np.max(lengths)

    fwd_packets = flow["fwd_packets"]
    bwd_packets = flow["bwd_packets"]

    flow_bytes_per_sec = (
        total_bytes / duration
        if duration > 0 else 0
    )

    flow_packets_per_sec = (
        total_packets / duration
        if duration > 0 else 0
    )

    iat = np.diff(flow["timestamps"])

    iat_mean = np.mean(iat) if len(iat) > 0 else 0
    iat_std = np.std(iat) if len(iat) > 0 else 0
    iat_max = np.max(iat) if len(iat) > 0 else 0
    iat_min = np.min(iat) if len(iat) > 0 else 0

    features = [
        duration,
        total_packets,
        total_bytes,
        mean_len,
        std_len,
        min_len,
        max_len,
        fwd_packets,
        bwd_packets,
        flow_bytes_per_sec,
        flow_packets_per_sec,
        iat_mean,
        iat_std,
        iat_max,
        iat_min
    ]

    if len(features) < 78:
        features += [0] * (78 - len(features))

    return features


# =========================
# NORMALIZE FLOW KEY
# =========================
def get_flow_key(src, dst, sport, dport, proto):

    if (src, sport) <= (dst, dport):
        return (src, dst, sport, dport, proto)

    return (dst, src, dport, sport, proto)


# =========================
# PACKET PROCESSOR
# =========================
def process_packet(packet):

    try:

        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"📦 Packet Captured: {src} → {dst}")

        sport = 0
        dport = 0

        # =========================
        # TCP / UDP PORTS
        # =========================
        if packet.haslayer(TCP):

            sport = packet[TCP].sport
            dport = packet[TCP].dport

        elif packet.haslayer(UDP):

            sport = packet[UDP].sport
            dport = packet[UDP].dport

        # =========================
        # FLOW KEY
        # =========================
        flow_key = get_flow_key(
            src,
            dst,
            sport,
            dport,
            proto
        )

        flow = flows[flow_key]

        # =========================
        # INIT FLOW
        # =========================
        if flow["src_ip"] is None:

            flow["src_ip"] = src
            flow["dst_ip"] = dst

        now = time.time()

        # =========================
        # FLOW UPDATE
        # =========================
        flow["packets"] += 1
        flow["bytes"] += len(packet)

        flow["lengths"].append(len(packet))
        flow["timestamps"].append(now)

        flow["ports"].add(dport)

        # =========================
        # DIRECTION TRACKING
        # =========================
        if src == flow["src_ip"]:
            flow["fwd_packets"] += 1
        else:
            flow["bwd_packets"] += 1

        # =========================
        # 🚨 GLOBAL PORTSCAN DETECTION
        # =========================
        global_ports = set()

        for key in flows:

            try:

                src_ip = key[0]
                dst_port = key[3]

                if src_ip == src:
                    global_ports.add(dst_port)

            except:
                pass

        if len(global_ports) > 30:

            print("\n🔥 PORTSCAN DETECTED")
            print(f"🚨 ALERT: {src} → PortScan")

            predict(
                [999] * 78,
                src,
                force_label="PortScan"
            )

            delete_keys = []

            for key in flows:

                if key[0] == src:
                    delete_keys.append(key)

            for k in delete_keys:

                if k in flows:
                    del flows[k]

            return

        # =========================
        # 🚨 DDOS DETECTION
        # =========================
        duration = now - flow["start_time"]

        if flow["packets"] > 150 and duration < 3:

            print("\n🔥 DDOS DETECTED")
            print(f"🚨 ALERT: {src} → DDoS")

            predict(
                [888] * 78,
                src,
                force_label="DDoS"
            )

            if flow_key in flows:
                del flows[flow_key]

            return

        # =========================
        # 🚨 BRUTE FORCE DETECTION
        # =========================
        if (
            dport in [21, 22, 23, 25, 110, 143, 3389]
            and flow["packets"] > 40
        ):

            print("\n🔥 BRUTE FORCE DETECTED")
            print(f"🚨 ALERT: {src} → BruteForce")

            predict(
                [777] * 78,
                src,
                force_label="BruteForce"
            )

            if flow_key in flows:
                del flows[flow_key]

            return

        # =========================
        # 🤖 ML DETECTION
        # =========================
        if flow["packets"] >= 5:

            features = extract_features(flow)

            result = predict(
                features,
                src
            )

            print(f"🔍 ML: {src} → {result}")

            if flow_key in flows:
                del flows[flow_key]

        # =========================
        # CLEANUP OLD FLOWS
        # =========================
        if now - flow["start_time"] > FLOW_TIMEOUT:

            if flow_key in flows:
                del flows[flow_key]

    except Exception as e:

        print("❌ Packet Processing Error:", e)


# =========================
# START CAPTURE
# =========================
def start_capture(target_ip=None):

    print("🚀 Real-time packet capture started...")

    try:

        if target_ip:

            print(f"🎯 Filtering only IP: {target_ip}")

            sniff(
                filter=f"host {target_ip}",
                prn=process_packet,
                store=0
            )

        else:

            print("🌐 Capturing full network traffic")

            sniff(
                prn=process_packet,
                store=0
            )

    except Exception as e:

        print("❌ Capture Error:", e)


# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":

    target_ip = None

    if len(sys.argv) > 1:
        target_ip = sys.argv[1]

    start_capture(target_ip)