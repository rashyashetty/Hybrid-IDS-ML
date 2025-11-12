from scapy.all import sniff, IP, TCP, UDP
import time, json, statistics

flows = {}  # key = (src_ip, dst_ip, src_port, dst_port, protocol)
MAX_PACKETS_PER_FLOW = 10  # Number of packets before exporting a flow

# ✅ Extract 5-tuple
def get_flow_key(pkt):
    if IP not in pkt:
        return None
    proto = 0
    sport = dport = None
    if TCP in pkt:
        proto = 6
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        proto = 17
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        return None
    return (pkt[IP].src, pkt[IP].dst, sport, dport, proto)

# ✅ Packet Processor
def process_packet(pkt):
    key = get_flow_key(pkt)
    if not key:
        return

    now = time.time()

    if key not in flows:
        flows[key] = {
            "start_time": now,
            "end_time": now,
            "last_seen": now,
            "fwd_pkts": [],
            "bwd_pkts": [],
            "fwd_sizes": [],
            "bwd_sizes": [],
            "fwd_times": [],
            "bwd_times": [],
            "flags": {"FIN":0,"SYN":0,"RST":0,"PSH":0,"ACK":0,"URG":0,"CWR":0,"ECE":0},
            "src": key[0],
            "dst": key[1],
            "proto": key[4],
        }

    flow = flows[key]
    flow["end_time"] = now
    flow["last_seen"] = now

    pkt_len = len(pkt)
    if pkt[IP].src == flow["src"]:
        flow["fwd_pkts"].append(pkt)
        flow["fwd_sizes"].append(pkt_len)
        flow["fwd_times"].append(now)
    else:
        flow["bwd_pkts"].append(pkt)
        flow["bwd_sizes"].append(pkt_len)
        flow["bwd_times"].append(now)

    # TCP Flags
    if TCP in pkt:
        t = pkt[TCP]
        flow["flags"]["FIN"] += int(t.flags.F)
        flow["flags"]["SYN"] += int(t.flags.S)
        flow["flags"]["RST"] += int(t.flags.R)
        flow["flags"]["PSH"] += int(t.flags.P)
        flow["flags"]["ACK"] += int(t.flags.A)
        flow["flags"]["URG"] += int(t.flags.U)
        flow["flags"]["CWR"] += int(t.flags.C)
        flow["flags"]["ECE"] += int(t.flags.E)

    total_pkts = len(flow["fwd_pkts"]) + len(flow["bwd_pkts"])
    if total_pkts >= MAX_PACKETS_PER_FLOW:
        export_flow(key)

# ✅ Inter-arrival time stats
def calc_iat(times):
    if len(times) < 2:
        return {"mean":0,"std":0,"max":0,"min":0,"total":0}
    diffs = [t2 - t1 for t1,t2 in zip(times, times[1:])]
    return {
        "mean": statistics.mean(diffs),
        "std": statistics.stdev(diffs) if len(diffs) > 1 else 0,
        "max": max(diffs),
        "min": min(diffs),
        "total": sum(diffs),
    }

def safe_mean(arr):
    return statistics.mean(arr) if arr else 0.0

def safe_std(arr):
    return statistics.stdev(arr) if len(arr) > 1 else 0.0

# ✅ Export flow as enriched JSON
def export_flow(key):
    flow = flows.pop(key, None)
    if not flow:
        return

    duration = max(flow["end_time"] - flow["start_time"], 1e-6)
    fwd_count = len(flow["fwd_pkts"])
    bwd_count = len(flow["bwd_pkts"])

    fwd_sizes = flow["fwd_sizes"]
    bwd_sizes = flow["bwd_sizes"]

    fwd_len_max = max(fwd_sizes) if fwd_sizes else 0
    fwd_len_min = min(fwd_sizes) if fwd_sizes else 0
    fwd_len_mean = safe_mean(fwd_sizes)
    fwd_len_std = safe_std(fwd_sizes)

    bwd_len_max = max(bwd_sizes) if bwd_sizes else 0
    bwd_len_min = min(bwd_sizes) if bwd_sizes else 0
    bwd_len_mean = safe_mean(bwd_sizes)
    bwd_len_std = safe_std(bwd_sizes)

    flow_iat = calc_iat(sorted(flow["fwd_times"] + flow["bwd_times"]))
    fwd_iat = calc_iat(sorted(flow["fwd_times"]))
    bwd_iat = calc_iat(sorted(flow["bwd_times"]))

    total_bytes = sum(fwd_sizes) + sum(bwd_sizes)
    total_pkts = fwd_count + bwd_count

    down_up_ratio = (bwd_count / fwd_count) if fwd_count > 0 else (bwd_count if bwd_count else 0)
    fwd_segment_size_avg = fwd_len_mean
    bwd_segment_size_avg = bwd_len_mean

    # Active/Idle approximation
    all_times = sorted(flow["fwd_times"] + flow["bwd_times"])
    idle_gaps = [t2 - t1 for t1, t2 in zip(all_times, all_times[1:]) if (t2 - t1) > 0]
    active_mean = duration - sum(idle_gaps)
    active_std = 0.0
    active_max = active_mean
    active_min = active_mean
    idle_mean = safe_mean(idle_gaps)
    idle_std = safe_std(idle_gaps)
    idle_max = max(idle_gaps) if idle_gaps else 0
    idle_min = min(idle_gaps) if idle_gaps else 0

    feature_json = {
        "Protocol": flow["proto"],
        "Flow Duration": round(duration, 6),
        "Total Fwd Packet": fwd_count,
        "Total Bwd packets": bwd_count,
        "Total Length of Fwd Packet": sum(fwd_sizes),
        "Total Length of Bwd Packet": sum(bwd_sizes),
        "Fwd Packet Length Max": fwd_len_max,
        "Fwd Packet Length Min": fwd_len_min,
        "Fwd Packet Length Mean": round(fwd_len_mean, 6),
        "Fwd Packet Length Std": round(fwd_len_std, 6),
        "Bwd Packet Length Max": bwd_len_max,
        "Bwd Packet Length Min": bwd_len_min,
        "Bwd Packet Length Mean": round(bwd_len_mean, 6),
        "Bwd Packet Length Std": round(bwd_len_std, 6),

        "Flow Bytes/s": round(total_bytes / duration, 6),
        "Flow Packets/s": round(total_pkts / duration, 6),

        "Flow IAT Mean": round(flow_iat["mean"], 6),
        "Flow IAT Std": round(flow_iat["std"], 6),
        "Flow IAT Max": round(flow_iat["max"], 6),
        "Flow IAT Min": round(flow_iat["min"], 6),

        "Fwd IAT Total": round(fwd_iat["total"], 6),
        "Fwd IAT Mean": round(fwd_iat["mean"], 6),
        "Fwd IAT Std": round(fwd_iat["std"], 6),
        "Fwd IAT Max": round(fwd_iat["max"], 6),
        "Fwd IAT Min": round(fwd_iat["min"], 6),

        "Bwd IAT Total": round(bwd_iat["total"], 6),
        "Bwd IAT Mean": round(bwd_iat["mean"], 6),
        "Bwd IAT Std": round(bwd_iat["std"], 6),
        "Bwd IAT Max": round(bwd_iat["max"], 6),
        "Bwd IAT Min": round(bwd_iat["min"], 6),

        "FIN Flag Count": flow["flags"]["FIN"],
        "SYN Flag Count": flow["flags"]["SYN"],
        "RST Flag Count": flow["flags"]["RST"],
        "PSH Flag Count": flow["flags"]["PSH"],
        "ACK Flag Count": flow["flags"]["ACK"],
        "URG Flag Count": flow["flags"]["URG"],
        "CWR Flag Count": flow["flags"]["CWR"],
        "ECE Flag Count": flow["flags"]["ECE"],

        "Average Packet Size": round(total_bytes / total_pkts, 6) if total_pkts else 0,
        "Down/Up Ratio": round(down_up_ratio, 6),
        "Fwd Segment Size Avg": round(fwd_segment_size_avg, 6),
        "Bwd Segment Size Avg": round(bwd_segment_size_avg, 6),
        "Active Mean": round(active_mean, 6),
        "Active Std": round(active_std, 6),
        "Active Max": round(active_max, 6),
        "Active Min": round(active_min, 6),
        "Idle Mean": round(idle_mean, 6),
        "Idle Std": round(idle_std, 6),
        "Idle Max": round(idle_max, 6),
        "Idle Min": round(idle_min, 6),
    }

    print("\n📡 Extracted Flow Features:")
    print(json.dumps(feature_json, indent=2))

# ✅ MAIN
if __name__ == "__main__":
    print("🟢 Starting live traffic capture...")
    print("⚠ Run as Administrator (Windows) or sudo (Linux)")
    iface_to_use = r"\Device\NPF_{13B043A5-C98B-417E-8803-C58669DBBB34}"  # change if needed
    sniff(prn=process_packet, store=False, iface=iface_to_use)
