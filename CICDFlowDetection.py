from scapy.all import sniff, IP, TCP, UDP
import time, json, statistics

flows = {}
MAX_PACKETS_PER_FLOW = 10

def get_flow_key(pkt):
    if IP not in pkt:
        return None
    proto = 6 if TCP in pkt else 17 if UDP in pkt else 0
    if proto == 0:
        return None
    sport = pkt[TCP].sport if proto == 6 else pkt[UDP].sport
    dport = pkt[TCP].dport if proto == 6 else pkt[UDP].dport
    return (pkt[IP].src, pkt[IP].dst, sport, dport, proto)

def process_packet(pkt):
    key = get_flow_key(pkt)
    if not key:
        return

    now = time.time()

    if key not in flows:
        flows[key] = {
            "start": now,
            "end": now,
            "fwd_sizes": [],
            "bwd_sizes": [],
            "fwd_times": [],
            "bwd_times": [],
            "ack_count": 0,
            "fwd_ports": key[2],
            "dst_ports": key[3],
            "proto": key[4],
            "fwd_header_len": 0,
            "first_fwd_win": None
        }

    f = flows[key]
    f["end"] = now

    length = len(pkt)
    is_fwd = pkt[IP].src == key[0]

    if is_fwd:
        f["fwd_sizes"].append(length)
        f["fwd_times"].append(now)
        if TCP in pkt:
            f["fwd_header_len"] += pkt[TCP].dataofs * 4  # header length in bytes
            if f["first_fwd_win"] is None:
                f["first_fwd_win"] = pkt[TCP].window
    else:
        f["bwd_sizes"].append(length)
        f["bwd_times"].append(now)

    if TCP in pkt and pkt[TCP].flags.A:
        f["ack_count"] += 1

    if len(f["fwd_sizes"]) + len(f["bwd_sizes"]) >= MAX_PACKETS_PER_FLOW:
        export_flow(key)

def calc_iat(times):
    if len(times) < 2:
        return {"mean": 0, "std": 0}
    diffs = [t2 - t1 for t1, t2 in zip(times, times[1:])]
    return {
        "mean": statistics.mean(diffs),
        "std": statistics.stdev(diffs) if len(diffs) > 1 else 0
    }

def export_flow(key):
    f = flows.pop(key, None)
    if not f:
        return

    duration = max(f["end"] - f["start"], 1e-6)
    total_bytes = sum(f["fwd_sizes"]) + sum(f["bwd_sizes"])
    total_pkts = len(f["fwd_sizes"]) + len(f["bwd_sizes"])
    pkt_lengths = f["fwd_sizes"] + f["bwd_sizes"]

    iat = calc_iat(f["fwd_times"] + f["bwd_times"])

    feature_json = {
        "total_length_of_fwd_packets": sum(f["fwd_sizes"]),
        "source_port": f["fwd_ports"],
        "max_packet_length": max(pkt_lengths) if pkt_lengths else 0,
        "flow_bytes/s": round(total_bytes / duration, 6),
        "unnamed:_0": 0,  # can use incremental counter if needed
        "fwd_header_length": f["fwd_header_len"],
        "min_seg_size_forward": min(f["fwd_sizes"]) if f["fwd_sizes"] else 0,
        "flow_packets/s": round(total_pkts / duration, 6),
        "flow_duration": round(duration, 6),
        "flow_iat_mean": round(iat["mean"], 6),
        "init_win_bytes_forward": f["first_fwd_win"] or 0,
        "destination_port": f["dst_ports"],
        "total_fwd_packets": len(f["fwd_sizes"]),
        "flow_iat_std": round(iat["std"], 6),
        "ack_flag_count": f["ack_count"],
        "packet_length_variance": statistics.pvariance(pkt_lengths) if len(pkt_lengths) > 1 else 0,
    }

    print("\n📡 CICIDS Feature JSON:")
    print(json.dumps(feature_json, indent=2))

if __name__ == "__main__":
    print("🟢 Starting live CICIDS flow feature capture...")
    iface_to_use = r"\Device\NPF_{13B043A5-C98B-417E-8803-C58669DBBB34}"
    sniff(prn=process_packet, store=False, iface=iface_to_use)
