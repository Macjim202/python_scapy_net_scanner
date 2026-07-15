from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime, timezone

def _packet_to_dict(pkt) -> dict:
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "summary": pkt.summary(),
        "src": None,
        "dst": None,
        "proto": None,
        "sport": None,
        "dport": None,
    }
    if pkt.haslayer(IP):
        entry["src"] = pkt[IP].src
        entry["dst"] = pkt[IP].dst
    if pkt.haslayer(TCP):
        entry["proto"] = "TCP"
        entry["sport"] = pkt[TCP].sport
        entry["dport"] = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        entry["proto"] = "UDP"
        entry["sport"] = pkt[UDP].sport
        entry["dport"] = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        entry["proto"] = "ICMP"
    return entry

def capture_traffic(
    duration: int = 10,
    bpf_filter: str = None,
    iface: str = None,
    max_packets: int = 0,
) -> list[dict]:
    captured = []
    def handle_packet(pkt):
        captured.append(_packet_to_dict(pkt))
    sniff(
        filter=bpf_filter,
        iface=iface,
        timeout=duration,
        count=max_packets,
        prn=handle_packet,
        store=False,
    )
    return captured

if __name__ == "__main__":
    import sys
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    bpf = sys.argv[2] if len(sys.argv) > 2 else None
    print(f"Перехват трафика {seconds} сек. (фильтр: {bpf or 'нет'})...")
    packets = capture_traffic(duration=seconds, bpf_filter=bpf)
    print(f"\nПерехвачено пакетов: {len(packets)}")
    for p in packets:
        proto = p["proto"] or "-"
        src = p["src"] or "-"
        dst = p["dst"] or "-"
        print(f"  [{proto:<5}] {src} -> {dst}  {p['summary']}")