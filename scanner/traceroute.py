from scapy.all import IP, ICMP, sr1


def traceroute(dst: str, max_ttl: int = 20, timeout: int = 1) -> list[dict]:
    hops = []

    for ttl in range(1, max_ttl + 1):
        pkt = IP(dst=dst, ttl=ttl) / ICMP()

        sent_time = pkt.sent_time
        reply = sr1(pkt, timeout=timeout, verbose=0)

        if reply is None:
            hops.append({"ttl": ttl, "ip": None, "rtt_ms": None})
            continue

        rtt_ms = None
        if reply.time and pkt.sent_time:
            rtt_ms = round((reply.time - pkt.sent_time) * 1000, 2)

        hops.append({"ttl": ttl, "ip": reply.src, "rtt_ms": rtt_ms})

        if reply.src == dst:
            break

    return hops


def traceroute_host(host: dict, max_ttl: int = 20, timeout: int = 1) -> dict:
    host["traceroute"] = traceroute(host["ip"], max_ttl=max_ttl, timeout=timeout)
    return host


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Использование: python traceroute.py <ip> [max_ttl]")
        sys.exit(1)

    target = sys.argv[1]
    max_hops = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    print(f"Трассировка маршрута до {target}...\n")
    result = traceroute(target, max_ttl=max_hops)

    for hop in result:
        ip = hop["ip"] or "*"
        rtt = f"{hop['rtt_ms']} мс" if hop["rtt_ms"] is not None else "-"
        print(f"  {hop['ttl']:<3} {ip:<16} {rtt}")