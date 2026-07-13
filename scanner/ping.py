from scapy.all import ARP, Ether, IP, ICMP, srp, sr1
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import ipaddress


def make_host(ip: str, mac: str | None = None, ttl: int | None = None) -> dict:
    return {
        "ip": ip,
        "mac": mac,
        "ttl": ttl,
        "os_guess": None,
        "ports": [],
        "traceroute": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def arp_scan(network: str, timeout: int = 2) -> list[dict]:
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=timeout, verbose=0)[0]

    hosts = []
    for sent, received in result:
        hosts.append(make_host(ip=received.psrc, mac=received.hwsrc))

    return sorted(hosts, key=lambda h: ipaddress.ip_address(h["ip"]))


def icmp_ping(ip: str, timeout: int = 1) -> dict | None:
    pkt = IP(dst=ip) / ICMP()
    reply = sr1(pkt, timeout=timeout, verbose=0)

    if reply is None:
        return None

    return make_host(ip=ip, ttl=reply.ttl)


def icmp_sweep(network: str, max_workers: int = 50, timeout: int = 1) -> list[dict]:
    try:
        net = ipaddress.ip_network(network, strict=False)
        targets = [str(ip) for ip in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError as e:
        raise ValueError(f"Некорректный адрес или сеть: {e}")

    alive = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(icmp_ping, ip, timeout): ip for ip in targets}

        for future in as_completed(futures):
            host = future.result()
            if host is not None:
                alive.append(host)

    return sorted(alive, key=lambda h: ipaddress.ip_address(h["ip"]))


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Использование:")
        print("  python ping.py arp 192.168.1.0/24")
        print("  python ping.py icmp 8.8.8.8")
        print("  python ping.py icmp 8.8.8.0/28")
        sys.exit(1)

    mode = sys.argv[1]
    target = sys.argv[2]

    if mode == "arp":
        found = arp_scan(target)
    elif mode == "icmp":
        found = icmp_sweep(target)
    else:
        print(f"Неизвестный режим: {mode} (доступно: arp, icmp)")
        sys.exit(1)

    if found:
        print(f"\nНайдено хостов: {len(found)}")
        for host in found:
            mac = host["mac"] or "-"
            ttl = host["ttl"] or "-"
            print(f"  {host['ip']:<16} MAC: {mac:<18} TTL: {ttl}")
    else:
        print("Активные хосты не найдены.")