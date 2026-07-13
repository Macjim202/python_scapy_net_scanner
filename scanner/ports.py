from scapy.all import IP, TCP, sr1, send
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]


def scan_port(ip: str, port: int, timeout: int = 1) -> dict:
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)

    if resp is None:
        return {"port": port, "status": "filtered", "ttl": None}

    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags == 0x12:  # SYN-ACK
            send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=0)
            return {"port": port, "status": "open", "ttl": resp.ttl}
        elif flags == 0x14:  # RST-ACK
            return {"port": port, "status": "closed", "ttl": resp.ttl}

    return {"port": port, "status": "unknown", "ttl": resp.ttl}


def scan_ports(ip: str, ports: list[int] = None, max_workers: int = 50, timeout: int = 1) -> list[dict]:
    if ports is None:
        ports = DEFAULT_PORTS

    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}

        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda r: r["port"])


def guess_os(ttl: int | None) -> str | None:
    if ttl is None:
        return None

    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    elif ttl <= 255:
        return "Сетевое оборудование (роутер/свитч)"

    return None


def scan_host(host: dict, ports: list[int] = None, max_workers: int = 50, timeout: int = 1) -> dict:
    port_results = scan_ports(host["ip"], ports=ports, max_workers=max_workers, timeout=timeout)
    host["ports"] = port_results

    ttl = host.get("ttl")
    if ttl is None:
        for r in port_results:
            if r["ttl"] is not None:
                ttl = r["ttl"]
                break

    host["os_guess"] = guess_os(ttl)

    return host


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Использование: python ports.py <ip> [порты через запятую]")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_ports = [int(p) for p in sys.argv[2].split(",")] if len(sys.argv) > 2 else DEFAULT_PORTS

    print(f"Сканирование портов {target_ip}...")
    results = scan_ports(target_ip, target_ports)

    open_ports = [r for r in results if r["status"] == "open"]
    ttl_value = next((r["ttl"] for r in results if r["ttl"] is not None), None)

    print(f"\nРезультаты:")
    for r in results:
        print(f"  Порт {r['port']:<6} {r['status']}")

    print(f"\nПредполагаемая ОС: {guess_os(ttl_value)}")