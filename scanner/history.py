import json
import os
from datetime import datetime, timezone

SCANS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scans")


def save_scan(hosts: list[dict], scans_dir: str = SCANS_DIR) -> str:
    os.makedirs(scans_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{timestamp}.json"
    filepath = os.path.join(scans_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(hosts, f, ensure_ascii=False, indent=2)

    return filepath


def list_scans(scans_dir: str = SCANS_DIR) -> list[str]:
    if not os.path.isdir(scans_dir):
        return []

    files = [f for f in os.listdir(scans_dir) if f.startswith("scan_") and f.endswith(".json")]
    files.sort()

    return [os.path.join(scans_dir, f) for f in files]


def load_scan(filepath: str) -> list[dict]:
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def load_previous_scan(scans_dir: str = SCANS_DIR) -> list[dict] | None:
    scans = list_scans(scans_dir)
    if not scans:
        return None

    return load_scan(scans[-1])


def _ports_by_number(host: dict) -> dict[int, str]:
    return {p["port"]: p["status"] for p in host.get("ports", [])}


def compare_scans(old_hosts: list[dict], new_hosts: list[dict]) -> dict:
    old_by_ip = {h["ip"]: h for h in old_hosts}
    new_by_ip = {h["ip"]: h for h in new_hosts}

    old_ips = set(old_by_ip.keys())
    new_ips = set(new_by_ip.keys())

    appeared = sorted(new_ips - old_ips)
    disappeared = sorted(old_ips - new_ips)
    common = sorted(old_ips & new_ips)

    changed = []
    for ip in common:
        old_ports = _ports_by_number(old_by_ip[ip])
        new_ports = _ports_by_number(new_by_ip[ip])

        opened = [p for p, status in new_ports.items()
                  if status == "open" and old_ports.get(p) != "open"]
        closed = [p for p, status in old_ports.items()
                  if status == "open" and new_ports.get(p) != "open"]

        if opened or closed:
            changed.append({
                "ip": ip,
                "opened_ports": sorted(opened),
                "closed_ports": sorted(closed),
            })

    return {
        "new_hosts": [new_by_ip[ip] for ip in appeared],
        "removed_hosts": [old_by_ip[ip] for ip in disappeared],
        "changed_hosts": changed,
    }


if __name__ == "__main__":
    scans = list_scans()
    print(f"Сохранённых сканов: {len(scans)}")
    for s in scans:
        print(f"  {s}")