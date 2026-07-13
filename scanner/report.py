import json
import csv
import os
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def print_hosts_table(hosts: list[dict], title: str = "Результаты сканирования") -> None:
    if not hosts:
        console.print(Panel("Хосты не найдены.", title=title, style="red"))
        return

    table = Table(title=title)
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("TTL", style="yellow")
    table.add_column("ОС (предположительно)", style="green")
    table.add_column("Открытые порты", style="white")

    for host in hosts:
        open_ports = [str(p["port"]) for p in host.get("ports", []) if p["status"] == "open"]
        ports_str = ", ".join(open_ports) if open_ports else "-"

        table.add_row(
            host.get("ip", "-"),
            host.get("mac") or "-",
            str(host.get("ttl")) if host.get("ttl") is not None else "-",
            host.get("os_guess") or "-",
            ports_str,
        )

    console.print(table)


def print_traceroute(host: dict) -> None:
    hops = host.get("traceroute")
    if not hops:
        console.print(Panel("Traceroute не выполнялся.", style="red"))
        return

    table = Table(title=f"Маршрут до {host['ip']}")
    table.add_column("Хоп", style="cyan")
    table.add_column("IP", style="white")
    table.add_column("RTT (мс)", style="yellow")

    for hop in hops:
        ip = hop["ip"] or "*"
        rtt = str(hop["rtt_ms"]) if hop["rtt_ms"] is not None else "-"
        table.add_row(str(hop["ttl"]), ip, rtt)

    console.print(table)


def print_sniff_results(packets: list[dict]) -> None:
    if not packets:
        console.print(Panel("Пакеты не перехвачены.", style="red"))
        return

    table = Table(title=f"Перехваченный трафик ({len(packets)} пакетов)")
    table.add_column("Протокол", style="cyan")
    table.add_column("Источник", style="white")
    table.add_column("Назначение", style="white")
    table.add_column("Порты (src->dst)", style="yellow")

    for p in packets:
        ports = f"{p['sport']} -> {p['dport']}" if p["sport"] and p["dport"] else "-"
        table.add_row(p["proto"] or "-", p["src"] or "-", p["dst"] or "-", ports)

    console.print(table)


def print_diff(diff: dict) -> None:
    new_hosts = diff.get("new_hosts", [])
    removed_hosts = diff.get("removed_hosts", [])
    changed_hosts = diff.get("changed_hosts", [])

    if not new_hosts and not removed_hosts and not changed_hosts:
        console.print(Panel("Изменений с прошлого скана нет.", style="green"))
        return

    if new_hosts:
        table = Table(title="Новые хосты")
        table.add_column("IP", style="green")
        table.add_column("MAC", style="magenta")
        for h in new_hosts:
            table.add_row(h["ip"], h.get("mac") or "-")
        console.print(table)

    if removed_hosts:
        table = Table(title="Пропавшие хосты")
        table.add_column("IP", style="red")
        table.add_column("MAC", style="magenta")
        for h in removed_hosts:
            table.add_row(h["ip"], h.get("mac") or "-")
        console.print(table)

    if changed_hosts:
        table = Table(title="Изменения портов")
        table.add_column("IP", style="cyan")
        table.add_column("Открылись", style="yellow")
        table.add_column("Закрылись", style="green")
        for c in changed_hosts:
            opened = ", ".join(map(str, c["opened_ports"])) or "-"
            closed = ", ".join(map(str, c["closed_ports"])) or "-"
            table.add_row(c["ip"], opened, closed)
        console.print(table)


def export_json(hosts: list[dict], filepath: str) -> str:
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(hosts, f, ensure_ascii=False, indent=2)
    return filepath


def export_csv(hosts: list[dict], filepath: str) -> str:
    with open(filepath, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "mac", "ttl", "os_guess", "open_ports"])

        for host in hosts:
            open_ports = [str(p["port"]) for p in host.get("ports", []) if p["status"] == "open"]
            writer.writerow([
                host.get("ip", ""),
                host.get("mac") or "",
                host.get("ttl") if host.get("ttl") is not None else "",
                host.get("os_guess") or "",
                ";".join(open_ports),
            ])

    return filepath


def export_html(hosts: list[dict], filepath: str, title: str = "Отчёт сканирования сети") -> str:
    rows = ""
    for host in hosts:
        open_ports = [str(p["port"]) for p in host.get("ports", []) if p["status"] == "open"]
        rows += f"""
        <tr>
            <td>{host.get('ip', '-')}</td>
            <td>{host.get('mac') or '-'}</td>
            <td>{host.get('ttl') if host.get('ttl') is not None else '-'}</td>
            <td>{host.get('os_guess') or '-'}</td>
            <td>{', '.join(open_ports) or '-'}</td>
        </tr>"""

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
    h1 {{ color: #222; }}
    table {{ border-collapse: collapse; width: 100%; background: white; }}
    th, td {{ border: 1px solid #ccc; padding: 8px 12px; text-align: left; }}
    th {{ background: #333; color: white; }}
    tr:nth-child(even) {{ background: #f0f0f0; }}
    .meta {{ color: #666; margin-bottom: 20px; }}
</style>
</head>
<body>
    <h1>{title}</h1>
    <p class="meta">Сгенерировано: {generated_at}</p>
    <table>
        <tr>
            <th>IP</th>
            <th>MAC</th>
            <th>TTL</th>
            <th>ОС (предположительно)</th>
            <th>Открытые порты</th>
        </tr>
        {rows}
    </table>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath


def export_report(hosts: list[dict], fmt: str, output_dir: str = ".") -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    fmt = fmt.lower()
    if fmt == "json":
        return export_json(hosts, os.path.join(output_dir, f"report_{timestamp}.json"))
    elif fmt == "csv":
        return export_csv(hosts, os.path.join(output_dir, f"report_{timestamp}.csv"))
    elif fmt == "html":
        return export_html(hosts, os.path.join(output_dir, f"report_{timestamp}.html"))
    else:
        raise ValueError(f"Неизвестный формат экспорта: {fmt} (доступно: json, csv, html)")