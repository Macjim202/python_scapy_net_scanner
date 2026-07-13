import os
import sys
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.panel import Panel
from scanner import ping, ports, traceroute, sniffer, history, report

console = Console()

session = {
    "hosts": [],
    "last_sniff": [],
}


def check_root() -> None:
    if os.name != "nt" and os.geteuid() != 0:
        if not Confirm.ask("Продолжить без root? (большинство функций не будет работать)", default=False):
            console.print("[red]Завершение работы: запустите программу через sudo.[/red]")
            sys.exit(0)


def print_header() -> None:
    console.print(Panel(
        "[bold cyan]Сканер сетей[/bold cyan]",
        style="cyan",
    ))


def action_scan_local() -> None:
    network = Prompt.ask("Введите сеть в формате CIDR", default="192.168.1.0/24")

    console.print(f"[cyan]Сканирование локальной сети {network} (ARP)...[/cyan]")
    hosts = ping.arp_scan(network)
    session["hosts"] = hosts

    console.print(f"[green]Найдено хостов: {len(hosts)}[/green]")
    report.print_hosts_table(hosts, title=f"ARP-скан: {network}")


def action_scan_external() -> None:
    target = Prompt.ask("Введите IP или CIDR-диапазон", default="8.8.8.8")

    console.print(f"[cyan]Сканирование через ICMP: {target}...[/cyan]")
    try:
        hosts = ping.icmp_sweep(target)
    except ValueError as e:
        console.print(f"[red]Ошибка: {e}[/red]")
        return

    session["hosts"] = hosts

    console.print(f"[green]Найдено хостов: {len(hosts)}[/green]")
    report.print_hosts_table(hosts, title=f"ICMP-скан: {target}")


def action_scan_ports() -> None:
    if not session["hosts"]:
        console.print("[yellow]Сначала выполните сканирование сети (пункты 1 или 2).[/yellow]")
        return

    ips = [h["ip"] for h in session["hosts"]]
    console.print("Найденные хосты: " + ", ".join(ips))

    target_ip = Prompt.ask("Введите IP хоста для сканирования портов (или 'all' для всех)", default=ips[0])

    ports_input = Prompt.ask(
        "Порты через запятую (Enter — стандартный список)",
        default="",
    )
    port_list = [int(p.strip()) for p in ports_input.split(",")] if ports_input.strip() else None

    targets = session["hosts"] if target_ip.lower() == "all" else [
        h for h in session["hosts"] if h["ip"] == target_ip
    ]

    if not targets:
        console.print(f"[red]Хост {target_ip} не найден среди отсканированных.[/red]")
        return

    for host in targets:
        console.print(f"[cyan]Сканирование портов {host['ip']}...[/cyan]")
        ports.scan_host(host, ports=port_list)

    report.print_hosts_table(session["hosts"], title="Результаты с портами и ОС")


def action_traceroute() -> None:
    if not session["hosts"]:
        target = Prompt.ask("Введите IP для трассировки", default="8.8.8.8")
        host = {"ip": target, "traceroute": None}
    else:
        ips = [h["ip"] for h in session["hosts"]]
        target = Prompt.ask("Введите IP хоста для трассировки", default=ips[0])
        host = next((h for h in session["hosts"] if h["ip"] == target), {"ip": target, "traceroute": None})

    max_ttl = IntPrompt.ask("Максимальное число хопов", default=20)

    console.print(f"[cyan]Трассировка маршрута до {host['ip']}...[/cyan]")
    traceroute.traceroute_host(host, max_ttl=max_ttl)
    report.print_traceroute(host)


def action_sniff() -> None:
    duration = IntPrompt.ask("Сколько секунд слушать трафик", default=10)
    bpf = Prompt.ask("BPF-фильтр (Enter — без фильтра, например: tcp, icmp, tcp port 80)", default="")
    bpf_filter = bpf.strip() or None

    console.print(f"[cyan]Перехват трафика {duration} сек. (фильтр: {bpf_filter or 'нет'})...[/cyan]")
    packets = sniffer.capture_traffic(duration=duration, bpf_filter=bpf_filter)
    session["last_sniff"] = packets

    report.print_sniff_results(packets)


def action_compare_scans() -> None:
    if not session["hosts"]:
        console.print("[yellow]Сначала выполните сканирование сети.[/yellow]")
        return

    previous = history.load_previous_scan()

    if previous is None:
        console.print("[yellow]Предыдущих сканов не найдено — сравнивать не с чем.[/yellow]")
    else:
        diff = history.compare_scans(previous, session["hosts"])
        report.print_diff(diff)

    if Confirm.ask("Сохранить текущий скан для дальнейших сравнений?", default=True):
        filepath = history.save_scan(session["hosts"])
        console.print(f"[green]Скан сохранён: {filepath}[/green]")


def action_export() -> None:
    if not session["hosts"]:
        console.print("[yellow]Сначала выполните сканирование сети.[/yellow]")
        return

    output_dir = Prompt.ask("Папка для сохранения отчёта", default="./reports")

    filepath = report.export_report(session["hosts"], fmt="json", output_dir=output_dir)
    console.print(f"[green]Отчёт сохранён: {filepath}[/green]")


def action_about() -> None:
    console.print(Panel(
        "[bold cyan]Сканер сетей[/bold cyan]\n\n"
        "Автор: Зайцев Максим Сергеевич\n"
        "Группа: ИБКСб-25-1\n"
        "Стек: Python, Scapy, Rich, html",
        title="Об авторе",
        style="cyan",
    ))


MENU_ACTIONS = {
    "1": ("Сканировать локальную сеть (ARP)", action_scan_local),
    "2": ("Сканировать внешний хост/сеть (ICMP)", action_scan_external),
    "3": ("Сканировать порты найденного хоста", action_scan_ports),
    "4": ("Трассировка маршрута", action_traceroute),
    "5": ("Перехват трафика", action_sniff),
    "6": ("Сравнить с предыдущим сканом / сохранить", action_compare_scans),
    "7": ("Экспортировать отчёт", action_export),
    "8": ("Об авторе", action_about),
    "0": ("Выход", None),
}


def print_menu() -> None:
    console.print()
    for key, (label, _) in MENU_ACTIONS.items():
        console.print(f"  [bold cyan]{key}[/bold cyan]. {label}")
    console.print()


def main() -> None:
    check_root()
    print_header()

    while True:
        print_menu()
        choice = Prompt.ask("Выберите пункт меню", choices=list(MENU_ACTIONS.keys()), default="1")

        if choice == "0":
            console.print("[cyan]Завершение работы.[/cyan]")
            break

        _, action = MENU_ACTIONS[choice]
        try:
            action()
        except KeyboardInterrupt:
            console.print("\n[yellow]Действие прервано пользователем.[/yellow]")
        except Exception as e:
            console.print(f"[red]Ошибка: {e}[/red]")


if __name__ == "__main__":
    main()