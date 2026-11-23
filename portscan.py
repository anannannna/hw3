import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr, send
from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR

conf.verb = 0


def parse_port_spec(spec: str) -> tuple[str, set[int]]:
    parts = spec.split("/", 1)
    proto = parts[0].lower()

    if proto not in ("tcp", "udp"):
        raise ValueError(f"Неизвестный протокол '{proto}'. Ожидается 'tcp' или 'udp'")

    if len(parts) == 1:
        return proto, set(range(1, 65536))

    ports_str = parts[1]
    if not ports_str:
        raise ValueError(f"Не указаны порты после '/' в аргументе '{spec}'")

    ports: set[int] = set()
    for chunk in ports_str.split(","):
        if not chunk:
            raise ValueError(f"Пустой элемент в списке портов '{spec}'")

        if "-" in chunk:
            bounds = chunk.split("-")
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                raise ValueError(f"Некорректный диапазон портов '{chunk}' в '{spec}'.")
            start, end = int(bounds[0]), int(bounds[1])
            if not (1 <= start <= 65535 and 1 <= end <= 65535) or start > end:
                raise ValueError(f"Диапазон портов '{chunk}' выходит за пределы 1-65535 или некорректен")
            ports.update(range(start, end + 1))
        else:
            if not chunk.isdigit():
                raise ValueError(f"Некорректный номер порта '{chunk}' в '{spec}'")
            port = int(chunk)
            if not (1 <= port <= 65535):
                raise ValueError(f"Порт '{port}' выходит за пределы 1-65535")
            ports.add(port)

    return proto, ports


def parse_args(argv: list[str] or None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="Сканер TCP и UDP портов",
        usage="portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]..."
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="таймаут ожидания ответа в секундах (по умолчанию 2с)"
    )
    parser.add_argument(
        "-j", "--num-threads",
        type=int,
        default=1,
        help="число потоков"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="подробный режим (время получения ответа в мс для TCP)"
    )
    parser.add_argument(
        "ip_address",
        metavar="IP_ADDRESS",
        help="IPv4-адрес"
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="{tcp|udp}[/[PORT|PORT-PORT],...]"
    )

    args = parser.parse_intermixed_args(argv)

    if args.timeout <= 0:
        parser.error("значение --timeout должно быть больше 0")
    if args.num_threads < 1:
        parser.error("значение -j/--num-threads должно быть не меньше 1")

    try:
        ipaddress.IPv4Address(args.ip_address)
    except ipaddress.AddressValueError:
        parser.error(f"некорректный IPv4-адрес: '{args.ip_address}'")

    tcp_ports: set[int] = set()
    udp_ports: set[int] = set()

    if not args.targets:
        tcp_ports = set(range(1, 65536))
        udp_ports = set(range(1, 65536))
    else:
        for spec in args.targets:
            try:
                proto, ports = parse_port_spec(spec)
            except ValueError as exc:
                parser.error(str(exc))
                raise SystemExit(2)

            if proto == "tcp":
                tcp_ports.update(ports)
            else:
                udp_ports.update(ports)

    args.tcp_ports = sorted(tcp_ports)
    args.udp_ports = sorted(udp_ports)

    return args


def chunked(items: list[int], size: int = 500):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _scan_tcp_chunk(target_ip: str, port_chunk: list[int], timeout: float) -> list[tuple[int, float]]:
    packets = IP(dst=target_ip) / TCP(dport=port_chunk, flags="S")
    answered, _ = sr(packets, timeout=timeout)

    chunk_open: list[tuple[int, float]] = []
    rst_packets = []

    for sent, received in answered:
        if received.haslayer(TCP):
            tcp_layer = received.getlayer(TCP)
            if tcp_layer.flags == 0x12:
                rtt_ms = (received.time - sent.time) * 1000
                chunk_open.append((sent[TCP].dport, round(rtt_ms, 2)))

                rst = IP(dst=target_ip) / TCP(
                    sport=sent[TCP].sport,
                    dport=sent[TCP].dport,
                    seq=tcp_layer.ack,
                    flags="R"
                )
                rst_packets.append(rst)

    if rst_packets:
        send(rst_packets)

    return chunk_open


def scan_tcp_syn(
    target_ip: str,
    ports: list[int],
    timeout: float = 2.0,
    num_threads: int = 1,
    verbose: bool = False
) -> None:
    if not ports:
        return

    chunks = list(chunked(ports, 500))

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(_scan_tcp_chunk, target_ip, chunk, timeout)
            for chunk in chunks
        ]
        for future in as_completed(futures):
            for port, rtt in sorted(future.result(), key=lambda x: x[0]):
                if verbose:
                    print(f"TCP {port} {rtt}", flush=True)
                else:
                    print(f"TCP {port}", flush=True)


def build_udp_packet(target_ip: str, port: int):
    if port == 53:
        return IP(dst=target_ip) / UDP(dport=port) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    if port == 7:
        return IP(dst=target_ip) / UDP(dport=port) / Raw(load=b"PING")
    return IP(dst=target_ip) / UDP(dport=port)


def _scan_udp_chunk(target_ip: str, port_chunk: list[int], timeout: float) -> list[int]:
    packets = [build_udp_packet(target_ip, p) for p in port_chunk]
    answered, unanswered = sr(packets, timeout=timeout)

    chunk_open: list[int] = []

    for sent, received in answered:
        if received.haslayer(UDP):
            chunk_open.append(sent[UDP].dport)

    for sent in unanswered:
        chunk_open.append(sent[UDP].dport)

    return chunk_open


def scan_udp(
    target_ip: str,
    ports: list[int],
    timeout: float = 2.0,
    num_threads: int = 1
) -> None:
    if not ports:
        return

    chunks = list(chunked(ports, 500))

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(_scan_udp_chunk, target_ip, chunk, timeout)
            for chunk in chunks
        ]
        for future in as_completed(futures):
            for port in sorted(future.result()):
                print(f"UDP {port}", flush=True)


def main():
    args = parse_args()

    if args.tcp_ports:
        scan_tcp_syn(
            args.ip_address,
            args.tcp_ports,
            timeout=args.timeout,
            num_threads=args.num_threads,
            verbose=args.verbose
        )

    if args.udp_ports:
        scan_udp(
            args.ip_address,
            args.udp_ports,
            timeout=args.timeout,
            num_threads=args.num_threads
        )


if __name__ == "__main__":
    main()
