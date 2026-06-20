"""
Network Port Scanner (Eğitim Amaçlı)
=======================================
Çok iş parçacıklı (multi-threaded) basit bir TCP port tarayıcı.
Yaygın servis portlarını tanır ve sonuçları okunabilir bir tabloda gösterir.

ÖNEMLİ - YASAL UYARI:
Bu aracı SADECE kendi sahip olduğunuz veya tarama izniniz olan
sistemlerde/ağlarda kullanın (örn. kendi ev ağınız, localhost, kendi
sunucularınız, ya da CTF/lab ortamları). İzinsiz port taraması birçok
ülkede yasalara aykırıdır ve yetkisiz erişim girişimi olarak
değerlendirilebilir. Bu araç tamamen eğitim ve ağ yönetimi amaçlıdır.

Kullanım:
    python port_scanner.py 192.168.1.1                    # Yaygın portları tara
    python port_scanner.py localhost --ports 1-1024        # Port aralığı
    python port_scanner.py 192.168.1.1 --ports 22,80,443   # Belirli portlar
    python port_scanner.py 10.0.0.5 --threads 100 --timeout 0.5
"""

import argparse
import socket
import sys
import threading
import time
from queue import Queue

# Yaygın portlar ve bilinen servisleri
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

COLORS = {
    "green": "\033[92m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}

print_lock = threading.Lock()


def is_private_or_local(host: str) -> bool:
    """Hedefin yerel/özel bir adres olup olmadığını kontrol eder (ek güvenlik için bilgilendirme amaçlı)."""
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return False

    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.",
                          "172.24.", "172.25.", "172.26.", "172.27.",
                          "172.28.", "172.29.", "172.30.", "172.31.",
                          "192.168.", "127.")
    return ip.startswith(private_prefixes) or ip == "::1"


def parse_ports(port_spec: str) -> list:
    """'80,443' veya '1-1024' veya '22,80,1000-2000' formatlarını parse eder."""
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def scan_port(host: str, port: int, timeout: float, results: list):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "bilinmeyen")
            with print_lock:
                results.append((port, service))
                print(f"  {COLORS['green']}●{COLORS['reset']} Port {port:<6} {COLORS['bold']}AÇIK{COLORS['reset']}   ({service})")
    except socket.error:
        pass
    finally:
        sock.close()


def worker(host: str, queue: Queue, timeout: float, results: list):
    while not queue.empty():
        try:
            port = queue.get_nowait()
        except Exception:
            return
        scan_port(host, port, timeout, results)
        queue.task_done()


def run_scan(host: str, ports: list, num_threads: int, timeout: float) -> list:
    queue = Queue()
    for port in ports:
        queue.put(port)

    results = []
    threads = []
    for _ in range(min(num_threads, len(ports))):
        t = threading.Thread(target=worker, args=(host, queue, timeout, results))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Eğitim amaçlı TCP port tarayıcı. SADECE kendi ağlarınızda kullanın.",
        epilog="Yasal uyarı: izinsiz tarama suç olabilir. Sorumluluk kullanıcıya aittir.",
    )
    parser.add_argument("host", type=str, help="Hedef IP adresi veya hostname")
    parser.add_argument("--ports", type=str, default=None,
                         help="Port listesi/aralığı (örn. '1-1024' veya '22,80,443'). Verilmezse yaygın portlar taranır.")
    parser.add_argument("--threads", type=int, default=50, help="Eşzamanlı iş parçacığı sayısı")
    parser.add_argument("--timeout", type=float, default=1.0, help="Bağlantı zaman aşımı (saniye)")
    parser.add_argument("--i-have-permission", action="store_true",
                         help="Bu hedefi taramak için izniniz olduğunu onaylar (zorunlu, dışarıdaki hedefler için)")
    args = parser.parse_args()

    local = is_private_or_local(args.host)

    if not local and not args.i_have_permission:
        print(f"{COLORS['red']}{COLORS['bold']}Uyarı:{COLORS['reset']} '{args.host}' yerel/özel bir adres gibi görünmüyor.")
        print("Genel internetteki sistemleri izinsiz taramak yasalara aykırı olabilir.")
        print("Eğer bu sistemi taramak için izniniz varsa, --i-have-permission bayrağını ekleyin.")
        sys.exit(1)

    ports = parse_ports(args.ports) if args.ports else sorted(COMMON_PORTS.keys())

    print(f"\n{COLORS['cyan']}{COLORS['bold']}Port Taraması: {args.host}{COLORS['reset']}")
    print(f"Taranan port sayısı: {len(ports)}  |  İş parçacığı: {args.threads}  |  Timeout: {args.timeout}s\n")

    start_time = time.time()
    results = run_scan(args.host, ports, args.threads, args.timeout)
    elapsed = time.time() - start_time

    print(f"\n{COLORS['bold']}Tarama tamamlandı.{COLORS['reset']} {elapsed:.2f} saniye sürdü.")
    print(f"Açık port sayısı: {len(results)} / {len(ports)}")

    if not results:
        print(f"{COLORS['yellow']}Hiçbir açık port bulunamadı (veya hedef erişilemiyor).{COLORS['reset']}")


if __name__ == "__main__":
    main()
