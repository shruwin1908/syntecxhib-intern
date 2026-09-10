import argparse
import ipaddress
import logging
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
 
# ----------------------------------------------------------------------
# Logging setup: logs to both console and a timestamped log file
# ----------------------------------------------------------------------
LOG_FILENAME = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
 
logger = logging.getLogger("port_scanner")
logger.setLevel(logging.DEBUG)
 
file_handler = logging.FileHandler(LOG_FILENAME)
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(file_formatter)
 
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter("%(message)s")
console_handler.setFormatter(console_formatter)
 
logger.addHandler(file_handler)
logger.addHandler(console_handler)
 
# Thread-safe counters for a summary at the end
lock = threading.Lock()
results_summary = {"open": 0, "closed": 0, "timeout": 0, "error": 0}
 
 
# ----------------------------------------------------------------------
# Core scanning logic
# ----------------------------------------------------------------------
def scan_port(host: str, port: int, timeout: float = 1.0) -> None:
    """
    Attempt a TCP connection to (host, port).
    Logs and counts the result: open / closed / timeout / error.
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))  # 0 == success (open)
 
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            logger.info(f"[OPEN]    {host}:{port:<5} ({service})")
            with lock:
                results_summary["open"] += 1
        else:
            logger.debug(f"[CLOSED]  {host}:{port}")
            with lock:
                results_summary["closed"] += 1
 
    except socket.timeout:
        logger.debug(f"[TIMEOUT] {host}:{port}")
        with lock:
            results_summary["timeout"] += 1
 
    except socket.gaierror:
        logger.error(f"[ERROR]   Could not resolve host: {host}")
        with lock:
            results_summary["error"] += 1
 
    except OSError as e:
        # Covers "network unreachable", "permission denied" (raw sockets),
        # "too many open files", etc.
        logger.error(f"[ERROR]   {host}:{port} -> {e}")
        with lock:
            results_summary["error"] += 1
 
    except Exception as e:
        logger.error(f"[ERROR]   Unexpected error on {host}:{port} -> {e}")
        with lock:
            results_summary["error"] += 1
 
    finally:
        if sock:
            sock.close()
 
 
# ----------------------------------------------------------------------
# Helpers to parse CLI input into concrete lists
# ----------------------------------------------------------------------
def parse_ports(port_str: str) -> list:
    """
    Parses a port spec like "80", "20-25", or "22,80,443,8000-8010"
    into a sorted list of unique ints.
    """
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        elif part:
            ports.add(int(part))
 
    invalid = [p for p in ports if p < 1 or p > 65535]
    if invalid:
        raise ValueError(f"Invalid port number(s): {invalid}")
 
    return sorted(ports)
 
 
def parse_hosts(host: str = None, host_range: str = None) -> list:
    """
    Returns a list of host strings to scan.
    - --host: a single hostname or IP
    - --host-range: "192.168.1.1-192.168.1.5" style IP range
    """
    if host:
        return [host]
 
    if host_range:
        start_ip, end_ip = host_range.split("-")
        start = ipaddress.IPv4Address(start_ip.strip())
        end = ipaddress.IPv4Address(end_ip.strip())
        if int(start) > int(end):
            start, end = end, start
        return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]
 
    raise ValueError("Must provide either --host or --host-range")
 
 
# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="A multi-threaded TCP port scanner for educational/authorized use."
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--host", help="Single hostname or IP address to scan")
    target_group.add_argument(
        "--host-range",
        help="Range of IPs to scan, e.g. 192.168.1.1-192.168.1.10",
    )
 
    parser.add_argument(
        "--ports",
        required=True,
        help='Ports to scan, e.g. "80", "20-25", or "22,80,443,8000-8010"',
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent worker threads (default: 100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds per port (default: 1.0)",
    )
 
    args = parser.parse_args()
 
    try:
        hosts = parse_hosts(host=args.host, host_range=args.host_range)
        ports = parse_ports(args.ports)
    except ValueError as e:
        logger.error(f"Input error: {e}")
        sys.exit(1)
 
    logger.info(f"Starting scan on {len(hosts)} host(s), {len(ports)} port(s) each.")
    logger.info(f"Log file: {LOG_FILENAME}")
    logger.info("-" * 60)
 
    start_time = datetime.now()
 
    # Build the full list of (host, port) jobs and run them concurrently
    jobs = [(h, p) for h in hosts for p in ports]
 
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, args.timeout): (host, port)
            for host, port in jobs
        }
        for future in as_completed(futures):
            # scan_port already handles its own exceptions internally,
            # but this guards against anything unexpected escaping the thread.
            try:
                future.result()
            except Exception as e:
                host, port = futures[future]
                logger.error(f"[ERROR]   Unhandled exception for {host}:{port} -> {e}")
 
    elapsed = (datetime.now() - start_time).total_seconds()
 
    logger.info("-" * 60)
    logger.info(
        f"Scan complete in {elapsed:.2f}s | "
        f"Open: {results_summary['open']} | "
        f"Closed: {results_summary['closed']} | "
        f"Timeouts: {results_summary['timeout']} | "
        f"Errors: {results_summary['error']}"
    )
    logger.info(f"Full results (including closed ports) saved to: {LOG_FILENAME}")
 
 
if __name__ == "__main__":
    main()
 
