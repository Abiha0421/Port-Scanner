#!/usr/bin/env python3
"""
tcp_port_scanner.py

- Scans single host or CIDR for TCP ports (single, list, range or top N).
- Performs banner grabbing and TLS cert CN probing.
- Prints newline-delimited JSON objects (JSONL) to stdout (one per scanned port).
- By default also prints a human-friendly (colored) summary to stderr.
- Use --json-only to output only JSON (recommended when run from GUI).
"""

from __future__ import annotations
import argparse
import concurrent.futures
import ipaddress
import json
import socket
import ssl
import sys
import time
from datetime import datetime
from typing import List, Tuple, Optional, Dict

# optional: colorama for pretty console output
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except Exception:
    Fore = Style = None


DEFAULT_TIMEOUT = 2.0
COMMON_TLS_PORTS = {443, 8443, 993, 995, 465, 636}


def parse_ports(ports_arg: Optional[str], top: Optional[int]) -> List[int]:
    if ports_arg:
        s = set()
        for part in ports_arg.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                a, b = part.split('-', 1)
                s.update(range(int(a), int(b) + 1))
            else:
                s.add(int(part))
        return sorted(p for p in s if 1 <= p <= 65535)
    if top and top > 0:
        return list(range(1, top + 1))
    # default common ports
    return [21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,587,636,990,993,995,3306,3389,5900,8000,8080,8443]


def expand_targets(target: str) -> List[str]:
    try:
        if '/' in target:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        ipaddress.ip_address(target)
        return [target]
    except Exception:
        # treat as hostname
        return [target]


def grab_banner(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Tuple[Optional[str], Optional[str]]:
    banner = None
    cert_cn = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(4096)
                if data:
                    banner = data.decode(errors='replace').strip()
            except Exception:
                banner = None

            # Try TLS certificate CN if likely TLS port
            try:
                if port in COMMON_TLS_PORTS or (banner and ('HTTP/' in banner or 'TLS' in banner or 'SSL' in banner)):
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host) as ssock:
                        ssock.settimeout(timeout)
                        ssock.connect((host, port))
                        cert = ssock.getpeercert()
                        subject = cert.get('subject', ())
                        for entry in subject:
                            for k, v in entry:
                                if k.lower() in ('commonname', 'cn'):
                                    cert_cn = v
                                    break
                            if cert_cn:
                                break
            except Exception:
                pass
    except Exception:
        return None, None
    return (banner[:200] if banner else None), cert_cn


def detect_service(port: int, banner: Optional[str]) -> str:
    try:
        serv = socket.getservbyport(port, 'tcp')
    except Exception:
        serv = None
    if banner:
        b = banner.lower()
        heur = [('ssh','ssh'), ('smtp','smtp'), ('http','http'), ('nginx','http'), ('apache','http'),
                ('ftp','ftp'), ('mysql','mysql'), ('mariadb','mysql'), ('rdp','rdp'),
                ('postgres','postgresql'), ('redis','redis'), ('mongodb','mongodb')]
        for key, name in heur:
            if key in b:
                return name
    return serv or 'unknown'


def scan_one(host: str, port: int, timeout: float) -> Dict:
    out = {
        'ts': datetime.utcnow().strftime('%H:%M:%S'),
        'host': host,
        'port': port,
        'open': False,
        'service': None,
        'banner': None,
        'cert_subject': None
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                out['open'] = True
                banner, cert = grab_banner(host, port, timeout)
                if banner:
                    out['banner'] = banner
                if cert:
                    out['cert_subject'] = cert
                out['service'] = detect_service(port, banner)
    except Exception:
        pass
    return out


def human_line(r: Dict) -> str:
    bp = r.get('banner') or 'N/A'
    service = r.get('service') or ''
    return f"[{r['ts']}] {r['host']}:{r['port']} open={r['open']} service={service} banner={bp}"


def main():
    parser = argparse.ArgumentParser(description='tcp_port_scanner (JSONL stdout for GUIs)')
    parser.add_argument('target', help='Target host, hostname, or CIDR (e.g. 192.168.1.0/28)')
    parser.add_argument('--ports', help='Ports (comma/range/single) e.g. 22,80,443 or 1-1024', default=None)
    parser.add_argument('--top', type=int, help='Top N ports', default=None)
    parser.add_argument('--timeout', type=float, help='Socket timeout (s)', default=DEFAULT_TIMEOUT)
    parser.add_argument('--threads', type=int, help='Worker threads', default=200)
    parser.add_argument('--csv', help='Export CSV path')
    parser.add_argument('--json', help='Export JSON (array) path')
    parser.add_argument('--pdf', help='Export PDF path (optional)')
    parser.add_argument('--json-only', action='store_true', help='Only output JSON lines (for GUI parsing)')
    args = parser.parse_args()

    ports = parse_ports(args.ports, args.top)
    targets = expand_targets(args.target)

    tasks: List[Tuple[str,int]] = []
    for t in targets:
        for p in ports:
            tasks.append((t, p))

    results = []
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads, max(1, len(tasks)))) as exe:
        future_to_task = {exe.submit(scan_one, h, p, args.timeout): (h,p) for h,p in tasks}
        for fut in concurrent.futures.as_completed(future_to_task):
            r = fut.result()
            results.append(r)
            # JSONL to stdout (GUI should read these lines)
            print(json.dumps(r, ensure_ascii=False), flush=True)
            # If not json-only, print human-friendly to stderr (so stdout remains pure JSONL)
            if not args.json_only:
                try:
                    if Fore and Style:
                        # colored output
                        status_col = (Fore.GREEN + '[OPEN]' + Style.RESET_ALL) if r.get('open') else (Fore.RED + '[CLOSED]' + Style.RESET_ALL)
                        sys.stderr.write(f"{Fore.CYAN}[{r['ts']}]{Style.RESET_ALL} {Fore.YELLOW}{r['host']}:{r['port']}{Style.RESET_ALL} {status_col} {Fore.MAGENTA}{r.get('service') or ''}{Style.RESET_ALL} Banner: {r.get('banner') or 'N/A'}\n")
                    else:
                        sys.stderr.write(human_line(r) + "\n")
                except Exception:
                    sys.stderr.write(human_line(r) + "\n")
                sys.stderr.flush()

    duration = time.time() - start

    # Exports (CSV/JSON/PDF) if requested
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    if args.csv:
        import csv as _csv
        keys = ['ts','host','port','open','service','cert_subject','banner']
        with open(args.csv, 'w', newline='', encoding='utf-8') as f:
            w = _csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in results:
                w.writerow({k: r.get(k, '') for k in keys})
    if args.pdf:
        # optional dependency; create a simple tabular pdf if reportlab available
        try:
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors
            doc = SimpleDocTemplate(args.pdf, pagesize=A4)
            styles = getSampleStyleSheet()
            story = [Paragraph('Port Scan Report', styles['Title']), Spacer(1,12)]
            data = [['Time','Host','Port','Open','Service','Banner']]
            for r in results:
                data.append([r['ts'], r['host'], r['port'], str(r['open']), r.get('service') or '', (r.get('banner') or '')[:150]])
            table = Table(data, repeatRows=1)
            table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.lightgrey),('GRID',(0,0),(-1,-1),0.5,colors.black)]))
            story.append(table)
            doc.build(story)
        except Exception:
            pass

    sys.stderr.write(f"Scan finished in {duration:.2f}s — tasks: {len(tasks)} open: {sum(1 for x in results if x.get('open'))}\n")
    sys.stderr.flush()


if __name__ == '__main__':
    import argparse as _ap
    main()
