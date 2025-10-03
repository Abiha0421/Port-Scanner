#!/usr/bin/env python3
"""
tcp_port_scanner_gui.py
Stable, single-file GUI for TCP port scanning with settings, persistence, banner grabbing, and exports.

Save as tcp_port_scanner_gui.py and run:
    python tcp_port_scanner_gui.py
"""

from __future__ import annotations
import os
import sys
import json
import socket
import ssl
import threading
import concurrent.futures
import queue
import time
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# GUI
try:
    import customtkinter as ctk
except Exception as e:
    print("Please install customtkinter: pip install customtkinter")
    raise
from tkinter import ttk, messagebox, filedialog

# Optional notification on Windows
try:
    import winsound
    HAVE_WINSOUND = True
except Exception:
    HAVE_WINSOUND = False

# Optional PDF export later
# CONFIG PATH
CONFIG_PATH = Path.home() / ".tcp_scanner_settings.json"
DEFAULT_CONFIG = {
    "appearance": "dark",
    "style": "default",           # "default", "neon", "purple" (maps to built-ins safely)
    "font_size": 11,
    "threads": 200,
    "timeout": 2.0,
    "json_only": True,
    "banner_grab": True,
    "aggressive": False,
    "cert_grab": True,
    "export_format": "json",
    "auto_save_folder": "",
    "notify_sound": True,
    "recent_targets": []
}

# ----------------- Utilities -----------------
def load_config() -> Dict[str, Any]:
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                c = json.load(f)
            # ensure keys exist
            for k, v in DEFAULT_CONFIG.items():
                c.setdefault(k, v)
            c["recent_targets"] = c.get("recent_targets", [])[:10]
            return c
    except Exception as e:
        print("Failed to load config:", e)
    return DEFAULT_CONFIG.copy()

def save_config(conf: Dict[str, Any]):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(conf, f, indent=2)
    except Exception as e:
        print("Failed to save config:", e)

def parse_ports(ports_str: str) -> List[int]:
    """Parse a string like '22,80,443' or '1-1024' or mixed."""
    out = set()
    if not ports_str:
        return []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                a_i = int(a); b_i = int(b)
                if a_i <= b_i:
                    out.update(range(a_i, b_i+1))
            except Exception:
                continue
        else:
            try:
                out.add(int(part))
            except Exception:
                continue
    return sorted(p for p in out if 1 <= p <= 65535)

def expand_targets(target: str) -> List[str]:
    """Accept single IP/host or CIDR like 192.168.1.0/28"""
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        ipaddress.ip_address(target)
        return [target]
    except Exception:
        # treat as hostname
        return [target]

# ----------------- Banner grabbing -----------------
COMMON_TLS_PORTS = {443, 8443, 993, 995, 465, 636}

def safe_recv(sock: socket.socket, n=4096) -> Optional[bytes]:
    try:
        data = sock.recv(n)
        return data if data else None
    except Exception:
        return None

def grab_banner(host: str, port: int, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    """
    Try banner grabbing:
    - plain recv()
    - if TLS-like port, attempt TLS handshake with SNI and send HEAD to get Server:
    - fallback: send HTTP HEAD on common HTTP ports
    Returns (banner_text_or_None, cert_cn_or_None)
    """
    banner = None
    cert_cn = None
    # 1) plain recv (some services send greeting)
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = safe_recv(s, 4096)
            if data:
                try:
                    banner = data.decode(errors="replace").strip()
                except Exception:
                    banner = None
    except Exception:
        pass

    # 2) TLS + HEAD
    if port in COMMON_TLS_PORTS:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((host, port), timeout=timeout)
            raw.settimeout(timeout)
            # For numeric IPs, server_hostname=None; many servers require hostname SNI; using host if not numeric
            hostname_for_sni = None
            try:
                ipaddress.ip_address(host)
            except Exception:
                hostname_for_sni = host
            with context.wrap_socket(raw, server_hostname=hostname_for_sni) as ssock:
                # cert CN
                try:
                    cert = ssock.getpeercert()
                    subject = cert.get("subject", ())
                    for entry in subject:
                        for k, v in entry:
                            if k.lower() in ("commonname", "cn"):
                                cert_cn = v
                                break
                        if cert_cn:
                            break
                except Exception:
                    cert_cn = None
                # send HEAD
                try:
                    req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: banner-grabber/1.0\r\n\r\n"
                    ssock.sendall(req.encode())
                    resp = b""
                    while True:
                        part = ssock.recv(4096)
                        if not part:
                            break
                        resp += part
                        if len(resp) > 65536:
                            break
                    resp_text = resp.decode(errors="replace")
                    for line in resp_text.splitlines():
                        if line.lower().startswith("server:"):
                            banner = line.partition(":")[2].strip()
                            break
                    if not banner:
                        first = resp_text.splitlines()[0] if resp_text.splitlines() else ""
                        if first:
                            banner = first.strip()
                except Exception:
                    pass
        except Exception:
            pass

    # 3) plain HTTP HEAD fallback
    if not banner and port in (80, 8000, 8080, 8888):
        try:
            with socket.create_connection((host, port), timeout=timeout) as s2:
                s2.settimeout(timeout)
                req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                s2.sendall(req.encode())
                data = b""
                while True:
                    part = s2.recv(4096)
                    if not part:
                        break
                    data += part
                    if len(data) > 65536:
                        break
                txt = data.decode(errors="replace")
                for line in txt.splitlines():
                    if line.lower().startswith("server:"):
                        banner = line.partition(":")[2].strip()
                        break
                if not banner:
                    first = txt.splitlines()[0] if txt.splitlines() else ""
                    if first:
                        banner = first.strip()
        except Exception:
            pass

    return (banner, cert_cn)

# ----------------- Single-port scan -----------------
def detect_service(port:int, banner:Optional[str]) -> str:
    try:
        s = socket.getservbyport(port, "tcp")
    except Exception:
        s = None
    if banner:
        b = banner.lower()
        heur = [("ssh","ssh"),("smtp","smtp"),("http","http"),("nginx","http"),("apache","http"),
                ("ftp","ftp"),("mysql","mysql"),("postgres","postgresql"),("rdp","rdp")]
        for key, nm in heur:
            if key in b:
                return nm
    return s or "unknown"

def scan_one(host:str, port:int, timeout:float, do_banner:bool, do_cert:bool, do_aggressive:bool) -> Dict[str,Any]:
    res = {"ts": datetime.utcnow().strftime("%H:%M:%S"), "host": host, "port": port, "open": False,
           "service": None, "banner": None, "cert_subject": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                res["open"] = True
                if do_banner:
                    banner, cert = grab_banner(host, port, timeout)
                    if banner:
                        res["banner"] = banner[:500]
                    if do_cert and cert:
                        res["cert_subject"] = cert
                res["service"] = detect_service(port, res.get("banner"))
    except Exception:
        pass
    return res

# ----------------- Threaded scanner (producer queue) -----------------
class ThreadedScanner:
    def __init__(self):
        self._q = queue.Queue()
        self._stop = threading.Event()
        self._thread = None

    def stop(self):
        self._stop.set()

    def scan(self, targets:List[str], ports:List[int], timeout:float, workers:int,
             do_banner:bool, do_cert:bool, do_aggressive:bool):
        self._stop.clear()
        def _runner():
            with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, 1000))) as exe:
                futures = {}
                for host in targets:
                    if self._stop.is_set(): break
                    for port in ports:
                        if self._stop.is_set(): break
                        fut = exe.submit(scan_one, host, port, timeout, do_banner, do_cert, do_aggressive)
                        futures[fut] = (host, port)
                # collect
                for fut in concurrent.futures.as_completed(futures):
                    if self._stop.is_set():
                        break
                    try:
                        r = fut.result()
                    except Exception:
                        r = {"ts": datetime.utcnow().strftime("%H:%M:%S"), "host": futures[fut][0], "port": futures[fut][1], "open": False}
                    self._q.put(r)
                # signal done
                self._q.put({"__done__": True})
        self._thread = threading.Thread(target=_runner, daemon=True)
        self._thread.start()

    def queue(self) -> queue.Queue:
        return self._q

# ----------------- GUI App -----------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class ScannerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("TCP Port Scanner")
        self.geometry("1150x760")
        self.minsize(980, 640)

        # config
        self.config_data = load_config()

        # state
        self.scanner = None
        self._queue = None
        self._running = False
        self.results:List[Dict[str,Any]] = []
        self.total_expected = 0
        self.scanned = 0
        self.open_count = 0

        # Build UI
        self._build_topbar()
        self._build_controls()
        self._build_table_and_log()
        self.apply_appearance()

        # poll queue
        self.after(200, self._poll_queue)

    # ---------------- UI construction ----------------
    def _build_topbar(self):
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=12, pady=(8,6))
        self.title_label = ctk.CTkLabel(top, text="TCP Port Scanner", font=("Segoe UI", 16, "bold"))
        self.title_label.pack(side="left", padx=(8,12))
        # Settings button
        self.settings_btn = ctk.CTkButton(top, text="⚙ Settings", width=120, command=self.open_settings)
        self.settings_btn.pack(side="right", padx=8)
        # Export button
        self.export_btn = ctk.CTkButton(top, text="Export", width=100, command=self.export_results)
        self.export_btn.pack(side="right", padx=8)

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self)
        ctrl.pack(fill="x", padx=12, pady=(0,8))

        # recent targets + entry
        recent = self.config_data.get("recent_targets", [])
        vals = [""] + recent
        self.recent_var = ctk.StringVar(value="")
        self.recent_menu = ctk.CTkOptionMenu(ctrl, values=vals, variable=self.recent_var, width=220, command=self._recent_selected)
        self.recent_menu.pack(side="left", padx=(0,6))
        self.target_entry = ctk.CTkEntry(ctrl, placeholder_text="Target (IP/host/CIDR)", width=360)
        self.target_entry.pack(side="left", padx=(0,6))
        # ports
        self.ports_entry = ctk.CTkEntry(ctrl, placeholder_text="Ports (e.g. 22,80 or 1-1024)", width=260)
        self.ports_entry.pack(side="left", padx=6)
        # threads + timeout
        self.threads_entry = ctk.CTkEntry(ctrl, width=80)
        self.threads_entry.insert(0, str(self.config_data.get("threads", DEFAULT_CONFIG["threads"])))
        self.threads_entry.pack(side="left", padx=6)
        self.timeout_entry = ctk.CTkEntry(ctrl, width=80)
        self.timeout_entry.insert(0, str(self.config_data.get("timeout", DEFAULT_CONFIG["timeout"])))
        self.timeout_entry.pack(side="left", padx=6)
        # start/stop
        self.start_btn = ctk.CTkButton(ctrl, text="▶ Start Scan", width=140, command=self.start_scan)
        self.start_btn.pack(side="left", padx=6)
        self.stop_btn = ctk.CTkButton(ctrl, text="⏹ Stop", width=90, fg_color="tomato", command=self.stop_scan)
        self.stop_btn.pack(side="left", padx=6)
        self.stop_btn.configure(state="disabled")
        # only show open toggle
        self.show_open_var = ctk.BooleanVar(value=False)
        self.show_open_chk = ctk.CTkCheckBox(ctrl, text="Only show open ports", variable=self.show_open_var, command=self._apply_filter)
        self.show_open_chk.pack(side="left", padx=12)

    def _recent_selected(self, v):
        if v:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, v)

    def _build_table_and_log(self):
        status = ctk.CTkFrame(self)
        status.pack(fill="x", padx=12, pady=(0,8))
        self.status_lbl = ctk.CTkLabel(status, text="Ready")
        self.status_lbl.pack(side="left", padx=(6,12))
        self.progress = ctk.CTkProgressBar(status)
        self.progress.set(0)
        self.progress.pack(side="left", fill="x", expand=True, padx=12)
        self.open_lbl = ctk.CTkLabel(status, text="Open: 0")
        self.open_lbl.pack(side="right", padx=12)

        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=12, pady=(0,12))

        # results table
        cols = ("time","host","port","status","service","banner")
        self.tree = ttk.Treeview(main_frame, columns=cols, show="headings")
        headings = [("time","Time"),("host","Host"),("port","Port"),("status","Status"),("service","Service"),("banner","Banner")]
        for k, t in headings:
            self.tree.heading(k, text=t)
            self.tree.column(k, width=120 if k!="banner" else 420, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        vsb = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.bind("<Double-1>", self._on_row_double)

        # log area
        self.log_frame = ctk.CTkFrame(self, corner_radius=10)
        self.log_frame.pack(fill="x", padx=12, pady=(0,12))
        self.welcome_lbl = ctk.CTkLabel(self.log_frame, text="Enter a target & ports, then Start Scan", font=("Segoe UI", 14))
        self.welcome_lbl.pack(expand=True, pady=20)
        self.logbox = ctk.CTkTextbox(self.log_frame, height=150)

    # ----------------- Settings dialog -----------------
    def open_settings(self):
        win = ctk.CTkToplevel(self)
        win.title("Settings")
        win.geometry("640x520")
        win.transient(self)
        win.grab_set()

        # print current settings to terminal when settings opened
        print("=== Current Settings (opened Settings dialog) ===")
        print(json.dumps(self.config_data, indent=2))

        tabs = ctk.CTkTabview(win)
        tabs.pack(fill="both", expand=True, padx=12, pady=12)
        tabs.add("Appearance"); tabs.add("Scan"); tabs.add("Reports")

        # Appearance tab
        t1 = tabs.tab("Appearance")
        ctk.CTkLabel(t1, text="Appearance", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=8, pady=(8,6))
        self.appearance_var = ctk.StringVar(value=self.config_data.get("appearance","dark"))
        ctk.CTkRadioButton(t1, text="Dark", variable=self.appearance_var, value="dark").pack(anchor="w", padx=12)
        ctk.CTkRadioButton(t1, text="Light", variable=self.appearance_var, value="light").pack(anchor="w", padx=12)
        ctk.CTkLabel(t1, text="Style / Accent", font=("Segoe UI", 12)).pack(anchor="w", padx=8, pady=(8,4))
        self.style_var = ctk.StringVar(value=self.config_data.get("style","default"))
        ctk.CTkOptionMenu(t1, values=["default","neon","purple","cyberpunk"], variable=self.style_var).pack(anchor="w", padx=12)

        # Scan tab
        t2 = tabs.tab("Scan")
        ctk.CTkLabel(t2, text="Scanner Defaults", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=8, pady=(8,6))
        # threads & timeout
        row = ctk.CTkFrame(t2); row.pack(fill="x", padx=12, pady=(4,6))
        ctk.CTkLabel(row, text="Threads:").pack(side="left", padx=(0,8))
        self.threads_spin = ctk.CTkEntry(row, width=80); self.threads_spin.insert(0, str(self.config_data.get("threads",200))); self.threads_spin.pack(side="left")
        ctk.CTkLabel(row, text="Timeout (s):").pack(side="left", padx=(12,8))
        self.timeout_spin = ctk.CTkEntry(row, width=80); self.timeout_spin.insert(0, str(self.config_data.get("timeout",2.0))); self.timeout_spin.pack(side="left")
        # toggles
        self.cb_json = ctk.StringVar(value="1" if self.config_data.get("json_only",True) else "0")
        self.cb_banner = ctk.StringVar(value="1" if self.config_data.get("banner_grab",True) else "0")
        self.cb_aggr = ctk.StringVar(value="1" if self.config_data.get("aggressive",False) else "0")
        self.cb_cert = ctk.StringVar(value="1" if self.config_data.get("cert_grab",True) else "0")
        ctk.CTkCheckBox(t2, text="Run with --json-only", variable=self.cb_json).pack(anchor="w", padx=12, pady=(6,2))
        ctk.CTkCheckBox(t2, text="Enable Banner Grabbing", variable=self.cb_banner).pack(anchor="w", padx=12, pady=2)
        ctk.CTkCheckBox(t2, text="Aggressive probes (HTTP HEAD etc.)", variable=self.cb_aggr).pack(anchor="w", padx=12, pady=2)
        ctk.CTkCheckBox(t2, text="Grab TLS certificate CN", variable=self.cb_cert).pack(anchor="w", padx=12, pady=2)

        # Reports tab
        t3 = tabs.tab("Reports")
        ctk.CTkLabel(t3, text="Reports & Notifications", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=8, pady=(8,6))
        self.export_var = ctk.StringVar(value=self.config_data.get("export_format","json"))
        ctk.CTkOptionMenu(t3, values=["json","csv","pdf"], variable=self.export_var).pack(anchor="w", padx=12)
        self.autosave_entry = ctk.CTkEntry(t3, width=420); self.autosave_entry.insert(0, self.config_data.get("auto_save_folder","")); self.autosave_entry.pack(anchor="w", padx=12, pady=(8,4))
        ctk.CTkButton(t3, text="Browse", command=self._pick_autosave).pack(anchor="w", padx=12)
        self.notify_var = ctk.StringVar(value="1" if self.config_data.get("notify_sound",True) else "0")
        ctk.CTkCheckBox(t3, text="Play sound on finish", variable=self.notify_var).pack(anchor="w", padx=12, pady=(8,2))

        # Save / Cancel
        bottom = ctk.CTkFrame(win); bottom.pack(fill="x", padx=12, pady=(6,12))
        ctk.CTkButton(bottom, text="Save Settings", command=lambda w=win: self._save_settings_and_close(w)).pack(side="right", padx=6)
        ctk.CTkButton(bottom, text="Cancel", command=win.destroy).pack(side="right", padx=6)

    def _pick_autosave(self):
        p = filedialog.askdirectory(title="Choose autosave folder")
        if p:
            self.autosave_entry.delete(0, "end"); self.autosave_entry.insert(0, p)

    def _save_settings_and_close(self, win):
        try:
            threads = int(self.threads_spin.get())
        except Exception:
            threads = DEFAULT_CONFIG["threads"]
        try:
            timeout = float(self.timeout_spin.get())
        except Exception:
            timeout = DEFAULT_CONFIG["timeout"]
        cfg = {
            "appearance": self.appearance_var.get(),
            "style": self.style_var.get(),
            "font_size": int(self.config_data.get("font_size", DEFAULT_CONFIG["font_size"])),
            "threads": threads,
            "timeout": timeout,
            "json_only": self.cb_json.get() == "1",
            "banner_grab": self.cb_banner.get() == "1",
            "aggressive": self.cb_aggr.get() == "1",
            "cert_grab": self.cb_cert.get() == "1",
            "export_format": self.export_var.get(),
            "auto_save_folder": self.autosave_entry.get().strip(),
            "notify_sound": self.notify_var.get() == "1",
            "recent_targets": self.config_data.get("recent_targets", [])  # preserve
        }
        self.config_data.update(cfg)
        save_config(self.config_data)
        # show applied settings in terminal (at save)
        print("=== Settings saved ===")
        print(json.dumps(self.config_data, indent=2))
        self.apply_appearance()
        # update recent menu values
        rec = [""] + self.config_data.get("recent_targets", [])[:10]
        try:
            self.recent_menu.configure(values=rec)
        except Exception:
            pass
        win.destroy()

    # ----------------- Appearance -----------------
    def apply_appearance(self):
        mode = self.config_data.get("appearance", "dark")
        ctk.set_appearance_mode(mode)
        style = self.config_data.get("style", "default")
        # use safe built-in themes where possible
        if style == "default":
            ctk.set_default_color_theme("blue")
        elif style == "neon":
            ctk.set_default_color_theme("green")
        elif style == "purple":
            ctk.set_default_color_theme("dark-blue")
        elif style == "cyberpunk":
            ctk.set_default_color_theme("green")
        else:
            ctk.set_default_color_theme("blue")

    # ----------------- Start / Stop scan -----------------
    def start_scan(self):
        if self._running:
            messagebox.showwarning("Scan running", "A scan is already running.")
            return
        target = self.target_entry.get().strip()
        ports_text = self.ports_entry.get().strip()
        if not target:
            messagebox.showwarning("Missing", "Enter a target host or CIDR.")
            return
        if not ports_text:
            # use default common ports if blank
            ports_list = [21,22,23,25,53,80,110,143,389,443,445,3306,3389,5900,8080]
        else:
            ports_list = parse_ports(ports_text)
            if not ports_list:
                messagebox.showwarning("Ports", "No valid ports parsed.")
                return

        # update recent targets
        rec = self.config_data.get("recent_targets", [])
        if target and target not in rec:
            rec.insert(0, target)
            rec = rec[:10]
            self.config_data["recent_targets"] = rec
            save_config(self.config_data)
            try:
                self.recent_menu.configure(values=[""] + rec)
            except Exception:
                pass

        # expand targets (CIDR)
        targets = expand_targets(target)
        try:
            threads = int(self.threads_entry.get().strip())
        except Exception:
            threads = int(self.config_data.get("threads", DEFAULT_CONFIG["threads"]))
        try:
            timeout = float(self.timeout_entry.get().strip())
        except Exception:
            timeout = float(self.config_data.get("timeout", DEFAULT_CONFIG["timeout"]))

        do_banner = self.config_data.get("banner_grab", True)
        do_cert = self.config_data.get("cert_grab", True)
        do_aggr = self.config_data.get("aggressive", False)

        # clear UI
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.logbox.delete("1.0", "end")
        self.welcome_lbl.pack_forget()
        self.logbox.pack(fill="both", expand=True, padx=12, pady=12)
        self.results = []
        self.total_expected = max(1, len(targets) * len(ports_list))
        self.scanned = 0
        self.open_count = 0
        self.progress.set(0)
        self.open_lbl.configure(text="Open: 0")
        self.status_lbl.configure(text="Scanning...")
        self._running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        # start threaded scanner
        self.scanner = ThreadedScanner()
        self.scanner.scan(targets, ports_list, timeout, threads, do_banner, do_cert, do_aggr)
        self._queue = self.scanner.queue()

    def stop_scan(self):
        if not self._running:
            return
        try:
            self.scanner.stop()
        except Exception:
            pass
        self.status_lbl.configure(text="Stopping...")

    def _poll_queue(self):
        if getattr(self, "_queue", None):
            q = self._queue
            try:
                while True:
                    item = q.get_nowait()
                    if isinstance(item, dict) and item.get("__done__"):
                        # finished
                        self._running = False
                        self._finish_scan()
                        self._queue = None
                        break
                    else:
                        self._handle_result(item)
            except queue.Empty:
                pass
        self.after(200, self._poll_queue)

    def _handle_result(self, r:Dict[str,Any]):
        # append, log, table
        self.results.append(r)
        try:
            self.logbox.insert("end", json.dumps(r, ensure_ascii=False) + "\n")
            self.logbox.see("end")
        except Exception:
            pass
        status_text = "OPEN" if r.get("open") else "CLOSED"
        values = (r.get("ts",""), r.get("host",""), r.get("port",""), status_text, r.get("service",""), (r.get("banner") or "")[:300])
        if self.show_open_var.get() and not r.get("open"):
            # filtered out
            pass
        else:
            iid = self.tree.insert("", "end", values=values)
            if r.get("open"):
                self.tree.item(iid, tags=("open",))
                self.open_count += 1
                self.open_lbl.configure(text=f"Open: {self.open_count}")
            else:
                self.tree.item(iid, tags=("closed",))
        self.scanned += 1
        frac = min(1.0, self.scanned / max(1, self.total_expected))
        self.progress.set(frac)

    def _finish_scan(self):
        self.status_lbl.configure(text="Completed")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self._running = False
        try:
            self.tree.tag_configure("open", background="#d6f5e1")
            self.tree.tag_configure("closed", background="#ffecec")
        except Exception:
            pass
        # notification
        if self.config_data.get("notify_sound", True):
            if HAVE_WINSOUND:
                try:
                    winsound.MessageBeep(winsound.MB_OK)
                except Exception:
                    pass
            else:
                try:
                    print("\a", end="", flush=True)
                except Exception:
                    pass

    # ----------------- Filtering -----------------
    def _apply_filter(self):
        # rebuild table according to show_open_var
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        for r in self.results:
            if self.show_open_var.get() and not r.get("open"):
                continue
            status_text = "OPEN" if r.get("open") else "CLOSED"
            iid = self.tree.insert("", "end", values=(r.get("ts",""), r.get("host",""), r.get("port",""), status_text, r.get("service",""), (r.get("banner") or "")[:300]))
            if r.get("open"):
                self.tree.item(iid, tags=("open",))
            else:
                self.tree.item(iid, tags=("closed",))

    # ----------------- Row double click -----------------
    def _on_row_double(self, event):
        iid = self.tree.focus()
        if not iid:
            return
        vals = self.tree.item(iid)["values"]
        host = vals[1]; port = vals[2]
        full = "N/A"
        for r in self.results:
            if str(r.get("host")) == str(host) and str(r.get("port")) == str(port):
                full = r.get("banner") or "N/A"
                break
        messagebox.showinfo("Banner", full)

    # ----------------- Export -----------------
    def export_results(self):
        if not self.results:
            messagebox.showinfo("No results", "No scan results to export.")
            return
        fpath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json"),("CSV","*.csv"),("PDF","*.pdf")])
        if not fpath:
            return
        try:
            if fpath.lower().endswith(".json"):
                with open(fpath, "w", encoding="utf-8") as fh:
                    json.dump(self.results, fh, indent=2, ensure_ascii=False)
            elif fpath.lower().endswith(".csv"):
                import csv
                keys = ["ts","host","port","open","service","cert_subject","banner"]
                with open(fpath, "w", newline="", encoding="utf-8") as fh:
                    w = csv.DictWriter(fh, fieldnames=keys)
                    w.writeheader()
                    for r in self.results:
                        w.writerow({k: r.get(k,"") for k in keys})
            elif fpath.lower().endswith(".pdf"):
                try:
                    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
                    from reportlab.lib.pagesizes import A4
                    from reportlab.lib import colors
                    from reportlab.lib.styles import getSampleStyleSheet
                except Exception:
                    messagebox.showerror("Missing", "Install reportlab to export PDF: pip install reportlab")
                    return
                doc = SimpleDocTemplate(fpath, pagesize=A4)
                styles = getSampleStyleSheet()
                story = [Paragraph("Scan Results", styles["Title"]), Spacer(1,12)]
                data = [["Time","Host","Port","Open","Service","Banner"]]
                for r in self.results:
                    data.append([r.get("ts",""), r.get("host",""), r.get("port",""), str(r.get("open")), r.get("service",""), (r.get("banner") or "")[:200]])
                table = Table(data, repeatRows=1)
                table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("GRID",(0,0),(-1,-1),0.5,colors.black)]))
                story.append(table)
                doc.build(story)
            messagebox.showinfo("Saved", f"Saved to: {fpath}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    # ----------------- Close -----------------
    def on_close(self):
        try:
            if getattr(self, "scanner", None):
                self.scanner.stop()
        except Exception:
            pass
        save_config(self.config_data)
        self.destroy()

# ----------------- Run -----------------
def main():
    app = ScannerGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()

if __name__ == "__main__":
    main()
