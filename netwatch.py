"""
NetWatch - local network activity monitor for Windows.

Shows which process is talking to which host, the process's parent chain,
loaded DLLs (with optional Authenticode signature checks) and keeps a
persistent JSONL log of everything it sees.

Two sensors:
  * polling  (psutil)  - always on; builds the live connection table
  * ETW      (etw_sensor.py) - when run as Administrator; catches every
    TCP connect / disconnect (even millisecond-lived ones), per-process DNS
    queries, URLs from the Windows HTTP stacks, process start/stop with
    parent PID, and live DLL loads.

UI: http://127.0.0.1:8765
"""
import atexit
import collections
import ctypes
import datetime
import hashlib
import ipaddress
import json
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import psutil
import reputation
from flask import Flask, abort, jsonify, request, send_file, send_from_directory

FROZEN = getattr(sys, "frozen", False)                       # running as NetWatch.exe (PyInstaller)
# Bundled read-only resources (static UI) vs. the folder the user sees (logs live next to the exe)
RES = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.dirname(sys.executable) if FROZEN else os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

HOST, PORT = "127.0.0.1", 8765
POLL_SEC = 0.75
DNS_CACHE_SEC = 8
UDP_FLOW_TTL = 120          # seconds before the same UDP flow is logged again
LOG_LOOPBACK = False        # ETW: log 127.0.0.1 / ::1 traffic (very noisy)
CREATE_NO_WINDOW = 0x08000000
# Child Windows PowerShell must not inherit a PowerShell 7 module path (breaks Get-AuthenticodeSignature)
PS_ENV = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}

PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 123: "NTP",
    135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 636: "LDAPS",
    853: "DNS-over-TLS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1900: "SSDP",
    3306: "MySQL", 3389: "RDP", 5353: "mDNS", 5355: "LLMNR", 5432: "Postgres",
    5985: "WinRM", 5986: "WinRM-TLS", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9001: "Tor?", 9050: "Tor?", 27017: "MongoDB",
}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY"}

TRUSTED_DIRS = [
    os.environ.get("SystemRoot", r"C:\Windows").lower() + "\\",
    os.environ.get("ProgramFiles", r"C:\Program Files").lower() + "\\",
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower() + "\\",
    os.environ.get("ProgramData", r"C:\ProgramData").lower() + "\\microsoft\\windows defender\\",
]
RISKY_MARKERS = ["\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\", "\\desktop\\", "\\$recycle.bin\\"]
MODULE_EXT = (".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl", ".node", ".pyd", ".mui")


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def path_risk(path):
    if not path:
        return "unknown"
    p = path.lower()
    if any(m in p for m in RISKY_MARKERS):
        return "user-writable"
    if any(p.startswith(d) for d in TRUSTED_DIRS):
        return "system"
    return "other"


def _safe(fn, default=None):
    try:
        v = fn()
        return default if v is None else v
    except Exception:
        return default


def _fmt_ip_port(ip, port):
    if not ip:
        return ""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts).isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------- #
# Process information (cached per pid+create_time to survive PID reuse).
# Falls back to what ETW recorded for processes that already exited.
# --------------------------------------------------------------------------- #
_proc_cache = {}
_proc_lock = threading.Lock()
_etw_procs = {}     # pid -> {pid,name,exe,ppid,start,stop,exit_code}


def _etw_fallback(pid):
    e = _etw_procs.get(pid)
    if not e:
        return None
    return {"pid": pid, "name": e["name"], "exe": e["exe"], "cmdline": "", "user": "", "ppid": e["ppid"],
            "create_time": e["start"], "alive": e.get("stop") is None, "risk": path_risk(e["exe"]),
            "source": "etw"}


def proc_info(pid):
    if pid == 0:
        # Windows reports sockets whose owner already exited (TIME_WAIT etc.) as PID 0.
        return {"pid": 0, "name": "[closed socket - owner exited]", "exe": "", "cmdline": "",
                "user": "", "ppid": None, "create_time": 0, "alive": False, "risk": "unknown"}
    try:
        p = psutil.Process(pid)
        ct = _safe(p.create_time, 0.0)
    except psutil.Error:
        with _proc_lock:
            c = _proc_cache.get(pid)
        if c:
            return dict(c[1], alive=False)
        fb = _etw_fallback(pid)
        if fb:
            return fb
        return {"pid": pid, "name": "<exited>", "exe": "", "cmdline": "", "user": "",
                "ppid": None, "create_time": 0, "alive": False, "risk": "unknown"}
    with _proc_lock:
        c = _proc_cache.get(pid)
        if c and c[0] == ct:
            return c[1]
    exe = _safe(p.exe, "")
    if not exe and pid in _etw_procs:
        exe = _etw_procs[pid]["exe"]
    info = {
        "pid": pid,
        "name": _safe(p.name, "?"),
        "exe": exe,
        "cmdline": " ".join(_safe(p.cmdline, [])),
        "user": _safe(p.username, ""),
        "ppid": _safe(p.ppid),
        "create_time": ct,
        "alive": True,
        "risk": path_risk(exe),
    }
    with _proc_lock:
        _proc_cache[pid] = (ct, info)
    return info


def parent_label(info):
    ppid = info.get("ppid")
    if not ppid:
        return ""
    par = proc_info(ppid)
    return f'{par["name"]} ({ppid})'


def ancestry(pid, max_depth=25):
    """Parent chain from the process up to the root. Detects PPID reuse."""
    chain = []
    seen = set()
    cur = proc_info(pid)
    chain.append(cur)
    while len(chain) < max_depth:
        ppid = cur.get("ppid")
        if ppid in (None, 0) or ppid in seen or ppid == cur["pid"]:
            break
        seen.add(ppid)
        par = proc_info(ppid)
        # A parent created *after* the child means the real parent exited and
        # the PID was reused - the link is not trustworthy.
        if par.get("create_time") and cur.get("create_time") and par["create_time"] > cur["create_time"] + 1:
            chain.append({"pid": ppid, "name": "<parent exited - PID reused>", "exe": "",
                          "cmdline": "", "user": "", "ppid": None, "alive": False, "risk": "unknown"})
            break
        if not par.get("alive", True) and par.get("name") == "<exited>":
            chain.append(dict(par, name="<parent exited>"))
            break
        chain.append(par)
        cur = par
    return chain


# --------------------------------------------------------------------------- #
# Hostname resolution. Order of preference:
#   1. ETW DNS query made by *this* process for this IP
#   2. Windows DNS client cache (any process)
#   3. reverse DNS
# --------------------------------------------------------------------------- #
_dns_map = {}          # ip -> set(queried names)
_pid_dns = {}          # (pid, ip) -> name
_rdns = {}             # ip -> name or ""
_rdns_pending = set()
_rdns_pool = ThreadPoolExecutor(max_workers=8)
_dns_lock = threading.Lock()


def _refresh_dns_cache_loop():
    ps = ("Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | "
          "ForEach-Object { $_.Entry + '|' + $_.Data }")
    while True:
        if ETW["active"]:
            # ETW DNS events supersede this, and Get-DnsClientCache makes WmiPrvSE do reverse lookups (noise)
            time.sleep(DNS_CACHE_SEC)
            continue
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                                 capture_output=True, text=True, timeout=20,
                                 creationflags=CREATE_NO_WINDOW, env=PS_ENV).stdout
            with _dns_lock:
                for line in out.splitlines():
                    if "|" in line:
                        name, ip = line.strip().split("|", 1)
                        _dns_map.setdefault(ip.strip(), set()).add(name.strip())
        except Exception:
            pass
        time.sleep(DNS_CACHE_SEC)


def _do_rdns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = ""
    with _dns_lock:
        _rdns[ip] = name
        _rdns_pending.discard(ip)


def resolve(ip, pid=None):
    with _dns_lock:
        if pid is not None:
            n = _pid_dns.get((pid, ip))
            if n:
                return {"host": n, "src": "etw-dns"}
        names = _dns_map.get(ip)
        if names:
            return {"host": sorted(names)[0], "src": "dns-cache"}
        if ip in _rdns:
            return {"host": _rdns[ip], "src": "rdns"}
        if ip not in _rdns_pending:
            _rdns_pending.add(ip)
            _rdns_pool.submit(_do_rdns, ip)
    return {"host": "", "src": "pending"}


def ip_scope(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "?"
    if a.is_loopback:
        return "loopback"
    if a.is_multicast:
        return "multicast"
    if a.is_private or a.is_link_local:
        return "private"
    if a.is_unspecified:
        return "any"
    return "public"


# --------------------------------------------------------------------------- #
# Event log (memory ring + daily JSONL file)
# --------------------------------------------------------------------------- #
_events = collections.deque(maxlen=80000)
_event_id = 0
_ev_lock = threading.Lock()
_kind_counts = collections.Counter()


def _log_path(day=None):
    day = day or datetime.date.today().isoformat()
    return os.path.join(LOG_DIR, f"netwatch-{day}.jsonl")


def emit(kind, pid, fields=None, ts=None, pinfo=None):
    global _event_id
    ts = ts or time.time()
    pinfo = pinfo or proc_info(pid)
    ev = {
        "ts": ts, "time": _iso(ts), "event": kind, "pid": pid,
        "process": pinfo["name"], "exe": pinfo["exe"], "parent": parent_label(pinfo),
        "proto": "", "local": "", "remote": "", "host": "", "service": "", "status": "",
        "target": "", "detail": "", "source": "poll",
    }
    if fields:
        ev.update(fields)
    with _ev_lock:
        _event_id += 1
        ev["id"] = _event_id
        _events.append(ev)
        _kind_counts[kind] += 1
        try:
            with open(_log_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception:
            pass
    if kind in ("open", "accept", "udp", "existing", "dns", "http"):
        try:
            _rep_hook(ev)
        except NameError:      # reputation module not initialised yet (early startup)
            pass
    return ev


# --------------------------------------------------------------------------- #
# Polling sensor -> live connection table
# --------------------------------------------------------------------------- #
_active = {}           # key -> conn dict
_state_lock = threading.Lock()
_stats = {"opened": 0, "closed": 0, "started": time.time(), "polls": 0}
ETW = {"active": False, "error": "", "sensor": None}


def _fmt(addr):
    return _fmt_ip_port(addr.ip, addr.port) if addr else ""


def _conn_fields(conn, extra=None):
    f = {k: conn[k] for k in ("proto", "local", "remote", "host", "service", "status", "scope")}
    f["target"] = conn["host"] or conn["remote"] or conn["local"]
    if extra:
        f.update(extra)
    return f


def _snapshot():
    now = time.time()
    seen = {}
    for c in psutil.net_connections(kind="inet"):
        proto = ("TCP" if c.type == socket.SOCK_STREAM else "UDP") + ("6" if c.family == socket.AF_INET6 else "")
        status = c.status if c.type == socket.SOCK_STREAM else "OPEN"
        key = (c.pid, proto, _fmt(c.laddr), _fmt(c.raddr), "L" if status == "LISTEN" else "")
        seen[key] = (c, proto, status)

    etw_on = ETW["active"]
    pending = []
    with _state_lock:
        _stats["polls"] += 1
        first = _stats["polls"] == 1
        for key in list(_active):
            if key not in seen:
                conn = _active.pop(key)
                conn["status"] = "CLOSED"
                _stats["closed"] += 1
                if conn["remote"] and not etw_on:
                    pending.append(("close", conn, {"duration": round(now - conn["first_seen"], 2)}))
        for key, (c, proto, status) in seen.items():
            rip = c.raddr.ip if c.raddr else ""
            if key in _active:
                conn = _active[key]
                if conn["status"] != status:
                    old = conn["status"]
                    conn["status"] = status
                    if conn["remote"] and status == "ESTABLISHED" and not etw_on:
                        pending.append(("state", conn, {"detail": f"{old} -> {status}"}))
                if rip and (not conn["host"] or conn["host_src"] in ("pending", "rdns")):
                    r = resolve(rip, conn["pid"])
                    if r["host"]:
                        conn["host"], conn["host_src"] = r["host"], r["src"]
                conn["last_seen"] = now
                continue
            pinfo = proc_info(c.pid or 0)
            r = resolve(rip, c.pid) if rip else {"host": "", "src": ""}
            rport = c.raddr.port if c.raddr else None
            lport = c.laddr.port if c.laddr else None
            conn = {
                "key": "|".join(str(k) for k in key),
                "pid": c.pid or 0,
                "process": pinfo,
                "parent": parent_label(pinfo),
                "proto": proto,
                "local": _fmt(c.laddr),
                "remote": _fmt(c.raddr),
                "remote_ip": rip,
                "remote_port": rport,
                "scope": ip_scope(rip) if rip else ("listen" if status == "LISTEN" else "local"),
                "host": r["host"],
                "host_src": r["src"],
                "service": PORT_NAMES.get(rport or lport, ""),
                "status": status,
                "first_seen": now,
                "last_seen": now,
            }
            _active[key] = conn
            _stats["opened"] += 1
            if conn["remote"]:
                if first:
                    pending.append(("existing", conn, None))
                elif not etw_on:
                    pending.append(("open", conn, None))
            elif status == "LISTEN" and not first:
                pending.append(("listen", conn, None))
    for kind, conn, extra in pending:
        if conn["pid"] == 0:      # TIME_WAIT leftovers with no owner - nothing useful to log
            continue
        if conn["scope"] == "public":
            mark_net(conn["pid"], conn["process"])
        emit(kind, conn["pid"], _conn_fields(conn, extra), pinfo=conn["process"])


def _tracker_loop():
    while True:
        try:
            _snapshot()
        except Exception as e:  # keep running no matter what
            print("tracker error:", e, file=sys.stderr)
        time.sleep(POLL_SEC)


# --------------------------------------------------------------------------- #
# ETW sensor handlers
# --------------------------------------------------------------------------- #
_tcp_open = {}                         # (pid, local, remote) -> ts
_udp_seen = {}                         # (pid, rip, rport) -> ts
_web_seen = {}                         # (pid, url) -> ts
_dns_seen = {}                         # (pid, name, qtype) -> ts
_dll_loads = collections.OrderedDict()  # pid -> deque of loads


def _skip_addr(ip):
    s = ip_scope(ip)
    return (s == "loopback" and not LOG_LOOPBACK) or s == "any"


def _parse_dns_results(res):
    ips, cnames = [], []
    for part in (res or "").split(";"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("type:"):
            bits = part.split()
            if len(bits) >= 3:
                cnames.append(bits[-1])
            continue
        ip = part[7:] if part.lower().startswith("::ffff:") else part
        try:
            ipaddress.ip_address(ip)
            ips.append(ip)
        except ValueError:
            pass
    return ips, cnames


SELF_PID = os.getpid()
_self_children = set()   # PowerShell helpers NetWatch spawns itself (DNS cache, signatures)


def _is_self(pid):
    return pid == SELF_PID or pid in _self_children


class Handlers:
    def on_tcp(self, kind, pid, rip, rport, lip, lport, v6, ts):
        if _skip_addr(rip) or _is_self(pid):
            return
        if kind != "disconnect" and ip_scope(rip) == "public":
            mark_net(pid)
        local, remote = _fmt_ip_port(lip, lport), _fmt_ip_port(rip, rport)
        key = (pid, local, remote)
        r = resolve(rip, pid)
        f = {"proto": "TCP6" if v6 else "TCP", "local": local, "remote": remote, "host": r["host"],
             "service": PORT_NAMES.get(rport if kind != "accept" else lport, ""), "source": "etw",
             "target": r["host"] or remote, "scope": ip_scope(rip)}
        if kind in ("connect", "reconnect", "accept"):
            _tcp_open[key] = ts
            emit("open" if kind != "accept" else "accept", pid, dict(f, status="ESTABLISHED"), ts)
        elif kind == "disconnect":
            start = _tcp_open.pop(key, None)
            f["status"] = "CLOSED"
            if start:
                f["duration"] = round(ts - start, 3)
            emit("close", pid, f, ts)
        if len(_tcp_open) > 50000:
            _tcp_open.clear()

    def on_udp(self, pid, rip, rport, lip, lport, v6, ts):
        if _skip_addr(rip) or _is_self(pid):
            return
        key = (pid, rip, rport)
        last = _udp_seen.get(key)
        if last and ts - last < UDP_FLOW_TTL:
            return
        _udp_seen[key] = ts
        if len(_udp_seen) > 50000:
            _udp_seen.clear()
        if ip_scope(rip) == "public":
            mark_net(pid)
        r = resolve(rip, pid)
        remote = _fmt_ip_port(rip, rport)
        svc = PORT_NAMES.get(rport, "")
        if rport == 443:
            svc = "QUIC / HTTP3"
        emit("udp", pid, {"proto": "UDP6" if v6 else "UDP", "local": _fmt_ip_port(lip, lport), "remote": remote,
                          "host": r["host"], "service": svc, "source": "etw", "target": r["host"] or remote,
                          "scope": ip_scope(rip)}, ts)

    def on_dns(self, pid, name, qtype, status, results, ts):
        if not name:
            return
        if _is_self(pid) or status == 87:   # own reverse lookups / unsupported sub-query noise
            return
        ips, cnames = _parse_dns_results(results)
        with _dns_lock:
            for ip in ips:
                _pid_dns[(pid, ip)] = name
                _dns_map.setdefault(ip, set()).add(name)
            if len(_pid_dns) > 100000:
                _pid_dns.clear()
        key = (pid, name, qtype)
        last = _dns_seen.get(key)
        if last and ts - last < 2:
            return
        _dns_seen[key] = ts
        if len(_dns_seen) > 50000:
            _dns_seen.clear()
        qt = DNS_TYPES.get(qtype, str(qtype))
        if status == 0:
            detail = ", ".join(ips) or ("CNAME " + " -> ".join(cnames) if cnames else "no answer")
            st = "OK"
        else:
            detail = {9003: "NXDOMAIN (name does not exist)", 9501: "no records", 1460: "timeout",
                      87: "invalid", 11001: "host not found"}.get(status, f"error {status}")
            st = "FAIL"
        emit("dns", pid, {"proto": "DNS", "host": name, "target": name, "service": qt, "status": st,
                          "detail": detail, "source": "etw", "cnames": cnames}, ts)

    def on_web(self, pid, provider, eid, props, ts):
        url = verb = status = ""
        for k, v in props.items():
            if not isinstance(v, str):
                continue
            lk = k.lower()
            if not url and v[:8].lower().startswith(("http://", "https://")):
                url = v.strip()
            elif lk in ("verb", "method", "requestverb", "httpverb") and v.isalpha():
                verb = v.upper()
            elif "status" in lk and v.isdigit():
                status = v
        if not url:
            server = next((v for k, v in props.items() if k.lower() in ("servername", "server", "host", "hostname")), "")
            path = next((v for k, v in props.items() if k.lower() in ("objectname", "path", "urlpath", "resource")), "")
            if server and path and path.startswith("/"):
                url = f"http(s)://{server}{path}"
        if not url:
            return
        key = (pid, url)
        last = _web_seen.get(key)
        if last and ts - last < 3:
            return
        _web_seen[key] = ts
        if len(_web_seen) > 50000:
            _web_seen.clear()
        host = urlsplit(url.replace("http(s)", "https")).hostname or ""
        emit("http", pid, {"proto": provider, "host": host, "target": url, "service": verb,
                           "status": status, "detail": " ".join(x for x in (verb, status, f"via {provider}") if x),
                           "source": "etw"}, ts)

    def on_proc_start(self, pid, ppid, image, session, ts):
        if _is_self(ppid):
            _self_children.add(pid)
            return
        _etw_procs[pid] = {"pid": pid, "name": os.path.basename(image) or "?", "exe": image, "ppid": ppid,
                           "start": ts, "stop": None, "exit_code": None}
        if len(_etw_procs) > 20000:
            for k in list(_etw_procs)[:5000]:
                del _etw_procs[k]
        inventory_add(image, pid, os.path.basename(image))
        par = proc_info(ppid) if ppid else {"name": ""}
        pinfo = proc_info(pid)
        if pinfo["name"] in ("<exited>", "?"):
            pinfo = _etw_fallback(pid)
        emit("proc_start", pid, {"target": image, "detail": f'parent {par["name"]} ({ppid}) · session {session}',
                                 "source": "etw", "parent": f'{par["name"]} ({ppid})'}, ts, pinfo=pinfo)

    def on_proc_stop(self, pid, image, exit_code, ts):
        if pid in _self_children:
            _self_children.discard(pid)
            return
        e = _etw_procs.get(pid)
        if e:
            e["stop"], e["exit_code"] = ts, exit_code
        pinfo = proc_info(pid)
        detail = f"exit code {exit_code}" if exit_code is not None else ""
        if e and e.get("start"):
            detail += f" · ran {ts - e['start']:.1f}s"
        emit("proc_stop", pid, {"target": pinfo.get("exe") or image, "detail": detail, "source": "etw"}, ts,
             pinfo=pinfo)

    def on_image_load(self, pid, image, ts):
        if _is_self(pid):
            return
        risk = path_risk(image)
        dq = _dll_loads.get(pid)
        if dq is None:
            dq = _dll_loads[pid] = collections.deque(maxlen=3000)
            while len(_dll_loads) > 3000:
                _dll_loads.popitem(last=False)
        dq.append({"ts": ts, "time": _iso(ts), "path": image, "name": os.path.basename(image), "risk": risk})
        e = _etw_procs.get(pid)
        inventory_add(image, pid, e["name"] if e else None, net=pid in _net_pids)
        if risk != "system":
            emit("dll_load", pid, {"target": image, "detail": risk, "status": risk, "source": "etw"}, ts)


def start_etw():
    if not is_admin():
        ETW["error"] = "Not running as Administrator"
        return
    try:
        import etw_sensor
        s = etw_sensor.EtwSensor(Handlers())
        s.start()
        ETW.update(active=True, sensor=s, error="")
        atexit.register(s.stop)
        print("[+] ETW sensor running (Kernel-Network, DNS-Client, WinINet/WinHTTP/WebIO, Kernel-Process)")
    except Exception as e:
        ETW["error"] = str(e)
        print("[!] ETW sensor failed, using polling only:", e)


# --------------------------------------------------------------------------- #
# DLLs / signatures
# --------------------------------------------------------------------------- #
_sig_cache = {}          # path.lower() -> {"status", "signer"}
_files = {}              # path.lower() -> inventory record
_files_lock = threading.Lock()
_net_pids = set()        # pids that talked to a public address
INVENTORY_EXT = (".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl", ".node", ".pyd", ".scr", ".com")
_SIG_PS = r"""
try { [Console]::InputEncoding = [Text.Encoding]::UTF8 } catch {}
[Console]::OutputEncoding = [Text.Encoding]::UTF8
while ($true) {
  $l = [Console]::In.ReadLine(); if ($null -eq $l) { break }
  try {
    if (-not (Test-Path -LiteralPath $l)) { $o = @{path=$l; status='Missing'; signer=''} }
    else { $s = Get-AuthenticodeSignature -LiteralPath $l -ErrorAction Stop
           $o = @{path=$l; status=[string]$s.Status; signer=$(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' })} }
  } catch { $o = @{path=$l; status='Error'; signer=$_.Exception.Message} }
  [Console]::Out.WriteLine(($o | ConvertTo-Json -Compress)); [Console]::Out.Flush()
}
"""


def _signer_cn(subject):
    m = re.search(r'CN=(?:"([^"]+)"|([^,]+))', subject or "")
    return (m.group(1) or m.group(2)).strip() if m else (subject or "")


def sig_class(sig, path=""):
    if not sig:
        return "pending"
    if sig["status"] == "NotSigned" and re.search(r"\\assembly\\nativeimages|\.ni\.(dll|exe)$", path, re.I):
        return "n/a"          # .NET NGEN native images are never signed by design
    if sig["status"] == "NotSigned" and re.search(r"\\program files\\windowsapps\\", path, re.I):
        return "store-pkg"    # Store apps are signed as a whole package (AppxSignature), not per file
    return {"Valid": "signed", "NotSigned": "unsigned", "HashMismatch": "tampered", "NotTrusted": "untrusted",
            "UnknownError": "untrusted", "Missing": "missing", "NotSupportedFileFormat": "n/a"}.get(sig["status"], "error")


class SigWorker:
    """Long-lived PowerShell processes that verify Authenticode signatures, highest priority first."""

    def __init__(self, workers=3):
        self.q = queue.PriorityQueue()
        self.pending = set()
        self.done = 0
        for i in range(workers):
            threading.Thread(target=self._run, name=f"sig-worker-{i}", daemon=True).start()

    def request(self, path, prio=5):
        key = path.lower()
        if key in _sig_cache or key in self.pending:
            return
        self.pending.add(key)
        self.q.put((prio, time.time(), path))

    @staticmethod
    def _spawn():
        proc = subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-Command", _SIG_PS],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, encoding="utf-8", errors="replace", bufsize=1,
                                creationflags=CREATE_NO_WINDOW, env=PS_ENV)
        _self_children.add(proc.pid)
        return proc

    def _run(self):
        proc = None
        while True:
            prio, _, path = self.q.get()
            key = path.lower()
            res = None
            for _attempt in range(2):
                try:
                    if proc is None or proc.poll() is not None:
                        proc = self._spawn()
                    proc.stdin.write(path + "\n")
                    proc.stdin.flush()
                    res = json.loads(proc.stdout.readline())
                    break
                except Exception as e:
                    res = {"status": "Error", "signer": str(e)}
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    proc = None
            sig = {"status": res.get("status") or "Unknown", "signer": _signer_cn(res.get("signer", ""))}
            _sig_cache[key] = sig
            self.pending.discard(key)
            self.done += 1
            with _files_lock:
                rec = _files.get(key)
            if rec is not None:
                rec["sig"] = sig
                rec["sig_class"] = sig_class(sig, path)
                if rec["sig_class"] != "missing" and (rec["risk"] != "system" or rec["sig_class"] not in ("signed", "n/a")):
                    rec["sha256"] = sha256_file(path)
                    # VirusTotal hash lookup for the files that matter (quota is small)
                    bad = rec["sig_class"] in ("unsigned", "untrusted", "tampered")
                    if (bad or rec["risk"] == "user-writable") and re.fullmatch(r"[0-9a-f]{64}", rec["sha256"]):
                        REP.want(rec["sha256"], "file", prio=1 if bad else 3,
                                 proc=next(iter(rec["procs"]), None) or rec["name"])


SIG = SigWorker()
REP = reputation.Reputation(BASE)


def _rep_hook(ev):
    """Queue reputation lookups for what an event touched (public IPs, public domains)."""
    k, proc = ev["event"], ev["process"]
    if k in ("open", "accept", "udp", "existing") and ev["remote"]:
        REP.want(ev["remote"].rpartition(":")[0].strip("[]"), "ip", prio=4, proc=proc)
    elif k == "dns" and ev["status"] == "OK":
        REP.want(ev["target"], "domain", prio=3, proc=proc)
    elif k == "http" and ev["host"]:
        REP.want(ev["host"], "domain", prio=2, proc=proc)


def inventory_add(path, pid=None, proc_name=None, net=False):
    """Record an executable/DLL we saw in use and queue its signature check."""
    if not path or not path.lower().endswith(INVENTORY_EXT) or _is_self(pid or -1):
        return
    key = path.lower()
    with _files_lock:
        rec = _files.get(key)
        if rec is None:
            risk = path_risk(path)
            sig = _sig_cache.get(key)
            rec = _files[key] = {
                "path": path, "name": os.path.basename(path),
                "kind": "exe" if key.endswith((".exe", ".scr", ".com")) else ("driver" if key.endswith((".sys", ".drv")) else "dll"),
                "risk": risk, "first_seen": time.time(), "pids": set(), "procs": set(), "net": False,
                "sig": sig, "sig_class": sig_class(sig, path), "sha256": "",
            }
            prio = (1 if net else 2) if risk != "system" else (4 if net else 7)
            SIG.request(path, prio)
        if pid is not None and len(rec["pids"]) < 200:
            rec["pids"].add(pid)
        if proc_name and len(rec["procs"]) < 50:
            rec["procs"].add(proc_name)
        if net and not rec["net"]:
            rec["net"] = True
            if rec["sig_class"] == "pending":
                SIG.request(path, 1)


def mark_net(pid, pinfo=None):
    if pid in _net_pids or not pid:
        return
    _net_pids.add(pid)
    pinfo = pinfo or proc_info(pid)
    inventory_add(pinfo.get("exe"), pid, pinfo.get("name"), net=True)


def scan_running():
    """Inventory every running process image + its loaded modules (background)."""
    n = 0
    for p in psutil.process_iter(["pid", "name", "exe"]):
        try:
            pid, name = p.info["pid"], p.info["name"]
            if _is_self(pid):
                continue
            if p.info["exe"]:
                inventory_add(p.info["exe"], pid, name, net=pid in _net_pids)
            for m in p.memory_maps(grouped=True):
                if m.path:
                    inventory_add(m.path, pid, name, net=pid in _net_pids)
            n += 1
        except (psutil.Error, OSError):
            continue
    return n


def list_modules(pid):
    p = psutil.Process(pid)
    pname = _safe(p.name, "?")
    mods = []
    seen = set()
    for m in p.memory_maps(grouped=True):
        path = m.path
        if not path or not path.lower().endswith(MODULE_EXT):
            continue
        key = path.lower()
        if key in seen:
            continue
        seen.add(key)
        inventory_add(path, pid, pname, net=pid in _net_pids)
        SIG.request(path, 3)
        st = _safe(lambda: os.stat(path))
        mods.append({
            "path": path,
            "name": os.path.basename(path),
            "size": st.st_size if st else None,
            "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds") if st else "",
            "rss": m.rss,
            "risk": path_risk(path),
            "sig": _sig_cache.get(key),
        })
    mods.sort(key=lambda x: ({"user-writable": 0, "other": 1, "unknown": 2, "system": 3}[x["risk"]], x["name"].lower()))
    return mods


def check_signatures(paths, timeout=120):
    """Jump the queue for these paths and wait (bounded) for the worker to verify them."""
    for p in paths:
        SIG.request(p, 0)
    end = time.time() + timeout
    while time.time() < end and any(p.lower() not in _sig_cache for p in paths):
        time.sleep(0.2)
    return {p: _sig_cache.get(p.lower(), {"status": "Pending", "signer": ""}) for p in paths}


# --------------------------------------------------------------------------- #
# Findings engine - rules that point at things worth a human look
# --------------------------------------------------------------------------- #
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe",
           "cscript.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
           "regsvcs.exe", "wmic.exe", "msiexec.exe", "hh.exe", "forfiles.exe", "schtasks.exe", "odbcconf.exe"}
BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "comet.exe", "vivaldi.exe",
            "arc.exe", "msedgewebview2.exe", "iexplore.exe"}
PROBE_RE = re.compile(r"/(wp-login\.php|xmlrpc\.php|wp-admin|wp-content/plugins|\.env\b|\.git/|phpmyadmin|"
                      r"checkout/|customer/account|catalog/product|brands/|shopby|downloader/|magento|"
                      r"cgi-bin/|boaform|HNAP1|actuator/|vendor/phpunit|eval-stdin|\.\./)", re.I)
FANOUT_IPS, FANOUT_IPS_BROWSER, PORTSCAN_PORTS, DGA_FAILS, WINDOW = 60, 200, 15, 25, 300
_findings = {}
_findings_lock = threading.Lock()


def _finding(key, sev, rule, title, detail, pid=None, process="", path=""):
    now = time.time()
    with _findings_lock:
        f = _findings.get(key)
        if f:
            f.update(last=now, detail=detail, severity=sev if SEV_ORDER[sev] < SEV_ORDER[f["severity"]] else f["severity"])
            if pid is not None:
                f["pid"] = pid
            return
        _findings[key] = {"id": hashlib.md5(key.encode()).hexdigest()[:10], "severity": sev, "rule": rule,
                          "title": title, "detail": detail, "pid": pid, "process": process, "path": path,
                          "first": now, "last": now}
    pinfo = None if pid else {"name": process or "-", "exe": path, "ppid": None}
    emit("finding", pid or 0, {"target": title, "detail": f"[{sev}] {detail}", "status": sev, "source": "rules"},
         pinfo=pinfo)


def _file_rules():
    with _files_lock:
        recs = list(_files.values())
    for r in recs:
        sc, risk, path = r["sig_class"], r["risk"], r["path"]
        procs = ", ".join(sorted(r["procs"])[:5])
        pid = next(iter(r["pids"]), None)
        if sc == "tampered":
            _finding("tamper:" + path.lower(), "critical", "signature",
                     f"Signature HASH MISMATCH: {r['name']}",
                     f"The file was modified after it was signed. Used by: {procs or '?'}", pid, procs, path)
        elif sc in ("unsigned", "untrusted"):
            if r["kind"] == "exe" and r["net"]:
                _finding("unsignednet:" + path.lower(), "high", "signature",
                         f"Unsigned program using the network: {r['name']}",
                         f"{sc} · {risk} path · talks to public internet", pid, procs, path)
            elif r["kind"] != "exe" and risk != "system":
                net = any(p in _net_pids for p in r["pids"])
                ext_mod = path.lower().endswith((".pyd", ".node"))   # Python/Node extensions: normally unsigned
                _finding("unsigneddll:" + path.lower(), "low" if ext_mod else ("high" if net else "medium"),
                         "unusual-path", f"Unsigned {r['kind'].upper()} from unusual location: {r['name']}",
                         f"{sc} · {risk} path · loaded by {procs or '?'}{' (network-active)' if net else ''}"
                         f"{' · Python/Node extension modules are usually unsigned' if ext_mod else ''}",
                         pid, procs, path)
            elif r["kind"] == "exe" and risk == "user-writable":
                _finding("unsignedexe:" + path.lower(), "medium", "unusual-path",
                         f"Unsigned program running from user-writable folder: {r['name']}",
                         f"{sc} · {path}", pid, procs, path)
            elif risk == "system" and r["kind"] != "exe":
                _finding("unsignedsys:" + path.lower(), "low", "signature",
                         f"Unsigned module in a system folder: {r['name']}",
                         f"{sc} · loaded by {procs or '?'} (often benign: some vendor/driver DLLs ship unsigned)",
                         pid, procs, path)
        elif sc == "signed" and risk == "user-writable" and r["kind"] == "exe" and \
                re.search(r"\\(temp|downloads|users\\public|\$recycle\.bin)\\", path, re.I):
            _finding("tempexe:" + path.lower(), "low", "unusual-path",
                     f"Program running from Temp/Downloads: {r['name']}",
                     f"signed by {r['sig']['signer'] if r['sig'] else '?'} - verify you expect it", pid, procs, path)


def _event_rules():
    now = time.time()
    with _ev_lock:
        evs = [e for e in _events if e["ts"] >= now - WINDOW]
    per = collections.defaultdict(lambda: {"ips": set(), "ports": set(), "nx": 0, "name": "", "exe": ""})
    for e in evs:
        k = e["event"]
        pid = e["pid"]
        if k in ("open", "udp") and (e.get("scope") or ip_scope(e["remote"].rpartition(":")[0].strip("[]"))) == "public":
            d = per[pid]
            d["name"], d["exe"] = e["process"], e["exe"]
            ip, _, port = e["remote"].rpartition(":")
            d["ips"].add(ip)
            d["ports"].add(port)
            if e["process"].lower() in LOLBINS:
                _finding(f"lolbin:{pid}", "medium", "behavior",
                         f"{e['process']} made an internet connection",
                         f"built-in Windows tool reached {e['host'] or e['remote']} (parent {e['parent']}) - "
                         f"common in malware loaders; fine if you ran it yourself", pid, e["process"], e["exe"])
        elif k == "dns" and e["status"] == "FAIL" and e["detail"].startswith("NXDOMAIN"):
            per[pid]["nx"] += 1
            per[pid]["name"], per[pid]["exe"] = e["process"], e["exe"]
        elif k == "http" and PROBE_RE.search(e["target"] or ""):
            _finding(f"probe:{pid}:{e['host']}", "high", "behavior",
                     f"Web-attack/scan style URL requested by {e['process']}",
                     f"{e['target'][:200]}", pid, e["process"], e["exe"])
    for pid, d in per.items():
        browser = d["name"].lower() in BROWSERS
        lim = FANOUT_IPS_BROWSER if browser else FANOUT_IPS
        if len(d["ips"]) >= lim:
            _finding(f"fanout:{pid}", "low" if browser else "high", "behavior",
                     f"{d['name']} contacted {len(d['ips'])} different internet IPs in 5 min",
                     "high fan-out is how scanners and botnet nodes behave" if not browser else
                     "browser - usually just busy pages, check if it happens with no tabs open", pid, d["name"], d["exe"])
        if len(d["ports"]) >= PORTSCAN_PORTS:
            _finding(f"portscan:{pid}", "high", "behavior",
                     f"{d['name']} used {len(d['ports'])} different remote ports in 5 min",
                     "looks like port scanning: " + ",".join(sorted(d["ports"], key=lambda x: int(x) if x.isdigit() else 0)[:20]),
                     pid, d["name"], d["exe"])
        if d["nx"] >= DGA_FAILS:
            _finding(f"dga:{pid}", "medium", "behavior",
                     f"{d['name']} had {d['nx']} failed DNS lookups in 5 min",
                     "many non-existent domains can indicate malware domain-generation (DGA)", pid, d["name"], d["exe"])


def _findings_loop():
    while True:
        try:
            _file_rules()
            _event_rules()
            _rep_rules()
        except Exception as e:
            print("findings error:", e, file=sys.stderr)
        time.sleep(5)


def _rep_rules():
    for r in REP.rows():
        v = r["verdict"]
        if v not in ("malicious", "suspicious"):
            continue
        a, t = r.get("abuse") or {}, r.get("vt") or {}
        bits = []
        if a.get("score") is not None:
            bits.append(f"AbuseIPDB {a['score']}% ({a.get('reports', 0)} reports, {a.get('isp') or '?'}, {a.get('usage') or '?'})")
        if t.get("found"):
            bits.append(f"VirusTotal {t.get('malicious', 0)} malicious / {t.get('suspicious', 0)} suspicious of {t.get('total', 0)}"
                        + (f" · {t['label']}" if t.get("label") else ""))
        procs = ", ".join(r["procs"][:5])
        if r["type"] == "file":
            sev = "critical" if (t.get("malicious") or 0) >= 3 else "high"
            title = f"File flagged by VirusTotal: {t.get('name') or r['value'][:16]}"
            with _files_lock:
                path = next((f["path"] for f in _files.values() if f["sha256"] == r["value"]), "")
                pid = next((next(iter(f["pids"]), None) for f in _files.values() if f["sha256"] == r["value"]), None)
        else:
            sev = "high" if v == "malicious" else "medium"
            title = f"{'Malicious' if v == 'malicious' else 'Suspicious'} {r['type']} contacted: {r['value']}"
            path, pid = "", None
        _finding(f"rep:{r['key']}", sev, "reputation", title,
                 " · ".join(bits) + (f" · used by {procs}" if procs else ""), pid, procs, path)


def sha256_file(path, limit=300 * 1024 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return "(file too large)"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"(unavailable: {e.__class__.__name__})"


# --------------------------------------------------------------------------- #
# Web API
# --------------------------------------------------------------------------- #
app = Flask(__name__, static_folder=os.path.join(RES, "static"))


@app.before_request
def _csrf_guard():
    # A custom header can't be sent cross-origin without a CORS preflight (which we never allow),
    # so other web pages can't drive NetWatch's POST endpoints (settings, lookups, scans).
    if request.method == "POST" and request.headers.get("X-NetWatch") != "1":
        abort(403)


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        b = request.get_json(silent=True) or {}
        REP.update_settings(abuse_key=b.get("abuseipdb_key") or None, vt_key=b.get("virustotal_key") or None,
                            auto=b.get("auto"), clear=b.get("clear"))
    return jsonify(REP.settings())        # never returns the keys themselves


@app.route("/api/reputation")
def api_reputation():
    rows = [r for r in REP.rows() if r and (r.get("abuse") or r.get("vt") or r["pending"])]
    order = {"malicious": 0, "suspicious": 1, "error": 2, "unchecked": 3, "clean": 4}
    rows.sort(key=lambda r: (order.get(r["verdict"], 5), -((r.get("abuse") or {}).get("score") or 0),
                             -((r.get("vt") or {}).get("malicious") or 0)))
    return jsonify({"rows": rows[:3000], "settings": REP.settings()})


@app.route("/api/reputation/map")
def api_reputation_map():
    return jsonify(REP.compact_map())


@app.route("/api/reputation/check", methods=["POST"])
def api_reputation_check():
    value = ((request.get_json(silent=True) or {}).get("value") or "").strip()
    return jsonify(REP.check_now(value))


@app.route("/api/myip", methods=["POST"])
def api_myip():
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=8) as r:
            ip = r.read().decode().strip()
    except Exception as e:
        return jsonify({"error": f"could not determine public IP: {e}"})
    return jsonify({"ip": ip, "result": REP.check_now(ip)})


@app.route("/api/status")
def api_status():
    with _state_lock:
        n = len(_active)
        remote = sum(1 for c in _active.values() if c["remote"])
        procs = len({c["pid"] for c in _active.values() if c["remote"]})
    s = ETW["sensor"]
    etw = {"active": ETW["active"] and bool(s and s.running), "error": ETW["error"]}
    if s:
        etw.update(counts=s.counts, callback_errors=s.errors, last_error=s.last_error,
                   providers=s.provider_status, **s.stats())
    return jsonify({"admin": is_admin(), "active": n, "remote": remote, "processes": procs,
                    "opened": _stats["opened"], "closed": _stats["closed"], "kinds": dict(_kind_counts),
                    "uptime": round(time.time() - _stats["started"]), "log_file": _log_path(),
                    "hostname": socket.gethostname(), "etw": etw})


@app.route("/api/connections")
def api_connections():
    now = time.time()
    with _state_lock:
        rows = []
        for c in _active.values():
            rows.append({k: v for k, v in c.items() if k != "process"} | {
                "name": c["process"]["name"], "exe": c["process"]["exe"],
                "user": c["process"]["user"], "risk": c["process"]["risk"],
                "age": round(now - c["first_seen"], 1)})
    return jsonify(rows)


@app.route("/api/events")
def api_events():
    after = request.args.get("after", 0, type=int)
    limit = request.args.get("limit", 3000, type=int)
    with _ev_lock:
        evs = [e for e in _events if e["id"] > after]
    return jsonify(evs[-limit:])


@app.route("/api/process/<int:pid>")
def api_process(pid):
    info = proc_info(pid)
    chain = ancestry(pid)
    children = []
    try:
        for ch in psutil.Process(pid).children():
            ci = proc_info(ch.pid)
            children.append({"pid": ci["pid"], "name": ci["name"], "exe": ci["exe"]})
    except psutil.Error:
        pass
    with _state_lock:
        conns = [{"proto": c["proto"], "local": c["local"], "remote": c["remote"], "host": c["host"],
                  "service": c["service"], "status": c["status"], "scope": c["scope"]}
                 for c in _active.values() if c["pid"] == pid]
    with _ev_lock:
        hist = [e for e in _events if e["pid"] == pid][-800:]
    extra = {}
    try:
        p = psutil.Process(pid)
        extra = {
            "cwd": _safe(p.cwd, ""),
            "threads": _safe(p.num_threads),
            "handles": _safe(p.num_handles),
            "memory_mb": round(_safe(lambda: p.memory_info().rss, 0) / 1048576, 1),
        }
    except psutil.Error:
        pass
    if info.get("create_time"):
        extra["started"] = datetime.datetime.fromtimestamp(info["create_time"]).isoformat(timespec="seconds")
    e = _etw_procs.get(pid)
    if e and e.get("stop"):
        extra["stopped"] = _iso(e["stop"])
        extra["exit_code"] = e.get("exit_code")
    return jsonify({"info": info | extra, "ancestry": chain, "children": children,
                    "connections": conns, "history": hist,
                    "dll_loads": list(_dll_loads.get(pid, [])), "etw": ETW["active"]})


@app.route("/api/process/<int:pid>/modules")
def api_modules(pid):
    try:
        return jsonify({"modules": list_modules(pid)})
    except psutil.AccessDenied:
        return jsonify({"error": "Access denied - run NetWatch as Administrator to read this process's DLLs."}), 403
    except psutil.NoSuchProcess:
        return jsonify({"error": "Process has exited - see the ETW load timeline below."}), 404


@app.route("/api/process/<int:pid>/hash")
def api_hash(pid):
    exe = proc_info(pid).get("exe")
    if not exe:
        abort(404)
    return jsonify({"path": exe, "sha256": sha256_file(exe), "sig": check_signatures([exe])[exe]})


@app.route("/api/signatures", methods=["POST"])
def api_signatures():
    paths = [p for p in (request.get_json(silent=True) or {}).get("paths", []) if isinstance(p, str)][:1000]
    return jsonify(check_signatures(paths))


@app.route("/api/logs")
def api_logs():
    files = sorted((f for f in os.listdir(LOG_DIR) if f.endswith(".jsonl")), reverse=True)
    return jsonify([{"name": f, "size": os.path.getsize(os.path.join(LOG_DIR, f))} for f in files])


@app.route("/api/logs/<name>")
def api_log_file(name):
    if os.path.basename(name) != name or not name.endswith(".jsonl"):
        abort(400)
    path = os.path.join(LOG_DIR, name)
    if not os.path.exists(path):
        abort(404)
    if request.args.get("view"):
        q = (request.args.get("q") or "").lower()
        rows = collections.deque(maxlen=5000)
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not q or q in line.lower():
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
        return jsonify(list(rows))
    return send_file(path, as_attachment=True)


def _file_row(r):
    return {"path": r["path"], "name": r["name"], "kind": r["kind"], "risk": r["risk"], "net": r["net"],
            "sig_class": r["sig_class"], "status": (r["sig"] or {}).get("status", ""),
            "signer": (r["sig"] or {}).get("signer", ""), "sha256": r["sha256"],
            "procs": sorted(r["procs"]), "pids": sorted(r["pids"])[:20], "first_seen": _iso(r["first_seen"])}


@app.route("/api/files")
def api_files():
    flt = request.args.get("filter", "flagged")
    with _files_lock:
        recs = list(_files.values())
    out = []
    for r in recs:
        bad = r["sig_class"] in ("unsigned", "untrusted", "tampered", "error")
        if flt == "flagged" and not (bad or r["risk"] != "system"):
            continue
        if flt == "unsigned" and not bad:
            continue
        if flt == "nonsystem" and r["risk"] == "system":
            continue
        if flt == "net" and not r["net"]:
            continue
        out.append(_file_row(r))
    rank = {"tampered": 0, "unsigned": 1, "untrusted": 1, "error": 2, "pending": 3, "missing": 4, "n/a": 5, "signed": 6}
    out.sort(key=lambda x: (rank.get(x["sig_class"], 5), {"user-writable": 0, "other": 1}.get(x["risk"], 2),
                            not x["net"], x["name"].lower()))
    counts = collections.Counter(r["sig_class"] for r in recs)
    return jsonify({"files": out[:3000], "total": len(recs), "by_sig": counts,
                    "nonsystem": sum(1 for r in recs if r["risk"] != "system"),
                    "queue": len(SIG.pending), "checked": SIG.done})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    threading.Thread(target=scan_running, daemon=True).start()
    return jsonify({"started": True})


@app.route("/api/findings")
def api_findings():
    with _findings_lock:
        rows = [dict(f, first=_iso(f["first"]), last=_iso(f["last"])) for f in _findings.values()]
    rows.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["last"]), reverse=False)
    return jsonify(rows)


@app.route("/api/dashboard")
def api_dashboard():
    minutes = max(5, min(request.args.get("minutes", 60, type=int), 1440))
    now = time.time()
    start = now - minutes * 60
    bs = 60 if minutes <= 60 else 300 if minutes <= 360 else 900
    nb = int((now - start) // bs) + 1
    with _ev_lock:
        evs = [e for e in _events if e["ts"] >= start]
    series_of = {"dns": "dns", "open": "tcp", "accept": "tcp", "udp": "udp", "http": "http"}
    series = {k: [0] * nb for k in ("dns", "tcp", "udp", "http")}
    dom = collections.defaultdict(lambda: {"n": 0, "procs": set()})
    procs = collections.defaultdict(lambda: {"n": 0, "domains": set(), "ips": set(), "nx": 0, "exe": "", "pids": set()})
    services = collections.Counter()
    ips, domains, dns_fail, urls = set(), set(), 0, []
    for e in evs:
        s = series_of.get(e["event"])
        if not s or not e["pid"]:
            continue
        if e["remote"] and (e.get("scope") or ip_scope(e["remote"].rpartition(":")[0].strip("[]"))) == "loopback":
            continue
        series[s][min(nb - 1, int((e["ts"] - start) // bs))] += 1
        p = procs[e["process"]]
        p["n"] += 1
        p["exe"] = e["exe"] or p["exe"]
        p["pids"].add(e["pid"])
        host = e["host"] or ""
        if e["event"] == "dns" and e["status"] == "FAIL":
            dns_fail += 1
            p["nx"] += 1
            continue
        if host:
            dom[host]["n"] += 1
            dom[host]["procs"].add(e["process"])
            domains.add(host)
            p["domains"].add(host)
        if e["event"] in ("open", "accept", "udp") and e["remote"]:
            ip = e["remote"].rpartition(":")[0].strip("[]")
            if ip_scope(ip) == "public":
                ips.add(ip)
                p["ips"].add(ip)
            services[e["service"] or ("port " + e["remote"].rpartition(":")[2])] += 1
        if e["event"] == "http":
            urls.append({"time": e["time"], "process": e["process"], "pid": e["pid"], "url": e["target"],
                         "detail": e["detail"]})

    def sigc(exe):
        with _files_lock:
            r = _files.get((exe or "").lower())
        return (r["sig_class"], (r["sig"] or {}).get("signer", "")) if r else ("pending" if exe else "unknown", "")

    top_procs = sorted(procs.items(), key=lambda kv: -kv[1]["n"])[:15]
    with _findings_lock:
        fsev = collections.Counter(f["severity"] for f in _findings.values())
        ftop = sorted(_findings.values(), key=lambda f: (SEV_ORDER[f["severity"]], -f["last"]))[:8]
    with _files_lock:
        unsigned = sum(1 for r in _files.values() if r["sig_class"] in ("unsigned", "untrusted", "tampered"))
        nfiles = len(_files)
    return jsonify({
        "minutes": minutes, "bucket": bs, "start": start,
        "series": series,
        "kpi": {"requests": sum(sum(v) for v in series.values()), "domains": len(domains), "ips": len(ips),
                "dns_fail": dns_fail, "processes": len(procs), "unsigned": unsigned, "files": nfiles,
                "findings": dict(fsev)},
        "top_domains": [{"host": h, "n": d["n"], "procs": sorted(d["procs"])[:4]}
                        for h, d in sorted(dom.items(), key=lambda kv: -kv[1]["n"])[:12]],
        "top_procs": [{"name": n, "n": d["n"], "domains": len(d["domains"]), "ips": len(d["ips"]), "nx": d["nx"],
                       "exe": d["exe"], "risk": path_risk(d["exe"]), "pid": max(d["pids"]) if d["pids"] else 0,
                       "sig": sigc(d["exe"])[0], "signer": sigc(d["exe"])[1]} for n, d in top_procs],
        "services": services.most_common(8),
        "urls": urls[-15:][::-1],
        "findings": [dict(f, first=_iso(f["first"]), last=_iso(f["last"])) for f in ftop],
        "etw": ETW["active"],
    })


def _load_history():
    """Reload today's log so the dashboard survives restarts."""
    global _event_id
    path = _log_path()
    if not os.path.exists(path):
        return
    rows = collections.deque(maxlen=_events.maxlen)
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    for i, e in enumerate(rows, 1):
        e["id"] = i
        for k in ("target", "detail", "host", "remote", "local", "service", "status", "proto", "exe", "parent"):
            e[k] = e.get(k) or ""
        e.setdefault("source", "poll")
        _events.append(e)
        _kind_counts[e.get("event", "?")] += 1
    _event_id = len(rows)
    print(f"[+] Reloaded {len(rows)} events from today's log")


def _existing_instance(port):
    """True if another NetWatch already serves this port (don't start a second ETW session)."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"http://{HOST}:{port}/api/status", timeout=2) as r:
            return "etw" in json.loads(r.read())
    except Exception:
        return False


def _port_free(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((HOST, port)) != 0


def main():
    global PORT
    import webbrowser
    if FROZEN:
        os.system("title NetWatch - close this window to stop")
    if not _port_free(PORT):
        if _existing_instance(PORT):
            print(f"[i] NetWatch is already running - opening http://{HOST}:{PORT}")
            webbrowser.open(f"http://{HOST}:{PORT}")
            time.sleep(2)
            return
        PORT = next(p for p in range(PORT + 1, PORT + 50) if _port_free(p))
    _load_history()
    if not is_admin():
        print("[!] Not running as Administrator - ETW sensor disabled, SYSTEM/other-user processes "
              "show limited info and their DLLs cannot be read.")
    start_etw()
    threading.Thread(target=_refresh_dns_cache_loop, daemon=True).start()
    threading.Thread(target=_tracker_loop, daemon=True).start()
    threading.Thread(target=_findings_loop, daemon=True).start()
    threading.Thread(target=lambda: (time.sleep(4), scan_running()), daemon=True).start()
    print(f"[+] NetWatch running at http://{HOST}:{PORT}  (logs: {LOG_DIR})")
    if FROZEN or "--open" in sys.argv:
        threading.Timer(1.5, lambda: webbrowser.open(f"http://{HOST}:{PORT}")).start()
    app.run(host=HOST, port=PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()
