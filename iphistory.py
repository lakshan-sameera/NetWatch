"""
Public IP history for NetWatch.

Every few minutes (and whenever the local network changes) it asks api.ipify.org /
api6.ipify.org for the current public IPv4 / IPv6 and records *periods*: which IP was in use
from when to when, over which adapter, and whether a VPN adapter carried the default route.
A gap longer than GAP seconds (PC asleep / offline) closes a period, so the timeline also
shows when the PC could not have been sending anything.

State lives in <base>/iphistory.json (git-ignored).
"""
import json
import os
import socket
import subprocess
import threading
import time
import urllib.request

CHECK_EVERY = 300
NET_POLL = 15
GAP = 15 * 60
CREATE_NO_WINDOW = 0x08000000
VPN_HINTS = ("windscribe", "warp", "cloudflare", "tailscale", "openvpn", "tap-", "tap ", "wireguard", "wintun",
             "nordlynx", "proton", "mullvad", "expressvpn", "surfshark", "zerotier", "vpn")
SOURCES = {4: "https://api.ipify.org", 6: "https://api6.ipify.org"}


def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "NetWatch/1.0"})
    with urllib.request.urlopen(req, timeout=8) as r:
        ip = r.read().decode().strip()
    socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)   # validate
    return ip


def default_route(ps_env=None):
    """(interface alias, next hop) of the active IPv4 default route."""
    ps = ("Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | "
          "Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4).InterfaceMetric } | "
          "Select-Object -First 1 | ForEach-Object { $_.InterfaceAlias + '|' + $_.NextHop }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], capture_output=True,
                             text=True, timeout=20, creationflags=CREATE_NO_WINDOW, env=ps_env).stdout.strip()
        alias, _, hop = out.partition("|")
        return alias.strip(), hop.strip()
    except Exception:
        return "", ""


def _netsig():
    import psutil
    return tuple(sorted((n, a.address) for n, addrs in psutil.net_if_addrs().items() for a in addrs
                        if a.family in (socket.AF_INET, socket.AF_INET6) and not a.address.startswith(("fe80", "169.254"))))


class IPHistory:
    def __init__(self, base_dir, on_change=None, lookup=None, ps_env=None):
        """on_change(family, old_period, new_period); lookup(ip) -> optional {'isp','score','country'}"""
        self.path = os.path.join(base_dir, "iphistory.json")
        self.on_change, self.lookup, self.ps_env = on_change, lookup, ps_env
        self.lock = threading.Lock()
        self.periods = self._load()
        self.last_error = ""
        self.last_check = 0
        self.kick = threading.Event()
        threading.Thread(target=self._loop, name="iphistory", daemon=True).start()
        threading.Thread(target=self._watch_net, name="iphistory-net", daemon=True).start()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save(self):
        with self.lock:
            snap = json.dumps(self.periods[-5000:])
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(snap)
        os.replace(tmp, self.path)

    def _watch_net(self):
        last = None
        while True:
            try:
                sig = _netsig()
                if last is not None and sig != last:
                    self.kick.set()          # adapter / VPN / Wi-Fi change -> check now
                last = sig
            except Exception:
                pass
            time.sleep(NET_POLL)

    def _loop(self):
        time.sleep(3)
        while True:
            try:
                self.check()
            except Exception as e:
                self.last_error = str(e)
            self.kick.wait(CHECK_EVERY)
            self.kick.clear()

    def check(self):
        alias, hop = default_route(self.ps_env)
        vpn = next((h.strip() for h in VPN_HINTS if h in alias.lower()), "") if alias else ""
        now = time.time()
        self.last_check = now
        errors = []
        for fam, url in SOURCES.items():
            try:
                ip = _fetch(url)
            except Exception as e:
                if fam == 4:
                    errors.append(f"IPv4: {e.__class__.__name__}")
                continue
            self._record(fam, ip, now, alias, hop, vpn)
        self.last_error = "; ".join(errors)
        self._save()

    def _record(self, fam, ip, now, alias, hop, vpn):
        with self.lock:
            cur = next((p for p in reversed(self.periods) if p["family"] == fam), None)
            if cur and cur["ip"] == ip and now - cur["last_seen"] <= GAP and cur.get("iface") == alias:
                cur["last_seen"] = now
                cur["checks"] = cur.get("checks", 0) + 1
                return
            new = {"family": fam, "ip": ip, "first_seen": now, "last_seen": now, "iface": alias, "gateway": hop,
                   "vpn": vpn, "checks": 1}
            if cur and now - cur["last_seen"] > GAP:
                new["after_gap"] = round(now - cur["last_seen"])
            self.periods.append(new)
        if self.lookup:
            try:
                new.update(self.lookup(ip) or {})
            except Exception:
                pass
        if self.on_change and cur and cur["ip"] != ip:
            self.on_change(fam, cur, new)

    def at(self, ts):
        """Which public IPs were in use at unix time ts (and was the PC online)?"""
        with self.lock:
            hits = [p for p in self.periods if p["first_seen"] - 60 <= ts <= p["last_seen"] + CHECK_EVERY + 60]
            before = [p for p in self.periods if p["last_seen"] < ts]
            after = [p for p in self.periods if p["first_seen"] > ts]
        return {"matches": hits, "last_before": before[-1] if before else None, "first_after": after[0] if after else None}

    def view(self):
        with self.lock:
            periods = [dict(p) for p in self.periods]
        cur = {}
        for p in periods:
            cur[p["family"]] = p
        return {"periods": periods, "current": cur, "last_check": self.last_check, "last_error": self.last_error,
                "check_every": CHECK_EVERY, "gap": GAP}
