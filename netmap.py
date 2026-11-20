"""
Local network discovery + topology for NetWatch's interactive map.

Sources (no promiscuous mode needed - Windows Wi-Fi drivers do not support it):
  * active ARP sweep of the local subnet with iphlpapi!SendARP (answers even when ping is blocked)
  * the Windows neighbour (ARP/NDP) table
  * reverse DNS
  * passive listening (pktmon) to broadcast/multicast that every device sends anyway:
    ARP, mDNS, SSDP/UPnP, LLMNR, NetBIOS, DHCP  -> hostnames, models, services
  * optional TCP connect check of common ports - private (RFC1918 / ULA) addresses only
  * traceroute to the internet for the ISP hops (shows CGNAT)

State lives in <base>/devices.json (git-ignored). Vendor names need the IEEE OUI list
(<base>/oui.txt), which the user downloads from the UI on demand.
"""
import ctypes
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CREATE_NO_WINDOW = 0x08000000
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
COMMON_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 139: "NetBIOS", 443: "HTTPS",
                445: "SMB", 554: "RTSP (camera)", 631: "IPP (printer)", 1883: "MQTT (IoT)", 3389: "RDP",
                5000: "UPnP/AirPlay", 5357: "WSD", 7000: "AirPlay", 8008: "Cast", 8009: "Cast",
                8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "Printer (RAW)", 49152: "UPnP", 62078: "Apple sync"}
DISCOVERY_FILTERS = [["-d", "ARP"], ["-t", "UDP", "-p", "5353"], ["-t", "UDP", "-p", "1900"],
                     ["-t", "UDP", "-p", "5355"], ["-t", "UDP", "-p", "137"], ["-t", "UDP", "-p", "67"],
                     ["-t", "UDP", "-p", "68"]]
VIRTUAL_HINTS = ("vmware", "virtualbox", "vethernet", "wsl", "hyper-v", "docker", "tailscale", "zerotier",
                 "loopback", "bluetooth", "tap", "wintun", "wireguard", "npcap")

iphlpapi = ctypes.WinDLL("iphlpapi")
dnsapi = ctypes.WinDLL("dnsapi")
dnsapi.DnsQuery_W.argtypes = [ctypes.c_wchar_p, ctypes.c_ushort, ctypes.c_ulong, ctypes.c_void_p,
                              ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
dnsapi.DnsQuery_W.restype = ctypes.c_long
dnsapi.DnsRecordListFree.argtypes = [ctypes.c_void_p, ctypes.c_int]
DNS_QUERY_NO_NETBT, DNS_QUERY_NO_MULTICAST = 0x80, 0x800


def ptr_lookup(ip):
    """Reverse DNS over DNS only. socket.gethostbyaddr() on Windows falls back to NetBIOS, which sends
    UDP/137 name queries straight to the (often public) IP - noisy and leaky. Returns '' if none."""
    try:
        a = ipaddress.ip_address(ip)
        if a.is_multicast or a.is_unspecified or a.is_loopback or (a.version == 4 and str(a).endswith(".255")):
            return ""
        res = ctypes.c_void_p()
        if dnsapi.DnsQuery_W(a.reverse_pointer, 12, DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST, None,
                             ctypes.byref(res), None) != 0 or not res.value:
            return ""
        try:
            rec = res.value
            while rec:
                wtype = ctypes.c_ushort.from_address(rec + 16).value
                if wtype == 12:                                  # DNS_TYPE_PTR -> Data.PTR.pNameHost
                    name = ctypes.c_wchar_p.from_address(rec + 32).value
                    if name:
                        return name.rstrip(".")
                rec = ctypes.c_void_p.from_address(rec).value     # pNext
        finally:
            dnsapi.DnsRecordListFree(res, 1)
    except Exception:
        pass
    return ""


def send_arp(ip):
    """Return MAC 'aa:bb:..' for an IPv4 on a directly-connected subnet, or None."""
    dest = struct.unpack("<I", socket.inet_aton(ip))[0]
    mac = (ctypes.c_ubyte * 8)()
    ln = ctypes.c_ulong(8)
    if iphlpapi.SendARP(dest, 0, ctypes.byref(mac), ctypes.byref(ln)) == 0 and ln.value == 6:
        m = ":".join(f"{b:02x}" for b in mac[:6])
        return None if m in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") else m
    return None


def is_random_mac(mac):
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def _ps(cmd, env=None, timeout=30):
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True,
                          text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW, env=env).stdout


class NetMap:
    def __init__(self, base_dir, ps_env=None, on_new_device=None):
        self.base = base_dir
        self.path = os.path.join(base_dir, "devices.json")
        self.oui_path = os.path.join(base_dir, "oui.txt")
        self.ps_env, self.on_new = ps_env, on_new_device
        self.lock = threading.Lock()
        self.devices = self._load()          # key (mac or ip) -> device dict
        self.oui = {}
        self._load_oui()
        self.hops = []                       # traceroute hop IPs
        self.hops_at = 0
        self.ifaces = []
        self.state = {"sweep": "idle", "trace": "idle", "oui": "present" if self.oui else "missing", "last_sweep": 0}
        self.pool = ThreadPoolExecutor(max_workers=64)

    # ---- persistence ----
    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save(self):
        with self.lock:
            snap = json.dumps(self.devices)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(snap)
        os.replace(tmp, self.path)

    def _load_oui(self):
        if not os.path.exists(self.oui_path):
            return
        rx = re.compile(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$")
        with open(self.oui_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = rx.match(line.strip())
                if m:
                    self.oui[(m.group(1) + m.group(2) + m.group(3)).lower()] = m.group(4).strip()

    def download_oui(self):
        self.state["oui"] = "downloading"
        try:
            req = urllib.request.Request(OUI_URL, headers={"User-Agent": "NetWatch/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            if b"(hex)" not in data[:20000]:
                raise ValueError("unexpected content")
            with open(self.oui_path, "wb") as f:
                f.write(data)
            self._load_oui()
            with self.lock:
                for d in self.devices.values():
                    if d.get("mac"):
                        d["vendor"] = self.vendor(d["mac"])
            self.state["oui"] = "present"
        except Exception as e:
            self.state["oui"] = f"error: {e}"

    def vendor(self, mac):
        if not mac:
            return ""
        if is_random_mac(mac):
            return "(private / randomized MAC)"
        return self.oui.get(mac.replace(":", "")[:6], "")

    # ---- interfaces / routes ----
    def interfaces(self):
        import psutil
        stats = psutil.net_if_stats()
        out = []
        route_alias, gw = "", ""
        try:
            line = _ps("Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Sort-Object RouteMetric | "
                       "Select-Object -First 1 | ForEach-Object { $_.InterfaceAlias + '|' + $_.NextHop }", self.ps_env).strip()
            route_alias, _, gw = line.partition("|")
        except Exception:
            pass
        for name, addrs in psutil.net_if_addrs().items():
            st = stats.get(name)
            if not st or not st.isup:
                continue
            v4 = [(a.address, a.netmask) for a in addrs if a.family == socket.AF_INET]
            v6 = [a.address.split("%")[0] for a in addrs if a.family == socket.AF_INET6 and not a.address.startswith("fe80")]
            mac = next((a.address.replace("-", ":").lower() for a in addrs if a.family == psutil.AF_LINK), "")
            v4 = [(a, m) for a, m in v4 if not a.startswith("169.254.")]   # APIPA = adapter not really connected
            if not v4 and not v6:
                continue
            if name.lower().startswith("loopback"):
                continue
            out.append({"name": name, "ipv4": v4, "ipv6": v6, "mac": mac, "speed": st.speed,
                        "virtual": any(h in name.lower() for h in VIRTUAL_HINTS),
                        "default": name == route_alias, "gateway": gw if name == route_alias else ""})
        self.ifaces = out
        return out

    def primary(self):
        ifs = self.ifaces or self.interfaces()
        return next((i for i in ifs if i["default"]), next((i for i in ifs if not i["virtual"]), None))

    # ---- device store ----
    def _upsert(self, ip=None, mac=None, source="", **info):
        mac = (mac or "").lower()
        key = mac or ip
        if not key:
            return
        if not self.ifaces:
            self.interfaces()
        mine_ip = {a for i in self.ifaces for a, _m in i["ipv4"]} | {a for i in self.ifaces for a in i["ipv6"]}
        mine_mac = {i["mac"] for i in self.ifaces if i["mac"]}
        if (ip and ip in mine_ip) or (mac and mac in mine_mac):    # this PC's own adapters are drawn separately
            return
        new = False
        with self.lock:
            d = self.devices.get(key)
            if d is None and ip:                       # merge IP-only record into MAC record
                d = self.devices.pop(ip, None)
                if d is not None and mac:
                    self.devices[key] = d
            if d is None:
                d = self.devices[key] = {"mac": mac, "ips": [], "names": [], "first_seen": time.time(),
                                         "sources": [], "ports": {}, "services": [], "info": {}}
                new = True
            d["mac"] = d.get("mac") or mac
            d["last_seen"] = time.time()
            if ip and ip not in d["ips"]:
                d["ips"] = ([ip] + d["ips"])[:8]
            if source and source not in d["sources"]:
                d["sources"].append(source)
            for n in info.pop("names", []):
                n = (n or "").strip().rstrip(".")
                if n and n not in d["names"] and len(d["names"]) < 10:
                    d["names"].append(n)
            for s in info.pop("services", []):
                if s and s not in d["services"] and len(d["services"]) < 20:
                    d["services"].append(s)
            d["info"].update({k: v for k, v in info.items() if v})
            if d.get("mac") and not d.get("vendor"):
                d["vendor"] = self.vendor(d["mac"])
        if new and self.on_new and (self.state["last_sweep"] or source == "passive"):
            self.on_new(d)

    def neighbor_table(self):
        out = _ps("Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Unreachable' -and "
                  "$_.State -ne 'Incomplete' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and "
                  "$_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' } | ForEach-Object { $_.IPAddress + '|' + $_.LinkLayerAddress + "
                  "'|' + $_.InterfaceAlias + '|' + $_.State }", self.ps_env)
        rows = []
        for line in out.splitlines():
            p = line.strip().split("|")
            if len(p) == 4:
                ip = p[0]
                try:
                    a = ipaddress.ip_address(ip)
                    if a.is_multicast or a.is_link_local and a.version == 6:
                        continue
                    if a.version == 4 and (str(a).endswith(".255") or a.is_multicast):
                        continue
                except ValueError:
                    continue
                rows.append({"ip": ip, "mac": p[1].replace("-", ":").lower(), "iface": p[2], "state": p[3]})
        return rows

    def sweep(self):
        """ARP-sweep every directly connected IPv4 subnet (up to /22 each)."""
        if self.state["sweep"] == "running":
            return
        self.state["sweep"] = "running"
        try:
            ifs = self.interfaces()
            jobs = []
            for i in ifs:
                for addr, mask in i["ipv4"]:
                    if not mask or addr.startswith("169.254."):
                        continue
                    net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
                    floor = 22 if i["default"] else 24        # virtual/host-only nets: just the /24 around us
                    if net.prefixlen < floor:
                        net = ipaddress.ip_network(f"{addr}/{floor}", strict=False)
                    for h in net.hosts():
                        if str(h) != addr:
                            jobs.append((str(h), i["name"]))
            with ThreadPoolExecutor(max_workers=192) as sweep_pool:
                futs = {sweep_pool.submit(send_arp, ip): (ip, ifn) for ip, ifn in jobs}
            for f, (ip, ifn) in futs.items():
                try:
                    mac = f.result(timeout=10)
                except Exception:
                    mac = None
                if mac:
                    self._upsert(ip, mac, "arp-sweep", iface=ifn)
            for n in self.neighbor_table():
                self._upsert(n["ip"], n["mac"], "neighbor-table", iface=n["iface"])
            self._resolve_names()
            self.state["last_sweep"] = time.time()
            self.save()
        finally:
            self.state["sweep"] = "idle"

    def _resolve_names(self):
        with self.lock:
            items = [(k, d["ips"][0]) for k, d in self.devices.items() if d["ips"]]

        for (k, ip), name in zip(items, self.pool.map(ptr_lookup, [ip for _, ip in items])):
            if name and name != ip:
                with self.lock:
                    d = self.devices.get(k)
                    if d is not None and name not in d["names"]:
                        d["names"].append(name)

    def traceroute(self, target="1.1.1.1"):
        self.state["trace"] = "running"
        try:
            out = subprocess.run(["tracert", "-d", "-h", "8", "-w", "700", target], capture_output=True, text=True,
                                 timeout=120, creationflags=CREATE_NO_WINDOW).stdout
            hops = []
            for line in out.splitlines():
                m = re.match(r"^\s*(\d+)\s+(.*?)(\d{1,3}(?:\.\d{1,3}){3})\s*$", line)
                if m:
                    ip = m.group(3)
                    a = ipaddress.ip_address(ip)
                    hop = int(m.group(1))
                    hops.append({"hop": hop, "ip": ip,
                                 "kind": "cgnat" if a in ipaddress.ip_network("100.64.0.0/10") or (a.is_private and hop > 1)
                                         else "private" if a.is_private else "public"})
                elif re.match(r"^\s*(\d+)\s+\*\s+\*\s+\*", line):
                    hops.append({"hop": int(line.split()[0]), "ip": "", "kind": "timeout"})
            self.hops, self.hops_at = hops, time.time()
        finally:
            self.state["trace"] = "idle"
        return self.hops

    # ---- passive discovery from a pktmon capture ----
    def ingest_capture(self, result):
        for r in result.get("packets", []):
            d = r["detail"]
            src_mac = d.get("eth_src", "")
            ip = d.get("src", "")
            if d.get("arp"):
                a = d["arp"]
                self._upsert(a["sender_ip"], a["sender_mac"], "passive", names=[])
                continue
            try:
                if not ip or not ipaddress.ip_address(ip).is_private and not ipaddress.ip_address(ip).is_link_local:
                    continue
            except ValueError:
                continue
            names, services, info = [], [], {}
            if d.get("dns") and d["dns"]["response"]:
                for q in d["dns"]["answers"] + d["dns"]["questions"]:
                    q = q.split()[0] if q else ""
                    if q.endswith(".local") and not q.startswith("_"):
                        names.append(q)
                    elif "._tcp.local" in q or "._udp.local" in q:
                        services.append(q.split("._")[0].lstrip("_") if q.startswith("_") else q.split(".")[0])
            if d.get("nbns"):
                names.append(d["nbns"]["name"])
            if d.get("dhcp"):
                dh = d["dhcp"]
                if dh.get("hostname"):
                    names.append(dh["hostname"])
                info["dhcp_vendor"] = dh.get("vendor_class", "")
                src_mac = dh.get("client_mac") or src_mac
                ip = dh.get("requested_ip") or ip
            if d.get("ssdp"):
                info["upnp_server"] = d["ssdp"].get("server", "")
                if d["ssdp"].get("location"):
                    info["upnp_location"] = d["ssdp"]["location"]
            if ip and (names or services or info or src_mac):
                if ip.startswith("0."):
                    ip = None
                self._upsert(ip, src_mac if not src_mac.startswith(("01:00:5e", "33:33", "ff:ff")) else "",
                             "passive", names=names, services=services, **info)
        self.save()

    # ---- port check (private addresses only) ----
    def check_ports(self, ip, timeout=0.6):
        a = ipaddress.ip_address(ip)
        if not (a.is_private or a.is_link_local) or a.is_loopback:
            raise ValueError("port checks are limited to devices on your local network")

        def probe(p):
            with socket.socket(socket.AF_INET6 if a.version == 6 else socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return p if s.connect_ex((ip, p)) == 0 else None
        open_ports = [p for p in self.pool.map(probe, COMMON_PORTS) if p]
        with self.lock:
            for d in self.devices.values():
                if ip in d["ips"]:
                    d["ports"] = {str(p): COMMON_PORTS[p] for p in open_ports}
                    d["ports_checked"] = time.time()
        self.save()
        return {str(p): COMMON_PORTS[p] for p in open_ports}

    # ---- classification + topology ----
    @staticmethod
    def guess_type(d, gateway_ips):
        names = " ".join(d.get("names", []) + d.get("services", []) + [d.get("vendor", ""),
                                                                         d.get("info", {}).get("upnp_server", ""),
                                                                         d.get("info", {}).get("dhcp_vendor", "")]).lower()
        ports = set(int(p) for p in d.get("ports", {}))
        if any(ip in gateway_ips for ip in d.get("ips", [])):
            return "router"
        rules = [("printer", ("printer", "ipp", "epson", "brother", "canon", "hp ")), ("camera", ("cam", "hikvision", "dahua", "ezviz", "imou", "reolink")),
                 ("tv", ("tv", "roku", "chromecast", "googlecast", "bravia", "webos", "tizen", "firetv", "androidtv")),
                 ("phone", ("iphone", "android", "galaxy", "pixel", "redmi", "oppo", "vivo", "realme", "oneplus")),
                 ("tablet", ("ipad", "tab")), ("speaker", ("echo", "alexa", "sonos", "homepod", "google-home", "nest")),
                 ("iot", ("espressif", "esp_", "esp-", "tasmota", "shelly", "tuya", "sonoff", "smartlife", "mqtt")),
                 ("console", ("xbox", "playstation", "ps4", "ps5", "nintendo")),
                 ("computer", ("desktop-", "laptop-", "macbook", "imac", "windows", "msft", "workstation", "_smb", "_rdp"))]
        for kind, keys in rules:
            if any(k in names for k in keys):
                return kind
        if ports & {9100, 631}:
            return "printer"
        if 554 in ports:
            return "camera"
        if ports & {8008, 8009}:
            return "tv"
        if 62078 in ports:
            return "phone"
        if ports & {3389, 445}:
            return "computer"
        if "randomized" in d.get("vendor", ""):
            return "phone"
        return "device"

    def topology(self, public_ip=""):
        ifs = self.ifaces or self.interfaces()
        prim = self.primary()
        gw_ips = {i["gateway"] for i in ifs if i.get("gateway")}
        nodes, edges = [], []
        nodes.append({"id": "internet", "type": "internet", "label": "Internet", "sub": public_ip and f"public IP {public_ip}"})
        parent = "internet"
        hops = [h for h in self.hops if h["ip"]]
        hop_nodes = []
        for h in reversed(hops[1:]):          # hop 1 is the router itself
            nid = f"hop:{h['ip']}"
            hop_nodes.append({"id": nid, "type": "isp", "label": h["ip"], "sub": f"hop {h['hop']} · {h['kind']}",
                              "kind": h["kind"]})
        for n in hop_nodes:
            nodes.append(n)
            edges.append([parent, n["id"]])
            parent = n["id"]
        router_ip = next(iter(gw_ips), "")
        with self.lock:
            devs = {k: dict(v) for k, v in self.devices.items()}
        router_dev = next((d for d in devs.values() if router_ip and router_ip in d["ips"]), None)
        rid = "router"
        nodes.append({"id": rid, "type": "router", "label": router_ip or "Router",
                      "sub": (router_dev or {}).get("vendor", "") or "default gateway",
                      "device": router_dev})
        edges.append([parent, rid])
        me = {"id": "me", "type": "this-pc", "label": socket.gethostname(), "sub": "this PC"}
        nodes.append(me)
        edges.append([rid, "me"])
        prim_net = None
        if prim and prim["ipv4"]:
            a, m = prim["ipv4"][0]
            prim_net = ipaddress.ip_network(f"{a}/{m}", strict=False)
            me["sub"] = f"this PC · {a} ({prim['name']})"
        virt_nets = {}
        for i in ifs:
            if i is prim:
                continue
            nid = f"if:{i['name']}"
            ip4 = i["ipv4"][0][0] if i["ipv4"] else (i["ipv6"][0] if i["ipv6"] else "")
            nodes.append({"id": nid, "type": "vnet" if i["virtual"] else "nic", "label": i["name"], "sub": ip4})
            edges.append(["me", nid])
            for a, m in i["ipv4"]:
                if m:
                    virt_nets[ipaddress.ip_network(f"{a}/{m}", strict=False)] = nid
        for k, d in devs.items():
            if any(ip in gw_ips for ip in d["ips"]):
                continue
            ipv4 = next((ip for ip in d["ips"] if ":" not in ip), d["ips"][0] if d["ips"] else "")
            par = rid
            if ipv4 and ":" not in ipv4:
                a = ipaddress.ip_address(ipv4)
                if prim_net is None or a not in prim_net:
                    par = next((nid for net, nid in virt_nets.items() if a in net), None)
                    if par is None:                     # e.g. an old Mobile Hotspot client (192.168.137.x)
                        if not any(n["id"] == "other" for n in nodes):
                            nodes.append({"id": "other", "type": "vnet", "label": "Other / earlier networks",
                                          "sub": "seen before, not on a current subnet"})
                            edges.append(["me", "other"])
                        par = "other"
            kind = self.guess_type(d, gw_ips)
            label = next((n for n in d["names"] if not re.fullmatch(r"[\d.:a-f]+", n)), "") or ipv4 or k
            nodes.append({"id": f"dev:{k}", "type": kind, "label": label[:32], "sub": ipv4 + (f" · {d['vendor']}" if d.get("vendor") else ""),
                          "device": d, "new": time.time() - d.get("first_seen", 0) < 86400,
                          "stale": time.time() - d.get("last_seen", 0) > 3600})
            edges.append([par, f"dev:{k}"])
        return {"nodes": nodes, "edges": edges, "state": self.state, "hops_at": self.hops_at,
                "interfaces": ifs, "device_count": len(devs)}
