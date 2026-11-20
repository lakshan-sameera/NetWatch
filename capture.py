"""
Packet capture for NetWatch, using Windows' built-in Packet Monitor (pktmon).

* One capture at a time (pktmon is a single global session), run in a background thread.
* Captures at the NIC only (--comp nics), full packets, then converts to .pcapng with
  `pktmon etl2pcap` and parses it with the small decoder below.
* The decoder understands Ethernet / 802.1Q / IPv4 / IPv6 / ARP / TCP / UDP / ICMP and
  summarises DNS, TLS ClientHello (SNI, ALPN), plaintext HTTP, QUIC, mDNS, SSDP, NetBIOS,
  LLMNR and DHCP - enough to explain what a request did on the wire.

Needs Administrator. Captures are stored in <base>/captures/ (git-ignored: they hold traffic).
"""
import datetime
import hashlib
import ipaddress
import os
import socket
import struct
import subprocess
import threading
import time
import uuid

CREATE_NO_WINDOW = 0x08000000
MAX_PACKETS = 5000
HEX_LIMIT = 2048


def _run(args, timeout=60):
    p = subprocess.run(["pktmon"] + args, capture_output=True, text=True, timeout=timeout,
                       creationflags=CREATE_NO_WINDOW)
    return p.returncode, (p.stdout + p.stderr).strip()


def pktmon_available():
    try:
        return _run(["help"], 15)[0] in (0, 1)
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# pcapng parsing
# --------------------------------------------------------------------------- #
def read_pcapng(path):
    """Yield (ts_float, linktype, bytes, direction) from a pcapng file."""
    with open(path, "rb") as f:
        data = f.read()
    off, ifaces, endian = 0, [], "<"
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from(endian + "II", data, off)
        if btype == 0x0A0D0D0A:  # section header: detect byte order
            bom = data[off + 8:off + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            btype, blen = struct.unpack_from(endian + "II", data, off)
            ifaces = []
        if blen < 12 or off + blen > len(data):
            break
        body = data[off + 8:off + blen - 4]
        if btype == 1:  # interface description
            link = struct.unpack_from(endian + "H", body, 0)[0]
            res = 1e-6
            o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack_from(endian + "HH", body, o)
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = body[o + 4]
                    res = 2 ** -(v & 0x7F) if v & 0x80 else 10 ** -v
                o += 4 + ((ln + 3) & ~3)
            ifaces.append((link, res))
        elif btype == 6 and len(body) >= 20:  # enhanced packet
            iid, th, tl, cap, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            pkt = body[20:20 + cap]
            link, res = ifaces[iid] if iid < len(ifaces) else (1, 1e-6)
            ts = ((th << 32) | tl) * res
            direction = ""
            o = 20 + ((cap + 3) & ~3)
            while o + 4 <= len(body):
                code, ln = struct.unpack_from(endian + "HH", body, o)
                if code == 0:
                    break
                if code == 2 and ln == 4:  # epb_flags: bits 0-1 = direction
                    d = struct.unpack_from(endian + "I", body, o + 4)[0] & 3
                    direction = {1: "in", 2: "out"}.get(d, "")
                o += 4 + ((ln + 3) & ~3)
            yield ts, link, pkt, direction
        off += blen


# --------------------------------------------------------------------------- #
# Protocol decoding
# --------------------------------------------------------------------------- #
TCP_FLAGS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
             64: "SVCB", 65: "HTTPS", 255: "ANY"}
TLS_VER = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _dns_name(buf, off, depth=0):
    labels, jumped, end = [], False, off
    while off < len(buf) and depth < 20:
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                break
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
            jumped, off, depth = True, ptr, depth + 1
            continue
        labels.append(buf[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels), (end if jumped else off)


def parse_dns(p):
    if len(p) < 12:
        return None
    tid, flags, qd, an = struct.unpack_from(">HHHH", p, 0)
    off, qs, answers = 12, [], []
    try:
        for _ in range(min(qd, 10)):
            name, off = _dns_name(p, off)
            qt = struct.unpack_from(">H", p, off)[0]
            off += 4
            qs.append(f"{name} {DNS_TYPES.get(qt, qt)}")
        for _ in range(min(an, 30)):
            name, off = _dns_name(p, off)
            at, _cls, _ttl, rl = struct.unpack_from(">HHIH", p, off)
            off += 10
            rd = p[off:off + rl]
            if at == 1 and rl == 4:
                answers.append(socket.inet_ntoa(rd))
            elif at == 28 and rl == 16:
                answers.append(socket.inet_ntop(socket.AF_INET6, rd))
            elif at in (5, 12, 2):
                answers.append(_dns_name(p, off)[0])
            elif at == 16:
                answers.append(rd[1:1 + rd[0]].decode("ascii", "replace") if rd else "")
            off += rl
    except Exception:
        pass
    resp = bool(flags & 0x8000)
    rcode = flags & 0xF
    return {"id": tid, "response": resp, "rcode": rcode, "questions": qs, "answers": answers}


def parse_tls(p):
    """ClientHello -> SNI/ALPN/version; ServerHello -> version; other records -> type."""
    if len(p) < 6 or p[0] not in (0x14, 0x15, 0x16, 0x17) or p[1] != 0x03:
        return None
    rtype = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake", 0x17: "Application Data"}[p[0]]
    out = {"record": rtype, "version": TLS_VER.get(struct.unpack_from(">H", p, 1)[0], "?")}
    if p[0] != 0x16 or len(p) < 10:
        return out
    hs = p[5]
    out["handshake"] = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
                        11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone",
                        15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished"}.get(hs, "encrypted handshake")
    try:
        if hs in (1, 2):
            o = 9 + 2 + 32                      # header + client_version + random
            sid = p[o]
            o += 1 + sid
            if hs == 1:
                cs = struct.unpack_from(">H", p, o)[0]
                o += 2 + cs
                o += 1 + p[o]                   # compression methods
            else:
                o += 2 + 1                      # cipher suite + compression
            ext_end = o + 2 + struct.unpack_from(">H", p, o)[0]
            o += 2
            while o + 4 <= min(ext_end, len(p)):
                et, el = struct.unpack_from(">HH", p, o)
                ed = p[o + 4:o + 4 + el]
                if et == 0 and len(ed) > 5:     # server_name
                    nl = struct.unpack_from(">H", ed, 3)[0]
                    out["sni"] = ed[5:5 + nl].decode("ascii", "replace")
                elif et == 16 and len(ed) > 2:  # ALPN
                    lst, i = [], 2
                    while i < len(ed):
                        ln = ed[i]
                        lst.append(ed[i + 1:i + 1 + ln].decode("ascii", "replace"))
                        i += 1 + ln
                    out["alpn"] = lst
                elif et == 43 and ed:           # supported_versions
                    if hs == 2 and len(ed) >= 2:
                        out["version"] = TLS_VER.get(struct.unpack_from(">H", ed, 0)[0], out["version"])
                    elif hs == 1:
                        vs = [TLS_VER.get(struct.unpack_from(">H", ed, 1 + 2 * k)[0], "") for k in range(ed[0] // 2)]
                        out["offers"] = [v for v in vs if v]
                o += 4 + el
    except Exception:
        pass
    return out


def parse_http(p):
    head = p[:2048]
    for m in (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"HTTP/1."):
        if head.startswith(m):
            text = head.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
            lines = text.split("\r\n")
            hdr = {}
            for ln in lines[1:30]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    hdr[k.strip()] = v.strip()[:200]
            return {"first_line": lines[0][:300], "headers": hdr}
    return None


def parse_dhcp(p):
    if len(p) < 240 or p[236:240] != b"\x63\x82\x53\x63":
        return None
    out = {"op": "request" if p[0] == 1 else "reply", "client_mac": _mac(p[28:34])}
    o = 240
    while o + 2 <= len(p) and p[o] != 255:
        if p[o] == 0:
            o += 1
            continue
        code, ln = p[o], p[o + 1]
        v = p[o + 2:o + 2 + ln]
        if code == 12:
            out["hostname"] = v.decode("ascii", "replace")
        elif code == 60:
            out["vendor_class"] = v.decode("ascii", "replace")
        elif code == 53 and v:
            out["type"] = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 7: "RELEASE", 8: "INFORM"}.get(v[0], v[0])
        elif code == 50 and ln == 4:
            out["requested_ip"] = socket.inet_ntoa(v)
        o += 2 + ln
    return out


def parse_nbns(p):
    """NetBIOS name: decode the first-level encoding of the question/answer name."""
    try:
        ln = p[12]
        enc = p[13:13 + ln]
        name = "".join(chr(((enc[i] - 65) << 4) | (enc[i + 1] - 65)) for i in range(0, 30, 2)).strip()
        return {"name": name}
    except Exception:
        return None


def parse_ssdp(p):
    text = p[:1500].decode("latin-1", "replace")
    if not (text.startswith("NOTIFY") or text.startswith("M-SEARCH") or text.startswith("HTTP/1.1 200")):
        return None
    out = {"first_line": text.split("\r\n", 1)[0]}
    for ln in text.split("\r\n")[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            if k.strip().upper() in ("SERVER", "USN", "NT", "ST", "LOCATION"):
                out[k.strip().lower()] = v.strip()[:200]
    return out


def _wifi_header_len(pkt):
    """If pkt is an 802.11 data frame followed by LLC/SNAP, return the 802.11 header length, else 0."""
    if len(pkt) < 34:
        return 0
    fc0, fc1 = pkt[0], pkt[1]
    if (fc0 & 0x0C) != 0x08:          # type must be Data
        return 0
    hl = 24
    if fc1 & 0x03 == 0x03:            # ToDS + FromDS -> 4th address
        hl += 6
    if fc0 & 0x80:                    # QoS data subtype
        hl += 2
        if fc1 & 0x80:                # +HTC
            hl += 4
    return hl if pkt[hl:hl + 3] == b"\xaa\xaa\x03" and len(pkt) >= hl + 8 else 0


def decode(pkt, link=1):
    """Return a dict describing the packet (layers + application summary)."""
    d = {"len": len(pkt), "layers": []}
    o, et = 0, None
    wifi = _wifi_header_len(pkt) if link in (1, 105) else 0
    if wifi:  # native 802.11 data frame (pktmon on Wi-Fi labels these as Ethernet)
        fc1 = pkt[1]
        a1, a2, a3 = _mac(pkt[4:10]), _mac(pkt[10:16]), _mac(pkt[16:22])
        to_ds, from_ds = fc1 & 0x01, fc1 & 0x02
        d["eth_dst"], d["eth_src"] = (a3, a2) if to_ds and not from_ds else (a1, a3) if from_ds and not to_ds else (a1, a2)
        d["bssid"] = a1 if to_ds else a2
        et, o = struct.unpack_from(">H", pkt, wifi + 6)[0], wifi + 8
        d["layers"].append("802.11")
    elif link == 1:  # Ethernet
        if len(pkt) < 14:
            return d
        d["eth_dst"], d["eth_src"] = _mac(pkt[0:6]), _mac(pkt[6:12])
        et, o = struct.unpack_from(">H", pkt, 12)[0], 14
        if et == 0x8100 and len(pkt) >= 18:
            et, o = struct.unpack_from(">H", pkt, 16)[0], 18
        d["layers"].append("Ethernet")
    elif link in (101, 228, 229, 12, 14):  # raw IP
        et = 0x0800 if (pkt[0] >> 4) == 4 else 0x86DD
    else:
        d["layers"].append(f"linktype {link}")
        return d
    if et == 0x0806 and len(pkt) >= o + 28:
        opc = struct.unpack_from(">H", pkt, o + 6)[0]
        d.update(proto="ARP", src=socket.inet_ntoa(pkt[o + 14:o + 18]), dst=socket.inet_ntoa(pkt[o + 24:o + 28]),
                 arp={"op": "request" if opc == 1 else "reply", "sender_mac": _mac(pkt[o + 8:o + 14]),
                      "sender_ip": socket.inet_ntoa(pkt[o + 14:o + 18]), "target_ip": socket.inet_ntoa(pkt[o + 24:o + 28])})
        d["layers"].append("ARP")
        d["info"] = (f"Who has {d['dst']}? Tell {d['src']}" if opc == 1 else f"{d['src']} is at {d['arp']['sender_mac']}")
        return d
    proto, payload_off, ip_end = None, None, len(pkt)
    if et == 0x0800 and len(pkt) >= o + 20:
        ihl = (pkt[o] & 0x0F) * 4
        tot = struct.unpack_from(">H", pkt, o + 2)[0]
        proto = pkt[o + 9]
        d["ttl"] = pkt[o + 8]
        d["src"], d["dst"] = socket.inet_ntoa(pkt[o + 12:o + 16]), socket.inet_ntoa(pkt[o + 16:o + 20])
        d["layers"].append("IPv4")
        payload_off, ip_end = o + ihl, min(len(pkt), o + tot) if tot else len(pkt)
    elif et == 0x86DD and len(pkt) >= o + 40:
        plen = struct.unpack_from(">H", pkt, o + 4)[0]
        proto = pkt[o + 6]
        d["ttl"] = pkt[o + 7]
        d["src"] = socket.inet_ntop(socket.AF_INET6, pkt[o + 8:o + 24])
        d["dst"] = socket.inet_ntop(socket.AF_INET6, pkt[o + 24:o + 40])
        d["layers"].append("IPv6")
        payload_off, ip_end = o + 40, min(len(pkt), o + 40 + plen)
        while proto in (0, 43, 60, 44) and payload_off + 8 <= len(pkt):  # extension headers
            nxt = pkt[payload_off]
            payload_off += 8 if proto == 44 else (pkt[payload_off + 1] + 1) * 8
            proto = nxt
    else:
        d["proto"] = f"ethertype 0x{et:04x}" if et else "?"
        return d
    seg = pkt[payload_off:ip_end]
    if proto == 6 and len(seg) >= 20:
        sp, dp, seq, ack, offf, fl, win = struct.unpack_from(">HHIIBBH", seg, 0)
        hl = (offf >> 4) * 4
        data = seg[hl:]
        flags = [n for b, n in TCP_FLAGS if fl & b]
        d.update(proto="TCP", sport=sp, dport=dp, seq=seq, ack=ack, win=win, flags=flags, payload_len=len(data))
        d["layers"].append("TCP")
        d["info"] = f"{sp} → {dp} [{','.join(flags)}] seq={seq} ack={ack} win={win} len={len(data)}"
        app = None
        if data:
            app = parse_tls(data) if 443 in (sp, dp) or data[:1] in (b"\x16", b"\x17") else None
            if app:
                d["tls"] = app
                d["layers"].append("TLS")
                d["info"] = (f"TLS {app.get('handshake') or app['record']}"
                             + (f" SNI={app['sni']}" if app.get("sni") else "")
                             + (f" ALPN={','.join(app['alpn'])}" if app.get("alpn") else "")
                             + f" ({'offers ' + max(app['offers']) if app.get('offers') else app['version']})")
            else:
                http = parse_http(data)
                if http:
                    d["http"] = http
                    d["layers"].append("HTTP")
                    d["info"] = "HTTP " + http["first_line"]
                elif 53 in (sp, dp) and len(data) > 2:
                    dns = parse_dns(data[2:])
                    if dns:
                        d["dns"] = dns
                        d["layers"].append("DNS")
        d["payload"] = data
    elif proto == 17 and len(seg) >= 8:
        sp, dp, ul = struct.unpack_from(">HHH", seg, 0)
        data = seg[8:]
        d.update(proto="UDP", sport=sp, dport=dp, payload_len=len(data))
        d["layers"].append("UDP")
        d["info"] = f"{sp} → {dp} len={len(data)}"
        ports = (sp, dp)
        if 53 in ports or 5353 in ports or 5355 in ports:
            dns = parse_dns(data)
            if dns:
                name = "mDNS" if 5353 in ports else "LLMNR" if 5355 in ports else "DNS"
                d["dns"] = dns
                d["layers"].append(name)
                d["info"] = (f"{name} {'response' if dns['response'] else 'query'} "
                             + ", ".join(dns["questions"][:3])
                             + (f" → {', '.join(dns['answers'][:4])}" if dns["answers"] else "")
                             + (f" (rcode {dns['rcode']})" if dns["rcode"] else ""))
        elif 67 in ports or 68 in ports:
            dh = parse_dhcp(data)
            if dh:
                d["dhcp"] = dh
                d["layers"].append("DHCP")
                d["info"] = f"DHCP {dh.get('type', dh['op'])} {dh.get('hostname', '')} {dh.get('vendor_class', '')}".strip()
        elif 137 in ports:
            nb = parse_nbns(data)
            if nb:
                d["nbns"] = nb
                d["layers"].append("NBNS")
                d["info"] = f"NetBIOS name {nb['name']}"
        elif 1900 in ports:
            ss = parse_ssdp(data)
            if ss:
                d["ssdp"] = ss
                d["layers"].append("SSDP")
                d["info"] = f"SSDP {ss['first_line'][:60]} {ss.get('server', '')}"
        elif 443 in ports and data:
            if data[0] & 0x80:
                d["layers"].append("QUIC")
                d["info"] = f"QUIC long header ({'Initial' if (data[0] & 0x30) == 0 else 'handshake'}) len={len(data)}"
            else:
                d["layers"].append("QUIC")
                d["info"] = f"QUIC short header (encrypted) len={len(data)}"
        d["payload"] = data
    elif proto in (1, 58) and seg:
        d.update(proto="ICMP" if proto == 1 else "ICMPv6", icmp_type=seg[0])
        d["layers"].append(d["proto"])
        names = {0: "echo reply", 8: "echo request", 3: "unreachable", 11: "time exceeded", 128: "echo request",
                 129: "echo reply", 133: "router solicitation", 134: "router advertisement",
                 135: "neighbor solicitation", 136: "neighbor advertisement", 1: "unreachable"}
        d["info"] = f"{d['proto']} {names.get(seg[0], seg[0])}"
    else:
        d["proto"] = f"IP proto {proto}"
    return d


def hexdump(b, limit=HEX_LIMIT):
    out = []
    for i in range(0, min(len(b), limit), 16):
        chunk = b[i:i + 16]
        out.append(f"{i:04x}  {' '.join(f'{x:02x}' for x in chunk):<47}  "
                   f"{''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)}")
    if len(b) > limit:
        out.append(f"… {len(b) - limit} more bytes")
    return "\n".join(out)


def local_ips():
    import psutil
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                ips.add(a.address.split("%")[0].lower())
    return ips


def analyse(pcap_path, want_dns_names=None):
    """Parse a pcapng into packet rows + a summary."""
    mine = local_ips()
    rows, seen, t0 = [], {}, None
    summary = {"sni": set(), "alpn": set(), "http": [], "dns": [], "tls_versions": set(), "hosts": set(),
               "bytes_out": 0, "bytes_in": 0, "packets": 0, "syn": 0, "rst": 0, "protocols": {}}
    for ts, link, pkt, direction in read_pcapng(pcap_path):
        h = hashlib.md5(pkt).digest()
        if h in seen and ts - seen[h] < 0.05:     # same frame seen on two NIC components
            continue
        seen[h] = ts
        d = decode(pkt, link)
        if want_dns_names and "dns" in d:   # keep only DNS about the target names
            text = " ".join(d["dns"]["questions"]).lower()
            if not any(n in text for n in want_dns_names):
                continue
        t0 = t0 if t0 is not None else ts
        if not direction:
            direction = "out" if (d.get("src") or "").lower() in mine else "in" if (d.get("dst") or "").lower() in mine else ""
        payload = d.pop("payload", b"")
        row = {"n": len(rows) + 1, "t": round(ts - t0, 6), "time": datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
               "dir": direction, "src": d.get("src") or d.get("eth_src", ""), "dst": d.get("dst") or d.get("eth_dst", ""),
               "proto": d["layers"][-1] if d["layers"] else d.get("proto", "?"), "len": len(pkt),
               "info": d.get("info", ""), "detail": d, "hex": hexdump(pkt),
               "payload_text": payload[:600].decode("latin-1", "replace") if payload and (d.get("http") or d.get("ssdp")) else ""}
        rows.append(row)
        summary["packets"] += 1
        summary["protocols"][row["proto"]] = summary["protocols"].get(row["proto"], 0) + 1
        summary["bytes_out" if direction == "out" else "bytes_in"] += len(pkt)
        if "SYN" in d.get("flags", []) and "ACK" not in d.get("flags", []):
            summary["syn"] += 1
        if "RST" in d.get("flags", []):
            summary["rst"] += 1
        if d.get("tls"):
            if d["tls"].get("sni"):
                summary["sni"].add(d["tls"]["sni"])
            for a in d["tls"].get("alpn", []):
                summary["alpn"].add(a)
            if d["tls"].get("handshake") == "ServerHello":
                summary["tls_versions"].add(d["tls"]["version"])
        if d.get("http"):
            summary["http"].append(d["http"]["first_line"])
        if d.get("dns"):
            summary["dns"].append(row["info"])
        if len(rows) >= MAX_PACKETS:
            break
    for k in ("sni", "alpn", "tls_versions"):
        summary[k] = sorted(summary[k])
    summary.pop("hosts", None)
    summary["duration"] = rows[-1]["t"] if rows else 0
    return rows, summary


# --------------------------------------------------------------------------- #
# Capture manager
# --------------------------------------------------------------------------- #
class CaptureManager:
    def __init__(self, base_dir):
        self.dir = os.path.join(base_dir, "captures")
        os.makedirs(self.dir, exist_ok=True)
        self.lock = threading.Lock()
        self.current = None          # dict describing the running capture
        self.results = {}            # id -> result (packets kept in memory for the UI)
        self.stop_evt = threading.Event()
        self.listeners = []          # callbacks(result) e.g. device discovery

    def busy(self):
        return self.current is not None

    def start(self, filters, seconds, label, kind="request", dns_names=None):
        """filters: list of pktmon filter arg lists, e.g. [["-i", "1.2.3.4", "-p", "443"]]"""
        if not self.lock.acquire(blocking=False):
            return {"error": f"Another capture is running ({self.current['label'] if self.current else '?'})"}
        cid = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        self.current = {"id": cid, "label": label, "kind": kind, "started": time.time(),
                        "seconds": seconds, "filters": filters, "state": "starting"}
        self.stop_evt.clear()
        threading.Thread(target=self._run, args=(cid, filters, seconds, label, kind, dns_names), daemon=True).start()
        return {"id": cid}

    def stop(self):
        self.stop_evt.set()

    def status(self):
        c = self.current
        if not c:
            return {"running": False}
        return {"running": True, "id": c["id"], "label": c["label"], "kind": c["kind"], "state": c["state"],
                "elapsed": round(time.time() - c["started"], 1), "seconds": c["seconds"]}

    def _run(self, cid, filters, seconds, label, kind, dns_names):
        etl = os.path.join(self.dir, cid + ".etl")
        pcap = os.path.join(self.dir, cid + ".pcapng")
        res = {"id": cid, "label": label, "kind": kind, "started": datetime.datetime.now().isoformat(timespec="seconds"),
               "filters": [" ".join(f) for f in filters]}
        try:
            _run(["stop"], 30)
            _run(["filter", "remove"], 30)
            for i, f in enumerate(filters):
                rc, out = _run(["filter", "add", f"NetWatch{i}"] + f, 30)
                if rc != 0:
                    raise RuntimeError(f"pktmon filter add failed: {out[-300:]}")
            rc, out = _run(["start", "--capture", "--comp", "nics", "--pkt-size", "0", "-f", etl, "-s", "256"], 60)
            if rc != 0:
                raise RuntimeError(f"pktmon start failed (needs Administrator): {out[-300:]}")
            self.current["state"] = "capturing"
            self.stop_evt.wait(seconds)
            self.current["state"] = "processing"
            _run(["stop"], 120)
            _run(["filter", "remove"], 30)
            rc, out = _run(["etl2pcap", etl, "-o", pcap], 300)
            if rc != 0 or not os.path.exists(pcap):
                raise RuntimeError(f"pktmon etl2pcap failed: {out[-300:]}")
            rows, summary = analyse(pcap, dns_names)
            res.update(packets=rows, summary=summary, pcap=os.path.basename(pcap))
        except Exception as e:
            res["error"] = str(e)
            try:
                _run(["stop"], 60)
                _run(["filter", "remove"], 30)
            except Exception:
                pass
        finally:
            try:
                if os.path.exists(etl):
                    os.remove(etl)
            except OSError:
                pass
            res["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
            self.results[cid] = res
            while len(self.results) > 10:
                self.results.pop(next(iter(self.results)))
            self.current = None
            self.lock.release()
            for cb in self.listeners:
                try:
                    cb(res)
                except Exception:
                    pass


def filters_for_target(remote_ip=None, port=None, extra_ips=(), include_dns=True):
    """Build pktmon filters for a request: its IP(s) [+ port], plus DNS so the lookup is shown."""
    fl, ips = [], [i for i in ([remote_ip] if remote_ip else []) + list(extra_ips) if i]
    for ip in list(dict.fromkeys(ips))[:6]:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        f = ["-i", ip]
        if port:
            f += ["-p", str(int(port))]
        fl.append(f)
    if include_dns:
        fl.append(["-t", "UDP", "-p", "53"])
        fl.append(["-t", "TCP", "-p", "53"])
    return fl
