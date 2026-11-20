"""
Reputation lookups for NetWatch: AbuseIPDB (IPs) and VirusTotal (IPs, domains, file hashes).

* API keys are entered by the user in the UI and stored encrypted with Windows DPAPI
  (only the same Windows account can decrypt them).
* Only public IPs, public domain names and file hashes are ever sent - never file contents.
* Results are cached for 24 h in reputation.json; per-provider rate limits and daily
  budgets keep usage inside the free tiers (AbuseIPDB 1000/day, VirusTotal 4/min + 500/day).
"""
import base64
import ctypes
import ctypes.wintypes as wt
import datetime
import ipaddress
import json
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/"
TTL_OK = 24 * 3600
TTL_ERR = 3600
INTERVAL = {"abuse": 2.0, "vt": 15.5}          # seconds between calls (VT free: 4/min)
DEFAULT_DAILY = {"abuse": 900, "vt": 450}       # automatic-lookup budget per day (manual checks always run)
SKIP_SUFFIX = (".local", ".lan", ".home", ".internal", ".arpa", ".localdomain", ".localhost", ".test",
               ".invalid", ".example", ".corp", ".mshome.net", ".home.arpa", ".intranet", ".private")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
HASH_RE = re.compile(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I)


# --------------------------------------------------------------------------- #
# DPAPI (CurrentUser) for API keys at rest
# --------------------------------------------------------------------------- #
class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data, protect):
    buf = ctypes.create_string_buffer(data, len(data))
    inp = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = _BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(inp), None, None, None, None, 0x1, ctypes.byref(out)):   # UI_FORBIDDEN
        raise OSError("DPAPI failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def protect(s):
    return base64.b64encode(_dpapi(s.encode(), True)).decode() if s else ""


def unprotect(s):
    try:
        return _dpapi(base64.b64decode(s), False).decode() if s else ""
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
def classify(value):
    v = (value or "").strip().lower()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(v):
        return "file"
    if DOMAIN_RE.match(v):
        return "domain"
    return None


NAT64 = ipaddress.ip_network("64:ff9b::/96")


def normalize_ip(v):
    """NAT64 (64:ff9b::a.b.c.d) and IPv4-mapped addresses -> the real IPv4 the reputation services know."""
    try:
        a = ipaddress.ip_address(v)
    except ValueError:
        return v
    if a.version == 6:
        if a in NAT64:
            return str(ipaddress.IPv4Address(int(a) & 0xFFFFFFFF))
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
    return str(a)


def is_public_ip(v):
    try:
        a = ipaddress.ip_address(v)
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        return a.is_global and not a.is_multicast
    except ValueError:
        return False


def is_public_domain(d):
    d = d.lower().rstrip(".")
    return bool(DOMAIN_RE.match(d)) and not d.endswith(SKIP_SUFFIX) and "." in d


def verdict(rec):
    a, v = rec.get("abuse") or {}, rec.get("vt") or {}
    score, mal, sus = a.get("score") or 0, v.get("malicious") or 0, v.get("suspicious") or 0
    if score >= 50 or mal >= 3:
        return "malicious"
    if score >= 15 or mal >= 1 or sus >= 2:
        return "suspicious"
    if "score" in a or v.get("found") is not None:
        return "clean"
    if a.get("error") or v.get("error"):
        return "error"
    return "unchecked"


class Reputation:
    def __init__(self, base_dir):
        self.cfg_path = os.path.join(base_dir, "netwatch-config.json")
        self.cache_path = os.path.join(base_dir, "reputation.json")
        self.lock = threading.Lock()
        self.cfg = self._load(self.cfg_path, {})
        self.keys = {"abuse": unprotect(self.cfg.get("abuseipdb_key", "")),
                     "vt": unprotect(self.cfg.get("virustotal_key", ""))}
        self.auto = self.cfg.get("auto", True)
        self.daily = {"abuse": self.cfg.get("abuse_daily", DEFAULT_DAILY["abuse"]),
                      "vt": self.cfg.get("vt_daily", DEFAULT_DAILY["vt"])}
        self.data = self._load(self.cache_path, {})
        self.q = {"abuse": queue.PriorityQueue(), "vt": queue.PriorityQueue()}
        self.pending = {"abuse": set(), "vt": set()}
        self.usage = {p: {"day": "", "auto": 0, "manual": 0, "remaining": None, "last_error": "", "paused_until": 0}
                      for p in ("abuse", "vt")}
        self.usage.update(self.cfg.get("usage", {}))
        self.dirty = False
        self.listeners = []          # callbacks(rec) when a result arrives
        for p in ("abuse", "vt"):
            threading.Thread(target=self._worker, args=(p,), name=f"rep-{p}", daemon=True).start()
        threading.Thread(target=self._saver, daemon=True).start()

    # ---- persistence ----
    @staticmethod
    def _load(path, default):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default

    def _save_cfg(self):
        self.cfg["usage"] = self.usage
        tmp = self.cfg_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.cfg, f, indent=1)
        os.replace(tmp, self.cfg_path)

    def _saver(self):
        while True:
            time.sleep(20)
            self.flush()

    def flush(self):
        """Write cache + usage to disk now (also called on shutdown)."""
        if not self.dirty:
            return
        with self.lock:
            if len(self.data) > 30000:   # keep the newest
                for k in sorted(self.data, key=lambda k: self.data[k].get("first", 0))[:5000]:
                    del self.data[k]
            snap = json.dumps(self.data)
            self.dirty = False
        try:
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(snap)
            os.replace(tmp, self.cache_path)
            self._save_cfg()
        except Exception:
            self.dirty = True     # try again next time

    # ---- settings ----
    def settings(self):
        return {"abuse_key_set": bool(self.keys["abuse"]), "vt_key_set": bool(self.keys["vt"]), "auto": self.auto,
                "daily": self.daily, "usage": self.usage,
                "queue": {p: len(self.pending[p]) for p in self.pending}, "cached": len(self.data)}

    def update_settings(self, abuse_key=None, vt_key=None, auto=None, clear=None):
        if abuse_key:
            self.keys["abuse"] = abuse_key.strip()
            self.cfg["abuseipdb_key"] = protect(self.keys["abuse"])
        if vt_key:
            self.keys["vt"] = vt_key.strip()
            self.cfg["virustotal_key"] = protect(self.keys["vt"])
        for p in clear or []:
            if p in self.keys:
                self.keys[p] = ""
                self.cfg.pop({"abuse": "abuseipdb_key", "vt": "virustotal_key"}[p], None)
        if auto is not None:
            self.auto = bool(auto)
            self.cfg["auto"] = self.auto
        for p in ("abuse", "vt"):
            self.usage[p]["paused_until"] = 0
            self.usage[p]["last_error"] = ""
        self._save_cfg()

    # ---- queueing ----
    def want(self, value, kind=None, prio=5, proc=None, manual=False):
        value = (value or "").strip().lower().rstrip(".")
        kind = kind or classify(value)
        if kind == "ip":
            value = normalize_ip(value)
        if kind == "ip" and not is_public_ip(value):
            return None
        if kind == "domain" and not is_public_domain(value):
            return None
        if kind is None:
            return None
        k = f"{kind}:{value}"
        now = time.time()
        with self.lock:
            rec = self.data.get(k)
            if rec is None:
                rec = self.data[k] = {"type": kind, "value": value, "procs": [], "first": now}
                self.dirty = True
            if proc and proc not in rec["procs"] and len(rec["procs"]) < 12:
                rec["procs"].append(proc)
                self.dirty = True
        if not manual and not self.auto:
            return k
        provs = {"ip": ("abuse", "vt"), "domain": ("vt",), "file": ("vt",)}[kind]
        for p in provs:
            if not self.keys[p]:
                continue
            res = rec.get(p)
            if res and not manual:
                ttl = TTL_ERR if res.get("error") else TTL_OK
                if now - res.get("checked", 0) < ttl:
                    continue
            if k in self.pending[p] and not manual:
                continue
            self.pending[p].add(k)
            self.q[p].put((0 if manual else prio, now, k, manual))
        return k

    def check_now(self, value, timeout=40):
        kind = classify(value)
        if kind == "ip":
            value = normalize_ip(value.strip())
        if kind is None:
            return {"error": "Not an IP, domain or file hash"}
        if kind == "ip" and not is_public_ip(value.strip()):
            return {"error": "Private / local IPs are not looked up"}
        if kind == "domain" and not is_public_domain(value.strip()):
            return {"error": "Local / internal domain names are not looked up"}
        if not any(self.keys[p] for p in ({"ip": ("abuse", "vt")}.get(kind, ("vt",)))):
            return {"error": "Add an API key in Settings first"}
        k = self.want(value, kind, manual=True)
        before = json.dumps({p: (self.data.get(k) or {}).get(p, {}).get("checked") for p in ("abuse", "vt")})
        end = time.time() + timeout
        while time.time() < end:
            time.sleep(0.4)
            rec = self.data.get(k) or {}
            now_state = json.dumps({p: rec.get(p, {}).get("checked") for p in ("abuse", "vt")})
            if now_state != before and not any(k in self.pending[p] for p in self.pending):
                break
        return self.row(k)

    # ---- workers ----
    def _today(self, p):
        d = datetime.date.today().isoformat()
        if self.usage[p]["day"] != d:
            self.usage[p].update(day=d, auto=0, manual=0)

    def _worker(self, p):
        last = 0.0
        while True:
            prio, ts, k, manual = self.q[p].get()
            self._today(p)
            if not manual:
                if self.usage[p]["auto"] >= self.daily[p] or time.time() < self.usage[p]["paused_until"]:
                    self.pending[p].discard(k)
                    continue
            wait = INTERVAL[p] - (time.time() - last)
            if wait > 0:
                time.sleep(wait)
            rec = self.data.get(k)
            if rec is None or not self.keys[p]:
                self.pending[p].discard(k)
                continue
            last = time.time()
            try:
                res = self._abuse(rec["value"]) if p == "abuse" else self._vt(rec["type"], rec["value"])
                self.usage[p]["last_error"] = ""
            except urllib.error.HTTPError as e:
                msg = f"HTTP {e.code}"
                if e.code == 429:
                    msg = "rate limit / quota reached - pausing"
                    self.usage[p]["paused_until"] = time.time() + (60 if p == "vt" else 3600)
                elif e.code in (401, 403):
                    msg = "API key rejected - check Settings"
                    self.usage[p]["paused_until"] = time.time() + 3600
                self.usage[p]["last_error"] = msg
                res = {"error": msg}
            except Exception as e:
                res = {"error": f"{e.__class__.__name__}: {e}"[:200]}
                self.usage[p]["last_error"] = res["error"]
            res["checked"] = time.time()
            self.usage[p]["manual" if manual else "auto"] += 1
            with self.lock:
                rec[p] = res
                rec["verdict"] = verdict(rec)
                self.dirty = True
            self.pending[p].discard(k)
            for cb in self.listeners:
                try:
                    cb(k, rec)
                except Exception:
                    pass

    def _get(self, url, headers):
        req = urllib.request.Request(url, headers=dict(headers, **{"User-Agent": "NetWatch/1.0"}))
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.headers, json.loads(r.read())

    def _abuse(self, ip):
        url = ABUSE_URL + "?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        h, body = self._get(url, {"Key": self.keys["abuse"], "Accept": "application/json"})
        rem = h.get("X-RateLimit-Remaining")
        if rem is not None and rem.isdigit():
            self.usage["abuse"]["remaining"] = int(rem)
        d = body.get("data", {})
        return {"score": d.get("abuseConfidenceScore", 0), "reports": d.get("totalReports", 0),
                "users": d.get("numDistinctUsers", 0), "country": d.get("countryCode") or "",
                "isp": d.get("isp") or "", "domain": d.get("domain") or "", "usage": d.get("usageType") or "",
                "tor": bool(d.get("isTor")), "whitelisted": d.get("isWhitelisted"),
                "last_reported": d.get("lastReportedAt") or ""}

    def _vt(self, kind, value):
        path = {"ip": "ip_addresses/", "domain": "domains/", "file": "files/"}[kind] + urllib.parse.quote(value)
        try:
            _h, body = self._get(VT_URL + path, {"x-apikey": self.keys["vt"]})
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"found": False}
            raise
        a = body.get("data", {}).get("attributes", {})
        st = a.get("last_analysis_stats", {}) or {}
        out = {"found": True, "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
               "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0),
               "total": sum(v for v in st.values() if isinstance(v, int)), "reputation": a.get("reputation", 0),
               "as_owner": a.get("as_owner", ""), "country": a.get("country", "")}
        if kind == "domain":
            out["categories"] = sorted(set((a.get("categories") or {}).values()))[:4]
            out["registrar"] = a.get("registrar", "")
        if kind == "file":
            out["name"] = a.get("meaningful_name", "")
            out["type"] = a.get("type_description", "")
            out["label"] = (a.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
            out["signer"] = ((a.get("signature_info") or {}).get("signers") or "")[:120]
        names = [n for n, r in (a.get("last_analysis_results") or {}).items() if r.get("category") == "malicious"]
        out["flagged_by"] = names[:8]
        return out

    # ---- views ----
    def row(self, k):
        rec = self.data.get(k)
        if not rec:
            return None
        r = dict(rec, key=k, verdict=verdict(rec))
        r["pending"] = [p for p in self.pending if k in self.pending[p]]
        return r

    def rows(self):
        with self.lock:
            keys = list(self.data)
        return [self.row(k) for k in keys]

    def compact_map(self):
        """{value: summary} for badges in the UI (checked entries only)."""
        out = {}
        with self.lock:
            items = list(self.data.items())
        for k, rec in items:
            a, v = rec.get("abuse") or {}, rec.get("vt") or {}
            if not a and not v:
                continue
            out[rec["value"]] = {"v": verdict(rec), "a": a.get("score"), "ar": a.get("reports"),
                                 "vm": v.get("malicious"), "vs": v.get("suspicious"), "vt": v.get("total"),
                                 "vf": v.get("found"), "t": rec["type"]}
        return out
