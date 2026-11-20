"""
File hash history for NetWatch.

Every executable / DLL NetWatch has seen is tracked by path. A background pass stat()s each
file every few minutes and re-hashes it only when size or mtime changed, so after the first
pass the cost is tiny. Each distinct SHA-256 becomes a "version" with its signature status;
a new version on an already-known file is a change, rated by what happened to the signature.

State lives in <base>/hashes.json (git-ignored).
"""
import hashlib
import json
import os
import threading
import time

MAX_SIZE = 200 * 1024 * 1024
PASS_INTERVAL = 300          # seconds between stat passes
FILE_PAUSE = 0.002           # yield between files so a first pass never hogs the disk


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rate_change(old, new, path):
    """Severity + reason for a hash change, based on what happened to the signature."""
    o, n = (old.get("sig") or {}), (new.get("sig") or {})
    os_, ns = o.get("status", ""), n.get("status", "")
    osg, nsg = (o.get("signer") or "").lower(), (n.get("signer") or "").lower()
    system = path.lower().startswith((os.environ.get("SystemRoot", r"C:\Windows").lower() + "\\",))
    if ns == "HashMismatch":
        return "critical", "new version's signature is BROKEN (file modified after signing)"
    if os_ == "Valid" and ns and ns != "Valid":
        return "high", f"was validly signed by {o.get('signer') or '?'}, now {ns}"
    if os_ == "Valid" and ns == "Valid" and osg and nsg and osg != nsg:
        return "high", f"signer changed: {o.get('signer')} → {n.get('signer')}"
    if system and ns != "Valid":
        return "high", f"Windows system file changed and is {ns or 'unverified'}"
    if ns == "Valid" and (osg == nsg or not osg):
        return "info", f"update - still signed by {n.get('signer') or '?'}"
    if not ns:
        return "low", "changed - signature not checked yet"
    return "medium", f"changed - {ns}"


class HashWatcher:
    def __init__(self, base_dir, get_files, check_sig, on_change):
        """
        get_files() -> iterable of (path, procs_list)
        check_sig(path) -> {"status","signer"}   (blocking, used only when a file changed)
        on_change(path, old_version, new_version, severity, reason)
        """
        self.path = os.path.join(base_dir, "hashes.json")
        self.get_files, self.check_sig, self.on_change = get_files, check_sig, on_change
        self.lock = threading.Lock()
        self.db = self._load()
        self.dirty = False
        self.stats = {"pass_started": 0, "pass_done": 0, "hashed": 0, "checked": 0, "running": False}
        self.kick = threading.Event()
        threading.Thread(target=self._loop, name="hashwatch", daemon=True).start()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def save(self):
        if not self.dirty:
            return
        with self.lock:
            snap = json.dumps(self.db)
            self.dirty = False
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(snap)
        os.replace(tmp, self.path)

    def known_sig(self, key, sig):
        """Record a signature result for the file's current version (from the signature worker)."""
        with self.lock:
            rec = self.db.get(key)
            if rec and rec["versions"] and not rec["versions"][-1].get("sig"):
                rec["versions"][-1]["sig"] = sig
                self.dirty = True

    def _loop(self):
        time.sleep(20)
        while True:
            try:
                self._pass()
            except Exception as e:
                print("hashwatch error:", e)
            self.save()
            self.kick.wait(PASS_INTERVAL)
            self.kick.clear()

    def _pass(self):
        self.stats.update(pass_started=time.time(), running=True, checked=0)
        files = list(self.get_files())
        for path, procs in files:
            key = path.lower()
            self.stats["checked"] += 1
            try:
                st = os.stat(path)
            except OSError:
                with self.lock:
                    rec = self.db.get(key)
                    if rec and not rec.get("deleted"):
                        rec["deleted"] = time.time()
                        self.dirty = True
                continue
            with self.lock:
                rec = self.db.get(key)
                cur = rec["versions"][-1] if rec and rec["versions"] else None
                if rec and rec.get("deleted"):
                    rec.pop("deleted")
                if cur and cur["size"] == st.st_size and cur["mtime"] == int(st.st_mtime):
                    cur["last_seen"] = time.time()
                    for p in procs:
                        if p and p not in rec["procs"] and len(rec["procs"]) < 12:
                            rec["procs"].append(p)
                    continue
            if st.st_size > MAX_SIZE:
                continue
            try:
                digest = sha256_of(path)
            except OSError:
                continue
            self.stats["hashed"] += 1
            now = time.time()
            ver = {"sha256": digest, "size": st.st_size, "mtime": int(st.st_mtime), "first_seen": now, "last_seen": now}
            changed_from = None
            with self.lock:
                rec = self.db.setdefault(key, {"path": path, "versions": [], "procs": []})
                cur = rec["versions"][-1] if rec["versions"] else None
                if cur and cur["sha256"] == digest:          # touched but same content
                    cur.update(size=st.st_size, mtime=int(st.st_mtime), last_seen=now)
                    self.dirty = True
                    continue
                rec["versions"].append(ver)
                rec["versions"] = rec["versions"][-30:]
                for p in procs:
                    if p and p not in rec["procs"] and len(rec["procs"]) < 12:
                        rec["procs"].append(p)
                self.dirty = True
                changed_from = cur
            if changed_from is not None:                    # a real change on a known file
                try:
                    ver["sig"] = self.check_sig(path)
                except Exception:
                    pass
                sev, why = rate_change(changed_from, ver, path)
                ver["severity"], ver["reason"] = sev, why
                self.on_change(path, changed_from, ver, sev, why)
            time.sleep(FILE_PAUSE)
        self.stats.update(pass_done=time.time(), running=False)

    # ---- views ----
    def summary(self):
        with self.lock:
            recs = list(self.db.values())
        changed = [r for r in recs if len(r["versions"]) > 1]
        day = time.time() - 86400
        return {"tracked": len(recs), "changed_files": len(changed),
                "changes_24h": sum(1 for r in changed for v in r["versions"][1:] if v["first_seen"] >= day),
                "deleted": sum(1 for r in recs if r.get("deleted")), **self.stats}

    def changes(self, limit=500):
        with self.lock:
            recs = [dict(r) for r in self.db.values() if len(r["versions"]) > 1 or r.get("deleted")]
        recs.sort(key=lambda r: -(r.get("deleted") or r["versions"][-1]["first_seen"]))
        return recs[:limit]

    def history(self, path):
        with self.lock:
            return self.db.get(path.lower())
