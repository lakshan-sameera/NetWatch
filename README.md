# NetWatch

A local network-activity monitor for Windows. It shows which process is talking to which host, with each process's parent tree, loaded DLLs, file signatures and reputation scores, in a web dashboard at `http://127.0.0.1:8765`.

## Features

- **Live connections:** every TCP/UDP socket with its process, parent process, hostname, service and state.
- **ETW sensor** (needs Administrator), built with `ctypes`, no extra dependencies:
  - every TCP connect and disconnect, including connections that last only milliseconds;
  - per-process DNS queries and their answers;
  - URLs requested through WinHTTP, WinINet and WebIO;
  - process start and stop with the parent PID, and live DLL loads.
- **Dashboard:** request timeline, top domains, top processes, services, recent URLs.
- **Findings engine** flags:
  - unsigned or tampered files;
  - DLLs loaded from unusual paths;
  - scanner-like fan-out and port scans;
  - DNS failure storms (a sign of malware generating random domains, called DGA);
  - built-in Windows tools (LOLBins) making network connections;
  - web-attack-style URLs.
- **Files & signatures:** automatic Authenticode checks of every executable and DLL seen, with SHA-256 hashes.
- **Reputation:** optional AbuseIPDB and VirusTotal scores for public IPs, domains and the hashes of flagged files.
  - Keys are stored encrypted with Windows DPAPI.
  - Results are cached for 24 h, and lookups stay inside the free-tier limits.
- **Logs:** everything is appended to a daily JSONL file in `logs/`.

## Run

```powershell
python -m pip install psutil flask
python netwatch.py --open
```

Or double-click `start-netwatch.bat`. It asks for Administrator rights, which ETW, other users' processes and their DLLs need.

## Build a portable exe

```powershell
.\build-exe.bat
```

This produces `dist\NetWatch.exe`: a single file that asks for admin rights on launch and keeps its logs next to itself.

## Files

| File | Purpose |
|---|---|
| `netwatch.py` | Web server, polling sensor, findings, file inventory, API |
| `etw_sensor.py` | Real-time ETW consumer (Kernel-Network, DNS-Client, WinINet/WinHTTP/WebIO, Kernel-Process) |
| `reputation.py` | AbuseIPDB and VirusTotal lookups, cache, quotas, DPAPI key storage |
| `static/index.html` | The whole UI |

## Privacy

- **NetWatch listens on `127.0.0.1` only.**
- **Reputation lookups send only public IPs, public domain names and file hashes,** never file contents or private addresses. They're off until you add API keys.
- **`logs/`, `netwatch-config.json` and `reputation.json` hold your own data** and are git-ignored.

Requires Windows 10/11 (64-bit) and Python 3.10+.
