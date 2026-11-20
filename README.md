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
- **Request checker:** click 🔍 on any request or connection to capture its packets with Windows' built-in **pktmon**. You see:
  - the TCP handshake, TLS ClientHello with SNI and ALPN, and the TLS version;
  - plaintext HTTP and DNS;
  - the decoded fields and a hex dump of each packet;
  - a `.pcapng` download for Wireshark.

  Works on Wi-Fi (native 802.11 frames) and Ethernet.
- **Network map:** an interactive map: Internet → ISP hops (shows carrier-grade NAT) → router → this PC and its virtual adapters → devices.
  - Devices are found by an ARP sweep (`SendARP`), the neighbour table, and passive listening to ARP, mDNS, SSDP, NetBIOS, LLMNR and DHCP.
  - Optional IEEE vendor list, and checks of common ports (LAN addresses only).
  - Windows Wi-Fi drivers can't do promiscuous mode, so the map uses what every device broadcasts.
- **Public IP history:** your public IPv4/IPv6 every 5 min and on network changes, with the adapter or VPN in use and the AbuseIPDB score.
  - Shown as a timeline whose gaps are when the PC was asleep or offline.
  - Includes a "what was my IP at…?" lookup, useful for checking abuse reports.
- **Hash changes:** a SHA-256 history of every executable and DLL seen.
  - Files are re-hashed only when their size or date changes.
  - Changes are rated by what happened to the signature (broken, lost, or a new signer is flagged).
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
| `capture.py` | pktmon packet capture + pcapng reader + protocol decoders (802.11/Ethernet, IP, TCP/UDP, TLS, HTTP, DNS, DHCP, SSDP…) |
| `netmap.py` | LAN discovery, DNS-only reverse lookups, traceroute, topology for the map |
| `iphistory.py` | Public IP history |
| `hashwatch.py` | File hash history and change rating |
| `static/index.html`, `static/features.js` | The UI |

## Privacy

- **NetWatch listens on `127.0.0.1` only.**
- **Reputation lookups send only public IPs, public domain names and file hashes,** never file contents or private addresses. They're off until you add API keys.
- **Your own data stays local and is git-ignored:** `logs/`, `captures/`, `netwatch-config.json`, `reputation.json`, `devices.json`, `hashes.json` and `iphistory.json`.
- **Public IP history asks api.ipify.org** for your public address.

Requires Windows 10/11 (64-bit) and Python 3.10+.
