# Changelog

## v1.1.0 (2026-11-20)

### New
- **Request checker:** click 🔍 on any request or connection to capture its packets with Windows' built-in pktmon. You get:
  - the TCP handshake, TLS ClientHello (server name / SNI, ALPN) and TLS version;
  - plaintext HTTP and DNS;
  - every decoded field, a hex dump, and a `.pcapng` download for Wireshark.

  Works on Wi-Fi (native 802.11 frames) and Ethernet.
- **Network map:** an interactive map: Internet → ISP hops (carrier-grade NAT is highlighted) → router → this PC and its virtual adapters → LAN devices.
  - Devices are found by ARP sweep, the neighbour table, and passive listening to ARP, mDNS, SSDP, NetBIOS, LLMNR and DHCP.
  - Optional IEEE vendor list, and common-port checks on LAN addresses only.
- **Public IP history:** your public IPv4/IPv6 every 5 minutes and on network changes, with the adapter or VPN in use and the AbuseIPDB score.
  - Shown as a timeline whose gaps are when the PC was asleep or offline.
  - Includes a "what was my IP at…?" lookup.
- **Hash changes:** a SHA-256 history of every executable and DLL seen, rated by what happened to the signature (broken, lost, or a new signer).
- **Version info:** the version is shown in the header and the exe's Properties.

### Improved
- **Saving on exit:** all data (IP history, devices, hashes, reputation) is saved when the window is closed, on Ctrl+C, and at logoff or shutdown. The ETW session is also cleaned up.
- **Read-only folders:** if the exe's folder is read-only, data goes to `%LOCALAPPDATA%\NetWatch`.
- **Reverse DNS is DNS-only:** Windows' `gethostbyaddr` also sent NetBIOS queries to public IPs.

## v1.0.0 (2026-11-19)
- **Live view:** connections with their process, parent tree and DLLs.
- **ETW sensor:** TCP, per-process DNS, WinHTTP/WinINet URLs, process start/stop, live DLL loads.
- **Analysis:** dashboard, findings engine, Authenticode signature checks, AbuseIPDB and VirusTotal reputation.
- **Output:** daily JSONL logs, portable one-file exe.
