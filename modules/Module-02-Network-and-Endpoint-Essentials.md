---
title: "Module 2 — Network & Endpoint Essentials"
course: CCDL1
type: Cheat Sheet
tags: [blueteam, soc, network-forensics, wireshark, endpoint, sysmon]
---

# Module 2 — Network & Endpoint Essentials

⚠ **First action:** `View > Time Display Format > UTC Date and Time of Day`. Host artifacts are UTC; relative seconds or local time will misalign your timeline.

---

## Part I — Wireshark

## Opening a new capture

| Menu | Use |
|---|---|
| `Statistics > Protocol Hierarchy` | Protocol mix — DNS at 40% is not normal |
| `Statistics > Conversations` | Top talkers, long sessions. Tick *Limit to display filter* |
| `Statistics > Capture File Properties` | First/last packet = investigation window |
| `Statistics > I/O Graph` | Evenly spaced spikes = C2 beaconing |

Right-click any field → **Apply as Column** (User-Agent, Host, SNI). `Edit > Preferences > Name Resolution`: enable MAC/network, **leave DNS off** — it queries live infrastructure and leaks the investigation.

## IP & port filters

```
ip.addr == 192.168.1.10
ip.src == 10.0.0.5 && ip.dst == 8.8.8.8
tcp.port == 80 || udp.port == 53
tcp.flags.syn == 1 && tcp.flags.ack == 0     # SYN scan
tcp.flags == 0x002                            # same, exact match
tcp.analysis.retransmission
frame.time >= "2024-01-15 10:00:00"
```

## HTTP

```
http.request                                  # requests only
http.request.method == "POST"                 # uploads, web shells, creds
http.request.full_uri                         # readable URL as column
http.response.code == 200
http.response.code >= 400                     # 403/404 storm = dir brute force
http.user_agent contains "Nmap"
http.host == "example.com"
```

## TLS

```
tls.handshake.type == 1                       # Client Hello
tls.handshake.extensions_server_name          # SNI — the domain
tls.handshake.type == 11                      # Certificate
```

**SNI as a column ≈ browsing history recovered.** Self-signed certs, mismatched CN, short-lived certs on high ports = C2 indicators. JA3/JA3S fingerprints the client library.

## Uploads & exfiltration

```
http.request.uri matches "\\.(php|exe|sh|bat|jsp|asp|aspx)"
http contains "multipart/form-data"
tcp contains "passwd"
frame contains "whoami"
```

⚠ Avoid `$` anchors in `matches` — `"\\.php$"` misses `shell.php?cmd=whoami` because the query string follows the extension. `matches` is case-insensitive PCRE.

**`File > Export Objects > HTTP`** (also SMB, FTP-DATA, IMF, TFTP) → hash the file → Module 1 workflow.

## C2 & reverse shells

**`Follow > TCP Stream`** reassembles the full conversation — commands, output, credentials. Everything else is about finding which stream.

```
tcp.flags.push == 1 && ip.src == <victim>     # victim pushing data out
tcp.len > 0 && tcp.port == 4444
```

**DNS tunnelling:**

```
dns.qry.type == 16                            # TXT — usual carrier
dns.qry.type == 255                           # ANY
dns.qry.name.len > 50                         # long random subdomains
dns.flags.rcode != 0                          # NXDOMAIN volume = DGA
```

Pattern: high query volume to one second-level domain, long random subdomains, little answer data. The subdomain **is** the payload.

**Beaconing:** regular intervals, low jitter, consistent small payloads, single long-lived external host.

## Other protocols

```
ftp.request.command == "USER" || ftp.request.command == "PASS"
telnet
smb2 || ntlmssp
kerberos.msg_type
icmp && data.len > 48                         # oversized ICMP = tunnelling
arp.duplicate-address-detected                # ARP spoofing
```

SSH/RDP are encrypted — SYN floods followed by RSTs on 22/3389 = brute force. Correlate timing with host auth logs.

## Identity & hostname discovery

```
nbns                                          # NetBIOS — hostname in cleartext
dhcp.option.hostname                          # Option 12
```

⚠ `bootp` was renamed `dhcp` in Wireshark 3.0+.

| NTLM field | Gives |
|---|---|
| `ntlmssp.auth.username` | The account — often the compromised credential |
| `ntlmssp.auth.domain` | Domain context |
| `ntlmssp.auth.hostname` | Source workstation (from `NTLMSSP_AUTH`) |
| `ntlmssp.challenge.target_name` | Target server (from `NTLMSSP_CHALLENGE`) |

Manual path: `NTLMSSP_AUTH` packet → `SMB2 > Session Setup Request > Security Blob > NTLMSSP` → `Workstation`.

## SMB lateral movement (PsExec)

```
smb2.cmd == 3                                 # Tree Connect — shares accessed
smb2.filename contains ".exe"
smb2.tree
```

Chain in order:

1. **`IPC$`** — named pipes for command/output channel
2. **`ADMIN$`** — maps to `%SystemRoot%`; service binary written here
3. **Binary upload** — classic PsExec drops `PSEXESVC.exe`
4. **`dcerpc` on 445** → Info column → **SVCCTL**: `OpenSCManagerW`, `CreateServiceW`, `StartServiceW`
5. **Cleanup** — `DeleteServiceW` + file deletion

⚠ Impacket and modern variants randomise the binary name. Filter on the SVCCTL calls, not the filename. Correlate with Event ID 7045 / 4697 on the target.

---

## Part II — Endpoint

Order of log sources: **Sysmon → native Windows logs → filesystem artifacts.**

## Initial access — tracing a download

| Method | Location | Gives |
|---|---|---|
| Browser history | `...\Chrome\User Data\Default\History` (SQLite) | Table `downloads`: `start_time`, `target_path`, `tab_url`, `referrer` |
| Filesystem | `C:\Users\<U>\Downloads` | **Created** timestamp; `Zone.Identifier` ADS |
| Sysmon | Event ID **11** (File Create) | `TargetFilename`, `UtcTime` (already UTC) |

`start_time` = WebKit timestamp, microseconds since 1601-01-01.
`Zone.Identifier` ADS: `ZoneId=3` = Internet; `HostUrl` / `ReferrerUrl` often hold the exact download URL.

## Execution — droppers

**Sysmon ID 11:** filter creating process = `WINWORD.EXE`, `EXCEL.EXE`, `AcroRd32.exe`. Office does not legitimately create `.exe`, `.vbs`, `.ps1`, `.bat`, `.hta`.

**Sysmon ID 1:** document handler as `ParentImage` spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`. `CommandLine` holds the payload path.

**Staging directories:**

```
C:\Users\<U>\AppData\Local\Temp\
C:\Users\<U>\AppData\Roaming\
C:\Users\Public\
C:\ProgramData\
```

**Evidence of execution without logs:** Prefetch (`PECmd`), Amcache (`AmcacheParser`, holds SHA-1 after deletion), ShimCache (presence only).

## C2 infrastructure

| Source | Event | Fields |
|---|---|---|
| Sysmon | **ID 3** Network Connection | `DestinationIp`, `DestinationPort`, `DestinationHostname` |
| Sysmon | **ID 22** DNS Query | `QueryName`, `QueryResults` |
| Security | **ID 5156** WFP allowed | `DestAddress`, `DestPort` — noisy, scope by time or app |

**Hardcoded C2 in scripts:** `Net.WebClient`, `Invoke-WebRequest`, `Invoke-RestMethod`, `Start-BitsTransfer` (PS); `WinHttp.WinHttpRequest`, `MSXML2.XMLHTTP` (VBS).

## Persistence

**Scheduled tasks — `Microsoft-Windows-TaskScheduler%4Operational.evtx`:**

| ID | Meaning |
|---|---|
| 106 | Task registered — gives the name |
| 140 | Task updated |
| 200 | Action started — exact run time |
| 201 | Action completed |

Records COM-API creation where no `schtasks.exe` appears. Security **4698** is a second auditable source.

**Sysmon ID 1:** `schtasks.exe /create` → `/tn` name, `/tr` command. `/run` = manual trigger, usually via C2.
⚠ **Stealthy creation:** no `schtasks` process. Search for `ParentImage` = `svchost.exe -k netsvcs -p -s Schedule` — anything with that parent was launched by a scheduled task.

**On disk:** `C:\Windows\System32\Tasks\` XML → `<Command>`, `<Arguments>`, `<Author>`. Registry: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`.

⚠ **Do not stop at scheduled tasks:**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SYSTEM\CurrentControlSet\Services\
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load
```

Startup folder: `...\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
Services: Event ID **7045**. WMI subscriptions: Sysmon **19/20/21** (fileless — nothing in Run keys or Task Scheduler).

**Chain tracking:** take `ProcessGuid` of one process, search it as `ParentProcessGuid` in later events.
⚠ Use `ProcessGuid`, not `ProcessId` — Windows recycles PIDs.

## Discovery

Signature = **burst** of native commands in a short window, usually 5–10 min after execution.

| Category | Commands |
|---|---|
| Identity | `whoami /all`, `whoami /priv`, `net user`, `net localgroup administrators` |
| Network | `ipconfig /all`, `netstat -ano`, `arp -a`, `route print`, `nltest /domain_trusts` |
| Defences | `systeminfo`, `tasklist`, `wmic qfe`, `net share` |
| AD | `net group "Domain Admins" /domain`, `dsquery` |

| Source | Event | Note |
|---|---|---|
| Sysmon | ID 1 | Best — `cmd.exe`/`powershell.exe` as `ParentImage`, children's `CommandLine` |
| Security | 4688 | `New Process Name`. ⚠ `Process Command Line` only populates with advanced audit policy enabled |
| PowerShell | 4104 | Script Block Logging — `Get-LocalUser`, `Get-NetIPAddress`, `Get-ADUser` |

## Collection & evasion

**Masquerading:** Sysmon ID 1 — compare `Image` (name on disk) vs `OriginalFileName` (compiled into the PE). Mismatch = red flag. Also compare `Hashes`. Static fallback: *Properties > Details* or `exiftool`.
⚠ Legitimate names in illegitimate locations count too — `svchost.exe` outside `System32` is never legitimate.

**Fileless registry storage:** Sysmon **ID 13** (Registry Value Set) → `TargetObject`. Large values under `HKCU\Software\` = keylogger buffer. In code: `Set-ItemProperty`, `New-ItemProperty`, `RegWrite`, `reg add`.

**File-based keyloggers:** Sysmon ID 11 — `.txt`/`.log`/`.dat` created repeatedly by one process in `%TEMP%` or `%APPDATA%`. Keystrokes interleaved with window titles = classic format.

## Exfiltration

**Sysmon ID 11** → `TargetFilename`: archives (`.zip`, `.rar`, `.7z`, `.cab`) or bland extensions (`.bin`, `.dat`, `.tmp`) in user-writable paths.

**In script code:**
- Write: `Out-File`, `Add-Content`, `Set-Content`, `[IO.File]::WriteAllBytes`, `Scripting.FileSystemObject`
- Obfuscation: `-bxor`, `[Convert]::ToBase64String`, `System.Security.Cryptography`, `Compress-Archive`
- Transfer: `Invoke-WebRequest`, `Invoke-RestMethod`, `Net.WebClient.UploadFile()`, `Start-BitsTransfer`

**Filesystem hunting:** parse `$MFT`, focus on `Temp`/`Public`/`ProgramData`, sort by mtime in the incident window. A randomly-named file **growing in size** = staging.

Then check Sysmon ID 3 for an outbound connection from the same process immediately after.
