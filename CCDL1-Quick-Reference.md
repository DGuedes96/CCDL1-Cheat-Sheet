---
title: "CCDL1 Quick Reference"
course: CCDL1
type: quick-reference
tags: [blueteam, soc, dfir, ccdl1, cheat-sheet]
---

# CCDL1 — Quick Reference

Commands, field names, event IDs, query templates, and the caveats that change an answer. Organised by the module structure of the CyberDefenders Certified CyberDefender Level 1 course, and by attack phase within each module.

**Use Ctrl+F.** Caveats are marked ⚠ and sit next to the item they apply to, so a search for a tool or a field surfaces the trap along with the syntax.

## Contents

- [Module 1 — Phishing & Email Security](#module-1--phishing--email-security)
- [Module 2 — Network & Endpoint Essentials](#module-2--network--endpoint-essentials)
- [Module 3 — SIEM Basics (Splunk)](#module-3--siem-basics-splunk)
- [Module 4 — Digital Forensics and Incident Response](#module-4--digital-forensics-and-incident-response)
- [Module 5 — Cloud Security](#module-5--cloud-security)

## Carries across all five modules

- **Normalise to UTC first.** Sysmon `UtcTime`, CloudTrail `eventTime`, Event Viewer local time, Wireshark relative seconds, Splunk profile timezone.
- **Presence ≠ execution. Authentication ≠ authorisation. Detection ≠ evidence.**
- **Volume is usually an exclusion signal** — the noisiest source is normally sanctioned automation. Rank by rarity and distinct identities.
- **Failures are evidence.** `AccessDenied`, HTTP 403 storms, failed logons map what was probed and when privileges changed.
- **An empty result is not a conclusion.** Check the source, the time window, then the field name.
- **Corroborate across two independent artifacts** before reporting.

---

## Module 1 — Phishing & Email Security

Order: hash → headers → body/URLs → carve attachments → identify type → internals → payload.

**Safety:** isolated VM, never open maldocs in Office, defang all IOCs (`hxxp`, `[.]`), public sandbox upload = public sample.

---

### Hashing & file identification

```bash
sha256sum <file>
md5sum <file>
file <file>              # true type from magic bytes
exiftool <file>          # author, timestamps, creating app
```

```powershell
Get-FileHash -Path <file> -Algorithm SHA256
certutil -hashfile <file> SHA256          # cmd, native
```

⚠ Extension ≠ type. `invoice.pdf` reporting as PE or OLE **is** the finding.

---

### Email headers

```bash
grep -i -E "^(From|To|Cc|Reply-To|Return-Path|Subject|Date|Message-ID):" -A2 <file.eml>
grep -i -A5 "Authentication-Results:" <file.eml>
grep -i "^Received:" -A2 <file.eml>
```

⚠ `-A2` required — headers fold across lines; plain grep truncates silently.

| Header | Signal |
|---|---|
| `Received:` | Read **bottom-up**. Anything above first trusted gateway is forgeable |
| `From:` vs `Reply-To:` | Mismatch = reply redirected to attacker |
| `Return-Path:` | Bounce address; differs from display in spoofed mail |
| `Authentication-Results:` | SPF / DKIM / DMARC verdicts |
| `Message-ID:` | Domain should match sending infra; malformed = suspicious |
| `X-Mailer` / `X-Originating-IP` | Bulk mailer, script, true origin |

- **SPF** — is sending IP authorised for the envelope-from domain?
- **DKIM** — is the signature valid and unbroken?
- **DMARC** — does SPF or DKIM *align* with the visible `From:` domain?

⚠ **`spf=pass` ≠ legitimate.** Attacker owning `micros0ft-support[.]com` passes SPF for their own domain. Alignment with the displayed `From:` is what matters. `spf=fail` on forwarded mail is normal.

---

### Parsing `.eml` / extracting attachments

```bash
emldump.py <file.eml>                       # list MIME parts
emldump.py -s 4 -d <file.eml> > payload.bin # dump part 4
base64 -d encoded.txt > decoded.bin
strings -n 8 <file>
strings -e l <file>                         # UTF-16LE, common in PE/VBA
msgconvert <file.msg>                       # .msg → .eml
```

⚠ Base64 is not an indicator — every MIME attachment is Base64.

---

### Office documents (oletools)

```bash
oleid <file>        # triage: encrypted / macros / embedded objects
olevba <file>       # extract VBA + suspicious keyword table
oleobj <file>       # embedded objects, external relationships
rtfobj <file>       # RTF objects, equation-editor exploits
msodde <file>       # DDE / DDEAUTO — execution with no macros
```

**`olevba` flags worth knowing on sight:**

| Category | Keywords |
|---|---|
| Auto-execution | `AutoOpen`, `Document_Open`, `Workbook_Open` |
| Process creation | `Shell`, `WScript.Shell`, `CreateObject` |
| Download | `URLDownloadToFileA`, `XMLHTTP`, `WinHttpRequest` |
| Obfuscation | `Chr`, `StrReverse`, `Xor`, long concatenation |
| LOL / WMI | `Environ`, `GetObject`, `Win32_Process` |

⚠ Heuristic keyword scanner. Benign macros trigger it. Read the code.

**Encrypted documents:**

```bash
msoffcrypto-tool <encrypted.xls> <decrypted.xls> -p VelvetSweatshop
msoffcrypto-crack.py <encrypted.xls>      # try known/default passwords
```

⚠ `VelvetSweatshop` is Excel's own hardcoded default, tried silently before prompting — not an attacker password. Used so the file opens seamlessly for the victim while looking encrypted to AV.

---

### oledump (OLE streams)

```bash
oledump.py <file>              # list streams
oledump.py -s 8 <file>         # select stream 8, raw
oledump.py -s 8 -v <file>      # decompress VBA source
oledump.py -s a -v <file>      # all streams
```

| Marker | Meaning |
|---|---|
| `M` | VBA macro **code** → target |
| `m` | Macro attributes only, no code |
| `O` | Embedded OLE object |
| `!` | Parsing anomaly |

---

### PDF

```bash
pdfid <file.pdf>                          # keyword counts
pdfid -e <file.pdf>                       # extended keywords
pdf-parser -s /JavaScript <file.pdf>      # find WHICH object
pdf-parser -o 15 <file.pdf>               # inspect object
pdf-parser -o 15 -f <file.pdf>            # apply filters (FlateDecode)
pdf-parser -o 15 -f -d out.js <file.pdf>  # dump decoded stream
```

⚠ `pdfid` gives **counts, not object numbers**. Use `pdf-parser -s <keyword>` to locate the object, then `-o`, then `-f` to decode.

| Keyword | Meaning |
|---|---|
| `/JavaScript`, `/JS` | Embedded script |
| `/OpenAction`, `/AA` | Auto-runs on open or event |
| `/Launch` | Launches external application |
| `/EmbeddedFile` | File hidden inside PDF |
| `/URI` | External link — most common phishing PDF |
| `/ObjStm` | Object stream — can hide the above from naive scans |

---

### OOXML internals & LNK

```bash
unzip <file.docx> -d extracted/
cat extracted/word/_rels/settings.xml.rels    # remote template injection
cat extracted/word/_rels/document.xml.rels    # external relationships
grep -r "http" extracted/
lnkinfo <file.lnk>                            # target, arguments, machine ID
```

⚠ **No macros ≠ clean.** Remote template injection uses zero VBA: the `.docx` is inert but its rels file fetches an external `.dotm` on open. Always read `word/_rels/`.

`.lnk` targets pointing at `powershell.exe` with encoded args = the whole chain in one field. On Windows use `LECmd` for MAC address and volume serial.

---

## Module 2 — Network & Endpoint Essentials

⚠ **First action:** `View > Time Display Format > UTC Date and Time of Day`. Host artifacts are UTC; relative seconds or local time will misalign your timeline.

---

### Part I — Wireshark

### Opening a new capture

| Menu | Use |
|---|---|
| `Statistics > Protocol Hierarchy` | Protocol mix — DNS at 40% is not normal |
| `Statistics > Conversations` | Top talkers, long sessions. Tick *Limit to display filter* |
| `Statistics > Capture File Properties` | First/last packet = investigation window |
| `Statistics > I/O Graph` | Evenly spaced spikes = C2 beaconing |

Right-click any field → **Apply as Column** (User-Agent, Host, SNI). `Edit > Preferences > Name Resolution`: enable MAC/network, **leave DNS off** — it queries live infrastructure and leaks the investigation.

### IP & port filters

```
ip.addr == 192.168.1.10
ip.src == 10.0.0.5 && ip.dst == 8.8.8.8
tcp.port == 80 || udp.port == 53
tcp.flags.syn == 1 && tcp.flags.ack == 0     # SYN scan
tcp.flags == 0x002                            # same, exact match
tcp.analysis.retransmission
frame.time >= "2024-01-15 10:00:00"
```

### HTTP

```
http.request                                  # requests only
http.request.method == "POST"                 # uploads, web shells, creds
http.request.full_uri                         # readable URL as column
http.response.code == 200
http.response.code >= 400                     # 403/404 storm = dir brute force
http.user_agent contains "Nmap"
http.host == "example.com"
```

### TLS

```
tls.handshake.type == 1                       # Client Hello
tls.handshake.extensions_server_name          # SNI — the domain
tls.handshake.type == 11                      # Certificate
```

**SNI as a column ≈ browsing history recovered.** Self-signed certs, mismatched CN, short-lived certs on high ports = C2 indicators. JA3/JA3S fingerprints the client library.

### Uploads & exfiltration

```
http.request.uri matches "\\.(php|exe|sh|bat|jsp|asp|aspx)"
http contains "multipart/form-data"
tcp contains "passwd"
frame contains "whoami"
```

⚠ Avoid `$` anchors in `matches` — `"\\.php$"` misses `shell.php?cmd=whoami` because the query string follows the extension. `matches` is case-insensitive PCRE.

**`File > Export Objects > HTTP`** (also SMB, FTP-DATA, IMF, TFTP) → hash the file → Module 1 workflow.

### C2 & reverse shells

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

### Other protocols

```
ftp.request.command == "USER" || ftp.request.command == "PASS"
telnet
smb2 || ntlmssp
kerberos.msg_type
icmp && data.len > 48                         # oversized ICMP = tunnelling
arp.duplicate-address-detected                # ARP spoofing
```

SSH/RDP are encrypted — SYN floods followed by RSTs on 22/3389 = brute force. Correlate timing with host auth logs.

### Identity & hostname discovery

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

### SMB lateral movement (PsExec)

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

### Part II — Endpoint

Order of log sources: **Sysmon → native Windows logs → filesystem artifacts.**

### Initial access — tracing a download

| Method | Location | Gives |
|---|---|---|
| Browser history | `...\Chrome\User Data\Default\History` (SQLite) | Table `downloads`: `start_time`, `target_path`, `tab_url`, `referrer` |
| Filesystem | `C:\Users\<U>\Downloads` | **Created** timestamp; `Zone.Identifier` ADS |
| Sysmon | Event ID **11** (File Create) | `TargetFilename`, `UtcTime` (already UTC) |

`start_time` = WebKit timestamp, microseconds since 1601-01-01.
`Zone.Identifier` ADS: `ZoneId=3` = Internet; `HostUrl` / `ReferrerUrl` often hold the exact download URL.

### Execution — droppers

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

### C2 infrastructure

| Source | Event | Fields |
|---|---|---|
| Sysmon | **ID 3** Network Connection | `DestinationIp`, `DestinationPort`, `DestinationHostname` |
| Sysmon | **ID 22** DNS Query | `QueryName`, `QueryResults` |
| Security | **ID 5156** WFP allowed | `DestAddress`, `DestPort` — noisy, scope by time or app |

**Hardcoded C2 in scripts:** `Net.WebClient`, `Invoke-WebRequest`, `Invoke-RestMethod`, `Start-BitsTransfer` (PS); `WinHttp.WinHttpRequest`, `MSXML2.XMLHTTP` (VBS).

### Persistence

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

### Discovery

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

### Collection & evasion

**Masquerading:** Sysmon ID 1 — compare `Image` (name on disk) vs `OriginalFileName` (compiled into the PE). Mismatch = red flag. Also compare `Hashes`. Static fallback: *Properties > Details* or `exiftool`.
⚠ Legitimate names in illegitimate locations count too — `svchost.exe` outside `System32` is never legitimate.

**Fileless registry storage:** Sysmon **ID 13** (Registry Value Set) → `TargetObject`. Large values under `HKCU\Software\` = keylogger buffer. In code: `Set-ItemProperty`, `New-ItemProperty`, `RegWrite`, `reg add`.

**File-based keyloggers:** Sysmon ID 11 — `.txt`/`.log`/`.dat` created repeatedly by one process in `%TEMP%` or `%APPDATA%`. Keystrokes interleaved with window titles = classic format.

### Exfiltration

**Sysmon ID 11** → `TargetFilename`: archives (`.zip`, `.rar`, `.7z`, `.cab`) or bland extensions (`.bin`, `.dat`, `.tmp`) in user-writable paths.

**In script code:**
- Write: `Out-File`, `Add-Content`, `Set-Content`, `[IO.File]::WriteAllBytes`, `Scripting.FileSystemObject`
- Obfuscation: `-bxor`, `[Convert]::ToBase64String`, `System.Security.Cryptography`, `Compress-Archive`
- Transfer: `Invoke-WebRequest`, `Invoke-RestMethod`, `Net.WebClient.UploadFile()`, `Start-BitsTransfer`

**Filesystem hunting:** parse `$MFT`, focus on `Temp`/`Public`/`ProgramData`, sort by mtime in the incident window. A randomly-named file **growing in size** = staging.

Then check Sysmon ID 3 for an outbound connection from the same process immediately after.

---

## Module 3 — SIEM Basics (Splunk)

Replace `<ANGLE_BRACKETS>` with your own values.

⚠ **The time range picker beats every filter you write.** *All time* on a busy index runs forever and returns nothing useful. In-query: `earliest=-24h latest=now` or `earliest="01/15/2024:10:00:00"`.

---

### Orientation — run these first

```
| eventcount summarize=false index=*             # indexes and sizes
index=* | stats count by index, sourcetype       # what lives where
index=<INDEX> | stats count by EventCode         # event types present
index=<INDEX> | stats dc(Computer)               # hosts reporting
| metadata type=sourcetypes index=<INDEX>        # first/last seen
index=<INDEX> EventCode=1 | fieldsummary | table field, count, distinct_count
```

### Search anatomy

```
index=<INDEX> sourcetype=<TYPE> EventCode=1 CommandLine="*powershell*"
| table _time, Computer, User, ParentImage, Image, CommandLine
| sort _time
```

Base search (narrow it) → transforming commands → presentation.

### Commands

| Command | Use |
|---|---|
| `table` | Fixed columns, ordered. Best for timelines |
| `stats count by <f>` | Dedupe + count. The workhorse |
| `stats dc(<f>)` | Distinct count — unique hosts/users/destinations |
| `top` / `rare` | Outliers. `rare` is underrated for hunting |
| `dedup <f>` | One event per unique value |
| `eval` | Create/transform a field |
| `rex` | Regex extraction when the TA didn't parse it |
| `timechart` | Trend — spots beaconing and bursts |
| `fields` | Restrict early; significant speed gain |
| `streamstats` | Deltas between consecutive events |
| `lookup` | Enrich against intel or asset lists |
| `tstats` | Very fast over accelerated data models |

**Cleanup filter** — never read raw events:

```
... | stats count by CommandLine
... | table _time, Computer, User, Image, CommandLine | sort _time
```

⚠ **Field names depend on the add-on.** Raw Sysmon TA: `Image`, `ParentImage`, `CommandLine`, `TargetFilename`. CIM-normalised: `process_name`, `parent_process_name`, `file_path`. Windows TA: `Account_Name`, `Logon_Type`, `Source_Network_Address`. Empty result → check the field name first.

---

### Identify user / host

```
index=<INDEX> "<HOSTNAME>" "<PROCESS_NAME>"
```

Then read the **Interesting Fields** sidebar: `User`, `UserName`, `Account_Name`, `SubjectUserName`.

### Phishing URLs

```
index=<INDEX> EventCode=1 ParentImage="*\\<PARENT>" CommandLine="*http*"
| stats count by ParentImage, CommandLine
```

Parents: `outlook.exe`, `winword.exe`, `excel.exe`, `chrome.exe`, `msedge.exe`.

```
index=<INDEX> "<HOSTNAME>" EventCode=1 (CommandLine="*http://*" OR CommandLine="*https://*")
| stats count by CommandLine
```

### Downloads (EventCode 11)

```
index=<INDEX> EventCode=11 (TargetFilename="*\\Downloads\\*" OR TargetFilename="*\\AppData\\Local\\Temp\\*")
| stats count by TargetFilename, Image

index=<INDEX> EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.vbs" OR TargetFilename="*.ps1"
    OR TargetFilename="*.bat" OR TargetFilename="*.hta" OR TargetFilename="*.iso" OR TargetFilename="*.lnk")
| stats count by TargetFilename
```

Filenames ending `:Zone.Identifier` = Mark of the Web → file came from outside the machine.

### Process lineage (EventCode 1)

```
index=<INDEX> EventCode=1 ParentImage="*\\<PARENT>"
| table _time, Computer, User, ParentImage, Image, CommandLine
| sort _time
```

Chain further: take `ProcessGuid`, search as `ParentProcessGuid` in later events.
⚠ GUIDs are unique; PIDs are recycled.

### Execution from user-writable paths

```
index=<INDEX> EventCode=1 (Image="*\\Users\\*\\Downloads\\*" OR Image="*\\AppData\\Local\\Temp\\*"
    OR Image="*\\Users\\Public\\*" OR Image="*\\ProgramData\\*")
| stats count by Image, CommandLine

index=<INDEX> EventCode=1 Image="C:\\Users\\<USERNAME>\\*"
```

⚠ Doubled backslashes — SPL treats `\` as an escape inside double quotes.

### LOLBins

```
index=<INDEX> EventCode=1 (Image="*\\schtasks.exe" OR Image="*\\icacls.exe" OR Image="*\\systeminfo.exe"
    OR Image="*\\whoami.exe" OR Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\reg.exe"
    OR Image="*\\wmic.exe" OR Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

⚠ The binary is not the finding — all run legitimately. **Parent + arguments + timing** decide. `certutil -urlcache -f` is a downloader; `certutil` verifying a cert is a Tuesday.

### Script creation via echo

```
index=<INDEX> EventCode=1 CommandLine="*echo *" CommandLine="*>*"
    (CommandLine="*.bat*" OR CommandLine="*.ps1*" OR CommandLine="*.vbs*" OR CommandLine="*.js*")
| table _time, Computer, User, CommandLine | sort _time
```

Sort ascending, read top to bottom = the script source in write order.

### AD enumeration

```
index=<INDEX> EventCode=1 CommandLine="*objectcategory=*"

index=<INDEX> EventCode=1 (CommandLine="*AdFind*" OR CommandLine="*dsquery*" OR CommandLine="*SharpHound*"
    OR CommandLine="*BloodHound*" OR CommandLine="*Get-ADUser*" OR CommandLine="*Get-DomainUser*"
    OR CommandLine="*nltest*" OR CommandLine="*net group*")
| table _time, Computer, User, CommandLine
```

LDAP syntax in a command line (`objectcategory=`, `samaccountname=`, `memberof=`) is a signal on its own.

### Hashes

```
index=<INDEX> EventCode=1 Image="*\\<FILENAME>.exe" | table _time, Computer, User, Image, Hashes

... | rex field=Hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})" | table _time, Image, sha256
```

`Hashes` arrives concatenated (`SHA1=...,MD5=...,SHA256=...,IMPHASH=...`). Keep `IMPHASH` — it fingerprints the import table and matches recompiled variants where SHA-256 differs.

### Command interpreters / ClickFix

```
index=<INDEX> EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine | sort _time
```

**The parent tells you the delivery method.** `explorer.exe` as parent = pasted into the Run dialog by a human. `winword.exe` = document macro.

Flags: `-w hidden`, `-nop`, `-ep bypass`, `-enc`, `IEX`, `Invoke-Expression`, `DownloadString`, `FromBase64String`, long Base64 blocks.

### C2 (EventCode 3)

```
index=<INDEX> EventCode=3 (Image="*\\powershell.exe" OR Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe")
| table _time, Computer, User, Image, DestinationIp, DestinationPort, DestinationHostname
```

**Beacon detection:**

```
index=<INDEX> EventCode=3 DestinationIp="<IP>"
| sort _time
| streamstats current=f last(_time) as prev_time by Image
| eval interval=_time-prev_time
| stats count, avg(interval), stdev(interval) by Image, DestinationIp
```

Low stdev over many connections = machine-scheduled, not human.

**Destinations contacted by only one host:**

```
index=<INDEX> EventCode=3 | stats dc(Computer) as hosts by DestinationIp | where hosts=1
```

### Compression & staging

```
index=<INDEX> EventCode=1 (CommandLine="*Compress-Archive*" OR CommandLine="*tar.exe*"
    OR CommandLine="*7z*" OR CommandLine="*rar *" OR CommandLine="*makecab*")
| table _time, Computer, User, CommandLine

index=<INDEX> EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z"
    OR TargetFilename="*.cab" OR TargetFilename="*.tar*")
    (TargetFilename="*\\Temp\\*" OR TargetFilename="*\\Public\\*" OR TargetFilename="*\\ProgramData\\*")
| table _time, Computer, Image, TargetFilename
```

`tar.exe` and `makecab` ship with Windows — installing WinRAR is noisy.

### Exfiltration

```
index=<INDEX> EventCode=1 CommandLine="*ToBase64String*"
    (CommandLine="*Invoke-WebRequest*" OR CommandLine="*Invoke-RestMethod*" OR CommandLine="*UploadFile*"
    OR CommandLine="*Start-BitsTransfer*" OR CommandLine="*curl*")
| table _time, Computer, User, CommandLine
```

### Hardcoded paths not matching the host

```
index=<INDEX> EventCode=1 CommandLine="*C:\\Users\\*"
    NOT (CommandLine="*<LEGIT_USER>*" OR CommandLine="*Public*" OR CommandLine="*Default*")
| table _time, Computer, User, CommandLine
```

Build the exclusion list from users actually on the host.

### Lateral movement — 4624

```
index=<INDEX> EventCode=4624 Account_Name="<ACCOUNT>"
| table _time, Account_Name, Source_Network_Address, Computer, Logon_Type, Logon_Process
| sort _time
```

| Type | Meaning | Relevance |
|---|---|---|
| 2 | Interactive | Console/physical |
| 3 | Network | SMB, remote WMI — **the lateral movement workhorse** |
| 4 | Batch | Scheduled task |
| 5 | Service | Service account start |
| 8 | NetworkCleartext | Cleartext credentials — investigate |
| 9 | NewCredentials | `runas /netonly`, Pass-the-Hash |
| 10 | RemoteInteractive | **RDP** |
| 11 | CachedInteractive | Cached domain credentials |

⚠ **`Account_Name` appears twice in 4624** — subject (often `HOST$`) and target. Splunk renders it multivalue, so `stats count by Account_Name` double-counts. Use `mvindex()` or `Target_Account_Name`, and filter `Account_Name="*$"` to drop machine accounts.

Also: **4625** failures (brute force), **4768/4769/4771** Kerberos (Kerberoasting).

### Remote services

```
index=<INDEX> Computer="<TARGET>" (EventCode=7045 OR EventCode=4697)
| table _time, Computer, ServiceName, ImagePath, ServiceType, StartType
```

Distrust in `ServiceName`: randomised strings, `PSEXESVC`, near-miss Windows names.
Distrust in `ImagePath`: `\\<IP>\ADMIN$\...`, `%SystemRoot%\Temp\`, or a command line embedded in the path (`cmd.exe /c ...`) = Impacket `smbexec`.

### Script Block Logging — 4104

```
index=<INDEX> EventCode=4104 "<KEYWORD>" | table _time, Computer, User, ScriptBlockText
```

Records deobfuscated source even when the `.ps1` is deleted. `ScriptBlockText` reveals filename-generation logic → search those in EventCode 11. Long scripts split across events: reassemble with `MessageNumber` / `MessageTotal`.

### Anti-forensics

| Sysmon ID | Meaning |
|---|---|
| 23 | FileDelete — deleted **and archived** by Sysmon (recoverable) |
| 26 | FileDeleteDetected — deleted, **not** archived |

```
index=<INDEX> (EventCode=23 OR EventCode=26) TargetFilename="*<NAME>*"
| table _time, Computer, User, Image, TargetFilename

index=<INDEX> EventCode=1 (CommandLine="*del *" OR CommandLine="*Remove-Item*" OR CommandLine="*rmdir*"
    OR CommandLine="*wevtutil*cl*" OR CommandLine="*Clear-EventLog*" OR CommandLine="*vssadmin*delete*")
| table _time, Computer, User, Image, CommandLine
```

`wevtutil cl` / `Clear-EventLog` / `vssadmin delete shadows` are higher severity — the last is a ransomware precursor. Windows **1102** independently records Security log clearing.

---

## Module 4 — Digital Forensics and Incident Response

⚠ **Order of volatility:** registers/cache → **RAM** → network state and processes → disk → remote logs → archived media. Imaging the disk before memory destroys the most valuable evidence. Hash on acquisition and after transfer. Work on copies, mounted read-only.

---

### Acquisition

| Goal | Tool |
|---|---|
| Full disk image | FTK Imager, dd, dc3dd, Guymager |
| Memory capture | WinPmem, DumpIt, FTK Imager (Capture Memory), Magnet RAM Capture |
| Targeted collection | **KAPE** — `Targets` = what to collect, `Modules` = what to parse |
| Mount / browse | FTK Imager, Arsenal Image Mounter |
| Full case | Autopsy, Velociraptor |

`!SANS_Triage` target = hives, event logs, `$MFT`, Prefetch, browser data — small enough to move over the network.

---

### Memory — Volatility 3

⚠ No `--profile` in Volatility 3; symbols resolve automatically.

**Processes**

```bash
python3 vol.py -f memory.dmp windows.pslist      # linked list
python3 vol.py -f memory.dmp windows.psscan      # pool scan — finds unlinked/hidden
python3 vol.py -f memory.dmp windows.pstree      # hierarchy, indented
```

⚠ Use `pstree` rather than grepping PPIDs manually. **`psscan` minus `pslist` = hidden processes** — that comparison is itself the detection.

**What looks wrong:** `svchost.exe` whose parent isn't `services.exe`; multiple or misspelled `lsass.exe`/`csrss.exe`/`winlogon.exe`; system processes outside `System32`; Office or browsers parenting a shell.

**Command lines**

```bash
python3 vol.py -f memory.dmp windows.cmdline
python3 vol.py -f memory.dmp windows.cmdline --pid <PID>
```

⚠ Use `--pid`, not `| grep`. Look for `Add-MpPreference -ExclusionPath`, `-EncodedCommand`, `-ExecutionPolicy Bypass`, `vssadmin delete shadows`.

**Network** — often the fastest route to C2, ties a connection to a PID:

```bash
python3 vol.py -f memory.dmp windows.netscan
python3 vol.py -f memory.dmp windows.netstat
```

**Injected code**

```bash
python3 vol.py -f memory.dmp windows.malfind                 # injected regions
python3 vol.py -f memory.dmp windows.malfind --dump
python3 vol.py -f memory.dmp windows.dlllist --pid <PID>
python3 vol.py -f memory.dmp windows.ldrmodules --pid <PID>  # DLLs hidden from PEB
python3 vol.py -f memory.dmp windows.handles --pid <PID>
```

`malfind` = private + executable + not file-backed. A region starting `MZ` is a whole PE in another process.

**Persistence / state / extraction**

```bash
python3 vol.py -f memory.dmp windows.svcscan
python3 vol.py -f memory.dmp windows.registry.hivelist
python3 vol.py -f memory.dmp windows.registry.printkey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
python3 vol.py -f memory.dmp windows.getsids --pid <PID>
python3 vol.py -f memory.dmp windows.filescan | grep -i "<pattern>"
python3 vol.py -f memory.dmp windows.dumpfiles --virtaddr <OFFSET>
python3 vol.py -f memory.dmp windows.memmap --pid <PID> --dump
```

---

### EZ Tools

Output CSV → open in **Timeline Explorer**, not Excel.

| Tool | Artifact | Proves |
|---|---|---|
| **MFTECmd** | `$MFT`, `$J`, `$LogFile`, `$Boot` | Filesystem timeline; creation/deletion to the millisecond |
| **PECmd** | `C:\Windows\Prefetch\*.pf` | **Execution.** Run count, last-run times, referenced files |
| **AmcacheParser** | `C:\Windows\AppCompat\Programs\Amcache.hve` | Presence, SHA-1, original filename, publisher |
| **AppCompatCacheParser** | ShimCache, inside `SYSTEM` | Presence + full path, survives deletion |
| **LECmd** | `.lnk` files | What was opened, from where, which volume |
| **JLECmd** | Jump Lists | Recent files per application |
| **SBECmd** | ShellBags (`NTUSER.DAT`, `USRCLASS.DAT`) | **Folders browsed** — incl. deleted and network shares |
| **RECmd** | Any hive, batch | Bulk keyword/plugin extraction |
| **EvtxECmd** | `.evtx` | Normalised greppable CSV |
| **SrumECmd** | `SRUDB.dat` | **Bytes sent/received per process** — proves exfil volume |

```
PECmd.exe -d "C:\path\Prefetch" --csv "C:\out" --csvf prefetch.csv
AmcacheParser.exe -f "C:\path\Amcache.hve" --csv "C:\out" --csvf amcache.csv
AppCompatCacheParser.exe -f "C:\path\SYSTEM" --csv "C:\out" --csvf shimcache.csv
LECmd.exe -d "C:\path\Recent" --csv "C:\out" --csvf lnk.csv
EvtxECmd.exe -d "C:\path\Logs" --csv "C:\out" --csvf events.csv
```

**MFTECmd — argument order matters:**

```
MFTECmd.exe -f "C:\path\$MFT" --csv "C:\out" --csvf mft.csv
MFTECmd.exe -f "C:\path\$J" -m "C:\path\$MFT" --csv "C:\out" --csvf usnjrnl.csv
```

⚠ `-f` = the file being parsed. `-m` supplies the `$MFT` when parsing `$J`, to resolve parent paths. Inverted, you get filenames with no path.

---

### Evidence of execution — what each artifact proves

| Artifact | Proves execution? |
|---|---|
| **Prefetch** | **Yes.** Run count + up to 8 last-run timestamps (Win8+) |
| **UserAssist** | **Yes** — GUI programs via Explorer, run count and focus time |
| **SRUM** | **Yes**, plus network bytes per process |
| **Amcache** | Presence + metadata; execution inferred |
| **ShimCache** | **No.** Only that Windows *inspected* the file — browsing a folder creates entries |

⚠ **ShimCache on Win10+ flushes to the `SYSTEM` hive only at shutdown.** Recent activity on a machine that hasn't rebooted won't be in the hive — but may be in memory. Its timestamps are the *file's* last-modified time, not execution time.
⚠ Prefetch is often disabled on SSD systems and server editions. Absence ≠ nothing ran.

---

### Filesystem timeline

- `$MFT` gives **MACB** from both `$STANDARD_INFORMATION` and `$FILE_NAME`. Comparing the two detects **timestomping** — attackers alter `$SI` (which most tools display) while `$FN` keeps the truth
- `$J` (USN Journal) records creation, deletion and rename with reasons — catches a tool dropped, used and deleted in one minute
- Sub-second precision of exactly `.0000000` = timestomping indicator

---

### Registry — user hives

`C:\Users\<U>\NTUSER.DAT` and `...\AppData\Local\Microsoft\Windows\UsrClass.dat`. Open in **Registry Explorer** (auto-bookmarks all of these).

```
Software\Microsoft\Windows\CurrentVersion\Run
Software\Microsoft\Windows\CurrentVersion\RunOnce
Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU            # Win+R history
Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist        # GUI execution
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs        # by extension
Software\Microsoft\Windows\CurrentVersion\Explorer\TypedURLs         # IE / legacy Edge
Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2      # network shares + USB
Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
```

⚠ **These are per-user, in `NTUSER.DAT` — not the `SOFTWARE` hive.** The internal path begins `Software\Microsoft\Windows\` in both, which is the trap.
⚠ **UserAssist values are ROT13-encoded.** Registry Explorer decodes; raw dumps don't.

### Registry — system hives (`C:\Windows\System32\config\`)

**SAM** — local accounts, SIDs, group membership, last logon, logon count, password hashes. Look for backdoor accounts and unexpected local Administrators.
⚠ Hashes can't be decrypted from SAM alone — the boot key is in `SYSTEM`, which is why dumpers take both.

**SYSTEM**

```
ControlSet001\Services\                      # malicious services running as SYSTEM
ControlSet001\Enum\USBSTOR\                  # every USB ever attached: vendor, serial, dates
ControlSet001\Control\ComputerName\ComputerName
ControlSet001\Control\TimeZoneInformation    # essential for the timeline
Select\Current                               # which ControlSet was active
```

**SOFTWARE**

```
Microsoft\Windows\CurrentVersion\Run                      # persistence for ALL users
Microsoft\Windows\CurrentVersion\Uninstall\               # AnyDesk, Ngrok, Advanced IP Scanner
Microsoft\Windows NT\CurrentVersion                       # OS version, install date
Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
```

⚠ **Sticky-keys backdoors live in IFEO, not DEFAULT.** A `Debugger` value under `Image File Execution Options\sethc.exe` (or `utilman.exe`, `osk.exe`) pointing at `cmd.exe` gives a SYSTEM shell from the lock screen. No accessibility binary has a legitimate `Debugger` value.

**SECURITY** — local policy + **LSA Secrets** (service account passwords, cached domain creds, DPAPI keys). Extraction alongside `SYSTEM` = credential theft indicator.

**DEFAULT** — the `HKU\.DEFAULT` profile, i.e. LocalSystem; the machine before anyone logs in.

**Deleted data:** at the bottom of the tree in Registry Explorer — **Associated deleted records** and **Unassociated deleted values**. Cleanup-removed persistence keys are frequently recoverable.

---

### Tracing a downloaded document

| Level | Where | Survives |
|---|---|---|
| 1 | `Downloads`, Desktop, `%TEMP%` — **every** user profile | Nothing |
| 2 | `...\AppData\Roaming\Microsoft\Windows\Recent\` (`.lnk`) | File deletion |
| 3 | Autopsy `Data Artifacts > Web Downloads` / `Recent Documents` | — |
| 4 | Sysmon **ID 11** (disk write), **ID 1** (handler opening it) | File deletion |
| 5 | Browser SQLite DB | File deletion entirely |

```
LECmd.exe -d "C:\path\Recent" --csv "C:\out" --csvf lnk.csv
```

LNK files retain original full path, file size, volume serial, and **MAC address** of the machine.

```
Chrome:  ...\AppData\Local\Google\Chrome\User Data\Default\History
Edge:    ...\AppData\Local\Microsoft\Edge\User Data\Default\History
Firefox: ...\AppData\Roaming\Mozilla\Firefox\Profiles\<p>\places.sqlite
```

DB Browser for SQLite → `Browse Data` → table `downloads` (+ `downloads_url_chains` for redirects). Chrome timestamps = WebKit, microseconds since 1601-01-01.
Also: `Web Data` (autofill), `Login Data`, `Cookies`, `Bookmarks`.

---

### Malicious scheduled tasks

| Level | Source | Detail |
|---|---|---|
| 1 | `Security.evtx` | **4698** created, 4699 deleted, 4700/4701 enabled/disabled, 4702 updated. Body has full task XML; `ClientProcessId` = creating process |
| 2 | `Microsoft-Windows-TaskScheduler%4Operational.evtx` | 106 registered, 140 updated, 200 started, 201 completed. **Catches COM-API creation with no `schtasks.exe`** |
| 3 | Sysmon | ID 1 `schtasks /create /tn /tr`; ID 11 under `C:\Windows\System32\Tasks\` |
| 4 | Filesystem | `C:\Windows\System32\Tasks\` XML → `<Command>`, `<Arguments>`, `<Author>` |
| 5 | Registry | `SOFTWARE\...\Schedule\TaskCache\Tree\` and `\Tasks\` — survives XML deletion |

Level 1 requires the *Other Object Access Events* audit subcategory. Sort task files by creation time — anything inside the incident window among years-older files is the flag.

---

### WMI persistence

Three components; all three must be found.

| Sysmon ID | Component | Read |
|---|---|---|
| **19** | `WmiEventFilter` — trigger | `Query` in WQL: `__InstanceCreationEvent`, `__InstanceModificationEvent` |
| **20** | `WmiEventConsumer` — payload | `Destination` / `CommandLineTemplate` — often encoded PowerShell |
| **21** | `WmiEventConsumerToFilter` — binding | Links the two; gives the SID that armed it |

**Native log:** `Microsoft-Windows-WMI-Activity%4Operational.evtx` — **5861** permanent consumer binding; 5859/5860 temporary.

**On disk:** `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` — binary. Parse with **python-cim** (Mandiant/Willi Ballenthin) or **PyWMIPersistenceFinder**.
⚠ Not PECmd — that's Prefetch.

Live system: `Get-WmiObject -Namespace root\Subscription -Class __EventConsumer`

---

### Autopsy — identity & communications

- **`Communications`** button (top toolbar) — contact graph from PSTs and mail DBs
- `Data Artifacts > Email Messages` / `Contacts` — sender/recipient, often full names
- `Analysis Results > Keyword Hits > Email Addresses` → click a hit → **Text** tab. The words around the highlighted match usually hold the associated full name
- `Data Artifacts > Web Accounts`, or the source: `...\Chrome\User Data\Default\Web Data`, table `autofill`

---

## Module 5 — Cloud Security

⚠ **Cloud incidents are identity chains, not process chains.** App flaw leaks a credential → used from somewhere unexpected → enumerates → escalates or persists → exfiltrates. Always ask *which identity, and where did it come from?*

---

### Log sources & blind spots

| Source | Records | Blind spot |
|---|---|---|
| **CloudTrail** | Control-plane API calls | ⚠ Data events (S3 objects, Lambda invokes) are **off by default** |
| **CloudWatch Logs** | App output — Lambda, API Gateway, ECS | Only what the app logs |
| **VPC Flow Logs** | Connection metadata | No payload |
| **S3 Server Access Logs** | Bucket-level requests | Best-effort, delayed |
| **GuardDuty** | Analysed findings | Detections, not evidence |
| **Config** | Resource state over time | What changed, not who exploited it |

First question every time: **were data events enabled?** If not, an attacker can read every object in a bucket and only the management-plane calls appear.

---

### AWS identifiers

| Format | Meaning |
|---|---|
| `AKIA...` | Long-term key, IAM **user** |
| `ASIA...` | Temporary STS key — requires session token, came from a role assumption |
| `arn:aws:iam::<ACCT>:role/<Role>` | Role |
| `arn:aws:iam::<ACCT>:user/<User>` | User |
| `arn:aws:sts::<ACCT>:assumed-role/<Role>/<SessionName>` | Assumed session — **`SessionName` is a strong pivot** |
| `/aws/lambda/<Fn>` | CloudWatch log group |
| `https://<API_ID>.execute-api.<Region>.amazonaws.com/<Stage>/<Path>` | API Gateway |

`ASIA` key used from a non-AWS IP shortly after a web exploit = classic stolen credential.

---

### Credential theft from compute — the pivot

**EC2 — IMDS**

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
```

Returns `AccessKeyId`, `SecretAccessKey`, `Token`.
- **IMDSv1** — plain GET. Vulnerable to SSRF
- **IMDSv2** — PUT to `/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds` first, token on every request

`169.254.169.254` in an application request parameter **is** the finding.

**Lambda — environment variables** (no IMDS):

```
AWS_ACCESS_KEY_ID   AWS_SECRET_ACCESS_KEY   AWS_SESSION_TOKEN
AWS_LAMBDA_FUNCTION_NAME   AWS_REGION
```

Any file-read reaching `/proc/self/environ` steals live credentials.

**XXE via SVG — detection signature:**

```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///proc/self/environ" > ]>
```

Alert on `<!DOCTYPE` / `<!ENTITY` inside an uploaded image, `SYSTEM` with `file://` or `http://169.254.169.254`, Base64 in upload params decoding to XML. Check raw **and** decoded.

---

### CloudTrail event fields

```json
"userIdentity": {
  "type": "AssumedRole",
  "arn": "arn:aws:sts::<ACCT>:assumed-role/<Role>/<Session>",
  "accessKeyId": "ASIA...",
  "sessionContext": { "attributes": { "mfaAuthenticated": "false" } }
}
```

`userIdentity.type`: `Root` (investigate every occurrence), `IAMUser`, `AssumedRole`, `FederatedUser`, `AWSService`, `AWSAccount`.

| Field | Why |
|---|---|
| `eventName` | The API call — primary filter |
| `sourceIPAddress` | Origin; service name instead of IP for AWS-internal calls |
| `userAgent` | Tool fingerprint |
| `errorCode` / `errorMessage` | `AccessDenied` bursts = enumeration or failed escalation |
| `requestParameters` | What was asked for |
| `responseElements` | What came back — new key IDs, created usernames |
| `readOnly` | Splits recon from modification |
| `mfaAuthenticated` | `false` on a sensitive action is itself a finding |

⚠ **Listing calls** (`ListBuckets`, `ListSecrets`, `ListUsers`) take no resource argument — result is in **`responseElements`**. **Resource calls** (`GetSecretValue`, `GetBucketAcl`, `PutObject`) name the target in **`requestParameters`**. `requestParameters.bucketName` is empty for `ListBuckets` by design.

---

### API calls by attack phase

**Discovery**

```
GetCallerIdentity                     # "who am I" — very often the first call
ListBuckets, ListObjects
ListUsers, ListRoles, ListPolicies, ListAttachedUserPolicies
GetAccountAuthorizationDetails        # dumps the entire IAM config
DescribeInstances, DescribeSecurityGroups, DescribeSnapshots
ListFunctions, GetFunction            # Lambda env vars returned here
```

**Privilege escalation**

```
AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy
CreatePolicyVersion --set-as-default  # silent escalation, attaches nothing new
UpdateAssumeRolePolicy                # lets attacker's principal assume a privileged role
PassRole (in requestParameters)
```

**Persistence**

```
CreateUser, CreateAccessKey           # second key on an existing user = backdoor
CreateLoginProfile, UpdateLoginProfile
CreateRole, UpdateAssumeRolePolicy
CreateFunction, UpdateFunctionCode
```

**Defence evasion**

```
StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors
DeleteFlowLogs
DeleteDetector, UpdateDetector        # GuardDuty
DeleteLogGroup, DeleteLogStream
```

`StopLogging` has essentially no benign incident-time explanation.

**Collection / exfiltration**

```
GetObject, CopyObject                 # needs S3 data events enabled
PutBucketPolicy, PutBucketAcl, DeletePublicAccessBlock
CreateSnapshot, ModifySnapshotAttribute      # shares EBS snapshot externally
CreateDBSnapshot, ModifyDBSnapshotAttribute
```

`ModifySnapshotAttribute` `requestParameters` contain the **destination account ID** — often the only identifier for attacker infrastructure.

**Session tracking:** `AssumeRole` → `responseElements.credentials.accessKeyId` = the new `ASIA` key. Search on it to follow the session. Repeat for role chaining.

---

### CloudWatch Logs Insights — CloudTrail

⚠ **`@timestamp` ≠ `eventTime`.** `@timestamp` = ingestion; `eventTime` = when the API call happened. The picker and `START=`/`END=` filter ingestion only. After a bulk import every record can share one `@timestamp` while `eventTime` spans days. **Always `sort eventTime asc`.** Error *"end date is either before the log groups creation time"* means exactly this — widen the picker and filter with `| filter eventTime like "2026-01-23"` (ISO 8601 sorts lexicographically).

⚠ **Confirm the source before trusting an empty result.** A CloudTrail query against `/aws/lambda/...` returns zeros for every identity field. Check the **Discovered fields** counter (a handful = unstructured text, ~25 = parsed CloudTrail) and the **Data sources** selector — `aws_cloudtrail.management` for control plane, `aws_cloudtrail.data` for object level.

Reference dotted fields directly; backticks if parsing fails: `` `userIdentity.arn` ``.

**Most identities per IP:**

```
stats count_distinct(userIdentity.arn) as identities,
      count_distinct(userIdentity.accessKeyId) as keys,
      count(*) as calls
      by sourceIPAddress
| sort identities desc
```

**Tool fingerprint:**

```
stats count(*) by sourceIPAddress, userAgent
| sort calls desc
```

**One actor's timeline / follow a stolen session / surface enumeration:**

```
fields @timestamp, eventName, eventSource, userIdentity.arn, errorCode
| filter sourceIPAddress = "<IP>"
| sort eventTime asc

| filter userIdentity.accessKeyId = "<ASIA...>"

| filter ispresent(errorCode)
| stats count(*) as denials by userIdentity.arn, eventName
| sort denials desc
```

---

### Identifying the actor

⚠ **Volume is an exclusion signal, not a suspicion signal.** The noisiest IP is almost always sanctioned automation. Rank by distinct identities. Discard rows whose `sourceIPAddress` is a service name (`lambda.amazonaws.com`, `AWS Internal`, `cloudtrail.amazonaws.com`).

| `userAgent` | Interpretation |
|---|---|
| `Mozilla/5.0 ... Chrome/...` | Console — a human in a browser |
| `Terraform/x.y.z terraform-provider-aws/...` | Infrastructure as code |
| `aws-sdk-go/... amazon-ssm-agent/...` | SSM agent |
| `aws-cli/2.x ... md/command#<service.operation>` | CLI — **the exact command is in the string** |
| `Boto3/x.y.z ... Botocore/x.y.z` | Python script |
| A bare product name | Named tooling — read it literally |

⚠ The `aws-cli` agent embeds the command, so `stats by userAgent` fragments into hundreds of rows. Filter it out for a tool inventory.
⚠ A shared Botocore version across two different agents suggests one host running several tools in one Python environment.
⚠ **When aggregation hides the needle, return to the raw timeline.** A tool making a single API call disappears inside a `stats` result.

**Baseline divergence:** legitimate hosts form a consistent fleet — same CLI and botocore version, same kernel string, a mix of console and CLI because real people use both. An intruder's machine diverges on all counts. `curl` calling the AWS API is close to conclusive: hand-crafted requests, typically testing a stolen key.

**Legitimate admin vs attacker:**

| Signal | Admin | Attacker |
|---|---|---|
| `userAgent` | Console, IaC | Boto3, python-requests, offensive tooling |
| `sourceIPAddress` | Consistent, corporate | External, hosting provider |
| `mfaAuthenticated` | `true` | `false` |
| Timing | Business hours, spread | Compressed into minutes |
| Identity | One stable principal | Several, chained via `AssumeRole` |

⚠ **`AccessDenied` is evidence.** Denial bursts map what was probed. The same call failing then succeeding marks the exact moment of privilege escalation.

**Region distribution:**

```bash
jq -r '.awsRegion' all_events.json | sort | uniq -c | sort -rn
jq -r '[.awsRegion, .eventName] | @tsv' all_events.json | sort | uniq -c | sort -rn | head -40
```

⚠ The same `Describe*`/`List*` set repeating in near-identical proportions across several regions = automated enumeration. A single region whose profile differs (bulk `GetObject` where others show only discovery) = where something happened. Global services (IAM, STS, CloudTrail, CloudFront) log to `us-east-1` regardless.

**Credentials stored in S3** are a recurring entry point:

```bash
jq -r 'select(.requestParameters.key != null) | .requestParameters.key' all_events.json \
  | sort -u | grep -iE "key|cred|secret|config|env|token|\.pem"
```

**First appearance of each identity** — exposes when a new credential entered service:

```bash
jq -r 'select(.sourceIPAddress=="<IP>")
  | [.eventTime, (.userIdentity.userName // .userIdentity.type), .eventName] | @tsv' \
  all_events.json | sort | awk '!seen[$2]++'
```

**Session names as IOCs:**

```
fields eventTime, requestParameters.roleArn, requestParameters.roleSessionName,
       responseElements.assumedRoleUser.arn, responseElements.credentials.accessKeyId,
       sourceIPAddress, errorCode
| filter eventName = "AssumeRole"
| sort eventTime asc
```

`roleSessionName` is attacker-chosen and arbitrary — durable, often reused across intrusions.

---

### Raw CloudTrail on disk

Structure: `AWSLogs/<ACCT>/CloudTrail/<REGION>/<YYYY>/<MM>/<DD>/`. `CloudTrail-Digest/` holds integrity signatures, no events.

```bash
cd AWSLogs/<ACCOUNT_ID>/CloudTrail
for d in */; do echo -n "$d "; find "$d" -name "*.json.gz" | wc -l; done
find . -name "*.json.gz" -exec gunzip -c {} \; | jq -c '.Records[]' > ~/all_events.json
wc -l ~/all_events.json
```

⚠ **`jq` fails silently on a mistyped field** — returns `null`, not an error, so an empty result looks like a finding. Case-sensitive: `awsRegion`, `sourceIPAddress`, `userIdentity`, `requestParameters`, `eventTime`.

```bash
jq -r 'keys[]' all_events.json | sort -u          # the field list
jq -s '.[0]' all_events.json                      # one full event
```

**Write field names once, then filter with `grep`:**

```bash
cat > ~/t.sh << 'EOF'
jq -r '[.eventTime, .awsRegion, .sourceIPAddress, .eventName,
        ((.requestParameters.bucketName // "-") + "/" + (.requestParameters.key // "-")),
        (.errorCode // "-")] | @tsv' ~/all_events.json
EOF
chmod +x ~/t.sh
./t.sh | grep StopLogging
```

**Recipes:**

```bash
jq -r 'select(.sourceIPAddress=="<IP>") | [.eventTime,.eventName,.userIdentity.arn] | @tsv' all_events.json | sort
jq -r 'select(.userIdentity.accessKeyId=="<ASIA...>") | [.eventTime,.eventName,.errorCode] | @tsv' all_events.json | sort
jq -r '.eventName' all_events.json | sort | uniq -c | sort -rn | head -30
jq -r 'select(.errorCode!=null) | [.eventTime,.userIdentity.arn,.eventName,.errorCode] | @tsv' all_events.json | sort
```

**Athena:**

```sql
SELECT eventtime, eventname, useridentity.arn, sourceipaddress, errorcode
FROM cloudtrail_logs WHERE sourceipaddress = '<IP>' ORDER BY eventtime;
```

Partition by region and date or every query scans the bucket.

---

### Secrets Manager / Parameter Store

```
fields eventTime, eventName, userIdentity.arn, requestParameters.secretId, sourceIPAddress, errorCode
| filter eventSource = "secretsmanager.amazonaws.com" or eventSource = "ssm.amazonaws.com"
| sort eventTime asc
```

`ListSecrets` (inventory) → successive `GetSecretValue` (collection) = credential exfiltration → **T1552 Unsecured Credentials**.

⚠ **`PutSecretValue` is not theft, it's sabotage or persistence.** Overwriting a secret consumed by an automated process makes everything downstream silently use attacker-supplied values. Same for `PutParameter` (SSM) and `UpdateFunctionConfiguration` (Lambda).

Every `GetSecretValue` on an encrypted secret produces a matching KMS `Decrypt` — independent corroboration.

---

### IAM persistence & anti-forensics

```bash
jq -r 'select(.eventName | test("^(CreateUser|CreateAccessKey|CreateLoginProfile|AddUserToGroup|AttachUserPolicy|PutUserPolicy)$"))
  | [.eventTime, .eventName, (.requestParameters.userName // "-"),
     (.requestParameters.groupName // .requestParameters.policyArn // "-"),
     (.userIdentity.arn // "-"), .sourceIPAddress] | @tsv' all_events.json | sort
```

| Step | Event | Grants |
|---|---|---|
| 1 | `CreateUser` | The identity |
| 2 | `CreateLoginProfile` | **Console** password — interactive |
| 2′ | `CreateAccessKey` | **Programmatic** key |
| 3 | `AddUserToGroup` / `AttachUserPolicy` | The privileges |

Steps 2 and 2′ are alternatives — which appears answers "how did they access the account they created".

```bash
jq -r 'select(.eventName | test("^(StopLogging|DeleteTrail|UpdateTrail|PutEventSelectors|DeleteFlowLogs|DeleteDetector)$"))
  | [.eventTime, .eventName, .userIdentity.type, (.userIdentity.arn // "-"), .sourceIPAddress] | @tsv' \
  all_events.json | sort
```

⚠ Attackers frequently disable logging **after** establishing persistence. Two consequences: check for an event gap after `StopLogging` — anything in it is invisible and needs another source; and the order itself is evidence, since persistence created before the blackout is fully documented.

---

### BEC / invoice fraud

**The function that builds the invoice:**

```
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress,
       requestParameters.functionName, requestParameters.environment
| filter eventSource = "lambda.amazonaws.com"
| filter eventName in ["UpdateFunctionCode","UpdateFunctionConfiguration","CreateFunction","AddPermission"]
| sort eventTime asc
```

`UpdateFunctionConfiguration` — changing an env var holding payment details alters every invoice with no code change and no file artifact.

**Sending channel:** `eventSource = "ses.amazonaws.com"` → `VerifyEmailIdentity`, `VerifyDomainIdentity`, `CreateReceiptRule`, `UpdateReceiptRule` (inbound mail redirected — how the victim's reply is intercepted), `SendEmail`/`SendRawEmail` from an unexpected principal.

**Stored artifacts:** `eventSource = "s3.amazonaws.com"` → `PutObject`, `GetObject`, `DeleteObject`, `PutBucketPolicy`, `PutBucketAcl`.

**Application logs** (`/aws/lambda/<Fn>`):

```
fields @timestamp, @message
| filter @message like /(?i)(iban|account|routing|swift|invoice|bank)/
| sort @timestamp asc
```

**Finding the fraudulent message:** establish the normal shape first, then invert. Rarity is the signal — a fraudulent invoice is sent once, routine notifications repeat.

```
parse @message '"to": "*"' as recipient
| stats count(*) as emails by recipient
| sort emails asc

fields @timestamp, @message
| filter @message not like "@<INTERNAL_DOMAIN>\"}"
| sort @timestamp asc
```

Look for lookalike domains in recipient and body — TLD swap (`.live` for `.com`), plausible compound (`<brand>pay.com`). Cross-reference send time against config changes.

---

### Indicator → campaign attribution

Once you hold concrete artifacts, attribution is an OSINT search, not a deduction. Typosquatted domains are the strongest search terms — unique strings, indexed directly by threat intel.

1. Search each attacker domain verbatim, in quotes, including defanged (`example[.]com`)
2. Search the tool combination as a phrase
3. Search the TTP set by ATT&CK technique IDs — four or five in combination narrows sharply
4. [ATT&CK Campaigns](https://attack.mitre.org/campaigns/) index and vendor research blogs

---

### GuardDuty & VPC Flow Logs

GuardDuty finding names: `ThreatPurpose:ResourceTypeAffected/ThreatFamilyName.DetectionMechanism`. Findings are leads pointing at a time window and a principal — prove it in CloudTrail.

VPC Flow Logs: src/dst IP and port, protocol, packet and byte counts, `ACCEPT`/`REJECT`. Use for large outbound transfers (sort by bytes), unexpected destinations, and to confirm connections CloudTrail can't see. No payload.
