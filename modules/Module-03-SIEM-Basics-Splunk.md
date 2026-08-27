---
title: "Module 3 — SIEM Basics / Splunk (Quick Reference)"
course: CCDL1
type: quick-reference
tags: [blueteam, soc, siem, splunk, spl, threat-hunting]
---

# Module 3 — SIEM Basics (Splunk)

Replace `<ANGLE_BRACKETS>` with your own values.

⚠ **The time range picker beats every filter you write.** *All time* on a busy index runs forever and returns nothing useful. In-query: `earliest=-24h latest=now` or `earliest="01/15/2024:10:00:00"`.

---

## Orientation — run these first

```
| eventcount summarize=false index=*             # indexes and sizes
index=* | stats count by index, sourcetype       # what lives where
index=<INDEX> | stats count by EventCode         # event types present
index=<INDEX> | stats dc(Computer)               # hosts reporting
| metadata type=sourcetypes index=<INDEX>        # first/last seen
index=<INDEX> EventCode=1 | fieldsummary | table field, count, distinct_count
```

## Search anatomy

```
index=<INDEX> sourcetype=<TYPE> EventCode=1 CommandLine="*powershell*"
| table _time, Computer, User, ParentImage, Image, CommandLine
| sort _time
```

Base search (narrow it) → transforming commands → presentation.

## Commands

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

## Identify user / host

```
index=<INDEX> "<HOSTNAME>" "<PROCESS_NAME>"
```

Then read the **Interesting Fields** sidebar: `User`, `UserName`, `Account_Name`, `SubjectUserName`.

## Phishing URLs

```
index=<INDEX> EventCode=1 ParentImage="*\\<PARENT>" CommandLine="*http*"
| stats count by ParentImage, CommandLine
```

Parents: `outlook.exe`, `winword.exe`, `excel.exe`, `chrome.exe`, `msedge.exe`.

```
index=<INDEX> "<HOSTNAME>" EventCode=1 (CommandLine="*http://*" OR CommandLine="*https://*")
| stats count by CommandLine
```

## Downloads (EventCode 11)

```
index=<INDEX> EventCode=11 (TargetFilename="*\\Downloads\\*" OR TargetFilename="*\\AppData\\Local\\Temp\\*")
| stats count by TargetFilename, Image

index=<INDEX> EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.vbs" OR TargetFilename="*.ps1"
    OR TargetFilename="*.bat" OR TargetFilename="*.hta" OR TargetFilename="*.iso" OR TargetFilename="*.lnk")
| stats count by TargetFilename
```

Filenames ending `:Zone.Identifier` = Mark of the Web → file came from outside the machine.

## Process lineage (EventCode 1)

```
index=<INDEX> EventCode=1 ParentImage="*\\<PARENT>"
| table _time, Computer, User, ParentImage, Image, CommandLine
| sort _time
```

Chain further: take `ProcessGuid`, search as `ParentProcessGuid` in later events.
⚠ GUIDs are unique; PIDs are recycled.

## Execution from user-writable paths

```
index=<INDEX> EventCode=1 (Image="*\\Users\\*\\Downloads\\*" OR Image="*\\AppData\\Local\\Temp\\*"
    OR Image="*\\Users\\Public\\*" OR Image="*\\ProgramData\\*")
| stats count by Image, CommandLine

index=<INDEX> EventCode=1 Image="C:\\Users\\<USERNAME>\\*"
```

⚠ Doubled backslashes — SPL treats `\` as an escape inside double quotes.

## LOLBins

```
index=<INDEX> EventCode=1 (Image="*\\schtasks.exe" OR Image="*\\icacls.exe" OR Image="*\\systeminfo.exe"
    OR Image="*\\whoami.exe" OR Image="*\\net.exe" OR Image="*\\net1.exe" OR Image="*\\reg.exe"
    OR Image="*\\wmic.exe" OR Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine
```

⚠ The binary is not the finding — all run legitimately. **Parent + arguments + timing** decide. `certutil -urlcache -f` is a downloader; `certutil` verifying a cert is a Tuesday.

## Script creation via echo

```
index=<INDEX> EventCode=1 CommandLine="*echo *" CommandLine="*>*"
    (CommandLine="*.bat*" OR CommandLine="*.ps1*" OR CommandLine="*.vbs*" OR CommandLine="*.js*")
| table _time, Computer, User, CommandLine | sort _time
```

Sort ascending, read top to bottom = the script source in write order.

## AD enumeration

```
index=<INDEX> EventCode=1 CommandLine="*objectcategory=*"

index=<INDEX> EventCode=1 (CommandLine="*AdFind*" OR CommandLine="*dsquery*" OR CommandLine="*SharpHound*"
    OR CommandLine="*BloodHound*" OR CommandLine="*Get-ADUser*" OR CommandLine="*Get-DomainUser*"
    OR CommandLine="*nltest*" OR CommandLine="*net group*")
| table _time, Computer, User, CommandLine
```

LDAP syntax in a command line (`objectcategory=`, `samaccountname=`, `memberof=`) is a signal on its own.

## Hashes

```
index=<INDEX> EventCode=1 Image="*\\<FILENAME>.exe" | table _time, Computer, User, Image, Hashes

... | rex field=Hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})" | table _time, Image, sha256
```

`Hashes` arrives concatenated (`SHA1=...,MD5=...,SHA256=...,IMPHASH=...`). Keep `IMPHASH` — it fingerprints the import table and matches recompiled variants where SHA-256 differs.

## Command interpreters / ClickFix

```
index=<INDEX> EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe" OR Image="*\\cmd.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine | sort _time
```

**The parent tells you the delivery method.** `explorer.exe` as parent = pasted into the Run dialog by a human. `winword.exe` = document macro.

Flags: `-w hidden`, `-nop`, `-ep bypass`, `-enc`, `IEX`, `Invoke-Expression`, `DownloadString`, `FromBase64String`, long Base64 blocks.

## C2 (EventCode 3)

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

## Compression & staging

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

## Exfiltration

```
index=<INDEX> EventCode=1 CommandLine="*ToBase64String*"
    (CommandLine="*Invoke-WebRequest*" OR CommandLine="*Invoke-RestMethod*" OR CommandLine="*UploadFile*"
    OR CommandLine="*Start-BitsTransfer*" OR CommandLine="*curl*")
| table _time, Computer, User, CommandLine
```

## Hardcoded paths not matching the host

```
index=<INDEX> EventCode=1 CommandLine="*C:\\Users\\*"
    NOT (CommandLine="*<LEGIT_USER>*" OR CommandLine="*Public*" OR CommandLine="*Default*")
| table _time, Computer, User, CommandLine
```

Build the exclusion list from users actually on the host.

## Lateral movement — 4624

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

## Remote services

```
index=<INDEX> Computer="<TARGET>" (EventCode=7045 OR EventCode=4697)
| table _time, Computer, ServiceName, ImagePath, ServiceType, StartType
```

Distrust in `ServiceName`: randomised strings, `PSEXESVC`, near-miss Windows names.
Distrust in `ImagePath`: `\\<IP>\ADMIN$\...`, `%SystemRoot%\Temp\`, or a command line embedded in the path (`cmd.exe /c ...`) = Impacket `smbexec`.

## Script Block Logging — 4104

```
index=<INDEX> EventCode=4104 "<KEYWORD>" | table _time, Computer, User, ScriptBlockText
```

Records deobfuscated source even when the `.ps1` is deleted. `ScriptBlockText` reveals filename-generation logic → search those in EventCode 11. Long scripts split across events: reassemble with `MessageNumber` / `MessageTotal`.

## Anti-forensics

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
