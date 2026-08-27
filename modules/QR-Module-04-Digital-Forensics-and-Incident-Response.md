---
title: "Module 4 — DFIR (Quick Reference)"
course: CCDL1
type: quick-reference
tags: [blueteam, dfir, forensics, volatility, registry, eztools, autopsy]
---

# Module 4 — Digital Forensics and Incident Response

⚠ **Order of volatility:** registers/cache → **RAM** → network state and processes → disk → remote logs → archived media. Imaging the disk before memory destroys the most valuable evidence. Hash on acquisition and after transfer. Work on copies, mounted read-only.

---

## Acquisition

| Goal | Tool |
|---|---|
| Full disk image | FTK Imager, dd, dc3dd, Guymager |
| Memory capture | WinPmem, DumpIt, FTK Imager (Capture Memory), Magnet RAM Capture |
| Targeted collection | **KAPE** — `Targets` = what to collect, `Modules` = what to parse |
| Mount / browse | FTK Imager, Arsenal Image Mounter |
| Full case | Autopsy, Velociraptor |

`!SANS_Triage` target = hives, event logs, `$MFT`, Prefetch, browser data — small enough to move over the network.

---

## Memory — Volatility 3

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

## EZ Tools

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

## Evidence of execution — what each artifact proves

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

## Filesystem timeline

- `$MFT` gives **MACB** from both `$STANDARD_INFORMATION` and `$FILE_NAME`. Comparing the two detects **timestomping** — attackers alter `$SI` (which most tools display) while `$FN` keeps the truth
- `$J` (USN Journal) records creation, deletion and rename with reasons — catches a tool dropped, used and deleted in one minute
- Sub-second precision of exactly `.0000000` = timestomping indicator

---

## Registry — user hives

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

## Registry — system hives (`C:\Windows\System32\config\`)

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

## Tracing a downloaded document

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

## Malicious scheduled tasks

| Level | Source | Detail |
|---|---|---|
| 1 | `Security.evtx` | **4698** created, 4699 deleted, 4700/4701 enabled/disabled, 4702 updated. Body has full task XML; `ClientProcessId` = creating process |
| 2 | `Microsoft-Windows-TaskScheduler%4Operational.evtx` | 106 registered, 140 updated, 200 started, 201 completed. **Catches COM-API creation with no `schtasks.exe`** |
| 3 | Sysmon | ID 1 `schtasks /create /tn /tr`; ID 11 under `C:\Windows\System32\Tasks\` |
| 4 | Filesystem | `C:\Windows\System32\Tasks\` XML → `<Command>`, `<Arguments>`, `<Author>` |
| 5 | Registry | `SOFTWARE\...\Schedule\TaskCache\Tree\` and `\Tasks\` — survives XML deletion |

Level 1 requires the *Other Object Access Events* audit subcategory. Sort task files by creation time — anything inside the incident window among years-older files is the flag.

---

## WMI persistence

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

## Autopsy — identity & communications

- **`Communications`** button (top toolbar) — contact graph from PSTs and mail DBs
- `Data Artifacts > Email Messages` / `Contacts` — sender/recipient, often full names
- `Analysis Results > Keyword Hits > Email Addresses` → click a hit → **Text** tab. The words around the highlighted match usually hold the associated full name
- `Data Artifacts > Web Accounts`, or the source: `...\Chrome\User Data\Default\Web Data`, table `autofill`
