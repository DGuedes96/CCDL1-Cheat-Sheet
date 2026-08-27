---
title: "Module 1 — Phishing & Email Security (Quick Reference)"
course: CCDL1
type: quick-reference
tags: [blueteam, soc, phishing, email-security, maldoc]
---

# Module 1 — Phishing & Email Security

Order: hash → headers → body/URLs → carve attachments → identify type → internals → payload.

**Safety:** isolated VM, never open maldocs in Office, defang all IOCs (`hxxp`, `[.]`), public sandbox upload = public sample.

---

## Hashing & file identification

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

## Email headers

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

## Parsing `.eml` / extracting attachments

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

## Office documents (oletools)

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

## oledump (OLE streams)

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

## PDF

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

## OOXML internals & LNK

```bash
unzip <file.docx> -d extracted/
cat extracted/word/_rels/settings.xml.rels    # remote template injection
cat extracted/word/_rels/document.xml.rels    # external relationships
grep -r "http" extracted/
lnkinfo <file.lnk>                            # target, arguments, machine ID
```

⚠ **No macros ≠ clean.** Remote template injection uses zero VBA: the `.docx` is inert but its rels file fetches an external `.dotm` on open. Always read `word/_rels/`.

`.lnk` targets pointing at `powershell.exe` with encoded args = the whole chain in one field. On Windows use `LECmd` for MAC address and volume serial.
