# CCDL1 Cheat Sheet

A lookup-optimised blue team reference covering the five core modules of the CyberDefenders **Certified CyberDefender Level 1** course.

Commands, field names, event IDs, query templates, and the caveats that change an answer — written to be searched with Ctrl+F while you work, not read start to finish.

## Scope

Organised by the module structure of the course. Module names are as published by CyberDefenders; the content is methodology and tooling drawn from vendor documentation and general blue team practice.

Covered:

| # | Module | Topics |
|---|---|---|
| 1 | Phishing & Email Security | Header and authentication analysis, maldoc triage, PDF and RTF analysis, OOXML internals |
| 2 | Network & Endpoint Essentials | Packet analysis, TLS metadata, SMB lateral movement, Sysmon and Windows event logs by attack phase |
| 3 | SIEM Basics (Splunk) | SPL fundamentals, threat hunting by attack phase, beacon detection, authentication analysis |
| 4 | Digital Forensics & Incident Response | Acquisition, memory forensics, filesystem timelines, registry, evidence of execution |
| 5 | Cloud Security | CloudTrail investigation, credential theft, IAM persistence, cloud BEC, attribution |

Not covered — the optional modules: **SOC & Threat Intelligence Foundations**, **Cloud Forensics & AI**, and **SIEM Basics (Sentinel)**.

## What this does not contain

**Methodology and tooling only.** No exam content and no lab solutions — no flags, no answers, no hashes, no filenames, no usernames, no IP addresses, and no artifacts from any specific scenario. Where a technique came out of hands-on practice, only the *pattern* is recorded, never the values.

> Published before I sat the CCDL1 exam. The commit history on this repository is the timestamp.

## Files

- **[CCDL1-Quick-Reference.md](CCDL1-Quick-Reference.md)** — everything in one file
- **[modules/](modules/)** — the same material split per module

Start from the phase of the intrusion you are investigating rather than from the tool. Caveats are marked ⚠ and sit next to the item they apply to, so searching for a tool or a field surfaces the trap along with the syntax.

## Contributing

Corrections and additions are welcome — open an issue or a pull request. Please do not submit lab or exam content.

## Disclaimer

Not affiliated with or endorsed by CyberDefenders. Provided as-is for educational use.
