# Tool Versions

Exact tool and target versions used in this engagement. These are the versions confirmed in the
source engagement documentation; they are recorded here so the methodology is reproducible and so
findings can be tied to a specific tooling baseline.

## Attacker tooling (Kali Linux workstation)

| Tool | Version | Role in engagement |
|------|---------|--------------------|
| nmap | 7.95 | Full-port SYN scan (`-sS -sV -O -p-`); service/OS fingerprinting |
| Gobuster | 3.6 | Directory enumeration against the web root (`common.txt`, 4,615 paths) |
| Nikto | 2.5.0 | HTTP misconfiguration scan (~8,102 requests, 15 findings) |
| WhatWeb | (aggression level 3) | HTTP fingerprinting and technology identification |
| LinPEAS (PEASS-ng) | 0.2.0 | Authenticated local privilege/service enumeration (scoped, halted pre-token-harvest) |

> WhatWeb was run at aggression level 3 (`-a 3`); the source documentation records the aggression
> level rather than a pinned package version. All other attacker tools are pinned to the exact
> versions confirmed in the engagement record.

## Target / defended-asset versions

| Component | Version | Notes |
|-----------|---------|-------|
| Apache HTTP Server (target) | 2.4.58 | Running on Ubuntu 24.04.2 LTS; fingerprint `Apache/2.4.58 (Ubuntu)` |
| OpenSSH (target) | 9.6p1 (Ubuntu) | Port 22/tcp, observed during the SYN scan |
| PostgreSQL (defended asset) | 16 | Built to CIS PostgreSQL 16 Benchmark v2.0.0 Level 1 |
| Ubuntu (both guests) | 24.04.2 LTS | Identical base for both target and defended asset |

## Benchmark and framework versions

| Framework | Version | Use |
|-----------|---------|-----|
| CIS Apache HTTP Server 2.4 Benchmark | v1.4.0 | Apache finding severity and remediation mapping |
| CIS PostgreSQL 16 Benchmark | v2.0.0 | PostgreSQL Level 1 hardening baseline |
| ISO/IEC 27002 | 2022 | Control mapping for findings and countermeasures |
| OWASP | Risk Rating Methodology (qualitative likelihood × impact) | Severity scoring |
| MITRE CWE | current | Weakness classification (e.g. CWE-548, CWE-200) |

## Reproducibility note

Versions above are the confirmed engagement baseline. Re-running the workflow against a different
Apache point release, or with newer Nikto/Gobuster signature sets, may surface additional findings;
the severity model and control mappings in [../findings/vulnerability-report.md](../findings/vulnerability-report.md)
remain applicable regardless of minor tool-version drift.
