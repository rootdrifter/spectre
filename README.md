# spectre

Grey-box penetration test of a peer-supplied Apache host, conducted against a
self-hardened PostgreSQL server. Full methodology documented: reconnaissance,
host enumeration, two exploitation attempts, SHA-256 evidence chain, and
countermeasures mapped to ISO/IEC 27002:2022 and CIS Apache HTTP Server 2.4
Benchmark v1.4.0.

---

## 1. Overview

This engagement documents both sides of a peer-exchange penetration test:
constructing and hardening a PostgreSQL 16 server to CIS Level 1 standard, then
conducting a structured assessment against a peer-operated Apache 2.4.58 host
running on Ubuntu 24.04.2 LTS.

A grey-box model was adopted — authenticated console access to the peer system
was available, but disruptive exploits were out of scope. The lab environment
comprised two VirtualBox guests (2 vCPUs, 2 GB RAM each) on an isolated
192.168.0.0/24 host-only subnet with bridged adapters for external reachability.
A Kali Linux workstation performed all external scanning and exploitation.

The engagement demonstrates that equivalent OS baselines produce markedly
different attack surfaces depending on configuration decisions: the
PostgreSQL server passed all CIS Level 1 controls and exposed no enumerable
attack surface; the Apache host returned exploitable directory indexing and
suppressed — but did not eliminate — server-status exposure.

---

## 2. Threat Model and Objectives

**Target:** Peer-operated Apache 2.4.58 host on Ubuntu 24.04.2 LTS  
**Scope:** Unauthenticated HTTP vectors only; no command injection, LFI/RFI, or
brute-force attempts  
**Rules of engagement:** Grey-box; no disruptive exploits; all actions logged and
SHA-256 verified

**Risk questions driving the assessment:**

- Does the Apache host expose service version and OS information to unauthenticated
  scanners?
- Is `mod_status` accessible without access controls?
- Is directory auto-indexing enabled, creating a path to credential or source
  disclosure?
- What is the privilege and service posture of the host OS?

**Defended asset:** Self-built PostgreSQL 16 server — constructed to demonstrate
that the same Ubuntu base can be hardened to a posture that survives the same
reconnaissance workflow without yielding enumerable findings.

---

## 3. Methodology

The engagement follows the Penetration Testing Execution Standard (PTES) phase model, scoped to
the rules of engagement above. Each PTES phase maps to a documented activity in this repository:

| PTES phase | Activity in this engagement | Reference |
|---|---|---|
| Pre-engagement interactions | Grey-box scope, rules of engagement, lab topology agreed with peer | [engagement-scope.md](methodology/engagement-scope.md) |
| Intelligence gathering | Full-port SYN scan, HTTP fingerprinting, directory enumeration | §3.2, [reconnaissance.md](methodology/reconnaissance.md) |
| Threat modelling | Risk questions and defended-asset definition (§2) | §2 |
| Vulnerability analysis | Findings cross-referenced to CWE, CIS Apache 2.4, OWASP | §4, [vulnerability-report.md](findings/vulnerability-report.md) |
| Exploitation | Two unauthenticated HTTP GET attempts (`/server-status`, web root) | §3.4, [exploitation.md](methodology/exploitation.md) |
| Post-exploitation | LinPEAS privilege/service enumeration (scoped, halted pre-token-harvest) | §3.3 |
| Reporting | Findings, severity, and ISO/IEC 27002-mapped countermeasures | §4–§5, [countermeasures.md](methodology/countermeasures.md) |

### 3.1 PostgreSQL Build and Baseline Hardening

PostgreSQL 16 was installed from the official PostgreSQL Global Development Group
repository. Hardening was scoped to CIS PostgreSQL 16 Benchmark v2.0.0 Level 1
controls.

**Configuration decisions:**

| Control | Implementation |
|---|---|
| Authentication | `pg_hba.conf`: `scram-sha-256` for all host connections |
| Network exposure | `listen_addresses = '*'` (for peer access); port 5432 loopback-only via UFW |
| Firewall | UFW default-deny inbound; only `22/tcp` permitted |
| Privilege | Least-privilege role created; default `postgres` superuser password invalidated |
| Logging | Followed CIS PostgreSQL 16 Benchmark v2.0.0 logging requirements |
| Monitoring | `auditd` and `fail2ban` deployed; logs confirmed baseline operation |

**Scope limitations acknowledged:** No encryption of data-at-rest and no
row-level security were enabled; both noted as out-of-scope and recommended
in post-assessment hardening guidance.

### 3.2 Reconnaissance Workflow — Peer Apache Host

All external commands were recorded to `external_session.log`. Internal
enumeration ran concurrently and was logged to `internal_session.log`.

**Full-port SYN scan:**
```
nmap -sS -sV -O -p- $PEER_IP -oA apache_full
```

**Directory enumeration:**
```
gobuster dir -u http://$PEER_IP/ -w /usr/share/wordlists/dirb/common.txt -o gobuster.txt
```

**HTTP fingerprinting:**
```
whatweb -a 3 http://$PEER_IP -v | tee whatweb.txt
nikto -h http://$PEER_IP -o nikto.html
```

Findings from Nikto and WhatWeb were cross-referenced against CIS Apache 2.4
Benchmark v1.4.0 controls to determine severity and CWE category mapping.

### 3.3 Host Enumeration — LinPEAS

`linpeas.sh` (PEASS-ng v0.2.0) was transferred to the Apache host and executed
with colour removal:

```
curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \
  -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh -a | tee ~/linpeas_out.txt
```

The scan was scoped to `/home/` and manually halted after the API-key phase to
avoid post-API token checks and file-scraping stages that would exceed ethical
testing boundaries. Sections completed before interruption: SUID/SGID, sudo
privileges, cron jobs, service audit, and writable-path checks.

### 3.4 Exploitation — Two Attempts

Both attempts used unauthenticated HTTP GET requests only. No command injection,
LFI/RFI, or credential attacks were conducted.

**Attempt 1 — `/server-status`:**  
Requested `/server-status?auto`. Target returned HTTP 403 Forbidden, confirming
`mod_status` was present but access-controlled — partial CIS compliance, not full
remediation. Evidence captured via `curl -s` to `status.txt` and screenshot.

**Attempt 2 — Directory auto-indexing (`/`):**  
Requested the web root. Target returned HTTP 200 with an auto-generated
`Index of /` page, confirming `autoindex_module` was active and
`Options Indexes` was set in `/etc/apache2/apache2.conf`. This constitutes
CWE-548 (Exposure of Information Through Directory Listing) and violates CIS
Apache 2.4 Benchmark control 2.5. Evidence captured via `curl -s` to
`listing_root.html`, verified with `grep -i 'Index of'`, and screenshot saved.

### 3.5 Evidence Handling

- External actions: `external_session.log`
- Internal enumeration: `internal_session.log`
- All artefacts SHA-256 hashed to confirm no post-acquisition modification
- File transfers via SSH key pairs (passphrase-protected private keys,
  restricted sudo access)
- Full evidence archive: `apache_pentest.zip` (24 files, 4.1 MiB)

---

## 4. Results and Findings

### 4.0 Findings Summary

All findings relate to the peer-operated Apache host. The self-hardened PostgreSQL server
returned no enumerable findings. Severity uses the OWASP qualitative likelihood × impact model.

| # | Vulnerability | Severity | CWE | Countermeasure |
|---|---------------|----------|-----|----------------|
| F1 | Directory auto-indexing enabled at web root (`Options Indexes`) | Medium-High | CWE-548 — Exposure of Information Through Directory Listing | `a2dismod autoindex`; `Options -Indexes` |
| F2 | Cleartext HTTP only; no TLS / HTTPS redirect | Medium | CWE-319 — Cleartext Transmission of Sensitive Information | HTTP→HTTPS 301 redirect; TLS virtual host |
| F3 | Security headers absent (`X-Frame-Options`, `X-Content-Type-Options`) | Medium | CWE-1021 — Improper Restriction of Rendered UI Layers; CWE-693 — Protection Mechanism Failure | `Header always set` X-Frame-Options DENY, X-Content-Type-Options nosniff, X-XSS-Protection |
| F4 | Service version and OS disclosure (`Apache/2.4.58 (Ubuntu)`) | Low | CWE-200 — Exposure of Sensitive Information to an Unauthorised Actor | `ServerTokens Prod`; `ServerSignature Off` |
| F5 | `mod_status` loaded (403 on `/server-status` confirms module present) | Low | CWE-200 — Exposure of Sensitive Information to an Unauthorised Actor | `Require ip 127.0.0.1` on `/server-status`; remove `mod_status` if unused |
| F6 | Host user in `sudo` group with unrestricted command execution | Medium | CWE-250 — Execution with Unnecessary Privileges | Remove from `sudo`; enforce least privilege; key-only SSH |
| F7 | Unnecessary services running (`snapd`, `ModemManager`) | Low | No single precise CWE — excessive attack surface; CIS minimisation control | Disable services not required by the web stack |

### 4.1 PostgreSQL Server — Baseline Posture

- Port scan: only `22/tcp` reachable externally; `4096/tcp` loopback-bound
- UFW logs: no dropped packets toward database
- All CIS PostgreSQL 16 Benchmark v2.0.0 Level 1 controls satisfied
- LinPEAS: no world-writable data directories, no escalation paths identified
- `pg_hba.conf`, `postgresql.conf`, and UFW status audit confirmed loopback-only
  client access

### 4.2 Apache Host — Network Footprint

**Nmap** (`-sS -sV -O -p-`):

| Port | State | Service | Version |
|---|---|---|---|
| 22/tcp | open | ssh | OpenSSH 9.6p1 Ubuntu |
| 80/tcp | open | http | Apache httpd 2.4.58 |

No firewall restrictions; all 65533 remaining ports closed (reset). Server
fingerprint resolved cleanly to `Apache/2.4.58` with no suppression.

**WhatWeb** (aggression level 3) output:
```
Apache[2.4.58], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], Index-Of
```
Title resolved as `Index of /`, confirming directory indexing active at the
web root.

**Gobuster** (`common.txt` wordlist, 4615 paths tested):

| Path | Status | Size |
|---|---|---|
| /.hta | 403 | 277 |
| /.htaccess | 403 | 277 |
| /.htpasswd | 403 | 277 |
| /server-status | 403 | 277 |

**Nikto** v2.5.0 (8102 requests, 15 findings):

- `X-Frame-Options` header absent
- `X-Content-Type-Options` header absent
- Directory indexing confirmed at `/`, `/.`, `//`, `///`, `/%2e/`
- `OPTIONS` method: GET, POST, OPTIONS, HEAD permitted
- No CGI directories found

**LinPEAS** (pre-API-key scope):

- Host user confirmed member of the `sudo` group with unrestricted command execution
- No iptables rules configured
- Unnecessary services running: `snapd`, `ModemManager` — neither required by the
  web stack, indicating excessive system surface area
- `autoindex_module` and `Options Indexes FollowSymLinks` confirmed active in
  `/etc/apache2/apache2.conf`

### 4.3 Exploit Attempt 1 — `/server-status` (HTTP 403)

`mod_status` returned HTTP 403 Forbidden. The endpoint was access-controlled,
satisfying OWASP information-disclosure guidance. However, the 403 response
itself confirmed the module was loaded — full remediation would require
either removing `mod_status` or suppressing the status code via firewall.
Evidence: `status.txt`, `status_403.png`.

### 4.4 Exploit Attempt 2 — Directory Auto-Indexing (HTTP 200)

Web-root request returned an auto-generated directory listing. Although empty
at time of test, the configuration exposes any future files — backup archives,
application source, PHP credential strings — to unauthenticated enumeration,
directly enabling SQL injection reconnaissance.

**Finding:** CWE-548 — Exposure of Information Through Directory Listing  
**CIS control violated:** Apache HTTP Server 2.4 Benchmark v1.4.0, control 2.5  
**OWASP risk rating:** Likelihood 3 (public HTTP) × Impact 4 (credential
leakage) / 5 = **2.4 — Medium-High**

Evidence: `listing_root.html`, `listing_root.png`.

### 4.5 Comparative Assessment

The PostgreSQL server and Apache host shared the same Ubuntu 24.04.2 LTS base
and virtualisation environment. The disparity in attack surface demonstrates
that secure defaults and minimal service footprint — not OS selection — determine
breach resistance. The PostgreSQL loopback binding and UFW rules produced a
posture that returned no enumerable findings; the Apache host yielded version
disclosure, directory indexing, and absent security headers from the same
reconnaissance workflow.

### 4.6 Scope Limitations

| Limitation | Source | Security Implication |
|---|---|---|
| LinPEAS halted pre-regex | Local enumeration | Potential missed secrets in archives >1 MB |
| No active backend or dynamic content | Application layer | Limited vulnerability chaining |
| TLS evaluated via self-signed certificate | TLS config | No OCSP/revocation chain validation |
| No `testssl.sh` / `sslscan` | TLS tooling | Incomplete cipher strength and forward secrecy checks |

---

## 5. Countermeasures and Recommendations

All countermeasures mapped to ISO/IEC 27002:2022 and CIS Apache HTTP Server 2.4
Benchmark v1.4.0.

### Immediate Fixes

**Disable directory auto-indexing:**
```
sudo a2dismod autoindex
sudo systemctl restart apache2
```

**Restrict `/server-status` to localhost** (`/etc/apache2/conf-available/status-local.conf`):
```apache
<Location /server-status>
    SetHandler server-status
    Require ip 127.0.0.1
</Location>
```

**Privilege reduction:** Remove host user from the `sudo` group; enforce
least-privilege (ISO/IEC 27002 control). Disable password-based SSH logins;
implement passphrase-protected public-private key pairs.

### Web Server Hardening

**HTTP → HTTPS redirect** (`/etc/apache2/sites-available/000-default.conf`):
```apache
RewriteEngine On
RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,R=301]
```

**HTTPS virtual host with security headers** (`000-default-ssl.conf`):
```apache
<VirtualHost *:443>
    SSLEngine on
    Options -Indexes
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
</VirtualHost>
```

**Server token suppression:** `ServerTokens Prod` and `ServerSignature Off`
to reduce version disclosure during reconnaissance. Set `LogLevel` to `info`.

### System-Level Controls

- UFW: default-deny inbound; permit `22/tcp` and `443/tcp` only
- `fail2ban`: 3-strike SSH ban policy
- `auditd`: capture access violations and service modifications
- Disable `snapd` and `ModemManager`; neither required by the web stack

### Ongoing Monitoring

- Monthly Nmap and Nikto scans scheduled via cron
- LinPEAS fast-mode scan after each kernel update
- `unattended-upgrades` enabled for automatic patching
- Future iteration: SIEM integration (Wazuh or Graylog) for proactive alerting

---

## 6. Skills Demonstrated

| Domain | Evidence |
|---|---|
| Network reconnaissance | Full-port SYN scan with `nmap -sS -sV -O -p-`; service and OS fingerprinting |
| Web application enumeration | Directory brute-force with Gobuster; HTTP fingerprinting with WhatWeb and Nikto |
| Host privilege and service analysis | LinPEAS privilege escalation enumeration; sudo, SUID/SGID, cron, and service audit |
| Vulnerability identification | CWE-548 directory listing; mod_status exposure; absent security headers |
| Risk quantification | OWASP qualitative likelihood × impact risk scoring |
| Database hardening | PostgreSQL 16 built to CIS Level 1 Benchmark v2.0.0; scram-sha-256 auth; UFW isolation |
| Web server hardening | CIS Apache 2.4 Benchmark v1.4.0 controls; TLS enforcement; security header deployment |
| Evidence integrity | SHA-256 artefact chain; dual session logs; structured evidence archive |
| Control framework mapping | Findings and countermeasures mapped to ISO/IEC 27002:2022 and CIS benchmarks |

---

*Part of the [rootdrifter](https://github.com/rootdrifter) security portfolio — built and maintained by a security-cleared candidate. UK-issued clearance held now, not pending vetting: deployable to cleared work from day one.*
