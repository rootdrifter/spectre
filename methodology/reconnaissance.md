# Reconnaissance — Peer Apache Host

All external commands were recorded to `external_session.log`; internal enumeration ran
concurrently and was recorded to `internal_session.log`. Findings were cross-referenced against
the CIS Apache HTTP Server 2.4 Benchmark v1.4.0 to determine severity and CWE mapping.

## 1. Full-port SYN scan — nmap

```
nmap -sS -sV -O -p- $PEER_IP -oA apache_full
```

- `-sS` SYN scan, `-sV` service/version detection, `-O` OS detection, `-p-` all 65,535 ports.

**Result summary:**

| Port | State | Service | Version |
|------|-------|---------|---------|
| 22/tcp | open | ssh | OpenSSH 9.6p1 (Ubuntu) |
| 80/tcp | open | http | Apache httpd 2.4.58 ((Ubuntu)) |

All remaining ports returned closed (reset). No firewall restrictions were present — no
`iptables` rules were configured on the host, leaving it without explicit inbound filtering.
The server fingerprint resolved cleanly to `Apache/2.4.58`, matching the CIS benchmark release
and confirming version disclosure to unauthenticated scanners (CWE-200).

## 2. HTTP fingerprinting — WhatWeb (aggression level 3)

```
whatweb -a 3 http://$PEER_IP -v | tee whatweb.txt
```

**Result summary:**

```
Apache[2.4.58], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], Index-Of
```

The page title resolved as `Index of /`, indicating directory indexing was active at the web
root before any directed exploitation was attempted.

## 3. HTTP misconfiguration scan — Nikto v2.5.0

```
nikto -h http://$PEER_IP -o nikto.html
```

Approximately **8,102 requests** were issued, producing **15 findings**. Summary of the most
security-relevant items:

- `X-Frame-Options` response header absent (clickjacking exposure).
- `X-Content-Type-Options` response header absent (MIME-sniffing exposure).
- Directory indexing confirmed at `/` and equivalent path variants (`/.`, `//`, `///`, `/%2e/`).
- Allowed HTTP methods: `GET, POST, OPTIONS, HEAD` (via `OPTIONS`).
- No CGI directories discovered.

## 4. Directory enumeration — Gobuster (common.txt)

```
gobuster dir -u http://$PEER_IP/ -w /usr/share/wordlists/dirb/common.txt -o gobuster.txt
```

Roughly **4,615 paths** were tested. Notable responses:

| Path | Status | Size |
|------|--------|------|
| /.hta | 403 | 277 |
| /.htaccess | 403 | 277 |
| /.htpasswd | 403 | 277 |
| /server-status | 403 | 277 |

The `403` on `/server-status` confirmed `mod_status` was loaded but access-controlled — partial,
not complete, remediation.

## 5. Internal reconnaissance and module discovery

Authenticated internal checks confirmed listening ports `80`, `22`, and `53`, and enumerated the
active modules in the Apache build (version and module discovery informs later exploit avenues).
`autoindex_module` and `Options Indexes FollowSymLinks` were confirmed active in
`/etc/apache2/apache2.conf`.

## Reconnaissance outcome

The Apache host exposed service/version and OS information, an active directory listing, and
absent security headers — all derivable from unauthenticated scanning alone. These observations
defined the two exploitation attempts documented in [exploitation.md](exploitation.md).
