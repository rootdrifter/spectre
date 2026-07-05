# Tools Deep-Dive — Reference

Technical reference for the tooling used in SPECTRE (see
[../tools/tool-versions.md](../tools/tool-versions.md) for pinned versions). Explains what each
flag/option does, why the choices fit the scope, and what each tool misses.

---

## 1. `nmap -sS -sV -O -p-`

The full-port service scan used in [../methodology/reconnaissance.md](../methodology/reconnaissance.md).

| Flag | What it does | Notes / cost |
|------|--------------|--------------|
| `-sS` | **SYN ("half-open") scan.** Sends SYN, reads SYN/ACK (open) or RST (closed), then sends RST instead of completing the handshake. | Fast, relatively low-noise, **requires root** (raw sockets). Doesn't fully connect, so it less often hits application logging than a full connect scan. |
| `-sV` | **Service/version detection.** After finding open ports, probes them and matches banners/responses against the nmap-service-probes DB. | This is what produced `OpenSSH 9.6p1` and `Apache httpd 2.4.58 ((Ubuntu))`. Adds traffic and is more detectable. |
| `-O` | **OS detection.** TCP/IP stack fingerprinting (window sizes, options, sequence behaviour) matched against the OS DB. | Needs at least one open and one closed port for confidence; can be imprecise behind NAT/VMs. |
| `-p-` | **All 65,535 TCP ports.** Without it nmap scans only its ~1,000 most-common ports. | Catches services on non-standard high ports; much slower. |

`-oA <base>` (used as `apache_full`) writes all three output formats (`.nmap`, `.gnmap`, `.xml`)
for record-keeping and tool interchange.

### 1.1 Why this combination is the standard full service scan

It answers the four first questions of any engagement in one pass: **what ports are open
(`-p-`), what's running on them (`-sV`), and what OS (`-O`)**, using a fast, root-level technique
(`-sS`). For SPECTRE it confirmed only 22 and 80 open, no firewall filtering, and exact versions —
the basis for everything downstream.

### 1.2 What it misses

- **UDP services.** This is TCP-only; DNS/53, SNMP/161, etc. need `-sU` (slow). Internal enum
  separately confirmed 53 listening — a UDP scan would have caught it externally.
- **Filtered/stealthed ports.** A firewall dropping (not resetting) packets shows ports as
  `filtered`; SPECTRE's target had no filtering, but real targets often do.
- **Default timing.** Without `-T4`/`--min-rate`, a 65k-port scan is slow; conversely faster timing
  is noisier and can miss ports under packet loss.
- **App-layer depth.** `-sV` identifies the service, not its vulnerabilities or virtual hosts;
  NSE scripts (`-sC`/`--script`) or dedicated web tools are needed for that.
- **Detectability.** `-sV` + `-O` generate distinctive probes that an IDS readily flags — fine in
  an authorised lab, a consideration in an evasive engagement.

---

## 2. Gobuster vs alternatives

SPECTRE used `gobuster dir -u … -w /usr/share/wordlists/dirb/common.txt` (~4,615 paths).

| Tool | Language | Model | Strengths | Trade-offs |
|------|----------|-------|-----------|------------|
| **Gobuster** | Go | Concurrent, single-pass directory/DNS/vhost brute | Fast, simple, low-overhead, stable output; ideal for a bounded wordlist | No native recursion (single level per run); fewer fuzzing features |
| **ffuf** | Go | Generic fuzzer (`FUZZ` keyword anywhere) | Extremely flexible — paths, params, headers, vhosts; filtering/matching by size/words/regex; recursion | More options to get right; can be overkill for a simple dir sweep |
| **feroxbuster** | Rust | Recursive content discovery | **Recursive by default**, fast, auto-extracts links; great for deep trees | Recursion can explode request volume / noise |
| **dirb** | C | Classic recursive scanner | Battle-tested, recursive, built-in wordlists | Slow (lower concurrency), dated, noisier output |

### 2.1 Why Gobuster + `common.txt` fits this scope

- **Scope is small and bounded.** A single static host with no application backend doesn't justify
  recursive/parameter fuzzing. `common.txt` (~4.6k well-known paths) is the right breadth to surface
  `/.htaccess`, `/.htpasswd`, `/server-status`, etc. — which it did (all 403).
- **Speed + clean, parseable output** suit the version-pinned, reproducible methodology.
- **Lower noise** than recursive tools, consistent with the conservative rules of engagement.

A deeper assessment would escalate to ffuf/feroxbuster with larger lists (e.g. SecLists
`directory-list-2.3-medium`) and recursion — but that is a coverage/realism trade against noise and
time, not a correctness issue for this scope.

---

## 3. Nikto — what 15 findings mean, and its limits

SPECTRE ran Nikto v2.5.0 (~8,102 requests → 15 findings).

### 3.1 What Nikto is

A signature-based web-server scanner that checks for known dangerous files/CGIs, outdated server
versions, server misconfigurations, and missing/insecure headers from a large built-in test DB. It
is **fast to run, noisy, and broad but shallow**.

### 3.2 What the 15 findings represent

For a clean, static Apache host the findings are dominated by **configuration/information-disclosure
items**, not exploitable bugs — consistent with SPECTRE's report: missing `X-Frame-Options` and
`X-Content-Type-Options`, directory indexing, allowed methods via `OPTIONS`, version disclosure,
and path-normalisation variants (`/.`, `//`, `/%2e/`). These corroborate findings F1, F3, F4 rather
than adding new exploit avenues.

### 3.3 Known false-positive / noise categories

- **Path-normalisation duplicates.** Nikto often reports the same indexing/issue under many
  equivalent path encodings (`/.`, `//`, `///`, `/%2e/`) — one issue, many lines.
- **Generic "file/dir found" entries** that are benign or expected.
- **Version-based inferences** flagged as "outdated" from banner alone, without confirming the
  specific build is actually vulnerable (banner ≠ patch level on distros that backport fixes — e.g.
  Ubuntu's `2.4.58 (Ubuntu)` may carry backported security patches).
- **Method/header observations** reported as findings that are informational, not vulnerabilities.

Each Nikto hit should be **manually validated**; the count (15) is a starting list, not 15 confirmed
vulnerabilities.

### 3.4 What a more thorough web assessment would add

- **TLS analysis** (`testssl.sh`/`sslscan`) — explicitly noted missing in the report's limitations.
- **Authenticated/app-logic testing**, parameter fuzzing, and an intercepting proxy (Burp/ZAP) for
  injection, access-control, and business-logic flaws — none reachable by Nikto's signature model.
- **Manual verification** of every signature hit to strip false positives.

---

## 4. WhatWeb aggression levels

SPECTRE ran `whatweb -a 3` (aggression level 3).

| Level | Name | Behaviour | Detection risk |
|-------|------|-----------|----------------|
| **1** | **Stealthy** | One HTTP request per target; identifies tech only from that single response | Lowest — looks like one ordinary request |
| (2) | *(reserved/unused in practice)* | — | — |
| **3** | **Aggressive** | When a plugin *suspects* a technology from the stealthy pass, it makes a **few additional targeted requests** to confirm it | Moderate — extra requests, but only where a match is plausible |
| **4** | **Heavy** | Makes **many** requests, running all plugins against the target regardless of initial signals | Highest — most thorough, noisiest, most likely to be logged/blocked |

### 4.1 What level 3 actually did here

Level 3 starts from the single-request stealthy identification and then issues a small number of
**confirmatory** requests only for technologies it already suspects. That is why SPECTRE's WhatWeb
output is concise (`Apache[2.4.58]`, `HTTPServer[Ubuntu Linux]`, `Index-Of`) yet confident — it
confirmed the directory-index (`Index-Of`) and exact version without the request volume of level 4.

### 4.2 The detection-risk trade-off

- **Level 1** is appropriate when stealth matters most and approximate fingerprinting suffices.
- **Level 3** (chosen) balances **confident identification against noise** — it only escalates where
  a plugin has reason to, fitting an authorised but conservative engagement.
- **Level 4** maximises detection completeness at the cost of being loud and easily flagged — useful
  in a full assessment where stealth is not a constraint, overkill (and noisier) for confirming a
  single host's stack.

For SPECTRE, level 3 is the correct middle ground: enough to confirm version + index exposure,
without the blanket request storm of heavy mode.

---

## 5. Tool-choice summary

| Goal | Tool/flags chosen | Why appropriate for the scope |
|------|-------------------|-------------------------------|
| Port/service/OS discovery | `nmap -sS -sV -O -p-` | One-pass full-surface map; root SYN scan; exact versions |
| Tech fingerprinting | `whatweb -a 3` | Confident ID with moderate noise |
| Misconfig sweep | `nikto v2.5.0` | Fast broad config/header/version checks (validate manually) |
| Content discovery | `gobuster dir` + `common.txt` | Bounded, fast, low-noise for a single static host |
| Local priv-esc enum | `linpeas.sh` (scoped, halted) | Structured post-exploitation within ethical limits |

> Behaviours described (scan techniques, aggression levels, false-positive classes) reflect
> documented tool design. Where tool behaviour may have changed across versions, treat the pinned
> versions in tool-versions.md as authoritative and re-verify before reuse.
