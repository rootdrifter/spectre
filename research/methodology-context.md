# Methodology Context — Reference

Places the SPECTRE engagement methodology in the context of recognised standards: PTES, the NCSC
CHECK scheme, forensic evidence-handling (ACPO), and the LinPEAS/PEASS-ng toolchain. Reference
document supporting [../methodology/engagement-scope.md](../methodology/engagement-scope.md).

---

## 1. PTES — Penetration Testing Execution Standard

PTES defines seven phases. The mapping to SPECTRE:

| # | PTES phase | What it covers | SPECTRE mapping |
|---|------------|----------------|-----------------|
| 1 | **Pre-engagement Interactions** | Scope, rules of engagement, authorisation, timelines | Peer-exchange agreement; in-scope = unauth HTTP GET + authenticated local enum; out-of-scope = injection/LFI/RFI/brute-force/destructive actions; console access permitted |
| 2 | **Intelligence Gathering** | Recon, footprinting, enumeration | nmap `-sS -sV -O -p-`; WhatWeb fingerprinting; Nikto; Gobuster directory enumeration; internal listening-port/module discovery |
| 3 | **Threat Modeling** | Identify assets, threats, attack avenues | Identifying directory listing, version/OS disclosure, missing headers, and a loaded `mod_status` as the candidate avenues |
| 4 | **Vulnerability Analysis** | Validate weaknesses, map to CWE/benchmarks | Mapping findings to CWE-548/200/319/1021/693/250 and CIS Apache 2.4 v1.4.0; OWASP qualitative severity |
| 5 | **Exploitation** | Gain access / confirm exploitability | Two unauthenticated HTTP GET attempts: `/server-status` (403) and web-root auto-index (200, success) |
| 6 | **Post-Exploitation** | Determine impact, escalation, value of access | Authenticated LinPEAS enumeration → over-privileged `sudo`, plaintext cron, unnecessary services; **deliberately halted** before token-harvesting |
| 7 | **Reporting** | Findings, risk, remediation, evidence | vulnerability-report.md + countermeasures.md; SHA-256 evidence chain; ISO 27002 control mapping |

### 1.1 Where SPECTRE deviates from a full PTES engagement (honestly)

- **Exploitation was intentionally shallow** — GET-only, no weaponisation — by rules of engagement.
  This is a *scoping* choice, not a methodology gap, but it means PTES phase 5 was exercised at its
  most conservative.
- **Post-exploitation was capped** at the ethical boundary (no credential/token harvesting), so
  full impact (e.g. lateral movement, data exfiltration) was reasoned about rather than
  demonstrated.
- **Threat Modeling** was lightweight given a single-host lab; in a real PTES engagement this phase
  would model business impact and attacker personas more formally.

---

## 2. NCSC CHECK scheme — and how this lab prepares for it

### 2.1 What CHECK is and requires

**CHECK** is the NCSC (UK) scheme governing penetration testing of **HMG and public-sector systems
and critical national infrastructure**. Core characteristics:

- Testing must be performed by an **NCSC-approved CHECK company** ("Green Light" status) using
  qualified individuals: **CHECK Team Member (CTM)** and **CHECK Team Leader (CTL)**.
- Individual qualification is evidenced through NCSC-recognised certification bodies — **CREST**,
  **The Cyber Scheme**, and **TigerScheme** — whose practical exams gate CTM/CTL status. *Verify the
  current recognised bodies/exam names before citing.*
- **Security clearance** is normally required because CHECK work touches government systems — which
  is directly relevant to the portfolio's clearance differentiator.
- Strong emphasis on **methodology rigour, scoping/authorisation, evidence handling, and reporting
  quality** — not just finding bugs.

### 2.2 How SPECTRE prepares for CHECK-standard work

- **Rules of engagement and authorisation** are explicit and respected (in/out of scope, no
  destructive actions) — CHECK-grade discipline.
- **Repeatable, version-pinned methodology** (tool-versions.md) and **standards mapping** (CIS, ISO
  27002, OWASP, NIST SP 800-41/-53) mirror CHECK's expectation of structured, defensible findings.
- **Evidence integrity** via SHA-256 hashing and separate session logs (§3) reflects the
  audit-trail rigour CHECK assessors expect.
- **Ethical restraint** (halting LinPEAS before token harvesting) demonstrates the judgement CHECK
  assessors look for.

What would still be needed to reach CHECK *standard* in practice: a formal qualification (CTM via
an approved body), work under a Green Light company, and engagement against authorised in-scope
government systems. SPECTRE is a credible **portfolio precursor**, not a substitute for
certification.

---

## 3. Evidence handling — SHA-256 chain vs ACPO principles

SPECTRE hashed every artefact and log with SHA-256 and verified with `sha256sum -c`. How that
relates to forensic-grade handling:

### 3.1 The ACPO Good Practice Guide principles

The ACPO (now NPCC) Good Practice Guide for Digital Evidence sets four principles:

1. **No action should change data** held on a device/media that may later be relied upon in court.
2. Where access to original data is necessary, the person must be **competent** and able to explain
   the implications of their actions.
3. An **audit trail** (or record) of all processes should be created and preserved; an independent
   party should be able to repeat them and reach the same result.
4. The case lead has **overall responsibility** for ensuring the law and these principles are
   followed.

### 3.2 How SPECTRE's SHA-256 approach maps (and where it differs)

| ACPO principle | SPECTRE practice | Gap vs full forensics |
|----------------|------------------|-----------------------|
| 1 — Do not alter data | Artefacts captured to file via `curl -s`, then hashed; `sha256sum -c` proves no post-acquisition change | A pentest *interacts with* the live target (it is not a read-only image), so "no change to the system" does not apply the way it does to seized media — the integrity guarantee is over the **collected artefacts**, not the target |
| 2 — Competence | Documented, deliberate methodology and tool versions | No formal forensic accreditation claimed |
| 3 — Audit trail / repeatability | Separate `external_session.log` / `internal_session.log`; version-pinned tools; hashed evidence enables independent verification | No write-blocker / cryptographic timestamping / signed custody form |
| 4 — Responsibility | Single-tester lab; clear scope | No multi-party custody transfer chain |

**Key honest distinction:** SHA-256 hashing here provides **integrity verification of collected
evidence** (it proves an artefact wasn't modified after capture). A full forensic **chain of
custody** additionally tracks *who held what, when, and how it was transferred*, ideally with
tamper-evident storage and trusted timestamps. SPECTRE's approach is appropriate and rigorous for a
pentest report; it should not be overstated as courtroom-grade forensic custody. Adding a signed,
timestamped custody log would close most of the gap.

---

## 4. LinPEAS / PEASS-ng in context

### 4.1 What PEASS-ng (LinPEAS) actually checks

LinPEAS (part of **PEASS-ng** — Privilege Escalation Awesome Scripts Suite, by Carlos Polop)
enumerates local privilege-escalation vectors and sensitive exposure on Linux. Categories include:

- **System info & kernel** — version, distro, potential kernel-exploit indicators.
- **SUID/SGID binaries and capabilities** — candidates for escalation (e.g. GTFOBins matches).
- **`sudo` configuration** — NOPASSWD entries, dangerous allowed binaries, version (sudo CVE
  indicators), group membership.
- **Cron jobs / timers** — writable scripts, wildcard injection, PATH abuse.
- **Writable files/paths** — world-writable files in sensitive locations, writable service units.
- **Services & sockets** — running services, exposed sockets, internal listeners.
- **Network** — listening ports, interfaces.
- **Credential / secret hunting** — config files, history files, and a **regex sweep for API keys,
  tokens, private keys, and passwords** across the filesystem ("the API-key phase").

SPECTRE completed SUID/SGID, sudo, cron, service audit, and writable-path checks — yielding the
over-privileged `sudo` account (F6) and unnecessary services (F7) — then **halted**.

### 4.2 Why halting before the API-key phase was the correct ethical decision

- The credential/secret regex sweep would **scrape secrets** (API keys, tokens, private keys,
  password strings) from across the host — material **out of scope** for the agreed engagement and
  belonging to the peer.
- Collecting such secrets, even incidentally, would breach the rules of engagement, create a data
  custody/handling liability, and exceed the authorised testing boundary.
- Stopping at the boundary and **marking the halt point in the output** demonstrates exactly the
  scope-discipline a professional (and CHECK-grade) engagement requires.

### 4.3 What the full scan would have revealed

The completed phases already establish escalation potential (the `sudo` finding alone is a viable
local-privilege path on its own merits). A full scan would additionally have surfaced any **secrets
in files/history**, **kernel-exploit candidates**, and **deeper credential reuse** — i.e. the data
needed to *demonstrate* escalation and lateral movement rather than merely identify the vector. The
report's limitation note ("potential missed secrets in archives > 1 MB") correctly records this as a
known, accepted coverage gap rather than a clean bill of health.

---

## 5. Open items / to verify

- [ ] Current NCSC-recognised CHECK certification bodies/exam names (CREST / Cyber Scheme /
      TigerScheme) and CTM/CTL requirements (§2.1).
- [ ] Exact ACPO/NPCC guide title and current revision (§3.1).
- [ ] Whether to add a signed, timestamped custody log to close the forensic-custody gap (§3.2).

> No certification requirement, advisory, or version is asserted here without verification.
