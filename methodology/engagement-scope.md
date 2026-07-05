# Engagement Scope and Lab Setup

## Engagement model

Grey-box penetration test conducted as a peer exchange. Authenticated console access to the
peer system was permitted; disruptive exploits were forbidden. The engagement combined two
roles in a single exercise:

- **Defence** — building and hardening a PostgreSQL 16 server to a CIS Level 1 baseline.
- **Offence** — assessing a peer-operated Apache host using unauthenticated HTTP vectors and
  authenticated local enumeration.

## Lab topology

| Component | Specification |
|-----------|---------------|
| Hypervisor | Oracle VirtualBox |
| PG-VM (defended asset) | Ubuntu 24, 2 native vCPUs, 2 GB RAM, PostgreSQL 16 |
| Apache-VM (target) | Ubuntu 24, 2 native vCPUs, 2 GB RAM, Apache 2.4.58 |
| Attacker workstation | Kali Linux — all external scanning and exploitation |
| Internal network | Isolated host-only subnet `192.168.0.0/24` |
| External reachability | Bridged adapters between guests for unrestricted scanning |

The host-only `/24` subnet eliminated collateral traffic and kept all testing contained. Bridged
adapters were used where external reachability between the guests was required; because of the
bridged-mode assignment, observed IP addresses differed from those originally supplied by the
peer.

## Snapshots and rollback

VirtualBox snapshots were captured at each significant stage to support iterative testing and
clean rollback:

1. Baseline setup
2. Post-enumeration
3. Post-hardening

## Access provisioning

SSH access was provisioned for separate accounts during different phases to simulate the
distinction between restricted (non-privileged) and administrative access. File transfers used
SSH key pairs with restricted `sudo` access. Account names from the source lab are intentionally
omitted; this document refers to the local account generically as *the host user*.

## Testing boundaries and ethical constraints

- **In scope:** unauthenticated HTTP GET vectors; authenticated local enumeration of the host.
- **Out of scope:** command injection, LFI/RFI, brute-force, and any destructive action.
- LinPEAS enumeration was deliberately scoped to `/home/<user>` and **manually halted after the
  API-key phase** to avoid file-scraping and token-harvesting stages that would exceed ethical
  testing boundaries.
- All commands were recorded to separate session logs; all artefacts were SHA-256 hashed for
  independent verification.

## Standards and frameworks

| Framework | Use in engagement |
|-----------|-------------------|
| ISO/IEC 27002:2022 | Control mapping for findings and countermeasures |
| CIS PostgreSQL 16 Benchmark v2.0.0 | PostgreSQL Level 1 hardening |
| CIS Apache HTTP Server 2.4 Benchmark v1.4.0 | Apache finding severity and remediation |
| OWASP (Top 10, qualitative risk rating) | Information-disclosure guidance and risk scoring |
| NIST SP 800-41 Rev. 1 / SP 800-53 Rev. 5 | Firewall policy and control selection |
| MITRE CWE | Weakness classification (e.g. CWE-548) |
