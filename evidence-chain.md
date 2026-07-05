# spectre — Evidence Integrity & Chain of Custody

The [README](README.md) §3.5 shows the commands that produce the SHA-256 evidence manifest. This
document explains the *reasoning* behind them: why evidence integrity is a first-class deliverable of a
penetration test, what chain of custody means when the evidence is digital, exactly how this engagement
implements it, and how any reviewer can verify the evidence independently. The point is to demonstrate
that the integrity discipline here is forensic, not decorative.

## 1. Why evidence integrity matters in a penetration test

A penetration test produces two things: access, and **a record that the access happened the way the
report says it did.** The second is what a client, an auditor, or — in the worst case — a court
actually relies on. If a finding cannot be tied to tamper-evident evidence, then:

- A client cannot distinguish a real finding from an assertion, and cannot prioritise remediation
  with confidence.
- A disputed result ("that listing was never exposed", "you modified the output") has no defence.
- The test cannot be reproduced or audited after the fact.

Treating evidence integrity as an afterthought is the difference between a report that *claims* and a
report that *proves*. The same discipline a DFIR analyst applies to incident artefacts applies here —
acquisition, integrity sealing, and verifiable custody.

## 2. Three properties, kept distinct

Loose talk conflates these; a credible evidence design keeps them separate.

| Property | Question it answers | How this engagement provides it |
|----------|--------------------|---------------------------------|
| **Integrity** | Has the artefact changed since acquisition? | SHA-256 of every artefact, captured at acquisition |
| **Authenticity** | Did it come from where it claims? | Dual session logs tie each artefact to the command and host that produced it |
| **Custody** | Who held it, and was the path trusted? | Acquisition → hash → transfer over authenticated SSH → archive, each step recorded |

SHA-256 gives integrity. It does **not**, by itself, give authenticity or custody — those come from the
session logs and the transfer discipline. Conflating "I hashed it" with "I proved chain of custody" is
the exact overclaim this document avoids.

## 3. Chain of custody, applied to digital evidence

Physical chain of custody asks: from seizure to courtroom, can every person who held the evidence, and
every transfer, be accounted for, with no unexplained gap in which tampering could have occurred? The
digital equivalent in this engagement:

1. **Acquisition.** Every external action is recorded to `external_session.log`; concurrent internal
   enumeration to `internal_session.log`. Both are timestamped and append-only during the engagement,
   so each artefact (a scan output, a saved response, a screenshot) is anchored to *when* it was
   produced and *by which command*.
2. **Integrity sealing at acquisition.** At the point of capture, every artefact is hashed into a
   single manifest (`evidence.sha256`). The hash is taken **before** the evidence leaves the
   acquisition host, so the sealed value reflects the artefact as produced, not as later handled.
3. **Trusted transfer.** Artefacts move over SSH key-pair authentication (passphrase-protected private
   keys, restricted sudo). The channel that carries the evidence is itself authenticated and encrypted,
   so the custody path is trusted — the hashes verify the bytes, and the transport proves the bytes
   travelled a controlled route.
4. **Archive sealing.** The packaged set (`apache_pentest.zip`, 24 files, 4.1 MiB) carries its own
   digest, so the bundle can be verified as a unit before it is even unpacked.

The "no unexplained gap" requirement maps to: hash-at-acquisition (no gap before sealing) + trusted
transfer (no gap in transit) + archive digest (no gap in storage).

## 4. The implementation — a reproducible manifest

The manifest is not a list of hashes printed into the report; it is **the verification instrument
itself**, designed so a third party can re-run it.

```bash
# At acquisition — one manifest over the whole evidence set
sha256sum external_session.log internal_session.log status.txt status_403.png \
          listing_root.html listing_root.png nmap/* gobuster.txt whatweb.txt \
          nikto.html linpeas_out.txt  > evidence.sha256

# At reporting / by any reviewer — re-verify nothing changed (must print "OK" per line)
sha256sum -c evidence.sha256

# Archive-level digest — verify the bundle as a unit before unpacking
sha256sum apache_pentest.zip > apache_pentest.zip.sha256
sha256sum -c apache_pentest.zip.sha256
```

Why this design rather than a hash table pasted into the report:

- **It is executable.** A reviewer runs `sha256sum -c evidence.sha256` and gets a per-line `OK`/`FAILED`
  verdict. A pasted table is a claim; a manifest is a test.
- **Tamper localises.** A single changed byte in any one artefact fails *that artefact's* line and no
  other, so the manifest pinpoints which item was altered — it is a per-artefact seal, not a
  whole-set checksum that only tells you *something* changed.
- **Order is preserved by the logs, not the manifest.** The manifest proves the bytes; the session logs
  prove the sequence and provenance. The two are complementary, which is why both are in the evidence
  set.

## 5. How a reviewer verifies independently

A recipient who trusts nothing about the tester can still establish integrity end-to-end:

1. Receive `apache_pentest.zip` + `apache_pentest.zip.sha256`. Run `sha256sum -c apache_pentest.zip.sha256`
   → confirms the bundle is intact before unpacking.
2. Unpack. Run `sha256sum -c evidence.sha256` in the evidence directory → every artefact returns `OK`,
   or the exact failing artefact is named.
3. Cross-read the session logs: each artefact in the manifest corresponds to a logged, timestamped
   command, so the reviewer can trace *how* each piece of evidence was produced.

No trust in the tester's word is required at any step — the artefacts attest to themselves.

## 6. Honest limits

- SHA-256 proves the bytes have not changed **since the manifest was written**; it cannot prove the
  manifest was written at acquisition rather than after editing. That assurance comes from the
  append-only, timestamped session logs and the engagement workflow — a process control, not a
  cryptographic one. (A future iteration could timestamp the manifest with an external trusted
  timestamping authority / transparency log to close that gap.)
- The hashes are not signed, so they provide integrity but not non-repudiation of the *tester's*
  identity; in a formal engagement a GPG signature over `evidence.sha256` would add that.

Stating these limits is the same discipline as the manifest itself: claim exactly what the mechanism
provides, and no more.

---

*Part of the [rootdrifter](https://github.com/rootdrifter) security portfolio. The offensive engagement
that produced this evidence is documented in the [README](README.md); the defensive read of the same
engagement is in §5, Detection Perspective.*
