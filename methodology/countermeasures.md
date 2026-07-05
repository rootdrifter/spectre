# Countermeasures and Recommendations

Countermeasures are prioritised by effectiveness and implementation effort, and mapped to
ISO/IEC 27002:2022 and the CIS Apache HTTP Server 2.4 Benchmark v1.4.0. Immediate fixes address
the discovered vulnerabilities; subsequent measures strengthen overall posture; ongoing
activities provide continuous assurance.

## 1. Immediate fixes

**Disable directory auto-indexing** (remediates CWE-548, Attempt 2):

```
sudo a2dismod autoindex
sudo systemctl restart apache2
```

Alternatively, set `Options -Indexes` in the relevant `<Directory>` block.

**Restrict `/server-status` to localhost** (`/etc/apache2/conf-available/status-local.conf`):

```apache
<Location /server-status>
    SetHandler server-status
    Require ip 127.0.0.1
</Location>
```

**Privilege reduction:** remove the host user from the `sudo` group and enforce least privilege
(ISO/IEC 27002). Disable password-based SSH logins and use passphrase-protected public/private
key pairs for password-less authentication.

## 2. Web-server hardening

**HTTP → HTTPS redirect** (`000-default.conf`):

```apache
RewriteEngine On
RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,R=301]
```

**HTTPS virtual host with security headers** (`000-default-ssl.conf`), using an intermediate TLS
profile:

```apache
<VirtualHost *:443>
    SSLEngine on
    Options -Indexes
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
</VirtualHost>
```

**Version-disclosure suppression:** set `ServerTokens Prod` and `ServerSignature Off`; review
headers with `curl -I`. Reduce Apache `LogLevel` to `info`.

## 3. System-level controls and firewalls

**UFW — default-deny inbound, permit only required services:**

```
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

**fail2ban — 3-strike SSH ban policy:** deployed for SSH brute-force mitigation; jail logs
confirmed passive monitoring readiness.

**auditd:** system auditing configured to capture access violations and service modifications.

**Service reduction:** disable services not required by the web stack (`snapd`, `ModemManager`)
to reduce attack surface.

## 4. Ongoing monitoring and verification

| Activity | Cadence / trigger |
|----------|-------------------|
| Nmap + Nikto scans via cron | Monthly |
| LinPEAS fast-mode scan | After each kernel update |
| `unattended-upgrades` | Continuous automatic patching |
| Audit log and fail2ban jail review | Ongoing |
| SIEM integration (Wazuh or Graylog) | Future iteration — proactive alerting |

## Control-mapping summary

| Countermeasure | Framework reference |
|----------------|---------------------|
| Disable autoindex / `Options -Indexes` | CIS Apache 2.4 control 2.5; CWE-548 |
| Restrict `/server-status` | OWASP information-disclosure guidance; CWE-200 |
| Security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection) | RFC 9110; CWE-1021 / CWE-693 |
| HTTPS enforcement / TLS intermediate profile | CIS Apache 2.4; CWE-319 |
| Remove `sudo` membership; key-only SSH | ISO/IEC 27002; CWE-250 |
| UFW default-deny; fail2ban; auditd | NIST SP 800-41 Rev. 1 / SP 800-53 Rev. 5 |
| Disable unneeded services | CIS minimisation guidance |
