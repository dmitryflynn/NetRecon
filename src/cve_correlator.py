"""
NetRecon - CVE Correlation Engine
Maps discovered service versions → NVD/CVE database for vulnerability matching.
Supports both offline signature matching and live NVD API queries.
"""

import re
import json
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from functools import lru_cache


# ─── Data Models ────────────────────────────────────────────────────────────────

@dataclass
class CVE:
    id: str
    description: str
    cvss_score: float
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW
    vector: str          # CVSS vector string
    published: str
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False

@dataclass
class VulnMatch:
    port: int
    service: str
    product: Optional[str]
    version: Optional[str]
    cves: list[CVE] = field(default_factory=list)
    risk_score: float = 0.0   # Weighted composite score
    notes: list[str] = field(default_factory=list)


# ─── Offline Signature Database ──────────────────────────────────────────────────
# Format: (product_regex, version_range_fn, CVE_id, cvss, severity, vector, description)
# Version range fn: lambda version_str → bool

OFFLINE_SIGNATURES = [
    # OpenSSH
    ("openssh", lambda v: _ver_lt(v, "8.5"),
     "CVE-2021-41617", 7.0, "HIGH",
     "AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
     "OpenSSH < 8.5 privilege escalation in sshd via PKCS#11 providers."),

    ("openssh", lambda v: _ver_lt(v, "7.7"),
     "CVE-2018-15473", 5.3, "MEDIUM",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "OpenSSH < 7.7 username enumeration via response timing difference."),

    ("openssh", lambda v: _ver_lt(v, "6.9"),
     "CVE-2015-5600", 8.5, "HIGH",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
     "OpenSSH < 6.9 keyboard-interactive unlimited authentication requests."),

    # Apache httpd
    ("apache", lambda v: _ver_in_range(v, "2.4.49", "2.4.50"),
     "CVE-2021-41773", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Apache 2.4.49 path traversal and RCE — actively exploited in the wild."),

    ("apache", lambda v: _ver_lt(v, "2.4.54"),
     "CVE-2022-22720", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Apache HTTP Server 2.4 request smuggling (HTTP/1.1)."),

    # nginx
    ("nginx", lambda v: _ver_lt(v, "1.22.0"),
     "CVE-2022-41741", 7.8, "HIGH",
     "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
     "nginx < 1.22.0 memory corruption in mp4 module."),

    # MySQL / MariaDB
    ("mysql", lambda v: _ver_lt(v, "8.0.28"),
     "CVE-2022-21417", 6.5, "MEDIUM",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
     "MySQL Server InnoDB DoS — authenticated remote exploitation."),

    ("mariadb", lambda v: _ver_lt(v, "10.6.8"),
     "CVE-2022-32091", 7.5, "HIGH",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
     "MariaDB < 10.6.8 use-after-free in WHERE conditions."),

    # Redis
    ("redis", lambda v: _ver_lt(v, "7.0.6"),
     "CVE-2022-35977", 5.5, "MEDIUM",
     "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
     "Redis < 7.0.6 integer overflow DoS in SETRANGE/SORT."),

    ("redis", lambda v: _ver_lt(v, "6.2.0"),
     "CVE-2021-32625", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Redis < 6.2.0 unauthenticated RCE via Lua scripting."),

    # vsftpd
    ("vsftpd", lambda v: v == "2.3.4",
     "CVE-2011-2523", 10.0, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "vsftpd 2.3.4 backdoor — remote root shell via smiley face trigger."),

    # ProFTPD
    ("proftpd", lambda v: _ver_lt(v, "1.3.7c"),
     "CVE-2021-46854", 9.1, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "ProFTPD < 1.3.7c out-of-bounds read via malformed UTF-8."),

    # Elasticsearch (unauthenticated by default)
    ("elasticsearch", lambda v: _ver_lt(v, "8.0.0"),
     "CVE-2021-22145", 6.5, "MEDIUM",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
     "Elasticsearch < 8.0.0 sensitive data exposure via error messages."),

    # MongoDB (unauthenticated by default before 2.6)
    ("mongodb", lambda v: _ver_lt(v, "2.6.0"),
     "CVE-2013-4650", 7.5, "HIGH",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "MongoDB < 2.6.0 unauthenticated access — no auth by default."),
]

# ─── Configuration / Missing-Auth Risk Flags ────────────────────────────────────

MISCONFIGURATION_CHECKS = {
    "redis":          ("CVE-2022-0543", "Redis exposed without authentication — RCE risk.", 9.8),
    "elasticsearch":  ("CVE-2020-7009", "Elasticsearch unauthenticated API exposure.", 9.8),
    "mongodb":        ("CVE-2015-7882", "MongoDB exposed without authentication.", 7.5),
    "memcached":      ("CVE-2018-1000115", "Memcached exposed to internet — DRDoS amplification.", 7.5),
    "docker":         ("CVE-2019-5736", "Docker daemon API exposed — container escape risk.", 8.6),
    "k8s-api":        ("CVE-2018-1002105", "Kubernetes API server exposed — privilege escalation.", 9.8),
    "vnc":            (None, "VNC exposed — brute-force and credential interception risk.", 7.3),
    "telnet":         (None, "Telnet in use — plaintext credential transmission.", 9.8),
    "smb":            ("CVE-2017-0144", "SMB exposed — EternalBlue/WannaCry exploit surface.", 9.8),
    "rdp":            ("CVE-2019-0708", "RDP exposed — BlueKeep pre-auth RCE risk.", 9.8),
    "ftp":            (None, "FTP in use — plaintext credential transmission.", 7.5),
}


# ─── Version Comparison Helpers ─────────────────────────────────────────────────

def _parse_ver(v: str) -> tuple:
    """Parse a version string into a comparable tuple."""
    parts = re.split(r"[.\-_]", v.strip())
    result = []
    for p in parts:
        # extract leading digits from parts like "1p1" → 1, "p1" → 0
        m = re.match(r"(\d+)", p)
        result.append(int(m.group(1)) if m else 0)
    return tuple(result)


def _ver_lt(v: str, threshold: str) -> bool:
    try:
        return _parse_ver(v) < _parse_ver(threshold)
    except Exception:
        return False


def _ver_in_range(v: str, low: str, high: str) -> bool:
    try:
        pv = _parse_ver(v)
        return _parse_ver(low) <= pv <= _parse_ver(high)
    except Exception:
        return False


# ─── NVD API Lookup (Live) ──────────────────────────────────────────────────────

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def query_nvd(keyword: str, max_results: int = 5) -> list[CVE]:
    """Query NIST NVD for CVEs matching a product/version keyword."""
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    })
    url = f"{NVD_API_BASE}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetRecon/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
    except Exception:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = c.get("id", "")
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        metrics = c.get("metrics", {})
        score, severity, vector = 0.0, "UNKNOWN", ""

        # Try CVSSv3.1 first, then v3.0, then v2.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                score = m.get("baseScore", 0.0)
                severity = m.get("baseSeverity", "UNKNOWN")
                vector = m.get("vectorString", "")
                break

        refs = [r["url"] for r in c.get("references", [])[:3]]
        published = c.get("published", "")[:10]

        cves.append(CVE(
            id=cve_id, description=desc[:300], cvss_score=score,
            severity=severity, vector=vector, published=published,
            references=refs
        ))

    return cves


# ─── Main Correlation Logic ──────────────────────────────────────────────────────

def correlate(port_results: list) -> list[VulnMatch]:
    """
    Given a list of PortResult objects, return VulnMatch entries for each
    open port with discovered vulnerabilities.
    """
    matches = []

    for pr in port_results:
        if pr.state != "open":
            continue

        service = pr.service or "unknown"
        product = pr.banner.product if pr.banner else None
        version = pr.banner.version if pr.banner else None

        match = VulnMatch(port=pr.port, service=service, product=product, version=version)

        # 1. Offline signature matching
        product_lower = (product or service).lower()
        if version:
            for (prod_pattern, ver_fn, cve_id, cvss, sev, vector, desc) in OFFLINE_SIGNATURES:
                if prod_pattern in product_lower:
                    try:
                        if ver_fn(version):
                            match.cves.append(CVE(
                                id=cve_id, description=desc, cvss_score=cvss,
                                severity=sev, vector=vector, published="",
                                exploit_available=(cvss >= 9.0)
                            ))
                    except Exception:
                        pass

        # 2. Misconfiguration / exposure checks
        if service in MISCONFIGURATION_CHECKS:
            cve_id, note, score = MISCONFIGURATION_CHECKS[service]
            match.notes.append(note)
            if cve_id:
                # Only add if not already in list
                if not any(c.id == cve_id for c in match.cves):
                    sev = "CRITICAL" if score >= 9.0 else ("HIGH" if score >= 7.0 else "MEDIUM")
                    match.cves.append(CVE(
                        id=cve_id, description=note, cvss_score=score,
                        severity=sev, vector="", published="",
                        exploit_available=(score >= 9.0)
                    ))

        # 3. Risk score = max CVSS × exposure factor
        if match.cves:
            max_cvss = max(c.cvss_score for c in match.cves)
            exploit_bonus = 1.2 if any(c.exploit_available for c in match.cves) else 1.0
            match.risk_score = round(min(max_cvss * exploit_bonus, 10.0), 2)

        if match.cves or match.notes:
            matches.append(match)

    return matches


def severity_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"

# ─── Extended CVE Signatures (appended) ──────────────────────────────────────
# These extend OFFLINE_SIGNATURES at runtime

EXTENDED_SIGNATURES = [
    # OpenSSH additional
    ("openssh", lambda v: _ver_lt(v, "9.3"),
     "CVE-2023-38408", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "OpenSSH < 9.3p2 ssh-agent RCE via malicious PKCS#11 provider — exploitable remotely if agent forwarding is enabled."),

    ("openssh", lambda v: _ver_lt(v, "8.4"),
     "CVE-2020-15778", 7.8, "HIGH",
     "AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
     "OpenSSH scp command injection via shell metacharacters in remote filenames."),

    # Apache additional
    ("apache", lambda v: _ver_in_range(v, "2.4.49", "2.4.49"),
     "CVE-2021-41773", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Apache 2.4.49 path traversal + RCE via ../ sequences. Massively exploited within 24h. Metasploit module available."),

    ("apache", lambda v: _ver_lt(v, "2.4.51"),
     "CVE-2021-40438", 9.0, "CRITICAL",
     "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "Apache mod_proxy SSRF via unix: scheme — routes requests to internal Unix domain sockets."),

    ("apache", lambda v: _ver_lt(v, "2.4.46"),
     "CVE-2020-11984", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Apache mod_proxy_uwsgi buffer overflow — unauthenticated RCE via crafted request."),

    # nginx additional
    ("nginx", lambda v: _ver_lt(v, "1.25.3"),
     "CVE-2023-44487", 7.5, "HIGH",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
     "HTTP/2 Rapid Reset Attack — send+cancel streams at high rate to exhaust nginx worker processes."),

    ("nginx", lambda v: _ver_lt(v, "1.20.1"),
     "CVE-2021-23017", 7.7, "HIGH",
     "AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:H",
     "nginx DNS resolver 1-byte heap overwrite via crafted DNS response."),

    # IIS
    ("iis", lambda v: True,
     "CVE-2022-21907", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "IIS HTTP Protocol Stack wormable RCE — pre-auth, enabled by default on Windows Server 2022/Win11."),

    ("iis", lambda v: _ver_lt(v, "7.5"),
     "CVE-2017-7269", 10.0, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "IIS 6.0 WebDAV buffer overflow — pre-auth RCE. Metasploit module available, widely exploited."),

    # PHP
    ("php", lambda v: _ver_lt(v, "8.1.0"),
     "CVE-2022-31626", 8.8, "HIGH",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
     "PHP < 8.1.0 password_verify() buffer overflow via very long password strings."),

    ("php", lambda v: _ver_lt(v, "7.4.0"),
     "CVE-2019-11043", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "PHP-FPM + nginx path_info buffer underflow — unauthenticated RCE. Exploitable with specific nginx config. PoC public."),

    ("php", lambda v: _ver_lt(v, "7.0.0"),
     "CVE-2016-7124", 7.5, "HIGH",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "PHP 5.x unserialize() invalid __wakeup() bypass — PHP object injection."),

    # WordPress (version-specific)
    ("wordpress", lambda v: _ver_lt(v, "6.4.2"),
     "CVE-2024-21726", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "WordPress < 6.4.2 PHP object injection in WP_HTML_Token — unauthenticated RCE in certain configurations."),

    ("wordpress", lambda v: _ver_lt(v, "5.8.3"),
     "CVE-2022-21663", 6.6, "MEDIUM",
     "AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
     "WordPress < 5.8.3 SQL injection in WP_Meta_Query — authenticated admin can extract db contents."),

    # Drupal
    ("drupal", lambda v: _ver_lt(v, "8.9.0"),
     "CVE-2018-7600", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Drupal 'Drupalgeddon2' — unauthenticated RCE via form API #access callbacks. Widely exploited, full Metasploit module."),

    ("drupal", lambda v: _ver_lt(v, "7.62"),
     "CVE-2019-6340", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Drupal REST API remote code execution via PHP object injection — unauthenticated with REST module enabled."),

    # Joomla
    ("joomla", lambda v: _ver_lt(v, "4.2.8"),
     "CVE-2023-23752", 5.3, "MEDIUM",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "Joomla < 4.2.8 improper access check — unauthenticated read of configuration.php via /api/index.php/v1/config/application?public=true."),

    # Tomcat
    ("tomcat", lambda v: _ver_lt(v, "9.0.31"),
     "CVE-2020-1938", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Apache Tomcat 'Ghostcat' — AJP connector file read/inclusion + RCE if file upload possible. Port 8009 vulnerable."),

    ("tomcat", lambda v: _ver_lt(v, "10.0.27"),
     "CVE-2022-34305", 6.1, "MEDIUM",
     "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "Apache Tomcat XSS in examples web applications via CGI servlet."),

    # Elasticsearch
    ("elasticsearch", lambda v: _ver_lt(v, "7.13.4"),
     "CVE-2021-22144", 6.5, "MEDIUM",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
     "Elasticsearch < 7.13.4 information disclosure — detailed error messages leak cluster configuration."),

    ("elasticsearch", lambda v: _ver_lt(v, "6.8.0"),
     "CVE-2019-7614", 7.5, "HIGH",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Elasticsearch CSRF via URLs that bypass security — data exfiltration via cross-origin requests."),

    # Redis additional
    ("redis", lambda v: _ver_lt(v, "7.0.6"),
     "CVE-2022-35977", 5.5, "MEDIUM",
     "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
     "Redis < 7.0.6 integer overflow DoS via SETRANGE or SORT commands with large values."),

    ("redis", lambda v: _ver_lt(v, "6.2.0"),
     "CVE-2021-32625", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Redis < 6.2.0 unauthenticated RCE via Lua script integer overflow — full server compromise."),

    ("redis", lambda v: _ver_lt(v, "5.0.14"),
     "CVE-2022-0543", 10.0, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "Redis Debian/Ubuntu package Lua sandbox escape — unauthenticated RCE via Lua environment variable leak."),

    # vsftpd
    ("vsftpd", lambda v: v == "2.3.4",
     "CVE-2011-2523", 10.0, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "vsftpd 2.3.4 backdoor — username with :) triggers a bind shell on port 6200. Remote root access. Metasploit module available."),

    # ProFTPD
    ("proftpd", lambda v: _ver_lt(v, "1.3.7c"),
     "CVE-2021-46854", 9.1, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "ProFTPD < 1.3.7c out-of-bounds read via malformed UTF-8 sequence — potential RCE."),

    ("proftpd", lambda v: _ver_lt(v, "1.3.6"),
     "CVE-2019-12815", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "ProFTPD mod_copy arbitrary file copy without authentication via SITE CPFR/CPTO commands."),

    # MongoDB
    ("mongodb", lambda v: _ver_lt(v, "4.4.0"),
     "CVE-2021-20328", 6.8, "MEDIUM",
     "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
     "MongoDB < 4.4 client-side field level encryption certificate validation bypass — MITM possible."),

    # PostgreSQL
    ("postgresql", lambda v: _ver_lt(v, "14.0"),
     "CVE-2021-3393", 3.1, "LOW",
     "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
     "PostgreSQL < 14.0 partial-index predicate information disclosure to unprivileged users."),

    ("postgresql", lambda v: _ver_lt(v, "13.3"),
     "CVE-2021-32029", 6.5, "MEDIUM",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
     "PostgreSQL incomplete fix for CVE-2021-20229 — authenticated users can read arbitrary server files via COPY."),

    # MSSQL
    ("mssql", lambda v: True,
     "CVE-2022-35845", 8.8, "HIGH",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
     "Microsoft SQL Server Remote Code Execution via Extended Stored Procedures — authenticated SQL exec."),

    # Memcached
    ("memcached", lambda v: _ver_lt(v, "1.6.0"),
     "CVE-2018-1000115", 7.5, "HIGH",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
     "Memcached UDP reflection/amplification DRDoS — 50,000x amplification factor. Used in 1.7Tbps attack."),

    # Log4j (Java apps)
    ("log4j", lambda v: _ver_lt(v, "2.17.1"),
     "CVE-2021-44228", 10.0, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "Log4Shell — Log4j2 JNDI injection unauthenticated RCE via any logged user input. Most critical Java vuln in a decade. Affects thousands of products."),

    # Spring Framework
    ("spring", lambda v: _ver_lt(v, "5.3.18"),
     "CVE-2022-22965", 9.8, "CRITICAL",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Spring4Shell — Spring MVC RCE via data binding on JDK 9+ with Tomcat WAR deployment. Metasploit module available."),
]

# Merge extended signatures into main list at import time
def _load_extended():
    global OFFLINE_SIGNATURES
    existing_cves = {s[2] for s in OFFLINE_SIGNATURES}
    for sig in EXTENDED_SIGNATURES:
        if sig[2] not in existing_cves:
            OFFLINE_SIGNATURES.append(sig)
            existing_cves.add(sig[2])

_load_extended()