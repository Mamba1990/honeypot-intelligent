# ml/feature_extraction.py
# ─────────────────────────────────────────────────────────────────────────────
# Shared featurizer for HTTP and SSH (Cowrie) events.
#
# Produces stable, numerical vectors for Isolation Forest inference.
# This file is the single source of truth for feature definitions:
# it is used identically at training time (train_http.py, train_ssh.py)
# and at inference time (collector.py) — preventing any feature drift.
#
# HTTP → 16-dimensional vector  (featurize_http)
# SSH  → 12-dimensional vector  (featurize_ssh_cowrie)
#
# Author  : Hafsa Daoudim
# Project : Final Training Project — JobInTech 2026
# ─────────────────────────────────────────────────────────────────────────────

from __future__ import annotations
import math
from urllib.parse import unquote

# ── HTTP detection dictionaries ───────────────────────────────────────────────

# Classic SQLi / XSS markers
SUSPICIOUS_HTTP = [
    "or 1=1", "union select", "<script",
    "../", "sleep(", "benchmark(", "xp_cmdshell",
]

# Paths frequently targeted during web reconnaissance
SENSITIVE_PATHS = [
    "/admin", "/login", "/signin", "/auth",
    "/.env", "/wp-admin", "/phpmyadmin", "/wp-login.php",
    "/render", "/actuator", "/server-status", "/config",
    "/upload", "/api/parse", "/api/search",
]

# SSTI / template injection markers and Log4Shell (${jndi:...})
TEMPLATE_PATTERNS = [
    "{{", "}}", "${", "#{", "%7b%7b", "%7d%7d",
    "tpl=", "template=", "freemarker", "thymeleaf",
    "${jndi", "jndi:ldap", "jndi:rmi", "jndi:dns",
]

# OS command injection operators and binaries
CMD_INJECTION_PATTERNS = [
    ";", "&&", "||", "|", "`", "$(", "wget ", "curl ",
    "bash ", "sh ", "nc ", "netcat", "chmod", "python",
]

# URL-encoded characters commonly used to bypass WAF / input validation
ENCODED_SUSPICIOUS = [
    "%3c",   # <
    "%3e",   # >
    "%27",   # '
    "%22",   # "
    "%7b",   # {
    "%7d",   # }
    "%2f",   # /
    "%00",   # null byte
    "%0a",   # newline
    "%25",   # % (double-encoded percent)
]

# SSRF targets — cloud metadata endpoints and private address ranges
SSRF_PATTERNS = [
    "169.254.169.254",  # AWS instance metadata
    "metadata.google",  # GCP metadata
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "internal", "intranet",
    "169.254.", "192.168.", "10.0.", "172.16.",
]

# LFI / RFI path and protocol patterns
FILE_INCLUSION_PATTERNS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/proc/self", "/var/log",
    "php://", "file://", "ftp://", "data://",
    "expect://", "zip://", "phar://",
    "c:\\windows", "c:/windows", "boot.ini",
]

# XXE markers — DOCTYPE / ENTITY injection in XML bodies
XXE_PATTERNS = [
    "<!doctype", "<!entity",
    "system \"file", "system 'file",
    "system \"http", "system 'http",
    "%xxe", "xmlrpc",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _string_entropy(s: str) -> float:
    """
    Compute normalized Shannon entropy of a string, clamped to [0, 1].

    High entropy → random-looking, scanner-generated or obfuscated content.
    Low entropy  → repetitive, human-typed content.
    Normalization divisor 6.57 ≈ log2(95) (printable ASCII charset size).
    """
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    entropy = -sum((f / n) * math.log2(f / n) for f in freq.values())
    return float(min(entropy / 6.57, 1.0))


# HTTP featurizer #

def featurize_http(evt: dict) -> list[float]:
    """
    Convert one HTTP event dict into a 16-dimensional float vector.

    Detection surface: query + body + path + user_agent (all lowercased).
    Double URL-decoding is applied before file-inclusion checks to catch
    double-encoded traversal payloads (%252F → %2F → /).

    Feature index map:
        0   is_post             — POST method flag
        1   query_len           — raw query string length
        2   has_suspicious_kw   — SQLi / XSS classic keywords
        3   is_sensitive_path   — path in SENSITIVE_PATHS
        4   ua_len              — User-Agent length
        5   body_len            — request body length
        6   has_encoded_chars   — suspicious URL-encoded characters
        7   path_depth          — number of path segments
        8   ua_entropy          — Shannon entropy of User-Agent
        9   has_template_syntax — SSTI / Log4Shell patterns
        10  has_cmd_injection   — OS command injection patterns
        11  query_entropy       — Shannon entropy of query string
        12  has_ssrf            — SSRF targets (metadata, private IPs)
        13  has_file_inclusion  — LFI / RFI paths and protocols
        14  has_xxe             — XXE DOCTYPE / ENTITY patterns
        15  body_entropy        — Shannon entropy of request body
    """
    path   = (evt.get("path")       or "")
    query  = (evt.get("query")      or "")
    ua     = (evt.get("user_agent") or "")
    method = (evt.get("method")     or "")
    body   = (evt.get("body")       or "")

    qlow     = query.lower()
    blow     = body.lower()
    ua_low   = ua.lower()
    path_low = path.lower()

    # Full detection surface — all fields lowercased and concatenated
    full_combined = qlow + " " + blow + " " + path_low + " " + ua_low

    # 0) POST method is more commonly used for injection attacks than GET
    is_post = 1.0 if method.upper() == "POST" else 0.0

    # 1) Long queries often carry encoded payloads
    query_len = float(len(query))

    # 2) Classic SQLi / XSS signatures
    has_suspicious = 1.0 if any(s in full_combined for s in SUSPICIOUS_HTTP) else 0.0

    # 3) Attacker-targeted path (admin panels, config files, API endpoints)
    is_sensitive_path = 1.0 if any(path_low.startswith(p) for p in SENSITIVE_PATHS) else 0.0

    # 4) Abnormally long User-Agents are typical of scanners and exploit kits
    ua_len = float(len(ua))

    # 5) Non-empty bodies signal active exploitation attempts
    body_len = float(len(body))

    # 6) Encoded characters used to bypass WAF / input filters
    has_encoded = 1.0 if any(e in full_combined for e in ENCODED_SUSPICIOUS) else 0.0

    # 7) Deep paths often indicate traversal or API enumeration
    path_depth = float(len([p for p in path.split("/") if p]))

    # 8) High entropy → scanner-generated or obfuscated User-Agent
    ua_entropy = _string_entropy(ua)

    # 9) SSTI and Log4Shell payloads — checked across all fields including User-Agent
    has_template = 1.0 if any(t in full_combined for t in TEMPLATE_PATTERNS) else 0.0

    # 10) Shell operators and attack binaries in any part of the request
    has_cmd = 1.0 if any(c in full_combined for c in CMD_INJECTION_PATTERNS) else 0.0

    # 11) High query entropy → obfuscated or encoded attack payload
    query_entropy = _string_entropy(query)

    # 12) SSRF attempts targeting internal services or cloud metadata endpoints
    has_ssrf = 1.0 if any(s in full_combined for s in SSRF_PATTERNS) else 0.0

    # 13) LFI / RFI — double-decode first to catch double-encoded traversals
    full_combined_decoded = unquote(unquote(full_combined))
    has_file_inclusion = 1.0 if any(f in full_combined_decoded for f in FILE_INCLUSION_PATTERNS) else 0.0

    # 14) XXE — body is already lowercased so comparison is case-insensitive
    has_xxe = 1.0 if any(x in full_combined for x in XXE_PATTERNS) else 0.0

    # 15) High body entropy → binary, encoded or obfuscated payload
    body_entropy = _string_entropy(body)

    return [
        is_post, query_len, has_suspicious, is_sensitive_path,
        ua_len, body_len, has_encoded, path_depth,
        ua_entropy, has_template, has_cmd, query_entropy,
        has_ssrf, has_file_inclusion, has_xxe, body_entropy,
    ]


# SSH (Cowrie) detection dictionaries #

# Commands indicating the attacker is establishing persistence or exfiltrating data
SSH_POST_EXP_KW = [
    "wget", "curl", "chmod", "bash", "python",
    "nc ", "netcat", "perl", "sh ",
    "apt-get", "apt ", "pip ", "yum ",
]

# Commands used to map the compromised environment
SSH_RECON_KW = [
    "uname", "whoami", "id", "cat /etc/passwd",
    "ip a", "ifconfig", "ps ", "netstat",
]

# Privilege escalation indicators
SSH_PRIVESC_KW = [
    "sudo", "su ", "passwd", "useradd", "usermod",
    "visudo", "/etc/sudoers", "chown root", "setuid",
    "docker", "nsenter", "unshare",
]

# Persistence mechanisms — modifying startup files or SSH keys
SSH_PERSIST_KW = [
    "authorized_keys", "crontab", "rc.local",
    "systemctl enable", ".bashrc", ".profile",
    "/etc/init.d",
]


# SSH featurizer #

def featurize_ssh_cowrie(ev: dict, fails_60s: int = 0) -> list[float]:
    """
    Convert one Cowrie SSH event dict into a 12-dimensional float vector.

    fails_60s must be passed by the caller (collector.py) — it represents
    the number of failed logins from the same IP in the last 60 seconds
    and serves as the brute-force frequency feature.

    Feature index map:
        0   is_login_failed     — cowrie.login.failed event
        1   is_login_success    — cowrie.login.success event
        2   is_command          — cowrie.command.input event
        3   has_post_exploitation — wget, curl, bash, nc…
        4   has_recon           — uname, whoami, id…
        5   cmd_len             — raw command length
        6   username_len        — attempted username length
        7   fails_60s           — failed login count in the last 60 seconds
        8   has_privesc         — sudo, useradd, chown root…
        9   has_persistence     — authorized_keys, crontab…
        10  cmd_entropy         — Shannon entropy of the command string
        11  is_common_user      — high-value target username (root, admin…)
    """
    etype = (ev.get("eventid")  or "")
    cmd   = (ev.get("input")    or "").lower()
    user  = (ev.get("username") or "")

    # 0–2) Event type flags
    is_failed  = 1.0 if etype == "cowrie.login.failed"  else 0.0
    is_success = 1.0 if etype == "cowrie.login.success" else 0.0
    is_cmd     = 1.0 if etype == "cowrie.command.input" else 0.0

    # 3) Attacker downloading tools or opening reverse shells
    has_post = 1.0 if any(k in cmd for k in SSH_POST_EXP_KW) else 0.0

    # 4) Attacker mapping the environment after login
    has_recon = 1.0 if any(k in cmd for k in SSH_RECON_KW) else 0.0

    # 5–6) Length features — long commands and usernames are statistically rare
    cmd_len  = float(len(cmd))
    user_len = float(len(user))

    # 7) Brute-force frequency — passed in from the sliding 60s window in collector.py
    fail_rate = float(fails_60s)

    # 8) Privilege escalation attempt
    has_privesc = 1.0 if any(k in cmd for k in SSH_PRIVESC_KW) else 0.0

    # 9) Persistence installation (backdoors, scheduled tasks, startup hooks)
    has_persist = 1.0 if any(k in cmd for k in SSH_PERSIST_KW) else 0.0

    # 10) High entropy → obfuscated or encoded command payload
    cmd_entropy = _string_entropy(cmd)

    # 11) High-value usernames are targeted disproportionately by attackers
    RISKY_USERS = {"root", "admin", "administrator", "oracle", "postgres", "guest"}
    is_common_user = 1.0 if user.lower() in RISKY_USERS else 0.0

    return [
        is_failed, is_success, is_cmd,
        has_post, has_recon,
        cmd_len, user_len, fail_rate,
        has_privesc, has_persist,
        cmd_entropy, is_common_user,
    ]