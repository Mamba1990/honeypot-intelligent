# ml/feature_extraction.py
# Features enrichies pour HTTP + SSH (Cowrie).
# Objectif: fournir des vecteurs numériques stables et expressifs pour IsolationForest.

from __future__ import annotations
import math
from urllib.parse import unquote

# --- HTTP ---

SUSPICIOUS_HTTP = [
    "or 1=1",
    "union select",
    "<script",
    "../",
    "sleep(",
    "benchmark(",
    "xp_cmdshell",
]

SENSITIVE_PATHS = [
    "/admin", "/login", "/.env", "/wp-admin",
    "/phpmyadmin", "/wp-login.php", "/render",
    "/actuator", "/server-status", "/config",
    "/upload",
]

# Patterns SSTI / template injection + Log4Shell
TEMPLATE_PATTERNS = [
    "{{", "}}", "${", "#{", "%7b%7b", "%7d%7d",
    "tpl=", "template=", "freemarker", "thymeleaf",
    "${jndi",
    "jndi:ldap", "jndi:rmi", "jndi:dns",
]

# Patterns command injection
CMD_INJECTION_PATTERNS = [
    ";", "&&", "||", "|", "`", "$(", "wget ", "curl ",
    "bash ", "sh ", "nc ", "netcat", "chmod", "python",
]

# Caracteres encodes suspects
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
    "%25",   # % (double encodage)
]

# Patterns SSRF
SSRF_PATTERNS = [
    "169.254.169.254",  # AWS metadata
    "metadata.google",  # GCP metadata
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "internal",
    "intranet",
    "169.254.",
    "192.168.",
    "10.0.",
    "172.16.",
]

# Patterns RFI / LFI
FILE_INCLUSION_PATTERNS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self",
    "/var/log",
    "php://",
    "file://",
    "ftp://",
    "data://",
    "expect://",
    "zip://",
    "phar://",
    "c:\\windows",
    "c:/windows",
    "boot.ini",
]

# Patterns XXE
XXE_PATTERNS = [
    "<!doctype",
    "<!entity",
    "system \"file",
    "system 'file",
    "system \"http",
    "system 'http",
    "%xxe",
    "xmlrpc",
]


def _string_entropy(s: str) -> float:
    """Entropie de Shannon normalisee [0, 1]."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    entropy = -sum((f / n) * math.log2(f / n) for f in freq.values())
    return float(min(entropy / 6.57, 1.0))


def featurize_http(evt: dict) -> list[float]:
    """
    Convertit un evenement HTTP en vecteur numerique enrichi.

    Features (16 dimensions):
      0)  is_post               - methode POST
      1)  query_len             - longueur query string
      2)  has_suspicious_kw     - mots-cles SQLi / XSS classiques
      3)  is_sensitive_path     - path sensible (admin, env, render...)
      4)  ua_len                - longueur User-Agent
      5)  body_len              - longueur du body
      6)  has_encoded_chars     - caracteres URL-encodes suspects
      7)  path_depth            - profondeur du path (/a/b/c -> 3)
      8)  ua_entropy            - entropie du User-Agent
      9)  has_template_syntax   - patterns SSTI / template injection + Log4Shell
      10) has_cmd_injection     - patterns command injection dans query+body+ua
      11) query_entropy         - entropie de la query string
      12) has_ssrf              - patterns SSRF (metadata, localhost, internal...)
      13) has_file_inclusion    - patterns RFI / LFI (/etc/passwd, php://...)
      14) has_xxe               - patterns XXE (DOCTYPE, ENTITY...)
      15) body_entropy          - entropie du body
    """
    path = (evt.get("path") or "")
    query = (evt.get("query") or "")
    ua = (evt.get("user_agent") or "")
    method = (evt.get("method") or "")
    body = (evt.get("body") or "")

    qlow = query.lower()
    blow = body.lower()
    ua_low = ua.lower()
    path_low = path.lower()

    # Surface de detection complete : query + body + path + user-agent
    full_combined = qlow + " " + blow + " " + path_low + " " + ua_low

    # 0) is_post
    is_post = 1.0 if method.upper() == "POST" else 0.0

    # 1) query_len
    query_len = float(len(query))

    # 2) has_suspicious_kw
    has_suspicious = 1.0 if any(s in full_combined for s in SUSPICIOUS_HTTP) else 0.0

    # 3) is_sensitive_path
    is_sensitive_path = 1.0 if any(path_low.startswith(p) for p in SENSITIVE_PATHS) else 0.0

    # 4) ua_len
    ua_len = float(len(ua))

    # 5) body_len
    body_len = float(len(body))

    # 6) has_encoded_chars
    has_encoded = 1.0 if any(e in full_combined for e in ENCODED_SUSPICIOUS) else 0.0

    # 7) path_depth
    path_depth = float(len([p for p in path.split("/") if p]))

    # 8) ua_entropy
    ua_entropy = _string_entropy(ua)

    # 9) has_template_syntax — SSTI + Log4Shell (inclut UA)
    has_template = 1.0 if any(t in full_combined for t in TEMPLATE_PATTERNS) else 0.0

    # 10) has_cmd_injection (inclut UA)
    has_cmd = 1.0 if any(c in full_combined for c in CMD_INJECTION_PATTERNS) else 0.0

    # 11) query_entropy
    query_entropy = _string_entropy(query)

    # 12) has_ssrf
    has_ssrf = 1.0 if any(s in full_combined for s in SSRF_PATTERNS) else 0.0

    # 13) has_file_inclusion — RFI / LFI
    # ✅ Fix: decoder les encodages doubles (%252F -> %2F -> /) avant de chercher
    full_combined_decoded = unquote(unquote(full_combined))
    has_file_inclusion = 1.0 if any(f in full_combined_decoded for f in FILE_INCLUSION_PATTERNS) else 0.0

    # 14) has_xxe — full_combined utilise blow (body.lower()) -> case insensitive garanti
    has_xxe = 1.0 if any(x in full_combined for x in XXE_PATTERNS) else 0.0

    # 15) body_entropy
    body_entropy = _string_entropy(body)

    return [
        is_post, query_len, has_suspicious, is_sensitive_path,
        ua_len, body_len, has_encoded, path_depth,
        ua_entropy, has_template, has_cmd, query_entropy,
        has_ssrf, has_file_inclusion, has_xxe, body_entropy,
    ]


# --- SSH (Cowrie) ---

SSH_POST_EXP_KW = [
    "wget", "curl", "chmod", "bash", "python",
    "nc ", "netcat", "perl", "sh ",
]

SSH_RECON_KW = [
    "uname", "whoami", "id", "cat /etc/passwd",
    "ip a", "ifconfig", "ps ", "netstat",
]

# Patterns d'escalade de privileges
SSH_PRIVESC_KW = [
    "sudo", "su ", "passwd", "useradd", "usermod",
    "visudo", "/etc/sudoers", "chown root", "setuid",
]

# Patterns de persistence
SSH_PERSIST_KW = [
    "authorized_keys", "crontab", "rc.local",
    "systemctl enable", ".bashrc", ".profile",
    "/etc/init.d",
]


def featurize_ssh_cowrie(ev: dict, fails_60s: int = 0) -> list[float]:
    """
    Convertit un event Cowrie en vecteur numerique enrichi.

    Features (12 dimensions):
      0)  is_login_failed       - cowrie.login.failed
      1)  is_login_success      - cowrie.login.success
      2)  is_command            - cowrie.command.input
      3)  has_post_exploitation - wget, curl, bash, nc...
      4)  has_recon             - uname, whoami, id...
      5)  cmd_len               - longueur de la commande
      6)  username_len          - longueur du username
      7)  fails_60s             - nb echecs login dans les 60s
      8)  has_privesc           - sudo, useradd, chown root...
      9)  has_persistence       - authorized_keys, crontab...
      10) cmd_entropy           - entropie de la commande
      11) is_common_user        - root/admin/administrator
    """
    etype = (ev.get("eventid") or "")
    cmd = (ev.get("input") or "").lower()
    user = (ev.get("username") or "")

    # 0-2) type d'event
    is_failed = 1.0 if etype == "cowrie.login.failed" else 0.0
    is_success = 1.0 if etype == "cowrie.login.success" else 0.0
    is_cmd = 1.0 if etype == "cowrie.command.input" else 0.0

    # 3) post-exploitation
    has_post = 1.0 if any(k in cmd for k in SSH_POST_EXP_KW) else 0.0

    # 4) recon
    has_recon = 1.0 if any(k in cmd for k in SSH_RECON_KW) else 0.0

    # 5-6) longueurs
    cmd_len = float(len(cmd))
    user_len = float(len(user))

    # 7) frequence d'echecs
    fail_rate = float(fails_60s)

    # 8) escalade de privileges
    has_privesc = 1.0 if any(k in cmd for k in SSH_PRIVESC_KW) else 0.0

    # 9) persistence
    has_persist = 1.0 if any(k in cmd for k in SSH_PERSIST_KW) else 0.0

    # 10) entropie de la commande
    cmd_entropy = _string_entropy(cmd)

    # 11) username a risque
    RISKY_USERS = {"root", "admin", "administrator", "oracle", "postgres", "guest"}
    is_common_user = 1.0 if user.lower() in RISKY_USERS else 0.0

    return [
        is_failed, is_success, is_cmd,
        has_post, has_recon,
        cmd_len, user_len, fail_rate,
        has_privesc, has_persist,
        cmd_entropy, is_common_user,
    ]