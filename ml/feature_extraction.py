# ml/feature_extraction.py
# Features simples (MVP) pour HTTP + SSH (Cowrie).
# Objectif: fournir des vecteurs numériques stables pour IsolationForest.

from __future__ import annotations

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

SENSITIVE_PATHS = ["/admin", "/login", "/.env", "/wp-admin", "/phpmyadmin", "/wp-login.php"]


def featurize_http(evt: dict) -> list[float]:
    """
    Convertit un événement HTTP (log brut) en vecteur numérique.
    Features:
      0) is_post
      1) query_len
      2) has_suspicious_keywords
      3) is_sensitive_path
      4) ua_len
    """
    path = (evt.get("path") or "")
    query = (evt.get("query") or "")
    ua = (evt.get("user_agent") or "")
    method = (evt.get("method") or "")

    qlow = query.lower()

    is_post = 1.0 if method.upper() == "POST" else 0.0
    query_len = float(len(query))
    has_suspicious = 1.0 if any(s in qlow for s in SUSPICIOUS_HTTP) else 0.0
    is_sensitive_path = 1.0 if any(path.startswith(p) for p in SENSITIVE_PATHS) else 0.0
    ua_len = float(len(ua))

    return [is_post, query_len, has_suspicious, is_sensitive_path, ua_len]


# --- SSH (Cowrie) ---
SSH_POST_EXP_KW = ["wget", "curl", "chmod", "bash", "python", "nc ", "netcat", "perl", "sh "]
SSH_RECON_KW = ["uname", "whoami", "id", "cat /etc/passwd", "ip a", "ifconfig", "ps ", "netstat"]


def featurize_ssh_cowrie(ev: dict, fails_60s: int = 0) -> list[float]:
    """
    Convertit un event Cowrie en vecteur numérique.
    Features:
      0) is_login_failed
      1) is_login_success
      2) is_command
      3) has_post_exploitation_kw
      4) has_recon_kw
      5) cmd_len
      6) username_len
      7) fails_60s
    """
    etype = (ev.get("eventid") or "")
    cmd = (ev.get("input") or "").lower()
    user = (ev.get("username") or "")

    is_failed = 1.0 if etype == "cowrie.login.failed" else 0.0
    is_success = 1.0 if etype == "cowrie.login.success" else 0.0
    is_cmd = 1.0 if etype == "cowrie.command.input" else 0.0

    has_post = 1.0 if any(k in cmd for k in SSH_POST_EXP_KW) else 0.0
    has_recon = 1.0 if any(k in cmd for k in SSH_RECON_KW) else 0.0

    cmd_len = float(len(cmd))
    user_len = float(len(user))
    fail_rate = float(fails_60s)

    return [is_failed, is_success, is_cmd, has_post, has_recon, cmd_len, user_len, fail_rate]