import os
import random
import time
import requests

BASE_URL = os.getenv("BASE_URL", "http://webhoneypot:8081")
MODE = os.getenv("MODE", "mixed")  # normal | suspicious | mixed
COUNT = int(os.getenv("COUNT", "300"))
DELAY_MIN = float(os.getenv("DELAY_MIN", "0.3"))
DELAY_MAX = float(os.getenv("DELAY_MAX", "2.5"))

NORMAL_PATHS = [
    "/", "/index.html", "/login", "/register", "/search?q=product",
    "/about", "/contact", "/images/logo.png", "/css/style.css", "/api/health"
]

MALICIOUS_PATTERNS = [
    # Path traversal
    "/../../../../etc/passwd", "/..%2F..%2F..%2Fetc%2Fpasswd",
    # SQLi
    "/login?user=admin'+OR+1=1--", "/search?id=1'+UNION+SELECT+1,2,3--",
    # XSS
    "/search?q=<script>alert(1)</script>", "/comment?post=1&text=<img src=x onerror=alert(1)>",
    # RCE / command injection
    "/ping?ip=127.0.0.1;cat+/etc/passwd", "/exec?cmd=id;uname+-a",
    # Scanner / probing
    "/admin", "/phpmyadmin", "/wp-login.php", "/.env", "/server-status",
    # Long / buffer overflow style
    "/login?user=" + "A" * 500, "/api?token=" + "B" * 1000,
    # CVE-like (exemple simplifié)
    "/vulnerable_endpoint?param=$(whoami)"
]

USER_AGENTS_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15"
]

USER_AGENTS_SCANNER = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "sqlmap/1.8.0#stable", "nikto/2.5.0", "Nuclei - https://github.com/projectdiscovery/nuclei",
    "masscan/1.3", "Mozilla/5.0 zgrab/0.x", "python-requests/2.31.0", "curl/8.4.0"
]

def do_request():
    is_susp = (MODE == "suspicious") or (MODE == "mixed" and random.random() < 0.35)

    if not is_susp:
        path = random.choice(NORMAL_PATHS)
        ua = random.choice(USER_AGENTS_NORMAL)
        method = random.choices(["GET", "POST"], weights=[8, 2])[0]
        headers = {"User-Agent": ua}
    else:
        path = random.choice(MALICIOUS_PATTERNS)
        ua = random.choice(USER_AGENTS_SCANNER + USER_AGENTS_NORMAL)
        method = random.choice(["GET", "POST", "HEAD", "OPTIONS"])
        headers = {
            "User-Agent": ua,
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "Accept-Language": "en-US,en;q=0.5" if random.random() > 0.7 else "ru-RU,ru;q=0.9"
        }

    url = BASE_URL + path
    try:
        if method == "POST":
            requests.post(url, headers=headers, data={"fake": "data"}, timeout=4)
        else:
            requests.request(method, url, headers=headers, timeout=4)
    except:
        pass

def main():
    for _ in range(COUNT):
        do_request()
        time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))

if __name__ == "__main__":
    main()