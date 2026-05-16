"""
generate_logs.py
Genera un archivo auth.log simulado con patrones de fuerza bruta SSH.
Uso: python3 generate_logs.py
"""

import random
import os
from datetime import datetime, timedelta

# Configuración 
OUTPUT_FILE   = "sample_logs/auth.log"
TOTAL_ENTRIES = 300

ATTACKER_IPS  = ["192.168.1.100", "10.0.0.50", "172.16.0.25"]   # IPs atacantes
NORMAL_IPS    = ["192.168.1.10",  "192.168.1.20", "192.168.1.30"] # IPs legítimas
USERNAMES     = ["root", "admin", "user", "ubuntu", "pi", "test", "oracle", "git"]
HOSTNAME      = "webserver01"
# 


def rand_port() -> int:
    return random.randint(40000, 65535)


def fmt_time(t: datetime) -> str:
    return t.strftime("%b %d %H:%M:%S")


def generate_auth_log():
    base_time = datetime.now().replace(hour=6, minute=0, second=0, microsecond=0)
    entries: list[tuple[datetime, str]] = []

    #  Tráfico normal (ruido legítimo)
    for _ in range(30):
        t    = base_time + timedelta(seconds=random.randint(0, 7200))
        ip   = random.choice(NORMAL_IPS)
        user = random.choice(USERNAMES)
        pid  = random.randint(1000, 9999)
        entries.append((
            t,
            f"{fmt_time(t)} {HOSTNAME} sshd[{pid}]: Failed password for {user} "
            f"from {ip} port {rand_port()} ssh2"
        ))

    # Logins exitosos legítimos
    for _ in range(10):
        t    = base_time + timedelta(seconds=random.randint(0, 7200))
        ip   = random.choice(NORMAL_IPS)
        pid  = random.randint(1000, 9999)
        entries.append((
            t,
            f"{fmt_time(t)} {HOSTNAME} sshd[{pid}]: Accepted password for ubuntu "
            f"from {ip} port {rand_port()} ssh2"
        ))

    # Ataques de fuerza bruta
    for attacker_ip in ATTACKER_IPS:
        num_attempts = random.randint(25, 60)
        start        = base_time + timedelta(seconds=random.randint(600, 3600))
        pid          = random.randint(1000, 9999)

        for i in range(num_attempts):
            t    = start + timedelta(seconds=i * random.randint(1, 4))
            user = random.choice(USERNAMES)
            entries.append((
                t,
                f"{fmt_time(t)} {HOSTNAME} sshd[{pid}]: Failed password for {user} "
                f"from {attacker_ip} port {rand_port()} ssh2"
            ))

        # Login exitoso tras el ataque (simula brute force ganador)
        t = start + timedelta(seconds=num_attempts * 3 + 5)
        entries.append((
            t,
            f"{fmt_time(t)} {HOSTNAME} sshd[{pid}]: Accepted password for root "
            f"from {attacker_ip} port {rand_port()} ssh2"
        ))

    # Ordenar por tiempo y guardar
    entries.sort(key=lambda x: x[0])
    os.makedirs("sample_logs", exist_ok=True)

    with open(OUTPUT_FILE, "w") as f:
        for _, line in entries:
            f.write(line + "\n")

    print(f"[+] Log generado: {OUTPUT_FILE}")
    print(f"[+] Total de entradas: {len(entries)}")
    print(f"[+] IPs atacantes simuladas: {', '.join(ATTACKER_IPS)}")


if __name__ == "__main__":
    generate_auth_log()
