"""
detector.py — SSH Brute Force Detector
Analiza archivos auth.log y detecta patrones de fuerza bruta SSH.

Uso:
    python3 detector.py                        # usa sample_logs/auth.log
    python3 detector.py /ruta/a/auth.log       # log personalizado
    python3 detector.py --threshold 10         # umbral personalizado
    python3 detector.py --report report.txt    # exporta reporte
"""

import re
import sys
import json
import argparse
from collections import defaultdict
from datetime import datetime

# Configuración por defecto
DEFAULT_LOG       = "sample_logs/auth.log"
DEFAULT_THRESHOLD = 5    # intentos fallidos para disparar alerta


# Regex para líneas de fallo SSH
FAIL_PATTERN    = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*"
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
)
# Regex para logins exitosos
SUCCESS_PATTERN = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*"
    r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)"
)

COLORS = {
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "green":  "\033[92m",
    "cyan":   "\033[96m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}


def c(text: str, color: str) -> str:
    """Aplica color ANSI al texto."""
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


# Parser 
def parse_log(filepath: str) -> tuple[list[dict], list[dict]]:
    """
    Lee el archivo de log y extrae:
    - failed: lista de intentos fallidos
    - successes: lista de logins exitosos
    """
    failed    = []
    successes = []

    try:
        with open(filepath, "r") as f:
            for lineno, line in enumerate(f, 1):
                m = FAIL_PATTERN.search(line)
                if m:
                    failed.append({
                        "timestamp": m.group(1),
                        "user":      m.group(2),
                        "ip":        m.group(3),
                        "line":      line.strip(),
                        "lineno":    lineno,
                    })
                    continue

                m = SUCCESS_PATTERN.search(line)
                if m:
                    successes.append({
                        "timestamp": m.group(1),
                        "user":      m.group(2),
                        "ip":        m.group(3),
                    })
    except FileNotFoundError:
        print(c(f"[ERROR] Archivo no encontrado: {filepath}", "red"))
        sys.exit(1)

    return failed, successes


# Detección 

def detect_brute_force(failed: list[dict], successes: list[dict],
                        threshold: int) -> list[dict]:
    """
    Agrupa intentos fallidos por IP.
    Marca como HIGH si la IP también logró un login exitoso (ataque completado).
    """
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for attempt in failed:
        by_ip[attempt["ip"]].append(attempt)

    successful_ips = {s["ip"] for s in successes}

    alerts = []
    for ip, events in by_ip.items():
        count = len(events)
        if count >= threshold:
            users_targeted = list({e["user"] for e in events})
            compromised    = ip in successful_ips

            severity = "CRITICAL" if compromised else ("HIGH" if count >= threshold * 3 else "MEDIUM")

            alerts.append({
                "ip":             ip,
                "attempts":       count,
                "users_targeted": users_targeted,
                "first_seen":     events[0]["timestamp"],
                "last_seen":      events[-1]["timestamp"],
                "severity":       severity,
                "compromised":    compromised,
            })

    return sorted(alerts, key=lambda x: x["attempts"], reverse=True)


# Reporte

SEVERITY_COLOR = {
    "CRITICAL": "red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}


def print_report(alerts: list[dict], failed: list[dict], successes: list[dict],
                 threshold: int, filepath: str):
    """Imprime el reporte en consola con colores."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "=" * 65

    print(c(sep, "cyan"))
    print(c("  SSH BRUTE FORCE DETECTION REPORT", "bold"))
    print(f"  Generated : {now}")
    print(f"  Log file  : {filepath}")
    print(f"  Threshold : {threshold} failed attempts")
    print(c(sep, "cyan"))

    print(f"\n  Total failed attempts : {c(str(len(failed)), 'yellow')}")
    print(f"  Successful logins    : {c(str(len(successes)), 'green')}")
    print(f"  Suspicious IPs       : {c(str(len(alerts)), 'red')}\n")

    if not alerts:
        print(c("  [OK] No brute force patterns detected.\n", "green"))
        return

    print(c("  ALERTS DETECTED:", "bold"))
    print("-" * 65)

    for alert in alerts:
        sev_color = SEVERITY_COLOR.get(alert["severity"], "reset")
        label     = c(f"[{alert['severity']}]", sev_color)
        comp_note = c("  ⚠ SUCCESSFUL LOGIN DETECTED — POSSIBLE COMPROMISE", "red") if alert["compromised"] else ""

        print(f"\n{label} {c(alert['ip'], 'bold')}")
        print(f"  Failed attempts  : {alert['attempts']}")
        print(f"  Users targeted   : {', '.join(alert['users_targeted'])}")
        print(f"  First seen       : {alert['first_seen']}")
        print(f"  Last seen        : {alert['last_seen']}")
        if comp_note:
            print(comp_note)

    print("\n" + "-" * 65)


def export_report(alerts: list[dict], failed: list[dict],
                  successes: list[dict], outfile: str):
    """Exporta el reporte en formato JSON."""
    data = {
        "generated_at":    datetime.now().isoformat(),
        "total_failed":    len(failed),
        "total_successes": len(successes),
        "alerts":          alerts,
    }
    with open(outfile, "w") as f:
        json.dump(data, f, indent=2)
    print(c(f"\n[+] Reporte exportado: {outfile}", "green"))


# CLI 

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect SSH brute force attacks from auth.log files."
    )
    parser.add_argument(
        "logfile", nargs="?", default=DEFAULT_LOG,
        help=f"Path to auth.log (default: {DEFAULT_LOG})"
    )
    parser.add_argument(
        "--threshold", type=int, default=DEFAULT_THRESHOLD,
        help=f"Failed attempts to trigger alert (default: {DEFAULT_THRESHOLD})"
    )
    parser.add_argument(
        "--report", metavar="FILE",
        help="Export results to JSON file"
    )
    return parser.parse_args()


def main():
    args    = parse_args()
    failed, successes = parse_log(args.logfile)
    alerts  = detect_brute_force(failed, successes, args.threshold)

    print_report(alerts, failed, successes, args.threshold, args.logfile)

    if args.report:
        export_report(alerts, failed, successes, args.report)


if __name__ == "__main__":
    main()
