import os
import re
import sys
import time
import socket
import threading
from datetime import datetime

_PRINT_LOCK = threading.Lock()


def eprint(msg: str, end="\n"):
    with _PRINT_LOCK:
        sys.stderr.write(msg + end)
        sys.stderr.flush()


def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def sleep_min(seconds: float = 1.0):
    try:
        t = float(seconds)
    except Exception:
        t = 1.0
    if t < 1.0:
        t = 1.0
    time.sleep(t)


def tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def sanitize_for_summary(msg: str) -> str:
    if not msg:
        return msg
    lines = [ln.strip() for ln in msg.splitlines() if ln.strip()]
    s = " ".join(lines)
    # Compactar mensajes muy verbosos de Netmiko sobre device_type
    if re.search(r"Unsupported 'device_type'", s, re.IGNORECASE):
        return "Unsupported 'device_type'"
    # Remover prefijos redundantes de Paramiko
    s = re.sub(r"^A paramiko SSHException occurred during connection creation:\s*", "", s, flags=re.IGNORECASE)
    # Acortar mensajes gigantes (p. ej., listados de plataformas soportadas)
    if len(s) > 300:
        s = s[:300] + "…"
    return s


def classify_error_message(msg: str) -> str:
    """Clasifica mensajes de error comunes en categorías compactas.
    Posibles retornos: AUTH, TIMEOUT, CONNECTION, SSH_BANNER, SSH_NEGOTIATION, CHANNEL, UNKNOWN.
    Preferimos clasificar 'banner' antes que CONNECTION, ya que a menudo coexisten en el mensaje.
    """
    if not msg:
        return "UNKNOWN"
    m = msg.lower()
    if "banner" in m:
        return "SSH_BANNER"
    if "kex" in m or "key exchange" in m or "cipher" in m or "no matching" in m:
        return "SSH_NEGOTIATION"
    if "unable to open channel" in m or "open channel" in m:
        return "CHANNEL"
    # Autenticación
    if "auth" in m or "permission denied" in m or "password" in m or "login failed" in m:
        return "AUTH"
    # Conectividad
    if "connection closed" in m or "closed by" in m or "eof" in m:
        return "CONNECTION"
    if "timed out" in m or "timeout" in m:
        return "TIMEOUT"
    if "connection reset" in m or "refused" in m or "unreachable" in m or "network is unreachable" in m:
        return "CONNECTION"
    if "ssh" in m:
        return "SSH_NEGOTIATION"
    return "UNKNOWN"


def parse_hosts_file(path: str):
    hosts = []
    ipv6_bracketed = re.compile(r"^\[(?P<ip6>[^]]+)\](?::(?P<port>\d+))?$")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            port = None
            m = ipv6_bracketed.match(raw)
            if m:
                h = m.group("ip6")
                p = m.group("port")
                port = int(p) if p else None
            elif raw.count(":") == 1 and not re.search(r"^[0-9a-f:]+:[0-9a-f:]+$", raw, re.I):
                h, p = raw.split(":")
                port = int(p)
            else:
                h = raw
            hosts.append({"host": h, "port": port})
    if not hosts:
        raise ValueError("El archivo de hosts no contiene entradas válidas.")
    return hosts


def dedupe_hosts(hosts, default_port):
    seen, uniq, removed = set(), [], 0
    for h in hosts:
        key = (h["host"], h["port"] or default_port)
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        uniq.append(h)
    return uniq, removed
