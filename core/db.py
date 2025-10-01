import os
import sqlite3
from typing import Dict, Any, Iterable
from .utils import classify_error_message


SCHEMA = [
    # Dispositivos y estado de operaciones
    """
    CREATE TABLE IF NOT EXISTS devices (
        host TEXT PRIMARY KEY,
        ssh_port INTEGER,
        telnet_port INTEGER,
        vendor TEXT,
        platform TEXT,
        device_type TEXT,
        access_proto TEXT,
        access_port INTEGER,
        user TEXT,
        comment TEXT,
        ssh_open INTEGER,
        telnet_open INTEGER,
        dump_done INTEGER DEFAULT 0,
        scan_done INTEGER DEFAULT 0,
        push_done INTEGER DEFAULT 0,
        done INTEGER DEFAULT 0,
        last_error TEXT,
        updated_at TEXT
    )
    """,
    # Inventario recolectado en --scan (y también datos usados por reportes)
    """
    CREATE TABLE IF NOT EXISTS inventory (
        host TEXT PRIMARY KEY,
        hostname TEXT,
        version_line TEXT,
        ifaces_with_ip TEXT,
        GigabitEthernet TEXT,
        Gi TEXT,
        Loopback TEXT,
        lo TEXT,
        VLAN TEXT,
        vrf_brief TEXT,
        syslog_config TEXT,
        sockets_found TEXT,
        route_brief TEXT,
        arp_brief TEXT,
        FOREIGN KEY(host) REFERENCES devices(host) ON DELETE CASCADE
    )
    """,
]


def connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True) if os.path.dirname(db_path) else None
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    # Mejorar concurrencia en escrituras desde múltiples hilos/conexiones
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    return conn


def init_db(conn: sqlite3.Connection):
    cur = conn.cursor()
    for stmt in SCHEMA:
        cur.execute(stmt)
    # Migración: agregar columnas faltantes si la tabla ya existía
    def ensure_column(table: str, name: str, coltype: str):
        cols = [r[1] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()]
        if name not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {name} {coltype}")
    try:
        ensure_column('devices', 'ssh_open', 'INTEGER')
        ensure_column('devices', 'telnet_open', 'INTEGER')
        ensure_column('devices', 'comment', 'TEXT')
    except Exception:
        pass
    conn.commit()


def upsert_device(conn: sqlite3.Connection, row: Dict[str, Any]):
    keys = [
        "host",
        "ssh_port",
        "telnet_port",
        "vendor",
        "platform",
        "device_type",
        "access_proto",
        "access_port",
        "user",
        "comment",
        "dump_done",
        "scan_done",
        "push_done",
        "done",
        "last_error",
        "updated_at",
    ]
    cols = ",".join(keys)
    placeholders = ",".join([":" + k for k in keys])
    stmt = f"INSERT INTO devices ({cols}) VALUES ({placeholders})\n" \
           f"ON CONFLICT(host) DO UPDATE SET " + ", ".join([f"{k}=excluded.{k}" for k in keys if k != "host"])  # noqa: E501
    conn.execute(stmt, {k: row.get(k) for k in keys})
    conn.commit()


def mark_status(conn: sqlite3.Connection, host: str, **flags):
    fields = []
    params = {"host": host}
    for k, v in flags.items():
        if k in ("dump_done", "scan_done", "push_done", "done", "vendor", "platform", "device_type", "access_proto", "access_port", "user", "comment", "last_error", "updated_at", "ssh_open", "telnet_open"):
            fields.append(f"{k} = :{k}")
            params[k] = v
    if not fields:
        return
    stmt = "UPDATE devices SET " + ", ".join(fields) + " WHERE host = :host"
    conn.execute(stmt, params)
    conn.commit()


def write_inventory(conn: sqlite3.Connection, host: str, inv: Dict[str, Any]):
    keys = [
        "host",
        "hostname",
        "version_line",
        "ifaces_with_ip",
        "GigabitEthernet",
        "Gi",
        "Loopback",
        "lo",
        "VLAN",
        "vrf_brief",
        "syslog_config",
        "sockets_found",
        "route_brief",
        "arp_brief",
    ]
    cols = ",".join(keys)
    placeholders = ",".join([":" + k for k in keys])
    stmt = f"INSERT INTO inventory ({cols}) VALUES ({placeholders})\n" \
           f"ON CONFLICT(host) DO UPDATE SET " + ", ".join([f"{k}=excluded.{k}" for k in keys if k != "host"])  # noqa: E501
    data = {k: inv.get(k, "") for k in keys}
    data["host"] = host
    conn.execute(stmt, data)
    conn.commit()


def pending_hosts(conn: sqlite3.Connection, mode: str) -> Iterable[str]:
    if mode == "allops":
        q = "SELECT host FROM devices WHERE dump_done=0 OR scan_done=0 OR push_done=0"
    elif mode == "dump":
        q = "SELECT host FROM devices WHERE dump_done=0"
    elif mode == "scan":
        q = "SELECT host FROM devices WHERE scan_done=0"
    elif mode == "push":
        q = "SELECT host FROM devices WHERE push_done=0"
    else:
        return []
    return [r[0] for r in conn.execute(q)]


def get_counts(conn: sqlite3.Connection) -> Dict[str, int]:
    cur = conn.cursor()
    out: Dict[str, int] = {}
    out["scan_only"] = cur.execute("SELECT COUNT(1) FROM devices WHERE scan_done=1").fetchone()[0]
    out["dump"] = cur.execute("SELECT COUNT(1) FROM devices WHERE dump_done=1").fetchone()[0]
    out["all_done"] = cur.execute(
        "SELECT COUNT(1) FROM devices WHERE dump_done=1 AND scan_done=1"
    ).fetchone()[0]
    out["push"] = cur.execute("SELECT COUNT(1) FROM devices WHERE push_done=1").fetchone()[0]
    out["total"] = cur.execute("SELECT COUNT(1) FROM devices").fetchone()[0]

    # Conteos por clase de error para hosts con fallas
    err_rows = cur.execute("SELECT last_error FROM devices WHERE (last_error IS NOT NULL AND last_error <> '')").fetchall()
    cls_counts: Dict[str, int] = {
        "AUTH": 0,
        "TIMEOUT": 0,
        "CONNECTION": 0,
        "SSH_BANNER": 0,
        "SSH_NEGOTIATION": 0,
        "CHANNEL": 0,
        "UNKNOWN": 0,
    }
    for r in err_rows:
        cls = classify_error_message(r[0] or "")
        cls_counts[cls] = cls_counts.get(cls, 0) + 1
    out.update({f"err_{k.lower()}": v for k, v in cls_counts.items()})
    # Agregado por tipo: conectividad
    out["err_connectivity"] = cls_counts["SSH_BANNER"] + cls_counts["TIMEOUT"] + cls_counts["CONNECTION"]
    out["err_auth"] = cls_counts["AUTH"]
    out["err_channel"] = cls_counts["CHANNEL"]
    out["err_unknown"] = cls_counts["UNKNOWN"]
    return out


def export_csv(conn: sqlite3.Connection, dest_path: str):
    import csv
    cur = conn.cursor()
    rows = cur.execute(
        """
        SELECT d.host, d.vendor, d.platform, d.device_type, d.access_proto, d.access_port,
               d.ssh_open, d.telnet_open,
               d.user, d.comment, d.last_error, d.dump_done, d.scan_done, d.push_done, d.done, d.updated_at,
               i.hostname, i.version_line, i.ifaces_with_ip, i.GigabitEthernet, i.Gi,
               i.Loopback, i.lo, i.VLAN, i.vrf_brief, i.syslog_config, i.sockets_found,
               i.arp_brief
        FROM devices d
        LEFT JOIN inventory i ON i.host = d.host
        ORDER BY d.host
        """
    ).fetchall()
    headers = [
        "host",
        "vendor",
        "platform",
        "device_type",
        "access_proto",
        "access_port",
        "ssh_open",
        "telnet_open",
        "user",
        "comment",
        "last_error",
        "last_error_class",
        "dump_done",
        "scan_done",
        "push_done",
        "done",
        "updated_at",
        "hostname",
        "version_line",
        "ifaces_with_ip",
        "GigabitEthernet",
        "Gi",
        "Loopback",
        "lo",
        "VLAN",
        "vrf_brief",
        "syslog_config",
        "sockets_found",
        "arp_brief",
    ]
    with open(dest_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in rows:
            rd = dict(r) if isinstance(r, sqlite3.Row) else {}
            # Derivar clase de error
            le = (rd.get("last_error") or "").strip()
            dump_ok = int(rd.get("dump_done", 0))
            scan_ok = int(rd.get("scan_done", 0))
            push_ok = int(rd.get("push_done", 0))
            done_ok = int(rd.get("done", 0))
            if dump_ok or scan_ok or push_ok or done_ok:
                err_class = "OK"
            elif not le:
                err_class = "PENDING"
            else:
                err_class = classify_error_message(le)

            out = []
            for h in headers:
                if h == "last_error_class":
                    out.append(err_class)
                else:
                    out.append(rd.get(h, ""))
            w.writerow(out)
