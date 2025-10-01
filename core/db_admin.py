import csv
import os
import sqlite3
from typing import Iterable, Optional

from . import db as dbmod
from .utils import classify_error_message


def _connect(db_path: str) -> sqlite3.Connection:
    return dbmod.connect(db_path)


def backup(db_path: str, out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with _connect(db_path) as src:
        with sqlite3.connect(out_path) as dst:
            src.backup(dst)


def counts(db_path: str) -> dict:
    with _connect(db_path) as conn:
        return dbmod.get_counts(conn)


def export_devices(db_path: str, out_path: str) -> None:
    with _connect(db_path) as conn:
        cur = conn.cursor()
        rows = cur.execute(
            """
            SELECT host, vendor, platform, device_type, access_proto, access_port,
                   ssh_open, telnet_open,
                   user, comment, last_error, dump_done, scan_done, push_done, done, updated_at
            FROM devices
            ORDER BY host
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
        ]
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in rows:
                rd = dict(r) if isinstance(r, sqlite3.Row) else None
                if rd is None:
                    # Older sqlite versions may not return Row; map manually
                    (host, vendor, platform, device_type, access_proto, access_port,
                     ssh_open, telnet_open, user, comment, last_error, dump_done, scan_done, push_done, done, updated_at) = r
                    rd = {
                        "host": host,
                        "vendor": vendor,
                        "platform": platform,
                        "device_type": device_type,
                        "access_proto": access_proto,
                        "access_port": access_port,
                        "ssh_open": ssh_open,
                        "telnet_open": telnet_open,
                        "user": user,
                        "comment": comment,
                        "last_error": last_error,
                        "dump_done": dump_done,
                        "scan_done": scan_done,
                        "push_done": push_done,
                        "done": done,
                        "updated_at": updated_at,
                    }
                le = (rd.get("last_error") or "").strip()
                if rd.get("dump_done") or rd.get("scan_done") or rd.get("push_done") or rd.get("done"):
                    cls = "OK"
                elif not le:
                    cls = "PENDING"
                else:
                    cls = classify_error_message(le)
                out_row = [
                    rd.get("host"),
                    rd.get("vendor"),
                    rd.get("platform"),
                    rd.get("device_type"),
                    rd.get("access_proto"),
                    rd.get("access_port"),
                    rd.get("ssh_open"),
                    rd.get("telnet_open"),
                    rd.get("user"),
                    rd.get("comment"),
                    le,
                    cls,
                    rd.get("dump_done"),
                    rd.get("scan_done"),
                    rd.get("push_done"),
                    rd.get("done"),
                    rd.get("updated_at"),
                ]
                w.writerow(out_row)


def export_inventory(db_path: str, out_path: str) -> None:
    with _connect(db_path) as conn:
        cur = conn.cursor()
        rows = cur.execute(
            """
            SELECT host, hostname, version_line, ifaces_with_ip, GigabitEthernet, Gi,
                   Loopback, lo, VLAN, vrf_brief, syslog_config, sockets_found,
                   arp_brief
            FROM inventory
            ORDER BY host
            """
        ).fetchall()
        headers = [
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
            "arp_brief",
        ]
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in rows:
                if isinstance(r, sqlite3.Row):
                    w.writerow([r[h] for h in headers])
                else:
                    w.writerow(list(r))


def list_hosts(db_path: str, where: Optional[str], fmt: str, out_path: Optional[str]) -> None:
    with _connect(db_path) as conn:
        cur = conn.cursor()
        q = "SELECT host FROM devices"
        if where:
            q += f" WHERE {where}"
        q += " ORDER BY host"
        rows = [r[0] for r in cur.execute(q).fetchall()]
    txt = "\n".join(rows) if fmt == "txt" else "\n".join(["host"] + rows)
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(txt + ("\n" if txt else ""))
    else:
        print(txt)


def pending(db_path: str, mode: str, out_path: Optional[str]) -> None:
    with _connect(db_path) as conn:
        key = {"all": "allops", "dump": "dump", "scan": "scan", "push": "push"}[mode]
        hosts = [h for h in dbmod.pending_hosts(conn, key)]
    txt = "\n".join(hosts)
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(txt + ("\n" if txt else ""))
    else:
        print(txt)


def list_errors(db_path: str, cls_filter: str, out_path: Optional[str]) -> None:
    with _connect(db_path) as conn:
        cur = conn.cursor()
        rows = cur.execute(
            "SELECT host,last_error,dump_done,scan_done,push_done,done FROM devices ORDER BY host"
        ).fetchall()
    headers = ["host", "last_error", "last_error_class"]
    out_rows = []
    for r in rows:
        host, le, dd, sd, pd, dn = r
        if (dd or sd or pd or dn):
            cls = "OK"
        elif not (le or "").strip():
            cls = "PENDING"
        else:
            cls = classify_error_message(le or "")
        if cls_filter == "connectivity" and cls not in ("SSH_BANNER", "TIMEOUT", "CONNECTION", "SSH_NEGOTIATION"):
            continue
        if cls_filter == "auth" and cls != "AUTH":
            continue
        if cls_filter == "channel" and cls != "CHANNEL":
            continue
        out_rows.append([host, (le or "").strip(), cls])
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(headers)
            w.writerows(out_rows)
    else:
        print("\n".join([",".join(headers)] + [",".join(map(str, r)) for r in out_rows]))


def reset(db_path: str) -> None:
    # Borrar datos en una transacción
    with _connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM inventory")
        cur.execute("DELETE FROM devices")
        conn.commit()
    # Ejecutar VACUUM fuera de transacción (autocommit)
    with sqlite3.connect(db_path) as vconn:
        # Asegurar autocommit para permitir VACUUM
        try:
            vconn.isolation_level = None
        except Exception:
            pass
        vconn.execute("VACUUM")


def vacuum(db_path: str) -> None:
    # Ejecutar VACUUM en conexión autocommit
    with sqlite3.connect(db_path) as conn:
        try:
            conn.isolation_level = None
        except Exception:
            pass
        conn.execute("VACUUM")


def migrate(db_path: str) -> None:
    with _connect(db_path) as conn:
        dbmod.init_db(conn)


def sql_readonly(db_path: str, query: str, fmt: str, out_path: Optional[str]) -> None:
    q = query.strip()
    if not q.lower().startswith("select"):
        raise ValueError("Solo se permiten consultas SELECT en modo readonly")
    with _connect(db_path) as conn:
        cur = conn.cursor()
        rows = cur.execute(q).fetchall()
        cols = [d[0] for d in cur.description]
    if fmt == "csv":
        if out_path:
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            with open(out_path, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(cols)
                for r in rows:
                    if isinstance(r, sqlite3.Row):
                        w.writerow([r[c] for c in cols])
                    else:
                        w.writerow(list(r))
        else:
            print(",".join(cols))
            for r in rows:
                if isinstance(r, sqlite3.Row):
                    print(",".join([str(r[c]) for c in cols]))
                else:
                    print(",".join(map(str, r)))
    else:
        # txt
        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("\t".join(cols) + "\n")
                for r in rows:
                    vals = [str(r[c]) if isinstance(r, sqlite3.Row) else str(v) for c, v in zip(cols, r)]
                    f.write("\t".join(vals) + "\n")
        else:
            print("\t".join(cols))
            for r in rows:
                vals = [str(r[c]) if isinstance(r, sqlite3.Row) else str(v) for c, v in zip(cols, r)]
                print("\t".join(vals))
