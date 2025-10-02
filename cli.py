#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import time
import threading
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from netmiko import ConnectHandler

from .version import __version__
from .core.utils import (
    eprint,
    ensure_dir,
    now,
    sleep_min,
    tcp_open,
    sanitize_for_summary,
    classify_error_message,
    parse_hosts_file,
    dedupe_hosts,
)
from .core.config import load_credentials
from .core import db as dbmod
from .core import db_admin as dbadmin
from .net.connect import connect_with_retries, guess_device_type_via_sshdetect
from .net.detect import detect_platform, detect_platform_telnet
from .vendors.commands import (
    DEVICE_TYPES,
    DEVICE_TYPES_TELNET,
    CMD_SETS,
    HUAWEI_PRE_CMDS,
    HUAWEI_CMDS,
    FORTI_PRE_CMDS,
    FORTI_CMDS,
)
from .ops.dump import write_dump_files
from .ops.scan import (
    scan_inventory,
    first_nonempty_line,
    parse_hostname_from_runinc,
    fortinet_hostname_from_status,
)
from .ops.push import push_syslog_cisco, push_syslog_huawei, push_syslog_fortinet


ABORT_EVENT = threading.Event()


def process_host(host_entry, args, logger, outdir, cred_sets, db_path, families_keywords=None):
    # Abrir conexión propia por hilo
    db_conn = dbmod.connect(db_path)
    host = host_entry["host"]
    ssh_port = host_entry["port"] or args.ssh_port

    # Upsert inicial del host
    dbmod.upsert_device(
        db_conn,
        {
            "host": host,
            "ssh_port": ssh_port,
            "telnet_port": args.telnet_port,
            "vendor": "",
            "platform": "",
            "device_type": "",
            "access_proto": "",
            "access_port": None,
            "user": "",
            "comment": getattr(args, "comment", None) or "",
            "dump_done": 0,
            "scan_done": 0,
            "push_done": 0,
            "done": 0,
            "last_error": "",
            "updated_at": now(),
        },
    )

    # Pre-check TCP
    ssh_ok = tcp_open(host, ssh_port, timeout=3.0)
    telnet_ok = tcp_open(host, args.telnet_port, timeout=3.0)
    if logger:
        logger.debug(
            f"[{host}] Pre-check resultados: ssh_port={ssh_port} ssh_ok={ssh_ok} | telnet_port={args.telnet_port} telnet_ok={telnet_ok}"
        )
    try:
        dbmod.mark_status(db_conn, host, ssh_open=int(ssh_ok), telnet_open=int(telnet_ok), updated_at=now())
    except Exception:
        pass
    if not ssh_ok and not telnet_ok:
        msg = "No accesible por SSH/TELNET (pre-check falló)"
        dbmod.mark_status(db_conn, host, last_error=msg, updated_at=now())
        try:
            db_conn.close()
        except Exception:
            pass
        return host, False, msg

    # Rotar credenciales
    last_error = ""
    # Registrar el "mejor" error (prioriza conectividad sobre auth/unknown)
    best_err = {"msg": "", "cat": "", "score": -1}
    def _score(cat: str) -> int:
        order = {
            "SSH_BANNER": 5,
            "TIMEOUT": 5,
            "CONNECTION": 5,
            "SSH_NEGOTIATION": 4,
            "CHANNEL": 3,
            "AUTH": 2,
            "UNKNOWN": 0,
        }
        return order.get(cat or "", 0)
    def _record_err(msg: str) -> str:
        nonlocal last_error, best_err
        last_error = msg
        cat = classify_error_message(msg)
        sc = _score(cat)
        if sc > best_err["score"]:
            best_err = {"msg": msg, "cat": cat, "score": sc}
        return cat
    for cred_idx, cred in enumerate(cred_sets, 1):
        if ABORT_EVENT.is_set():
            try:
                db_conn.close()
            except Exception:
                pass
            return host, False, "ABORT"

        username = cred.get("username", "")
        password = cred.get("password", "")
        secret = cred.get("secret", "")
        logger.info(f"[{host}] Probando cred#{cred_idx} ({username})")

        # Detección por protocolo: SSH primero (si está abierto), luego Telnet
        det = None
        used_proto = None
        used_port = None
        # Callback para marcar cuando la autenticación fue exitosa (aunque falle la detección)
        def _auth_ok_cb(proto: str):
            try:
                # Persistir el usuario/proto/puerto apenas se valida credencial
                dbmod.mark_status(db_conn, host, user=username, access_proto=proto, access_port=(ssh_port if proto == 'ssh' else args.telnet_port), updated_at=now())
                if logger:
                    logger.debug(f"[{host}] AUTH OK via {proto} (cred={username})")
            except Exception:
                pass

        # Forzar Huawei si se indicó la bandera
        if args.huawei:
            if ssh_ok:
                used_proto = "ssh"
                used_port = ssh_port
                det = {
                    "platform": "huawei",
                    "device_type": DEVICE_TYPES.get("huawei", "huawei"),
                    "pre_cmds": list(HUAWEI_PRE_CMDS),
                    "commands": list(HUAWEI_CMDS),
                }
            elif telnet_ok:
                used_proto = "telnet"
                used_port = args.telnet_port
                det = {
                    "platform": "huawei",
                    "device_type": DEVICE_TYPES_TELNET.get("huawei", "huawei_telnet"),
                    "pre_cmds": list(HUAWEI_PRE_CMDS),
                    "commands": list(HUAWEI_CMDS),
                }
            else:
                msg = "No accesible por SSH/TELNET (pre-check falló)"
                dbmod.mark_status(db_conn, host, last_error=msg, updated_at=now())
                try:
                    db_conn.close()
                except Exception:
                    pass
                return host, False, msg
            logger.info(f"[{host}] Forzado Huawei via {used_proto}:{used_port}")
        # Forzar Fortinet si se indicó la bandera (y aún no hay det)
        if args.fortinet and det is None:
            if ssh_ok:
                used_proto = "ssh"
                used_port = ssh_port
                det = {
                    "platform": "fortinet",
                    "device_type": DEVICE_TYPES.get("fortinet", "fortinet"),
                    "pre_cmds": list(FORTI_PRE_CMDS),
                    "commands": list(FORTI_CMDS),
                }
            elif telnet_ok:
                used_proto = "telnet"
                used_port = args.telnet_port
                det = {
                    "platform": "fortinet",
                    "device_type": DEVICE_TYPES_TELNET.get("fortinet", "fortinet_telnet"),
                    "pre_cmds": list(FORTI_PRE_CMDS),
                    "commands": list(FORTI_CMDS),
                }
            else:
                msg = "No accesible por SSH/TELNET (pre-check falló)"
                dbmod.mark_status(db_conn, host, last_error=msg, updated_at=now())
                try:
                    db_conn.close()
                except Exception:
                    pass
                return host, False, msg
            logger.info(f"[{host}] Forzado Fortinet via {used_proto}:{used_port}")
        # Forzar Cisco si se indicó la bandera (y aún no hay det)
        if args.cisco and det is None:
            if ssh_ok:
                used_proto = "ssh"
                used_port = ssh_port
                det = {
                    "platform": "ios",
                    "device_type": DEVICE_TYPES.get("ios", "cisco_ios"),
                    "pre_cmds": [],
                    "commands": CMD_SETS.get("ios", []),
                }
            elif telnet_ok:
                used_proto = "telnet"
                used_port = args.telnet_port
                det = {
                    "platform": "ios",
                    "device_type": DEVICE_TYPES_TELNET.get("ios", "cisco_ios_telnet"),
                    "pre_cmds": [],
                    "commands": CMD_SETS.get("ios", []),
                }
            else:
                msg = "No accesible por SSH/TELNET (pre-check falló)"
                dbmod.mark_status(db_conn, host, last_error=msg, updated_at=now())
                try:
                    db_conn.close()
                except Exception:
                    pass
                return host, False, msg
            logger.info(f"[{host}] Forzado Cisco via {used_proto}:{used_port}")
        # Preferir Telnet si se pidió
        if args.prefer_telnet and telnet_ok and det is None:
            try:
                if logger:
                    logger.debug(f"[{host}] Preferencia Telnet: iniciando deteccion via telnet")
                det = detect_platform_telnet(
                    host=host,
                    username=username,
                    password=password,
                    secret=secret,
                    port=args.telnet_port,
                    vendor_hint=("huawei" if args.huawei else ("fortinet" if args.fortinet else ("cisco" if args.cisco else None))),
                    families_keywords=families_keywords,
                    logger=logger,
                    auth_cb=_auth_ok_cb,
                )
                used_proto = "telnet"
                used_port = args.telnet_port
            except Exception as e:
                msg = sanitize_for_summary(str(e))
                cat = _record_err(msg)
                logger.warning(f"[{host}] DETECT TELNET error ({cat}): {msg}")

        # SSH detection
        if ssh_ok and det is None:
            try:
                if logger:
                    logger.debug(f"[{host}] Intentando deteccion via SSH")
                det = detect_platform(
                    host=host,
                    username=username,
                    password=password,
                    secret=secret,
                    port=ssh_port,
                    vendor_hint=("huawei" if args.huawei else ("fortinet" if args.fortinet else ("cisco" if args.cisco else None))),
                    families_keywords=families_keywords,
                    logger=logger,
                    legacy=args.ssh_legacy,
                    auth_cb=_auth_ok_cb,
                )
                used_proto = "ssh"
                used_port = ssh_port
            except Exception as e:
                msg = sanitize_for_summary(str(e))
                cat = _record_err(msg)
                logger.warning(f"[{host}] DETECT SSH error ({cat}): {msg}")
                # Tras AUTH: no intentar Telnet (a menos que el usuario lo pida)
                skip_telnet_due_to_auth = (cat == "AUTH") and (not getattr(args, "fallback_telnet_on_auth", False))
                # Fallback inmediato a Telnet si falla negociación/connectividad y 23 está abierto
                if telnet_ok and det is None and (not skip_telnet_due_to_auth) and cat in ("SSH_NEGOTIATION", "SSH_BANNER", "CONNECTION"):
                    try:
                        det = detect_platform_telnet(
                            host=host,
                            username=username,
                            password=password,
                            secret=secret,
                            port=args.telnet_port,
                            vendor_hint=("huawei" if args.huawei else ("fortinet" if args.fortinet else ("cisco" if args.cisco else None))),
                            families_keywords=families_keywords,
                            logger=logger,
                            auth_cb=_auth_ok_cb,
                        )
                        used_proto = "telnet"
                        used_port = args.telnet_port
                    except Exception as e2:
                        msg2 = sanitize_for_summary(str(e2))
                        _record_err(msg2)
                        logger.warning(f"[{host}] DETECT TELNET fallback error: {msg2}")
                if args.cred_backoff and cat in ("SSH_BANNER", "SSH_NEGOTIATION", "CHANNEL", "CONNECTION") and det is None:
                    logger.info(f"[{host}] Backoff {args.cred_backoff}s antes de siguiente credencial")
                    try:
                        time.sleep(max(0, int(args.cred_backoff)))
                    except Exception:
                        time.sleep(1)

        # Telnet detection (multi-vendor) — se omite si venimos de AUTH en SSH y no se permite fallback
        if telnet_ok and det is None and not locals().get('skip_telnet_due_to_auth', False):
            try:
                if logger:
                    logger.debug(f"[{host}] Intentando deteccion via Telnet")
                det = detect_platform_telnet(
                    host=host,
                    username=username,
                    password=password,
                    secret=secret,
                    port=args.telnet_port,
                    vendor_hint=("huawei" if args.huawei else ("fortinet" if args.fortinet else ("cisco" if args.cisco else None))),
                    families_keywords=families_keywords,
                    logger=logger,
                    auth_cb=_auth_ok_cb,
                )
                used_proto = "telnet"
                used_port = args.telnet_port
            except Exception as e:
                msg = sanitize_for_summary(str(e))
                cat = _record_err(msg)
                logger.warning(f"[{host}] DETECT TELNET error ({cat}): {msg}")
                # Backoff sólo si aplica (normalmente no para Telnet)
                if args.cred_backoff and cat in ("TIMEOUT", "CONNECTION"):
                    logger.info(f"[{host}] Backoff {args.cred_backoff}s antes de siguiente credencial (telnet)")
                    try:
                        time.sleep(max(0, int(args.cred_backoff)))
                    except Exception:
                        time.sleep(1)

        if det is None:
            continue  # siguiente credencial

        # Log de detección
        try:
            logger.info(f"[{host}] Detectado {det['platform']}/{det['device_type']} via {used_proto}:{used_port}")
        except Exception:
            pass

        # Conectar ya con el device_type final
        platform_hint = str(det.get("platform", ""))
        params = dict(
            device_type=det["device_type"],
            host=host,
            port=used_port,
            username=username,
            password=password,
            secret=secret,
            fast_cli=False,
            conn_timeout=20 if platform_hint == "huawei" else 15,
            banner_timeout=45 if platform_hint == "huawei" else 20,
            auth_timeout=60 if platform_hint == "huawei" else 40,
            global_delay_factor=1,
        )
        # Pausa breve si venimos de una detección inmediata (algunos VRP cierran si se reconecta al instante)
        if platform_hint == "huawei":
            try:
                time.sleep(1.0)
            except Exception:
                pass
        # Compatibilidad con equipos antiguos: forzar algoritmos legacy y desactivar keys del agente
        if args.ssh_legacy:
            params.update(
                {
                    # Netmiko 4+: preferir no usar claves locales
                    "use_keys": False,
                    # Ampliar timeouts de banner/auth para stacks SSH lentos
                    "banner_timeout": 45,
                    "auth_timeout": 60,
                    # Deshabilitar algoritmos modernos para forzar fallback a ssh-rsa, CBC y DH antiguos
                    "disabled_algorithms": {
                        # Forzar ssh-rsa (SHA1) deshabilitando alternativas SHA2/ed25519/ecdsa
                        "pubkeys": [
                            "rsa-sha2-256",
                            "rsa-sha2-512",
                            "ssh-ed25519",
                            "ecdsa-sha2-nistp256",
                            "ecdsa-sha2-nistp384",
                            "ecdsa-sha2-nistp521",
                        ],
                        # Permitir DH group14/group1 dejando fuera curve/ecdhe/gex más nuevos
                        "kex": [
                            "curve25519-sha256",
                            "curve25519-sha256@libssh.org",
                            "ecdh-sha2-nistp256",
                            "ecdh-sha2-nistp384",
                            "ecdh-sha2-nistp521",
                            "diffie-hellman-group-exchange-sha256",
                            "diffie-hellman-group-exchange-sha1",
                            # Mantener group14-sha1 disponible; no lo deshabilitamos
                            # Nota: si el servidor sólo soporta group1, dependerá del soporte de Paramiko
                        ],
                        # Preferir CBC deshabilitando CTR/GCM/CHACHA modernos
                        "ciphers": [
                            "chacha20-poly1305@openssh.com",
                            "aes128-ctr",
                            "aes192-ctr",
                            "aes256-ctr",
                            "aes128-gcm@openssh.com",
                            "aes256-gcm@openssh.com",
                        ],
                        # Permitir hmac-sha1/md5 deshabilitando variantes sha2/etm/umac
                        "macs": [
                            "hmac-sha2-256",
                            "hmac-sha2-512",
                            "hmac-sha2-256-etm@openssh.com",
                            "hmac-sha2-512-etm@openssh.com",
                            "umac-64-etm@openssh.com",
                            "umac-128-etm@openssh.com",
                        ],
                    },
                }
            )
        conn = None
        try:
            conn = connect_with_retries(params, retries=3, logger=logger)
        except Exception as e:
            msg = sanitize_for_summary(str(e))
            cat = _record_err(msg)
            logger.warning(f"[{host}] CONNECT error ({cat}): {msg}")
            if args.cred_backoff and cat in ("SSH_BANNER", "SSH_NEGOTIATION", "CHANNEL", "TIMEOUT", "CONNECTION"):
                logger.info(f"[{host}] Backoff {args.cred_backoff}s antes de siguiente credencial")
                try:
                    time.sleep(max(0, int(args.cred_backoff)))
                except Exception:
                    time.sleep(1)
            continue

        platform = det["platform"]
        device_type = det["device_type"]
        if logger:
            logger.debug(
                f"[{host}] Deteccion resuelta: platform={platform} device_type={device_type} via={used_proto} pre_cmds={len(det.get('pre_cmds') or [])} cmds={len(det.get('commands') or [])}"
            )
        dbmod.mark_status(
            db_conn,
            host,
            vendor=platform if platform in ("huawei", "hp", "fortinet", "nokia") else "cisco",
            platform=platform,
            device_type=device_type,
            access_proto=used_proto,
            access_port=used_port,
            user=username,
            last_error="",
            updated_at=now(),
        )

        # Conexión establecida

        # Si hay secret, intentar enable en Cisco
        if secret and device_type.startswith("cisco"):
            try:
                conn.enable()
            except Exception:
                pass

        # Pre-cmds por vendor
        for pre in det.get("pre_cmds", []) or []:
            try:
                if logger:
                    logger.debug(f"PRE> {pre}")
                conn.send_command(pre, read_timeout=30)
            except Exception:
                pass
        # Fallback específico Huawei VRP 3.x: si 'temporary' no existe, usar 'screen-length 0'
        if platform == "huawei":
            try:
                conn.send_command("screen-length 0", read_timeout=10)
            except Exception:
                pass

        # 1) DUMP
        dump_ok = True
        if args.allops or args.dump:
            outputs = {}
            try:
                for cmd in det["commands"]:
                    if logger:
                        logger.debug(f"DUMP> {cmd}")
                    sleep_min(5)
                    # Huawei VRP muy antiguos pueden paginar 'display current-configuration' aun con pre-cmds.
                    if platform == "huawei" and re.match(r"^display (current|saved)-configuration", cmd, re.I):
                        try:
                            out = conn.send_command_timing(cmd, strip_prompt=False, strip_command=False)
                            # Consumir 'More' si aparece
                            tries = 0
                            while re.search(r"more|\-+\s*more\s*\-+", out, re.I) and tries < 500:
                                chunk = conn.send_command_timing(" ", strip_prompt=False, strip_command=False)
                                out += chunk
                                tries += 1
                        except Exception:
                            out = conn.send_command(cmd, read_timeout=300, expect_string=None)
                    elif platform in ("ios", "nxos", "iosxr", "asa") and re.match(r"^terminal\s+(length|width)\b", cmd, re.I):
                        # Para evitar problemas de patrón con 'terminal width 511'
                        out = conn.send_command_timing(cmd, strip_prompt=False, strip_command=False)
                    else:
                        out = conn.send_command(cmd, read_timeout=300, expect_string=None)
                    outputs[cmd] = out
                write_dump_files(outdir, host, platform, device_type, outputs)
                dbmod.mark_status(db_conn, host, dump_done=1, updated_at=now())
                logger.info(f"[{host}] DUMP OK ({platform}/{device_type})")

                # Mini-llenado post-DUMP: hostname y version_line para todos los vendors
                try:
                    inv = {"hostname": "", "version_line": ""}
                    if platform in ("ios", "nxos", "iosxr", "asa"):
                        try:
                            run_all = outputs.get("show running-config", "") or ""
                            # Buscar línea 'hostname <name>'
                            m = re.search(r"^\s*hostname\s+(.+)$", run_all, re.M | re.I)
                            if m:
                                inv["hostname"] = parse_hostname_from_runinc(m.group(0))
                        except Exception:
                            pass
                        ver_all = outputs.get("show version", "") or ""
                        inv["version_line"] = first_nonempty_line(ver_all)
                    elif platform == "huawei":
                        try:
                            cur = outputs.get("display current-configuration", "") or ""
                            # sysname <name>
                            for ln in cur.splitlines():
                                s = ln.strip()
                                if s.lower().startswith("sysname"):
                                    parts = s.split()
                                    if len(parts) >= 2:
                                        inv["hostname"] = parts[1]
                                        break
                        except Exception:
                            pass
                        ver_all = outputs.get("display version", "") or ""
                        try:
                            from .ops.scan import huawei_version_line as _hvrp
                            inv["version_line"] = _hvrp(ver_all)
                        except Exception:
                            inv["version_line"] = first_nonempty_line(ver_all)
                    elif platform == "hp":
                        try:
                            cur = outputs.get("display current-configuration", "") or ""
                            # Comware también usa 'sysname'
                            for ln in cur.splitlines():
                                s = ln.strip()
                                if s.lower().startswith("sysname"):
                                    parts = s.split()
                                    if len(parts) >= 2:
                                        inv["hostname"] = parts[1]
                                        break
                        except Exception:
                            pass
                        ver_all = outputs.get("display version", "") or ""
                        inv["version_line"] = first_nonempty_line(ver_all)
                    elif platform == "fortinet":
                        st = outputs.get("get system status", "") or ""
                        inv["hostname"] = fortinet_hostname_from_status(st)
                        # Extraer línea 'Version:'
                        ver_line = ""
                        for ln in st.splitlines():
                            s = ln.strip()
                            if s.lower().startswith("version:"):
                                ver_line = s
                                break
                        inv["version_line"] = ver_line or first_nonempty_line(st)
                    elif platform == "nokia":
                        # Intentar del config: 'configure system name "HOST"' o 'system name "HOST"'
                        cfg = outputs.get("admin display-config") or outputs.get("show configuration") or ""
                        try:
                            m = re.search(r"\bsystem\s+name\s+\"([^\"]+)\"", cfg)
                            if m:
                                inv["hostname"] = m.group(1)
                        except Exception:
                            pass
                        ver_all = outputs.get("show version", "") or ""
                        inv["version_line"] = first_nonempty_line(ver_all)
                    # Escribir si hay algún dato
                    if inv.get("hostname") or inv.get("version_line"):
                        dbmod.write_inventory(db_conn, host, inv)
                except Exception:
                    pass
            except Exception as e:
                dump_ok = False
                msg = sanitize_for_summary(str(e))
                dbmod.mark_status(db_conn, host, dump_done=0, last_error=f"DUMP: {msg}", updated_at=now())
                logger.warning(f"[{host}] DUMP ERROR: {msg}")

        # 2) PUSH (Cisco/Huawei/Fortinet)
        push_ok = True
        if (args.allops or args.push):
            if platform in ("ios", "nxos", "iosxr", "asa"):
                ok, msg = push_syslog_cisco(
                    conn,
                    host,
                    args.syslog_ip,
                    args.syslog_port,
                    args.logging_source,
                    sleep_min,
                    logger,
                )
            elif platform == "huawei":
                ok, msg = push_syslog_huawei(
                    conn,
                    host,
                    args.syslog_ip,
                    args.syslog_port,
                    args.logging_source,
                    sleep_min,
                    logger,
                )
            elif platform == "fortinet":
                ok, msg = push_syslog_fortinet(
                    conn,
                    host,
                    args.syslog_ip,
                    args.syslog_port,
                    args.logging_source,
                    sleep_min,
                    logger,
                )
            else:
                ok, msg = False, f"PUSH no soportado para plataforma {platform}"
            if ok:
                dbmod.mark_status(db_conn, host, push_done=1, updated_at=now())
                # Mini-llenado: capturar solo hostname post-PUSH (sin SCAN completo)
                try:
                    inv = {"hostname": ""}
                    if platform in ("ios", "nxos", "iosxr", "asa"):
                        try:
                            if logger:
                                logger.debug("PUSH-META> show run | include ^hostname")
                            hn = conn.send_command("show run | include ^hostname", read_timeout=20)
                            inv["hostname"] = parse_hostname_from_runinc(first_nonempty_line(hn))
                        except Exception:
                            pass
                    elif platform == "huawei":
                        try:
                            if logger:
                                logger.debug("PUSH-META> display current-configuration | include sysname")
                            hn = conn.send_command("display current-configuration | include sysname", read_timeout=20)
                            line = first_nonempty_line(hn)
                            inv["hostname"] = (line.split()[1] if line.lower().startswith("sysname") and len(line.split()) > 1 else line)
                        except Exception:
                            pass
                    elif platform == "fortinet":
                        try:
                            if logger:
                                logger.debug("PUSH-META> get system status")
                            st = conn.send_command("get system status", read_timeout=30)
                            inv["hostname"] = fortinet_hostname_from_status(st)
                        except Exception:
                            pass
                    if inv.get("hostname"):
                        dbmod.write_inventory(db_conn, host, inv)
                except Exception:
                    pass
            else:
                push_ok = False
                dbmod.mark_status(db_conn, host, push_done=0, last_error=msg, updated_at=now())
                logger.warning(f"[{host}] {msg}")

        # 3) SCAN
        scan_ok = True
        if args.allops or args.scan or args.scan_only:
            inventory = {
                "hostname": "",
                "version_line": "",
                "ifaces_with_ip": "",
                "GigabitEthernet": "",
                "Gi": "",
                "Loopback": "",
                "lo": "",
                "VLAN": "",
                "vrf_brief": "",
                "syslog_config": "",
                "sockets_found": "",
                "route_brief": "",
                "arp_brief": "",
            }
            ok, msg = scan_inventory(conn, host, platform, args, logger, inventory)
            if ok:
                dbmod.write_inventory(db_conn, host, inventory)
                dbmod.mark_status(db_conn, host, scan_done=1, updated_at=now())
                logger.info(f"[{host}] SCAN OK")
            else:
                scan_ok = False
                dbmod.mark_status(db_conn, host, scan_done=0, last_error=msg, updated_at=now())
                logger.warning(f"[{host}] {msg}")

        try:
            conn.disconnect()
        except Exception:
            pass

        # Done
        # done=1 si todas las operaciones solicitadas terminaron OK
        if args.allops:
            is_done = int(bool(dump_ok and scan_ok and push_ok))
        else:
            requested = []
            if args.dump:
                requested.append(dump_ok)
            if args.scan or args.scan_only:
                requested.append(scan_ok)
            if args.push:
                requested.append(push_ok)
            # Si no se solicitó ninguna, no marcar done
            is_done = int(all(requested)) if requested else 0
        dbmod.mark_status(db_conn, host, done=is_done, updated_at=now())

        if (args.allops and is_done) or (args.dump and dump_ok) or ((args.scan or args.scan_only) and scan_ok) or (args.push and push_ok):
            try:
                db_conn.close()
            except Exception:
                pass
            return host, True, f"OK {used_proto}:{used_port} (cred#{cred_idx})"
        else:
            try:
                db_conn.close()
            except Exception:
                pass
            return host, False, f"FAIL {used_proto}:{used_port} (cred#{cred_idx})"

    # agotadas credenciales
    final_msg = best_err.get("msg") or last_error or "AUTH/CONNECT failed"
    dbmod.mark_status(db_conn, host, last_error=final_msg, updated_at=now())
    try:
        db_conn.close()
    except Exception:
        pass
    return host, False, final_msg
    # Nota: la conexión se cerrará al finalizar el hilo


def main():
    parser = argparse.ArgumentParser(
        description=f"Multivendor Tool v{__version__} — Dump/Scan/Push con reanudación (SQLite)"
    )

    sub = parser.add_subparsers(dest="cmd", required=True)

    # run
    p_run = sub.add_parser("run", help="Procesa una lista de hosts (dump/scan/push/allops)")
    p_run.add_argument("-H", "--hosts-file", help="Archivo de hosts (uno por línea)")
    p_run.add_argument("--config", help="Archivo JSON con configuración por defecto para 'run'")
    p_run.add_argument("-o", "--outdir", default="mv_results", help="Directorio de salida (default: mv_results/)")
    p_run.add_argument("-d", "--db", help="Ruta a SQLite (default: <outdir>/mvtool.db)")
    p_run.add_argument("--comment", help="Comentario libre para anotar la corrida (se guarda por host)")
    p_run.add_argument("-w", "--workers", type=int, default=40, help="Hilos en paralelo (default: 40)")
    p_run.add_argument("-r", "--retries", type=int, default=2, help="Reintentos (default: 2)")
    p_run.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Nivel de logging")
    # Puertos
    p_run.add_argument("--ssh-port", type=int, default=22, help="Puerto SSH (default: 22)")
    p_run.add_argument("--telnet-port", type=int, default=23, help="Puerto Telnet (default: 23)")
    # Modos (combinables). Mantener --scan-only por compatibilidad.
    p_run.add_argument("--dump", action="store_true", help="DUMP: extraer configuraciones completas")
    p_run.add_argument("--scan", action="store_true", help="SCAN: inventario/columnas")
    p_run.add_argument("--scan-only", action="store_true", help="[Compat] igual a --scan")
    p_run.add_argument("--push", action="store_true", help="PUSH: configura syslog (según vendor)")
    p_run.add_argument("--allops", action="store_true", help="ALL: dump + scan + push")
    # Syslog
    p_run.add_argument("--syslog-ip", help="IP del servidor Syslog (requerido para --scan-only/--push/--allops si se desea sockets)")
    p_run.add_argument("--syslog-port", type=int, default=514, help="Puerto UDP syslog (default: 514)")
    p_run.add_argument("-s", "--logging-source", help="Interfaz para 'logging source-interface'")
    # Extras
    p_run.add_argument("--ssh-legacy", action="store_true", help="Compatibilidad con equipos antiguos")
    p_run.add_argument("--cred-backoff", type=int, default=0, help="Dormir N segundos entre credenciales cuando ocurren errores de banner/negociación SSH")
    p_run.add_argument("--prefer-netconf", action="store_true", help="(Reservado) Intentar NETCONF para IOS")
    p_run.add_argument("--prefer-telnet", action="store_true", help="Intentar detección por Telnet antes que SSH si 23 está abierto")
    p_run.add_argument("--netconf-port", type=int, default=830, help="Puerto NETCONF (default: 830)")
    p_run.add_argument("--families-file", help="Archivo de familias para hints de detección")
    p_run.add_argument("--credentials-file", help="Ruta a JSON con credenciales [{username,password,secret}]")
    p_run.add_argument("--no-prompt", action="store_true", help="No preguntar en consola (sin reanudación interactiva)")
    p_run.add_argument("--huawei", action="store_true", help="Forzar Huawei (omite autodetección multi-vendor)")
    p_run.add_argument("--fortinet", action="store_true", help="Forzar Fortinet (omite autodetección multi-vendor)")
    p_run.add_argument("--cisco", action="store_true", help="Forzar Cisco IOS/IOS-XE (omite autodetección multi-vendor)")

    # db
    p_db = sub.add_parser("db", help="Operaciones sobre la base de datos (backup, export, pending, counts, reset, etc.)")
    sp = p_db.add_subparsers(dest="db_cmd", required=True)

    p_db_backup = sp.add_parser("backup", help="Crea un backup de la BD")
    p_db_backup.add_argument("-d", "--db", required=True, help="Ruta a SQLite")
    p_db_backup.add_argument("-o", "--output", required=True, help="Ruta destino del backup .db")

    p_db_counts = sp.add_parser("counts", help="Muestra conteos y métricas")
    p_db_counts.add_argument("-d", "--db", required=True, help="Ruta a SQLite")

    p_db_exp_dev = sp.add_parser("export-devices", help="Exporta tabla devices a CSV")
    p_db_exp_dev.add_argument("-d", "--db", required=True, help="Ruta a SQLite")
    p_db_exp_dev.add_argument("-o", "--output", required=True, help="Archivo CSV destino")

    p_db_exp_inv = sp.add_parser("export-inventory", help="Exporta tabla inventory a CSV")
    p_db_exp_inv.add_argument("-d", "--db", required=True, help="Ruta a SQLite")
    p_db_exp_inv.add_argument("-o", "--output", required=True, help="Archivo CSV destino")

    p_db_hosts = sp.add_parser("hosts", help="Lista hosts de devices")
    p_db_hosts.add_argument("-d", "--db", required=True, help="Ruta a SQLite")
    p_db_hosts.add_argument("--where", help="Cláusula WHERE opcional (sin 'WHERE')")
    p_db_hosts.add_argument("--format", choices=["txt", "csv"], default="txt")
    p_db_hosts.add_argument("-o", "--output", help="Archivo de salida (si no, stdout)")

    p_db_pending = sp.add_parser("pending", help="Lista hosts pendientes por operación")
    p_db_pending.add_argument("-d", "--db", required=True, help="Ruta a SQLite")
    p_db_pending.add_argument("--mode", choices=["dump", "scan", "push", "all"], required=True)
    p_db_pending.add_argument("-o", "--output", help="Archivo de salida (si no, stdout)")

    p_db_errors = sp.add_parser("errors", help="Lista hosts con errores (clasificados)")
    p_db_errors.add_argument("-d", "--db", required=True, help="Ruta a SQLite")
    p_db_errors.add_argument("--class", dest="err_class", choices=["connectivity", "auth", "channel", "all"], default="all")
    p_db_errors.add_argument("-o", "--output", help="Archivo CSV destino (si no, stdout)")

    p_db_reset = sp.add_parser("reset", help="Vacía las tablas (requiere --yes)")
    p_db_reset.add_argument("-d", "--db", required=True, help="Ruta a SQLite")
    p_db_reset.add_argument("--yes", action="store_true", help="Confirmar operación destructiva")

    p_db_vacuum = sp.add_parser("vacuum", help="Compacta la base de datos")
    p_db_vacuum.add_argument("-d", "--db", required=True, help="Ruta a SQLite")

    p_db_migrate = sp.add_parser("migrate", help="Asegura columnas/estructura (migración suave)")
    p_db_migrate.add_argument("-d", "--db", required=True, help="Ruta a SQLite")

    p_db_sql = sp.add_parser("sql", help="Ejecuta SELECT de solo lectura")
    p_db_sql.add_argument("-d", "--db", required=True, help="Ruta a SQLite")
    p_db_sql.add_argument("--query", required=True, help="Consulta SELECT a ejecutar")
    p_db_sql.add_argument("--format", choices=["txt", "csv"], default="txt")
    p_db_sql.add_argument("-o", "--output", help="Archivo de salida (si no, stdout)")

    # report
    p_rep = sub.add_parser("report", help="Muestra conteos por estado desde SQLite")
    p_rep.add_argument("-d", "--db", required=True, help="Ruta a SQLite")

    # export
    p_exp = sub.add_parser("export", help="Exporta CSV consolidado")
    p_exp.add_argument("-d", "--db", required=True, help="Ruta a SQLite")
    p_exp.add_argument("-o", "--output", required=True, help="Archivo CSV destino")

    args = parser.parse_args()

    # db subcommands
    if args.cmd == "db":
        if args.db_cmd == "backup":
            dbadmin.backup(args.db, args.output)
            print(f"Backup creado en {args.output}")
            return
        if args.db_cmd == "counts":
            print(json.dumps(dbadmin.counts(args.db), indent=2, ensure_ascii=False))
            return
        if args.db_cmd == "export-devices":
            dbadmin.export_devices(args.db, args.output)
            print(f"Devices exportado en {args.output}")
            return
        if args.db_cmd == "export-inventory":
            dbadmin.export_inventory(args.db, args.output)
            print(f"Inventory exportado en {args.output}")
            return
        if args.db_cmd == "hosts":
            dbadmin.list_hosts(args.db, args.where, args.format, args.output)
            return
        if args.db_cmd == "pending":
            dbadmin.pending(args.db, args.mode, args.output)
            return
        if args.db_cmd == "errors":
            dbadmin.list_errors(args.db, args.err_class, args.output)
            return
        if args.db_cmd == "reset":
            if not args.yes:
                print("ERROR: usa --yes para confirmar reset")
                return
            dbadmin.reset(args.db)
            print("Base limpiada")
            return
        if args.db_cmd == "vacuum":
            dbadmin.vacuum(args.db)
            print("VACUUM ejecutado")
            return
        if args.db_cmd == "migrate":
            dbadmin.migrate(args.db)
            print("Migración/estructura asegurada")
            return
        if args.db_cmd == "sql":
            dbadmin.sql_readonly(args.db, args.query, args.format, args.output)
            return

    if args.cmd == "report":
        conn = dbmod.connect(args.db)
        cnt = dbmod.get_counts(conn)
        print(json.dumps(cnt, indent=2, ensure_ascii=False))
        return

    if args.cmd == "export":
        conn = dbmod.connect(args.db)
        dbmod.export_csv(conn, args.output)
        print(f"CSV exportado en {args.output}")
        return

    # cmd == run
    if args.cmd == "run":
        eprint(f"=== MVTool v{__version__} === {now()}")
        # Cargar configuración (si existe) y aplicar valores por defecto
        try:
            from .core.config import load_run_config
            conf = load_run_config(args.config)
        except Exception:
            conf = {}
        def apply_conf(key, attr=None):
            k = key
            a = attr or key.replace("-", "_")
            if k in conf:
                try:
                    setattr(args, a, conf[k])
                except Exception:
                    pass
        # Lista de claves soportadas en config
        for k in (
            "hosts_file","outdir","db","workers","retries","log_level",
            "ssh_port","telnet_port","dump","scan","scan_only","push","allops",
            "syslog_ip","syslog_port","logging_source","ssh_legacy","cred_backoff",
            "prefer_netconf","prefer_telnet","netconf_port","families_file",
            "credentials_file","no_prompt","huawei","fortinet","cisco","comment",
            "fallback_telnet_on_auth",
        ):
            apply_conf(k)
        # Validaciones mínimas
        if not args.hosts_file:
            eprint("ERROR: se requiere --hosts-file o 'hosts_file' en el archivo de configuración")
            return
    # Compatibilidad: --scan-only equivale a --scan
    if getattr(args, "scan_only", False):
        args.scan = True
    # Flags de forzado: no permitir múltiples a la vez
    forced_flags = int(bool(args.huawei)) + int(bool(args.fortinet)) + int(bool(args.cisco))
    if forced_flags > 1:
        eprint("ERROR: Flags de forzado mutualmente excluyentes (--huawei/--fortinet/--cisco)")
        return
    if (args.push or args.allops) and not args.syslog_ip:
        eprint("ERROR: --syslog-ip es requerido para --push y --allops")
        return
    outdir = args.outdir
    ensure_dir(outdir)
    db_path = args.db or os.path.join(outdir, "mvtool.db")
    conn = dbmod.connect(db_path)
    dbmod.init_db(conn)

    # Logging
    log_path = os.path.join(outdir, "run.log")
    logger = logging.getLogger("MVTool")
    logger.setLevel(getattr(logging, args.log_level))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    fh.setLevel(getattr(logging, args.log_level))
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    ch.setLevel(getattr(logging, args.log_level))
    logger.handlers.clear()
    logger.addHandler(fh)
    logger.addHandler(ch)
    comment_txt = getattr(args, "comment", "") or ""
    logger.info(f"MVTool v{__version__} iniciado comment='{comment_txt}'")
    try:
        for name in (
            "paramiko",
            "paramiko.transport",
            "paramiko.transport.sftp",
        ):
            plog = logging.getLogger(name)
            plog.setLevel(logging.CRITICAL)
            plog.propagate = False
            for h in list(plog.handlers or []):
                plog.removeHandler(h)
        logging.getLogger("netmiko").setLevel(logging.INFO)
    except Exception:
        pass

    # Cargar hosts
    try:
        hosts_raw = parse_hosts_file(args.hosts_file)
    except Exception as e:
        logger.error(f"ERROR leyendo hosts: {e}")
        return
    hosts, removed = dedupe_hosts(hosts_raw, args.ssh_port)
    logger.info(f"Hosts totales: {len(hosts_raw)} | únicos: {len(hosts)} | duplicados eliminados: {removed}")

    # Opcional: reanudación interactiva (si no hay modo especificado y no --no-prompt)
    if not (args.dump or args.scan or args.scan_only or args.push or args.allops) and not args.no_prompt:
        pend_all = list(dbmod.pending_hosts(conn, "allops"))
        pend_dump = list(dbmod.pending_hosts(conn, "dump"))
        pend_scan = list(dbmod.pending_hosts(conn, "scan"))
        pend_push = list(dbmod.pending_hosts(conn, "push"))
        eprint(f"Pendientes: all={len(pend_all)} dump={len(pend_dump)} scan={len(pend_scan)} push={len(pend_push)}")
        choice = input("¿Ejecutar --allops para todos los pendientes? (y/n) ").strip().lower()
        if choice == "y":
            args.allops = True
        else:
            choice = input("¿Ejecutar --dump para los que falten? (y/n) ").strip().lower()
            if choice == "y":
                args.dump = True
            choice = input("¿Ejecutar --scan para los que falten? (y/n) ").strip().lower()
            if choice == "y":
                args.scan = True
            choice = input("¿Ejecutar --push para los que falten? (y/n) ").strip().lower()
            if choice == "y":
                args.push = True

    # Cargar credenciales
    cred_sets = load_credentials(args.credentials_file)
    if not cred_sets:
        eprint("ATENCIÓN: No se cargaron credenciales. Usa --credentials-file o MV_CREDENTIALS_FILE.")
        return

    # Families file
    families_keywords = None
    if args.families_file and os.path.exists(args.families_file):
        try:
            families_keywords = {}
            with open(args.families_file, "r", encoding="utf-8") as f:
                for line in f:
                    name = line.strip().upper()
                    if not name or name.startswith("#"):
                        continue
                    if "NEXUS" in name:
                        families_keywords[name] = "nxos"
                    elif "ASR 9" in name or "ASR9" in name:
                        families_keywords[name] = "iosxr"
                    elif "ASA" in name or "FIREPOWER" in name:
                        families_keywords[name] = "asa"
                    else:
                        families_keywords[name] = "ios"
        except Exception:
            families_keywords = None

    # Ejecutar en paralelo
    ok_count = 0
    total = len(hosts)
    completed = 0
    lock = threading.Lock()

    def progress_cb(host, ok, msg):
        nonlocal ok_count, completed
        with lock:
            completed += 1
            if ok:
                ok_count += 1
            prefix = f"[{completed}/{total}]"
            eprint(f"{prefix} {host} {'OK' if ok else 'FAIL'} - {msg}")

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [
            ex.submit(process_host, h, args, logger, outdir, cred_sets, db_path, families_keywords)
            for h in hosts
        ]
        for fut in as_completed(futures):
            try:
                host, ok, msg = fut.result()
                progress_cb(host, ok, msg)
            except Exception as e:
                eprint(f"Worker exception: {sanitize_for_summary(str(e))}")

    fail_count = total - ok_count
    try:
        conn.close()
    except Exception:
        pass
    eprint(f"Resumen: OK={ok_count} FAIL={fail_count} Total={total}")
    eprint(f"DB: {db_path}")
    eprint(f"Log: {log_path}")


if __name__ == "__main__":
    main()
