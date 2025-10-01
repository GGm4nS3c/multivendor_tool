import re
from typing import Dict


def get_config_commands(syslog_ip: str, syslog_port: int, logging_source_iface: str | None = None):
    base = [
        f"no logging host {syslog_ip}",
        f"logging host {syslog_ip} transport udp port {syslog_port}",
        "service timestamps log datetime msec localtime show-timezone",
        "service sequence-numbers",
        "logging userinfo",
        "logging buffered 52000",
        "logging history debugging",
        "logging trap debugging",
        "logging origin-id hostname",
        "logging facility syslog",
        "archive",
        " log config",
        "  logging enable",
        "  notify syslog contenttype plaintext",
        "  hidekeys",
        "login on-success log",
        "login on-failure log",
    ]
    if logging_source_iface:
        idx = base.index("logging facility syslog")
        base.insert(idx + 1, f"logging source-interface {logging_source_iface}")
    return base


def send_config_with_delay(conn, commands, sleep_fn, logger=None):
    try:
        conn.config_mode()
    except Exception:
        try:
            conn.send_config_set([], exit_config_mode=False)
        except Exception:
            pass
    sleep_fn(1)
    for cmd in commands:
        if logger:
            logger.debug(f"CFG> {cmd}")
        conn.send_command_timing(cmd, strip_prompt=False, strip_command=False)
        sleep_fn(1)
    try:
        conn.exit_config_mode()
    except Exception:
        pass


def push_syslog_cisco(conn, host: str, syslog_ip: str, syslog_port: int, logging_source: str | None, sleep_fn, logger=None) -> tuple[bool, str]:
    try:
        cfg = get_config_commands(syslog_ip, syslog_port, logging_source)
        if logger:
            logger.info(f"[{host}] Enviando config syslog (Cisco)")
        send_config_with_delay(conn, cfg, sleep_fn, logger)

        try:
            sleep_fn(1)
            conn.save_config()
        except Exception:
            try:
                sleep_fn(1)
                conn.send_command_timing("write memory", strip_prompt=False, strip_command=False)
            except Exception:
                pass
        return True, "PUSH OK"
    except Exception as e:
        return False, f"PUSH ERROR: {e}"


def push_syslog_huawei(conn, host: str, syslog_ip: str, syslog_port: int, logging_source: str | None, sleep_fn, logger=None) -> tuple[bool, str]:
    """
    Configura syslog remoto en Huawei VRP/WAP.

    Estrategia:
    - Intentar VRP 5/8: 'info-center ... level debugging' + 'info-center loghost <ip> facility local7 port <port>'.
    - Si falla 'level', fallback VRP 3.x: usar 'severity debugging'.
    - Si 'info-center' no existe (WAP clásico), usar:
      'syslog enable' + 'syslog host <ip> facility local7' (severity opcional: informational).

    Siempre aplicando delays entre líneas y registrando cada comando en DEBUG.
    Al final intenta 'save' confirmando con 'Y'.
    """
    try:
        if logger:
            logger.info(f"[{host}] Enviando config syslog (Huawei)")

        # Primero intentamos variante VRP 5/8 (level debugging)
        cmds_vrp_level = [
            "info-center enable",
            "info-center source default channel loghost level debugging",
            f"info-center loghost {syslog_ip} facility local7 port {syslog_port}",
        ]
        try:
            send_config_with_delay(conn, cmds_vrp_level, sleep_fn, logger)
            vrp_variant_ok = True
        except Exception:
            vrp_variant_ok = False

        # Si falló, intentamos VRP 3.x (severity debugging)
        if not vrp_variant_ok:
            cmds_vrp_severity = [
                "info-center enable",
                "info-center source default channel loghost severity debugging",
                f"info-center loghost {syslog_ip} facility local7 port {syslog_port}",
            ]
            try:
                send_config_with_delay(conn, cmds_vrp_severity, sleep_fn, logger)
                vrp_variant_ok = True
            except Exception:
                vrp_variant_ok = False

        # Si tampoco, intentamos WAP clásico (sin info-center)
        if not vrp_variant_ok:
            cmds_wap = [
                "syslog enable",
                # Algunos WAP no aceptan 'severity debugging'; usar 'informational' por compatibilidad
                f"syslog host {syslog_ip} facility local7",
            ]
            send_config_with_delay(conn, cmds_wap, sleep_fn, logger)

        # Guardar config (manejar prompt)
        sleep_fn(1)
        out = conn.send_command_timing("save", strip_prompt=False, strip_command=False)
        if isinstance(out, str) and ("[Y/N]" in out or "(y/n)" in out or "continue" in out.lower()):
            out2 = conn.send_command_timing("Y", strip_prompt=False, strip_command=False)
            if logger:
                logger.debug(f"[{host}] SAVE reply: {out2[:120] if isinstance(out2,str) else out2}")

        return True, "PUSH OK"
    except Exception as e:
        return False, f"PUSH ERROR: {e}"


def push_syslog_fortinet(conn, host: str, syslog_ip: str, syslog_port: int, logging_source: str | None, sleep_fn, logger=None) -> tuple[bool, str]:
    """
    Configura syslog remoto en Fortinet (FortiOS) vía syslogd.
    - Habilita syslogd, apunta a <ip>:<port>, facility local7, modo UDP.
    - Ajusta filtro de severidad a 'information' para mayor verbosidad.
    - 'source-ip' sólo si se pasó logging_source con formato IP.
    """
    try:
        if logger:
            logger.info(f"[{host}] Enviando config syslog (Fortinet)")

        cmds = [
            "config log syslogd setting",
            "set status enable",
            f"set server {syslog_ip}",
            "set mode udp",
            f"set port {syslog_port}",
            "set facility local7",
        ]
        # Si se indicó logging_source y parece IP, usarlo como source-ip
        try:
            if logging_source and any(c.isdigit() for c in logging_source):
                cmds.append(f"set source-ip {logging_source}")
        except Exception:
            pass
        cmds.append("end")

        send_config_with_delay(conn, cmds, sleep_fn, logger)

        # Filtro de severidad para syslogd
        cmds_filter = [
            "config log syslogd filter",
            "set severity information",
            "end",
        ]
        try:
            send_config_with_delay(conn, cmds_filter, sleep_fn, logger)
        except Exception:
            # Si la sección no existe en versiones antiguas, lo ignoramos
            pass

        return True, "PUSH OK"
    except Exception as e:
        return False, f"PUSH ERROR: {e}"
