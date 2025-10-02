import re
from typing import Dict, Optional, Callable
import time
from netmiko import ConnectHandler
try:
    from netmiko.exceptions import NetMikoTimeoutException
except Exception:  # pragma: no cover - compat Netmiko < 4
    from netmiko.ssh_exception import NetMikoTimeoutException  # type: ignore
from ..vendors.commands import (
    DEVICE_TYPES,
    DEVICE_TYPES_TELNET,
    PLATFORM_PATTERNS,
    MODEL_HINTS,
    HUAWEI_CMDS,
    HP_CMDS,
    FORTI_CMDS,
    HUAWEI_PRE_CMDS,
    HUAWEI_PRE_CMDS_LEGACY,
    HP_PRE_CMDS,
    FORTI_PRE_CMDS,
    CMD_SETS,
)
def _ver_snippet(ver_txt: str) -> str:
    """Extract a concise 'version' line for logging.
    Tries common patterns (Huawei VRP, Fortinet, etc.), falls back to first non-empty line.
    """
    if not ver_txt:
        return ""
    lines = [ln.strip() for ln in (ver_txt or "").splitlines() if ln.strip()]
    patterns = [
        r"VRP.*Version.*",          # Huawei VRP
        r"^Version:\s*.*",         # Fortinet get system status
        r"Cisco.*Version.*",        # Cisco variants
        r"Comware.*Version.*",      # HP Comware
        r"Software.*Version.*",
    ]
    for pat in patterns:
        for s in lines:
            if re.search(pat, s, re.IGNORECASE):
                return s
    return lines[0] if lines else ""
def _try_connect_and_get_version(device_type: str, host: str, username: str, password: str, secret: str, port: int, legacy: bool = False, auth_cb: Optional[Callable[[str], None]] = None, logger=None):
    params = dict(
        device_type=device_type,
        host=host,
        username=username,
        password=password,
        secret=secret,
        port=port,
        conn_timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        fast_cli=False,
    )
    channel = "TELNET" if "telnet" in (device_type or "").lower() else "SSH"
    if legacy:
        params.update(
            {
                # Netmiko 4+: usa 'use_keys' en vez de 'look_for_keys'.
                "use_keys": False,
                # Extender timeouts de banner/auth para stacks lentos
                "banner_timeout": 45,
                "auth_timeout": 60,
                # Intentar algoritmos más antiguos
                "disabled_algorithms": {
                    "pubkeys": [
                        "rsa-sha2-256",
                        "rsa-sha2-512",
                        "ssh-ed25519",
                        "ecdsa-sha2-nistp256",
                        "ecdsa-sha2-nistp384",
                        "ecdsa-sha2-nistp521",
                    ],
                    "kex": [
                        "curve25519-sha256",
                        "curve25519-sha256@libssh.org",
                        "ecdh-sha2-nistp256",
                        "ecdh-sha2-nistp384",
                        "ecdh-sha2-nistp521",
                        "diffie-hellman-group-exchange-sha256",
                        "diffie-hellman-group-exchange-sha1",
                    ],
                    "ciphers": [
                        "chacha20-poly1305@openssh.com",
                        "aes128-ctr",
                        "aes192-ctr",
                        "aes256-ctr",
                        "aes128-gcm@openssh.com",
                        "aes256-gcm@openssh.com",
                    ],
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
    def _prompt_retry_needed(exc: Exception) -> bool:
        msg = str(exc)
        return (
            "Pattern not detected" in msg
            or "Search pattern never" in msg
            or "Timed out trying to read" in msg
        )
    try:
        if logger:
            logger.debug(
                f"[DETECT][{channel}] ConnectHandler device_type={device_type} host={host}:{port} legacy={legacy}"
            )
        conn = ConnectHandler(**params)
        if logger:
            logger.debug(f"[DETECT][{channel}] Conexion establecida {host}:{port}")
        try:
            conn.write_channel("\n")
            time.sleep(0.5)
            conn.write_channel("\n")
            time.sleep(0.5)
            conn.read_until_pattern(pattern=r"[>#\]]", read_timeout=15)
            if logger:
                logger.debug(f"[DETECT][{channel}] prompt tras newline")
        except Exception as exc:
            if logger:
                logger.debug(f"[DETECT][{channel}] newline primer fallo: {type(exc).__name__}: {str(exc)[:200]}")
            try:
                conn.send_command_timing("", strip_prompt=False, strip_command=False)
            except Exception as exc2:
                if logger:
                return ""
    except (NetMikoTimeoutException, ValueError) as e:
        if logger:
            logger.debug(f"[DETECT][{channel}] ConnectHandler fallo: {str(e)[:200]}")
        if not _prompt_retry_needed(e):
            raise
        if logger:
            logger.debug(f"[DETECT][SSH] prompt fallback for {host} ({device_type}) tras error: {str(e)[:160]}")
        fallback_params = dict(params)
        fallback_params["fast_cli"] = False
        fallback_params["global_delay_factor"] = max(int(fallback_params.get("global_delay_factor", 1) or 1), 5)
        fallback_params["conn_timeout"] = max(int(fallback_params.get("conn_timeout", 20) or 20), 45)
        fallback_params["banner_timeout"] = max(int(fallback_params.get("banner_timeout", 20) or 20), 60)
        fallback_params["auth_timeout"] = max(int(fallback_params.get("auth_timeout", 20) or 20), 80)
        try:
            conn = ConnectHandler(**fallback_params)
        except Exception as e2:
            if logger:
                logger.debug(f"[DETECT][SSH] fallback connect failed para {host} ({device_type}): {str(e2)[:160]}")
            raise e2 from e
        params = fallback_params
        # En algunos equipos (Cisco IOS-XE) el banner deja la sesion "colgada" sin
        # prompt hasta que se envian ENTERs extra. Forzamos dos retornos y
        # esperamos al prompt real antes de continuar con la deteccion.
        try:
            conn.write_channel("\n")
            time.sleep(0.6)
            conn.write_channel("\n")
            time.sleep(0.6)
            conn.read_until_pattern(pattern=r"[>#\]]", read_timeout=15)
            if logger:
                logger.debug(f"[DETECT][SSH] prompt obtenido tras fallback en {host} ({device_type})")
        except Exception:
            try:
                conn.send_command_timing("", strip_prompt=False, strip_command=False)
            except Exception:
                pass
    # Authentication succeeded at this point
    try:
        if auth_cb:
            auth_cb("ssh")
    except Exception:
        pass
    if secret and device_type.startswith("cisco"):
        try:
            conn.enable()
        except Exception:
            pass
    def _send_with_fallback(command: str, timeout: int = 60) -> str:
        if logger:
            logger.debug(f"[DETECT][{channel}] ejecutando '{command}' (timeout {timeout}s)")
        try:
            return conn.send_command(command, read_timeout=timeout)
        except Exception as exc:
            if logger:
                logger.debug(f"[DETECT][{channel}] send_command fallo: {type(exc).__name__}: {str(exc)[:200]}")
            try:
                return conn.send_command_timing(command, strip_prompt=False, strip_command=False)
            except Exception as exc2:
                if logger:
                    logger.debug(f"[DETECT][{channel}] send_command_timing fallo: {type(exc2).__name__}: {str(exc2)[:200]}")
                return ""
    # Elegir comando de versión según driver (incluye variantes _telnet)
    if ("huawei" in device_type) or (device_type == "hp_comware"):
        ver_txt = _send_with_fallback("display version", 60)
        # Si la salida es vacía o muy corta, intenta deshabilitar paginación y reintentar
        try:
            if not (ver_txt or "").strip() or len((ver_txt or "").strip()) < 10:
                for pre in (HUAWEI_PRE_CMDS or []):
                    try:
                        _ = _send_with_fallback(pre, 10)
                    except Exception:
                        pass
                ver_txt = _send_with_fallback("display version", 60)
        except Exception:
            pass
    elif "fortinet" in device_type:
        ver_txt = _send_with_fallback("get system status", 60)
    else:
        ver_txt = _send_with_fallback("show version", 60)
    if logger:
        snippet = _ver_snippet(ver_txt)
        logger.debug(f"[DETECT][{channel}] fragmento version='{snippet[:160]}'")
    return conn, ver_txt
def detect_platform(host: str, username: str, password: str, secret: str = "", port: int = 22, vendor_hint: Optional[str] = None, families_keywords: Optional[Dict[str, str]] = None, logger=None, legacy: bool = False, auth_cb: Optional[Callable[[str], None]] = None) -> Dict:
    candidates = []
    if vendor_hint == "huawei":
        candidates = ["huawei"]
    elif vendor_hint == "cisco":
        candidates = ["cisco_xe", "cisco_ios", "cisco_xr", "cisco_nxos", "cisco_asa"]
    elif vendor_hint == "fortinet":
        candidates = ["fortinet"]
    elif vendor_hint == "hp":
        candidates = ["hp_comware"]
    else:
        # Orden solicitado: Cisco -> Huawei -> Fortinet -> demás (HP)
        candidates = ["cisco_xe", "cisco_ios", "huawei", "fortinet", "hp_comware"]
    last_exc = None
    for cand in candidates:
        try:
            if logger:
                logger.debug(f"[DETECT][SSH] intentando driver {cand} en {host}:{port}")
            conn, ver_txt = _try_connect_and_get_version(cand, host, username, password, secret, port, legacy=legacy, auth_cb=auth_cb, logger=logger)
            if logger:
                first = _ver_snippet(ver_txt)
                logger.debug(f"[DETECT][SSH] cand={cand} host={host} ver='{first[:160]}'")
            # Clasificación por contenido de versión primero (más fiable que el driver)
            platform = None
            for rx, plat in PLATFORM_PATTERNS:
                if re.search(rx, ver_txt or ""):
                    platform = plat
                    break
            if not platform:
                for rx, plat in MODEL_HINTS:
                    if re.search(rx, ver_txt or ""):
                        platform = plat
                        break
            if not platform and families_keywords:
                t = (ver_txt or "").upper()
                for kw, plat in families_keywords.items():
                    if kw in t:
                        platform = plat
                        break
            # Fallback al candidato si aún no hay match
            if not platform:
                if cand == "huawei":
                    platform = "huawei"
                elif cand == "hp_comware":
                    platform = "hp"
                elif cand == "fortinet":
                    platform = "fortinet"
            # Sin match: probar siguiente candidato
            if not platform:
                try:
                    conn.disconnect()
                except Exception:
                    pass
                if logger:
                    logger.debug(f"[DETECT][SSH] sin match con cand={cand}, probando siguiente")
                continue
            final_device_type = DEVICE_TYPES.get(platform, cand)
            if final_device_type != cand:
                # Intentar reconectar con el driver final; si falla, conservar el driver original
                new_conn = None
                try:
                    new_conn, ver2 = _try_connect_and_get_version(
                        final_device_type, host, username, password, secret, port, legacy=legacy, auth_cb=auth_cb, logger=logger
                    )
                    try:
                        conn.disconnect()
                    except Exception:
                        pass
                    conn = new_conn
                    ver_txt = ver2 or ver_txt
                except Exception as e_sw:
                    if logger:
                        logger.debug(f"[DETECT][SSH] switch driver to {final_device_type} failed, keep {cand}: {e_sw}")
                    final_device_type = cand
            pre_cmds = []
            if platform == "huawei":
                # Detectar VRP antiguo (3.x) desde la segunda línea
                is_legacy = False
                try:
                    ver_line = "\n".join((ver_txt or "").splitlines()[:3])
                    m = re.search(r"VRP\s*(?:\(R\)\s*)?software,\s*Version\s*([0-9]+)\.", ver_line, re.I)
                    if m and int(m.group(1)) <= 3:
                        is_legacy = True
                except Exception:
                    is_legacy = False
                pre_cmds = list(HUAWEI_PRE_CMDS_LEGACY if is_legacy else HUAWEI_PRE_CMDS)
                commands = list(HUAWEI_CMDS)
            elif platform == "hp":
                pre_cmds = list(HP_PRE_CMDS)
                commands = list(HP_CMDS)
            elif platform == "fortinet":
                pre_cmds = list(FORTI_PRE_CMDS)
                commands = list(FORTI_CMDS)
            else:
                commands = CMD_SETS.get(platform, CMD_SETS["ios"])  # default ios
            if logger:
                logger.debug(
                    f"[DETECT][SSH] platform={platform} device_type={final_device_type} pre_cmds={'; '.join(pre_cmds) if pre_cmds else 'None'} cmds={'; '.join(commands)}"
                )
            try:
                conn.disconnect()
            except Exception:
                pass
            return {
                "platform": platform,
                "device_type": final_device_type,
                "raw_version": ver_txt,
                "pre_cmds": pre_cmds,
                "commands": commands,
            }
        except Exception as e:
            # Reintento puntual con 'legacy' si el error sugiere problema de negociación SSH
            msg = str(e)
            retried = False
            if not legacy and any(s in msg for s in ["Error reading SSH protocol banner", "kex", "no matching key exchange", "cipher"]):
                try:
                    if logger:
                        logger.debug(f"[DETECT][SSH] retry legacy cand={cand} host={host}: {msg}")
                    conn, ver_txt = _try_connect_and_get_version(cand, host, username, password, secret, port, legacy=True, auth_cb=auth_cb, logger=logger)
                    retried = True
                    if logger:
                        first = _ver_snippet(ver_txt)
                        logger.debug(f"[DETECT][SSH][legacy] cand={cand} host={host} ver='{first[:160]}'")
                    # continuar flujo normal después del reintento exitoso
                    # Determinar plataforma por contenido de versión (preferente)
                    platform = None
                    for rx, plat in PLATFORM_PATTERNS:
                        if re.search(rx, ver_txt or ""):
                            platform = plat
                            break
                    if not platform:
                        for rx, plat in MODEL_HINTS:
                            if re.search(rx, ver_txt or ""):
                                platform = plat
                                break
                    if not platform and families_keywords:
                        t = (ver_txt or "").upper()
                        for kw, plat in families_keywords.items():
                            if kw in t:
                                platform = plat
                                break
                    if not platform:
                        if cand == "huawei":
                            platform = "huawei"
                        elif cand == "hp_comware":
                            platform = "hp"
                        elif cand == "fortinet":
                            platform = "fortinet"
                    if not platform:
                        try:
                            conn.disconnect()
                        except Exception:
                            pass
                        if logger:
                            logger.debug(f"[DETECT][SSH][legacy] sin match con cand={cand}, probando siguiente")
                        continue
                    final_device_type = DEVICE_TYPES.get(platform, cand)
                    if final_device_type != cand:
                        new_conn = None
                        try:
                            new_conn, ver2 = _try_connect_and_get_version(
                                final_device_type, host, username, password, secret, port, legacy=True, auth_cb=auth_cb, logger=logger
                            )
                            try:
                                conn.disconnect()
                            except Exception:
                                pass
                            conn = new_conn
                            ver_txt = ver2 or ver_txt
                        except Exception as e_sw:
                            if logger:
                                logger.debug(f"[DETECT][SSH][legacy] switch driver to {final_device_type} failed, keep {cand}: {e_sw}")
                            final_device_type = cand
                    pre_cmds = []
                    if platform == "huawei":
                        pre_cmds = list(HUAWEI_PRE_CMDS)
                        commands = list(HUAWEI_CMDS)
                    elif platform == "hp":
                        pre_cmds = list(HP_PRE_CMDS)
                        commands = list(HP_CMDS)
                    elif platform == "fortinet":
                        pre_cmds = list(FORTI_PRE_CMDS)
                        commands = list(FORTI_CMDS)
                    else:
                        commands = CMD_SETS.get(platform, CMD_SETS["ios"])  # default ios
                    if logger:
                        logger.debug(
                            f"[DETECT][SSH][legacy] platform={platform} device_type={final_device_type} pre_cmds={'; '.join(pre_cmds) if pre_cmds else 'None'} cmds={'; '.join(commands)}"
                        )
                    try:
                        conn.disconnect()
                    except Exception:
                        pass
                    return {
                        "platform": platform,
                        "device_type": final_device_type,
                        "raw_version": ver_txt,
                        "pre_cmds": pre_cmds,
                        "commands": commands,
                    }
                except Exception as e2:
                    if logger:
                        logger.debug(f"[DETECT][SSH] retry legacy failed cand={cand} host={host}: {e2}")
            if not retried:
                last_exc = e
                continue
    if last_exc:
        raise last_exc
    raise RuntimeError("No se pudo detectar la plataforma")
def detect_platform_telnet(host: str, username: str, password: str, secret: str = "", port: int = 23, vendor_hint: Optional[str] = None, families_keywords: Optional[Dict[str, str]] = None, logger=None, auth_cb: Optional[Callable[[str], None]] = None) -> Dict:
    """Detección por Telnet probando device_types _telnet conocidos."""
    if vendor_hint == "huawei":
        candidates = [DEVICE_TYPES_TELNET.get("huawei")]
    else:
        # Orden solicitado: Cisco -> Huawei -> Fortinet -> demás
        candidates = [
            DEVICE_TYPES_TELNET.get("ios"),
            DEVICE_TYPES_TELNET.get("iosxr"),
            DEVICE_TYPES_TELNET.get("nxos"),
            DEVICE_TYPES_TELNET.get("asa"),
            DEVICE_TYPES_TELNET.get("huawei"),
            DEVICE_TYPES_TELNET.get("fortinet"),
            DEVICE_TYPES_TELNET.get("hp"),
            DEVICE_TYPES_TELNET.get("nokia"),
        ]
    candidates = [c for c in candidates if c]
    last_exc = None
    for cand in candidates:
        try:
            if logger:
                logger.debug(f"[DETECT][TELNET] intentando driver {cand} en {host}:{port}")
            conn, ver_txt = _try_connect_and_get_version(cand, host, username, password, secret, port, auth_cb=auth_cb, logger=logger)
            if logger:
                first = _ver_snippet(ver_txt)
                logger.debug(f"[DETECT][TELNET] cand={cand} host={host} ver='{first[:160]}'")
            # Clasificación por contenido de versión primero
            platform = None
            for rx, plat in PLATFORM_PATTERNS:
                if re.search(rx, ver_txt or ""):
                    platform = plat
                    break
            if not platform:
                for rx, plat in MODEL_HINTS:
                    if re.search(rx, ver_txt or ""):
                        platform = plat
                        break
            if not platform and families_keywords:
                t = (ver_txt or "").upper()
                for kw, plat in (families_keywords or {}).items():
                    if kw in t:
                        platform = plat
                        break
            if not platform:
                if "huawei" in cand:
                    platform = "huawei"
                elif "hp_comware" in cand:
                    platform = "hp"
            elif "fortinet" in cand:
                platform = "fortinet"
            if not platform:
                try:
                    conn.disconnect()
                except Exception:
                    pass
                if logger:
                    logger.debug(f"[DETECT][TELNET] sin match con cand={cand}, probando siguiente")
                continue
            final_device_type = DEVICE_TYPES_TELNET.get(platform, cand)
            if final_device_type != cand:
                try:
                    conn.disconnect()
                except Exception:
                    pass
                conn, ver_txt = _try_connect_and_get_version(final_device_type, host, username, password, secret, port, logger=logger)
            pre_cmds = []
            if platform == "huawei":
                is_legacy = False
                try:
                    ver_line = "\n".join((ver_txt or "").splitlines()[:3])
                    m = re.search(r"VRP\s*(?:\(R\)\s*)?software,\s*Version\s*([0-9]+)\.", ver_line, re.I)
                    if m and int(m.group(1)) <= 3:
                        is_legacy = True
                except Exception:
                    is_legacy = False
                pre_cmds = list(HUAWEI_PRE_CMDS_LEGACY if is_legacy else HUAWEI_PRE_CMDS)
                commands = list(HUAWEI_CMDS)
            elif platform == "hp":
                pre_cmds = list(HP_PRE_CMDS)
                commands = list(HP_CMDS)
            elif platform == "fortinet":
                pre_cmds = list(FORTI_PRE_CMDS)
                commands = list(FORTI_CMDS)
            else:
                commands = CMD_SETS.get(platform, CMD_SETS["ios"])  # default ios
            if logger:
                logger.debug(
                    f"[DETECT][TELNET] platform={platform} device_type={final_device_type} pre_cmds={'; '.join(pre_cmds) if pre_cmds else 'None'} cmds={'; '.join(commands)}"
                )
            try:
                conn.disconnect()
            except Exception:
                pass
            return {
                "platform": platform,
                "device_type": final_device_type,
                "raw_version": ver_txt,
                "pre_cmds": pre_cmds,
                "commands": commands,
            }
        except Exception as e:
            last_exc = e
            continue
    if last_exc:
        raise last_exc
    raise RuntimeError("No se pudo detectar la plataforma por Telnet")
