

def _classify_connection(conn, ver_txt, cand, host, port, legacy_flag, auth_cb, logger, context_label, families_keywords):
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
            logger.debug(f"{context_label} sin match con cand={cand}, probando siguiente")
        return None
    final_device_type = PRIMARY_CISCO_DRIVER if platform == "ios_xe" else DEVICE_TYPES.get(platform, cand)
    if final_device_type != cand:
        new_conn = None
        try:
            new_conn, ver2 = _try_connect_and_get_version(
                final_device_type,
                host,
                "" if host is None else host,
                "" if host is None else host,
                "",
                port,
                legacy=legacy_flag,
                auth_cb=auth_cb,
                logger=logger,
            )
            try:
                conn.disconnect()
            except Exception:
                pass
            conn = new_conn
            ver_txt = ver2 or ver_txt
        except Exception as e_sw:
            if logger:
                logger.debug(f"{context_label} switch driver to {final_device_type} failed, keep {cand}: {e_sw}")
            final_device_type = cand
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
        commands = CMD_SETS.get(platform, CMD_SETS["ios"])
    if logger:
        pre_descr = '; '.join(pre_cmds) if pre_cmds else 'None'
        cmd_descr = '; '.join(commands)
        logger.debug(f"{context_label} platform={platform} device_type={final_device_type} pre_cmds={pre_descr} cmds={cmd_descr}")
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

def detect_platform(host: str, username: str, password: str, secret: str = "", port: int = 22, vendor_hint: Optional[str] = None, families_keywords: Optional[Dict[str, str]] = None, logger=None, legacy: bool = False, auth_cb: Optional[Callable[[str], None]] = None) -> Dict:
    if vendor_hint == "huawei":
        candidates = ["huawei"]
    elif vendor_hint == "cisco":
        candidates = [PRIMARY_CISCO_DRIVER, "cisco_ios", "cisco_xr", "cisco_nxos", "cisco_asa"]
    elif vendor_hint == "fortinet":
        candidates = ["fortinet"]
    elif vendor_hint == "hp":
        candidates = ["hp_comware"]
    else:
        candidates = [PRIMARY_CISCO_DRIVER, "cisco_ios", "huawei", "fortinet", "hp_comware"]
    last_exc = None
    for cand in candidates:
        try:
            if logger:
                logger.debug(f"[DETECT][SSH] intentando driver {cand} en {host}:{port}")
            conn, ver_txt = _try_connect_and_get_version(cand, host, username, password, secret, port, legacy=legacy, auth_cb=auth_cb, logger=logger)
            if logger:
                first = _ver_snippet(ver_txt)
                logger.debug(f"[DETECT][SSH] cand={cand} host={host} ver='{first[:160]}'")
            result = _classify_connection(conn, ver_txt, cand, host, port, legacy, auth_cb, logger, "[DETECT][SSH]", families_keywords)
            if result:
                return result
        except Exception as e:
            msg = str(e)
            retried = False
            if not legacy and any(s in msg for s in ["Error reading SSH protocol banner", "kex", "no matching key exchange", "cipher"]):
                if logger:
                    logger.debug(f"[DETECT][SSH] retry legacy cand={cand} host={host}: {msg}")
                try:
                    conn, ver_txt = _try_connect_and_get_version(cand, host, username, password, secret, port, legacy=True, auth_cb=auth_cb, logger=logger)
                    retried = True
                    if logger:
                        first = _ver_snippet(ver_txt)
                        logger.debug(f"[DETECT][SSH][legacy] cand={cand} host={host} ver='{first[:160]}'")
                    result = _classify_connection(conn, ver_txt, cand, host, port, True, auth_cb, logger, "[DETECT][SSH][legacy]", families_keywords)
                    if result:
                        return result
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
