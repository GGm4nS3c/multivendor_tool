import re
from typing import Dict, List, Tuple

from ..vendors.commands import SCAN_EXTRAS


def first_nonempty_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def fortinet_hostname_from_status(text: str) -> str:
    for ln in (text or "").splitlines():
        s = ln.strip()
        if s.lower().startswith("hostname:"):
            return s.split(":", 1)[1].strip()
    return ""


def fortinet_first_route_line(text: str) -> str:
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        low = s.lower()
        if low.startswith("codes:") or low.startswith("routing table"):
            continue
        # Heurística: una línea de ruta suele empezar por letra/código o '*'
        if s[0] in "*KCSRBOINEADF":
            return s
    return ""


def fortinet_first_arp_line(text: str) -> str:
    import re as _re
    saw_header = False
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.lower().startswith("codes:") or s.lower().startswith("address"):
            saw_header = True
            continue
        if _re.search(r"\b\d+\.\d+\.\d+\.\d+\b", s):
            return s
    return ""


def fortinet_ifaces_up_pairs(text: str) -> list[tuple[str, str]]:
    """Extrae (name, ip) desde 'get system interface | grep \"status: up\"'."""
    res: list[tuple[str, str]] = []
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        # name: XYZ ... ip: A.B.C.D ... status: up
        m_name = re.search(r"name:\s*([^\s]+)", s)
        m_ip = re.search(r"ip:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", s)
        if m_name and m_ip:
            res.append((m_name.group(1), m_ip.group(1)))
    return res


def fortinet_vlan_entries(text: str) -> str:
    """Parses 'show system interface | grep -C 6 " set vlanid "' blocks.
    Devuelve 'vlanid=ID ip=... alias=... parent=...; ...'
    """
    entries = []
    cur = {"vlanid": "", "ip": "", "alias": "", "parent": ""}
    open_block = False
    for ln in (text or "").splitlines():
        s = ln.strip()
        if s.startswith("edit "):
            # nuevo bloque
            if open_block and cur.get("vlanid"):
                entries.append(f"vlanid={cur['vlanid']} ip={cur['ip']} alias={cur['alias']} if={cur['parent']}")
            cur = {"vlanid": "", "ip": "", "alias": "", "parent": ""}
            open_block = True
            continue
        if " set vlanid " in s:
            m = re.search(r"set vlanid (\d+)", s)
            if m:
                cur["vlanid"] = m.group(1)
            continue
        if " set ip " in s:
            m = re.search(r"set ip\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", s)
            if m:
                cur["ip"] = m.group(1)
            continue
        if " set alias " in s:
            m = re.search(r"set alias \"([^\"]*)\"", s)
            if m:
                cur["alias"] = m.group(1)
            continue
        if " set interface " in s:
            m = re.search(r"set interface \"([^\"]+)\"", s)
            if m:
                cur["parent"] = m.group(1)
            continue
    if open_block and cur.get("vlanid"):
        entries.append(f"vlanid={cur['vlanid']} ip={cur['ip']} alias={cur['alias']} if={cur['parent']}")
    return "; ".join([e for e in entries if e])


def cisco_routes_after_gateway(text: str) -> str:
    """Para 'show ip route': tomar desde 'Gateway of last resort' hacia abajo.
    Si no se halla el marcador, intenta devolver la primera línea de datos útil.
    """
    lines = (text or "").splitlines()
    start = 0
    for i, ln in enumerate(lines):
        if ln.strip().lower().startswith("gateway of last resort"):
            start = i
            break
    if start < len(lines):
        chunk = "\n".join(lines[start:])
        return collapse_lines(chunk)
    # Fallback: primera línea no vacía que no sea encabezado de 'Codes:'
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s.lower().startswith("codes:"):
            continue
        return s
    return ""


def cisco_arp_without_header(text: str) -> str:
    """Para 'show arp': excluir encabezado y devolver resto aplanado."""
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    out = []
    skipped_header = False
    for ln in lines:
        s = ln.strip()
        if not skipped_header and s.lower().startswith("protocol"):
            skipped_header = True
            continue
        if skipped_header:
            out.append(s)
    return "; ".join(out) if out else (lines[0].strip() if lines else "")


def parse_hostname_from_runinc(line: str) -> str:
    m = re.match(r"^\s*hostname\s+(.+)$", (line or "").strip(), re.IGNORECASE)
    return m.group(1).strip() if m else (line or "").strip()


def huawei_hostname_from_sysname(text: str) -> str:
    """Extrae el sysname desde 'display current-configuration | include ^sysname'."""
    for ln in (text or "").splitlines():
        s = ln.strip()
        if s.lower().startswith("sysname"):
            parts = s.split()
            if len(parts) >= 2:
                return parts[1]
            return s
    return ""


def huawei_version_line(text: str) -> str:
    """Devuelve la línea que contiene 'VRP ... Version ... Release ...' si existe."""
    for ln in (text or "").splitlines():
        s = ln.strip()
        if re.search(r"\bVRP\b.*\bVersion\b", s, re.IGNORECASE):
            return s
    return first_nonempty_line(text)


def parse_ip_int_brief(raw: str):
    res = []
    for ln in (raw or "").splitlines():
        if not ln.strip() or ln.strip().lower().startswith("interface"):
            continue
        parts = re.split(r"\s{2,}", ln.strip())
        if len(parts) < 2:
            continue
        ifname, ipaddr = parts[0].strip(), parts[1].strip()
        if ipaddr and ipaddr.lower() != "unassigned":
            res.append((ifname, ipaddr))
    return res


def parse_huawei_ip_int_brief(raw: str) -> List[Tuple[str, str]]:
    """Parsea salida de 'display ip interface brief' en VRP.
    Busca pares (ifname, ip) ignorando 'unassigned/0.0.0.0'.
    """
    res: List[Tuple[str, str]] = []
    for ln in (raw or "").splitlines():
        s = ln.strip()
        if not s or s.lower().startswith(("interface", "vlanif", "vpn-instance")):
            # no filtramos encabezados estrictamente, tomamos cualquier línea con IP
            pass
        m = re.search(r"^(\S+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", s)
        if not m:
            # IP con máscara con barra
            m = re.search(r"^(\S+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/(\d+)", s)
        if m:
            ifname = m.group(1)
            ip = m.group(2)
            if ip != "0.0.0.0":
                res.append((ifname, ip))
            continue
        # Algunas tablas muestran 'IP Address/Mask' en segunda columna separada por espacios múltiples
        parts = re.split(r"\s{2,}", s)
        if len(parts) >= 2:
            ifname, ipaddr = parts[0].strip(), parts[1].strip()
            if ipaddr and ipaddr.lower() not in ("unassigned", "0.0.0.0"):
                res.append((ifname, ipaddr.split()[0]))
    return res


def parse_hp_ip_int_brief(raw: str) -> List[Tuple[str, str]]:
    res: List[Tuple[str, str]] = []
    for ln in (raw or "").splitlines():
        s = ln.strip()
        if not s or s.lower().startswith(("interface", "brief")):
            continue
        parts = re.split(r"\s{2,}", s)
        if len(parts) >= 2:
            ifname, ipaddr = parts[0].strip(), parts[1].strip()
            if ipaddr and ipaddr.lower() not in ("unassigned", "0.0.0.0"):
                res.append((ifname, ipaddr.split()[0]))
    return res


def parse_fortinet_system_interface(raw: str) -> List[Tuple[str, str]]:
    """Parsea 'get system interface' para pares (name, ip)."""
    res: List[Tuple[str, str]] = []
    cur_name = None
    for ln in (raw or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.lower().startswith("name:"):
            cur_name = s.split(":", 1)[1].strip()
            continue
        if s.lower().startswith("ip:") and cur_name:
            # ip: 10.0.0.1 255.255.255.0
            parts = s.split()
            if len(parts) >= 2:
                ip = parts[1]
                if ip != "0.0.0.0":
                    res.append((cur_name, ip))
            cur_name = None
    return res


def fill_iface_columns(inventory: Dict[str, str], pairs: List[Tuple[str, str]]):
    inventory["ifaces_with_ip"] = "; ".join([f"{n}={ip}" for n, ip in pairs])
    def pj(pred):
        return "; ".join([f"{n}={ip}" for n, ip in pairs if pred(n)])
    inventory["GigabitEthernet"] = pj(lambda n: n.lower().startswith("gigabitethernet") or n.startswith("Gi") or n.upper().startswith("GE"))
    inventory["Gi"] = pj(lambda n: n.startswith("Gi") or n.upper().startswith("GE"))
    inventory["Loopback"] = pj(lambda n: re.match(r"^Loopback|^LoopBack", n, re.IGNORECASE))
    inventory["lo"] = pj(lambda n: n == "lo")
    inventory["VLAN"] = pj(lambda n: re.match(r"^(Vlan|VLAN|Vlanif|Vlan-interface)", n))


def collapse_lines(s: str) -> str:
    lines = [x.strip() for x in (s or "").replace("\r", "").splitlines() if x.strip()]
    return "; ".join(lines)


def parse_vrf_brief(raw: str):
    out = []
    for ln in (raw or "").splitlines():
        s = ln.strip()
        if not s:
            continue
        if re.search(r"\bname\b", s, re.IGNORECASE) and re.search(r"\binterfaces?\b", s, re.IGNORECASE):
            continue
        cols = re.split(r"\s{2,}", s)
        if not cols:
            continue
        name = cols[0].strip()
        if not name or name.lower().startswith(("vrf", "table")):
            continue
        ifs = cols[-1].strip() if len(cols) >= 2 else ""
        out.append((name, ifs))
    return out


def detect_targets_in_sockets(raw: str, targets):
    found = []
    for ip in targets or []:
        patt = rf"(?:^|[^\d])({re.escape(ip)})(?:(?:[:.])\d+)?(?!\d)"
        if re.search(patt, raw or ""):
            found.append(ip)
    return ";".join(found)


def scan_inventory(conn, host: str, platform: str, args, logger, inventory: Dict[str, str]):
    try:
        def send(cmd: str, timeout: int = 60):
            if logger:
                logger.debug(f"SCAN> {cmd}")
            return conn.send_command(cmd, read_timeout=timeout)
        # Desactivar paginación / preparar terminal
        try:
            if platform in ("ios", "nxos", "iosxr", "asa"):
                # Usar timing para evitar patrones al ajustar terminal
                if logger:
                    logger.debug("SCAN> terminal length 0")
                conn.send_command_timing("terminal length 0", strip_prompt=False, strip_command=False)
                if platform == "ios":
                    if logger:
                        logger.debug("SCAN> terminal width 511")
                    conn.send_command_timing("terminal width 511", strip_prompt=False, strip_command=False)
            elif platform == "huawei":
                send("screen-length 0 temporary", 10)
            elif platform == "hp":
                send("screen-length disable", 10)
        except Exception:
            pass

        # Hostname (Cisco/Fortinet/Huawei)
        try:
            if platform in ("ios", "nxos", "iosxr", "asa"):
                hn_run = send("show run | include ^hostname", 30)
                inventory["hostname"] = parse_hostname_from_runinc(first_nonempty_line(hn_run))
            elif platform == "fortinet":
                st = send("get system status", 60)
                inventory["hostname"] = fortinet_hostname_from_status(st)
            elif platform == "huawei":
                sysn = send("display current-configuration | include sysname", 60)
                inventory["hostname"] = huawei_hostname_from_sysname(sysn)
        except Exception:
            pass

        # Versión
        try:
            ver_cmd = {
                "ios": "show version",
                "nxos": "show version",
                "iosxr": "show version",
                "asa": "show version",
                "huawei": "display version",
                "hp": "display version",
                "fortinet": "get system status",
            }.get(platform, "show version")
            ver_all = send(ver_cmd, 90)
            if platform == "huawei":
                inventory["version_line"] = huawei_version_line(ver_all)
            else:
                inventory["version_line"] = first_nonempty_line(ver_all)
        except Exception:
            pass

        # Interfaces con IP
        try:
            if platform in ("ios", "nxos", "iosxr", "asa"):
                ip_brief = send("show ip interface brief", 90)
                ifs = parse_ip_int_brief(ip_brief)
                fill_iface_columns(inventory, ifs)
            elif platform == "huawei":
                ip_brief = send("display ip interface brief", 90)
                ifs = parse_huawei_ip_int_brief(ip_brief)
                fill_iface_columns(inventory, ifs)
            elif platform == "hp":
                ip_brief = send("display ip interface brief", 90)
                ifs = parse_hp_ip_int_brief(ip_brief)
                fill_iface_columns(inventory, ifs)
            elif platform == "fortinet":
                up = send("get system interface | grep 'status: up'", 90)
                ifs = fortinet_ifaces_up_pairs(up)
                if not ifs:
                    gi = send("get system interface", 120)
                    ifs = parse_fortinet_system_interface(gi)
                fill_iface_columns(inventory, ifs)
        except Exception:
            pass

        # VRFs (Cisco/Huawei/HP)
        try:
            if platform in ("ios", "nxos", "iosxr"):
                vrf_raw = send("show vrf brief", 60)
                if not vrf_raw or "Invalid" in (vrf_raw or ""):
                    vrf_raw = send("show ip vrf brief", 60)
                    if not vrf_raw:
                        vrf_raw = send("show ip vrf", 60)
                vrfs = parse_vrf_brief(vrf_raw)
                inventory["vrf_brief"] = "; ".join([f"{v}={ifs}" for v, ifs in (vrfs or [])])
            elif platform in ("huawei", "hp"):
                try:
                    vrf_raw = send("display ip vpn-instance", 60)
                    names = []
                    for ln in (vrf_raw or "").splitlines():
                        s = ln.strip()
                        if not s:
                            continue
                        # Capturar nombres al inicio de línea
                        m = re.match(r"^(\S+)$", s)
                        if m and m.group(1).lower() not in ("name", "total"):
                            names.append(m.group(1))
                    if names:
                        inventory["vrf_brief"] = "; ".join(names)
                except Exception:
                    pass
        except Exception:
            pass

        # Syslog config (Cisco/Fortinet)
        try:
            if platform in ("ios", "nxos", "iosxr", "asa"):
                syslog_inc = send("show running-config | include logging", 90)
                inventory["syslog_config"] = collapse_lines(syslog_inc)
            elif platform == "fortinet":
                s0 = send("show full-configuration log syslogd setting", 90)
                s1 = send("show log syslogd setting", 60)
                s2 = send("show log syslogd filter", 60)
                extra = ""
                try:
                    if getattr(args, "syslog_ip", None):
                        rt = send(f"get router info routing-table all | grep {args.syslog_ip}", 60)
                        extra = ("\n" + rt) if rt else ""
                except Exception:
                    pass
                inventory["syslog_config"] = collapse_lines("\n" + (s0 or "") + "\n" + (s1 or "") + "\n" + (s2 or "") + extra)
        except Exception:
            pass

        # Sockets (Cisco: syslog)
        try:
            if platform in ("ios", "nxos", "iosxr") and args.syslog_ip:
                sockets_raw = send("show ip sockets", 90)
                inventory["sockets_found"] = detect_targets_in_sockets(sockets_raw, [args.syslog_ip])
        except Exception:
            pass

        # ARP (ya no recolectamos rutas)
        try:
            arp_cmd = SCAN_EXTRAS["arp"].get(platform)
            if arp_cmd:
                if platform == "fortinet":
                    arp = send("get system arp", 120)
                    inventory["arp_brief"] = collapse_lines(arp)
                elif platform == "ios":
                    arp = send(arp_cmd, 120)
                    inventory["arp_brief"] = cisco_arp_without_header(arp)
                else:
                    arp = send(arp_cmd, 120)
                    inventory["arp_brief"] = first_nonempty_line(arp)
        except Exception:
            pass

        # VLAN (Fortinet): bloques alrededor de 'set vlanid'
        try:
            if platform == "fortinet":
                vtxt = send("show system interface | grep -C 6 ' set vlanid '", 180)
                inventory["VLAN"] = fortinet_vlan_entries(vtxt)
        except Exception:
            pass

        # Sockets 514 (Fortinet): sesiones activas hacia el syslog-ip
        try:
            if platform == "fortinet" and getattr(args, "syslog_ip", None):
                sess = send(f"diagnose sys session list | grep {args.syslog_ip}", 20)
                inventory["sockets_found"] = collapse_lines(sess)
        except Exception:
            pass

        return True, "SCAN OK"
    except Exception as e:
        return False, f"SCAN ERROR: {e}"
