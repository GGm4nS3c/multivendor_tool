#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cisco_topology_probe.py
- SSH (Netmiko) a Cisco IOS/IOS-XE
- Extrae hostname, IOS-XE, interfaces (desc, IPs prim/sec, políticas), ARP, rutas (filtra Null0), vecinos, ACL/NAT/PBR/QoS
- Infiere PE por default y deduplica con el aprendido por ARP
- Marca interfaz por la que accedimos (--host) para dibujar "ssh adm"
- Ejecuta automáticamente traceroute al puerto SSH (22) y agrega los hops al modelo
"""

import argparse
import sys
import re
import json
import shutil
import subprocess
from datetime import datetime, timezone
from ipaddress import ip_interface, ip_network, ip_address
from netmiko import ConnectHandler

RFC1918 = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]


def is_private_ip(ip_str: str) -> bool:
    try:
        return any(ip_address(ip_str) in n for n in RFC1918)
    except Exception:
        return False


def safe_send(conn, cmd):
    print(f"$ {cmd}")
    out = conn.send_command(cmd, expect_string=r"#|\(config.*\)#", read_timeout=30)
    return out or ""


def detect_iosxe_version(sv: str):
    m = re.search(r"Cisco IOS XE Software,\s+Version\s+([^\r\n]+)", sv, re.I)
    return m.group(1).strip() if m else ""


def detect_platform(sv: str):
    m = re.search(r"cisco\s+([A-Za-z0-9\-\/]+)\s*\(", sv, re.I)
    return m.group(1).strip() if m else "Cisco IOS/IOS-XE"


# -------- traceroute helpers --------
def parse_traceroute(text: str):
    """
    Acepta salida de traceroute/tcptraceroute/tracert.
    Para cada hop toma SIEMPRE la PRIMERA IP que aparezca en la línea (columna 2 de tu ejemplo).
    Devuelve [{"hop":N, "host":"<fqdn|None>", "ip":"A.B.C.D|None"}...]
    """
    hops = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        # Formato Unix típico: "10   10.233.223.238  18.6ms  *  19.0ms"
        m = re.match(r"^(\d+)\s+(.+)$", line)
        if m:
            idx = int(m.group(1))
            rest = m.group(2)

            # Host (si primero token no es IP)
            host = None
            first_tok = rest.split()[0] if rest.split() else ""
            if (
                first_tok
                and not re.match(r"^\d+\.\d+\.\d+\.\d+$", first_tok)
                and first_tok != "*"
            ):
                host = first_tok

            # PRIMERA IP de la línea (prioridad absoluta)
            m_ip_first = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
            ip = m_ip_first.group(1) if m_ip_first else None

            # Hop con sólo asteriscos
            if rest.startswith("*") or "***" in rest:
                host = host or "*"
                ip = ip or None

            hops.append({"hop": idx, "host": host, "ip": ip})
            continue

        # Windows tracert: " 10   10.233.223.238   19 ms ..."
        mw = re.match(r"^(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+", line)
        if mw:
            idx = int(mw.group(1))
            ip = mw.group(2)
            hops.append({"hop": idx, "host": None, "ip": ip})
            continue
    hops.sort(key=lambda x: x["hop"])
    return hops


def run_traceroute_auto(
    dst: str,
    port: int = 22,
    max_hops: int = 30,
    timeout_s: int = 2,
    queries: int = 1,
    numeric: bool = False,
):
    """
    Ejecuta traceroute automáticamente probando:
      1) tcptraceroute <dst> <port>
      2) traceroute -T -p <port> <dst>
      3) traceroute <dst>
    Retorna dict: {"command": "...", "stdout": str, "stderr": str, "hops": [...]}
    """
    candidates = []
    if shutil.which("tcptraceroute"):
        args = [
            "tcptraceroute",
            dst,
            str(port),
            "-q",
            str(queries),
            "-w",
            str(timeout_s),
            "-m",
            str(max_hops),
        ]
        if numeric:
            args.insert(1, "-n")
        candidates.append(args)
    if shutil.which("traceroute"):
        args = [
            "traceroute",
            "-T",
            "-p",
            str(port),
            "-q",
            str(queries),
            "-w",
            str(timeout_s),
            "-m",
            str(max_hops),
            dst,
        ]
        if numeric:
            args.insert(1, "-n")
        candidates.append(args)
        args2 = [
            "traceroute",
            "-q",
            str(queries),
            "-w",
            str(timeout_s),
            "-m",
            str(max_hops),
            dst,
        ]
        if numeric:
            args2.insert(1, "-n")
        candidates.append(args2)
    if shutil.which("tracert"):
        candidates.append(["tracert", "-d", "-h", str(max_hops), dst])

    last = {"command": "", "stdout": "", "stderr": "", "hops": []}
    for cmd in candidates:
        try:
            print(f"[*] Ejecutando traceroute: {' '.join(cmd)}")
            cp = subprocess.run(
                cmd, capture_output=True, text=True, timeout=max_hops * (timeout_s + 2)
            )
            out = cp.stdout or ""
            hops = parse_traceroute(out)
            if hops:
                return {
                    "command": " ".join(cmd),
                    "stdout": out,
                    "stderr": cp.stderr or "",
                    "hops": hops,
                }
            last = {
                "command": " ".join(cmd),
                "stdout": out,
                "stderr": cp.stderr or "",
                "hops": [],
            }
        except Exception as e:
            last = {
                "command": " ".join(cmd),
                "stdout": "",
                "stderr": str(e),
                "hops": [],
            }
            continue
    return last


# -----------------------------------


def probe(
    host, username, password, enable=None, port=22, device_type="cisco_xe", fast=False
):
    device = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "secret": enable or "",
        "fast_cli": False,
    }
    print(f"[*] Connecting to {host} as {username} (device_type={device_type})")
    conn = ConnectHandler(**device)
    if enable:
        print("[*] Entering enable mode")
        conn.enable()
    print("[*] Disabling paging (terminal length 0)")
    conn.send_command("terminal length 0")

    o = {}
    o["show_version"] = safe_send(conn, "show version")
    o["show_run_hostname"] = safe_send(conn, "show running-config | i ^hostname")
    o["show_vrf"] = safe_send(conn, "show vrf")
    o["show_vrf_detail"] = safe_send(conn, "show vrf detail")
    o["show_ip_int_br"] = safe_send(conn, "show ip interface brief")
    o["show_int_desc"] = safe_send(conn, "show interfaces description")

    # per-interface for up/up
    up = []
    for line in o["show_ip_int_br"].splitlines():
        p = line.split()
        if len(p) >= 6 and p[0] != "Interface":
            intf, ipaddr, ok, method, status, proto = p[:6]
            if (
                status.lower() == "up"
                and proto.lower() == "up"
                and re.match(r"^\S+\d", intf)
            ):
                up.append(intf)
    o["per_interface"] = {}
    for intf in up:
        o["per_interface"][intf] = {
            "show_ip_interface": safe_send(conn, f"show ip interface {intf}"),
            "show_run_interface": safe_send(conn, f"show run interface {intf}"),
            "show_policy_map_int": safe_send(conn, f"show policy-map interface {intf}"),
        }

    o["show_ip_route_sum"] = safe_send(conn, "show ip route summary")
    o["show_ip_route"] = "" if fast else safe_send(conn, "show ip route")
    o["show_ip_cef_sum"] = safe_send(conn, "show ip cef summary")
    o["show_ip_protocols"] = safe_send(conn, "show ip protocols")
    o["show_ip_eigrp_neighbors_detail"] = safe_send(
        conn, "show ip eigrp neighbors detail"
    )
    o["show_ip_bgp_summary"] = safe_send(conn, "show ip bgp summary")
    o["show_ip_ospf_neighbor"] = safe_send(conn, "show ip ospf neighbor")
    o["show_cdp_neighbors_detail"] = safe_send(conn, "show cdp neighbors detail")
    o["show_lldp_neighbors_detail"] = safe_send(conn, "show lldp neighbors detail")
    o["show_ip_arp"] = safe_send(conn, "show ip arp")

    # MPLS (best effort)
    mpls_out = safe_send(conn, "show mpls interfaces")
    if "% Invalid input" in mpls_out or "Unknown" in mpls_out or mpls_out.strip() == "":
        o["show_mpls_interfaces"] = ""
        o["mpls_supported"] = False
        print("[i] MPLS no soportado aquí (probablemente CE).")
    else:
        o["show_mpls_interfaces"] = mpls_out
        o["mpls_supported"] = True
        o["show_mpls_ldp_neighbor"] = safe_send(conn, "show mpls ldp neighbor")

    o["show_ip_access_lists"] = safe_send(conn, "show ip access-lists")
    o["show_run_filters"] = safe_send(
        conn,
        "show run | i access-group|ip access-list|ip nat|ip policy|zone-pair|class-map|policy-map",
    )
    o["show_ip_policy"] = safe_send(conn, "show ip policy")
    o["show_ip_nat_stats"] = safe_send(conn, "show ip nat statistics")
    o["show_ip_nat_trans"] = safe_send(conn, "show ip nat translations")

    conn.disconnect()
    print("[*] Disconnected")
    return o


def parse_routes_by_proto(show_ip_route: str, max_per_proto=25):
    by_proto = {
        "connected": [],
        "static": [],
        "eigrp_internal": [],
        "eigrp_external": [],
        "bgp": [],
        "ospf": [],
    }
    blackhole, default_nh = [], None
    for line in (show_ip_route or "").splitlines():
        mdef = re.search(r"0\.0\.0\.0/0.*via\s+(\d+\.\d+\.\d+\.\d+)", line)
        if mdef and not default_nh:
            default_nh = mdef.group(1)
        m = re.match(r"^\s*([A-Z]{1,3})\s+(\d+\.\d+\.\d+\.\d+/\d+)(.*)$", line)
        if not m:
            continue
        code, prefix, trail = m.group(1).strip(), m.group(2), m.group(3)
        if code == "C":
            if len(by_proto["connected"]) < max_per_proto:
                by_proto["connected"].append(prefix)
                continue
        if code == "S":
            if "Null0" in trail:
                if len(blackhole) < max_per_proto:
                    blackhole.append(prefix)
            else:
                if len(by_proto["static"]) < max_per_proto:
                    by_proto["static"].append(prefix)
            continue
        if code == "D":
            if len(by_proto["eigrp_internal"]) < max_per_proto:
                by_proto["eigrp_internal"].append(prefix)
                continue
        if code in ("EX", "D EX"):
            if len(by_proto["eigrp_external"]) < max_per_proto:
                by_proto["eigrp_external"].append(prefix)
                continue
        if code == "B":
            if len(by_proto["bgp"]) < max_per_proto:
                by_proto["bgp"].append(prefix)
                continue
        if code in ("O", "IA", "N1", "N2", "E1", "E2"):
            if len(by_proto["ospf"]) < max_per_proto:
                by_proto["ospf"].append(prefix)
                continue
    return by_proto, default_nh, blackhole


def parse_model(
    outputs, host_for_label="Router", traceroute_hops=None, traceroute_cmd=""
):
    # Hostname
    hr = outputs.get("show_run_hostname", "")
    m = re.search(r"^hostname\s+(\S+)", hr, re.M)
    hostname = (
        m.group(1)
        if m
        else (
            re.search(
                r"([A-Za-z0-9\-\._]+)\s+uptime is", outputs.get("show_version", "")
            )
            or [None, None]
        )[1]
        or host_for_label
    )

    model = {
        "metadata": {
            "device": host_for_label,
            "hostname": hostname,
            "access_ip": host_for_label,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ssh_path": {"hops": traceroute_hops or [], "command": traceroute_cmd},
        },
        "vrfs": [{"name": "global"}],
        "nodes": [],
        "interfaces": [],
        "edges": [],
        "routes": {
            "summary": {},
            "connected": [],
            "by_proto": {},
            "default_next_hop": None,
            "blackhole": [],
        },
        "hints": {
            "mpls_supported": outputs.get("mpls_supported", False),
            "role": "CE",
            "ssh_access": {},
        },
    }

    iosxe = detect_iosxe_version(outputs.get("show_version", ""))
    plat = detect_platform(outputs.get("show_version", ""))
    router_label = (
        f"{hostname}\n{plat} (IOS-XE {iosxe})" if iosxe else f"{hostname}\n{plat}"
    )

    model["nodes"].append(
        {
            "id": "rtr",
            "label": router_label,
            "role": "router",
            "vendor": "cisco",
            "vrf": "global",
            "ip_loopbacks": [],
            "risk": [],
        }
    )

    # Loopbacks
    for line in outputs.get("show_ip_int_br", "").splitlines():
        if line.startswith("Loopback") and "up" in line and "up" in line:
            parts = line.split()
            if len(parts) >= 2 and parts[1] != "unassigned":
                model["nodes"][0]["ip_loopbacks"].append(f"{parts[1]}/32")

    # VRFs
    vrf_names = re.findall(
        r"^\s*([A-Za-z0-9\-\._]+)\s+<", outputs.get("show_vrf", ""), re.M
    )
    model["vrfs"] = (
        [{"name": n} for n in sorted(set(vrf_names))]
        if vrf_names
        else [{"name": "global"}]
    )

    # VRF->interfaces (detail)
    vrf_if_map, current_vrf = {}, None
    for line in outputs.get("show_vrf_detail", "").splitlines():
        m1 = re.match(r"VRF\s+(\S+)\s+.+", line)
        if m1:
            current_vrf = m1.group(1)
        m2 = re.search(r"Interfaces:\s*(.*)$", line)
        if current_vrf and m2:
            for name in [i.strip() for i in m2.group(1).split(",") if i.strip()]:
                vrf_if_map[name] = current_vrf

    # Descripciones
    desc_map = {}
    for line in outputs.get("show_int_desc", "").splitlines():
        m = re.match(
            r"^(?P<intf>\S+)\s+(?P<status>up|down|admin down)\s+\S+\s+(?P<desc>.*)$",
            line.strip(),
        )
        if m:
            desc_map[m.group("intf")] = m.group("desc").strip()

    # Interfaces up
    for intf, data in outputs.get("per_interface", {}).items():
        ipi = data.get("show_ip_interface", "")
        runi = data.get("show_run_interface", "")
        mdesc = re.search(r"^\s*description\s+(.+)$", runi, re.M)
        desc_final = mdesc.group(1).strip() if mdesc else desc_map.get(intf, "")

        ips = []
        prim = re.search(r"Internet address is\s+(\d+\.\d+\.\d+\.\d+/\d+)", ipi)
        if prim:
            ips.append(prim.group(1))
        for sec in re.findall(r"Secondary address\s+(\d+\.\d+\.\d+\.\d+/\d+)", ipi):
            ips.append(sec)

        pol, risk = {}, []
        m = re.search(r"service-policy input\s+(\S+)", runi)
        pol["qos_in"] = m.group(1) if m else None
        m = re.search(r"service-policy output\s+(\S+)", runi)
        pol["qos_out"] = m.group(1) if m else None
        if "ip nat inside" in runi:
            pol["nat"] = "inside"
        if "ip nat outside" in runi:
            pol["nat"] = "outside"
        m = re.search(r"ip policy route-map\s+(\S+)", runi)
        pol["pbr"] = m.group(1) if m else None
        if "Proxy ARP is enabled" in ipi:
            risk.append("proxy-arp")
        if "ICMP redirects are always sent" in ipi:
            risk.append("icmp-redirects")

        model["interfaces"].append(
            {
                "node": "rtr",
                "name": intf,
                "ipv4": ips,
                "desc": desc_final,
                "up": True,
                "policies": {k: v for k, v in pol.items() if v},
                "risk": risk,
                "vrf": vrf_if_map.get(intf, "global"),
                "ip_class": [
                    ("private" if is_private_ip(str(ip_interface(x).ip)) else "public")
                    for x in ips
                ],
            }
        )

    # Resolver interfaz por la que accedimos (ssh_access)
    access_ip, access_iface = model["metadata"]["access_ip"], None
    try:
        ip_acc = ip_address(access_ip)
        for iface in model["interfaces"]:
            for ipn in iface.get("ipv4", []):
                try:
                    if ip_acc in ip_interface(ipn).network:
                        access_iface = iface["name"]
                        break
                except Exception:
                    pass
            if access_iface:
                break
    except Exception:
        pass
    model["hints"]["ssh_access"] = {"ip": access_ip, "iface": access_iface}

    # ARP -> vecinos
    neighbor_id_seq = 1
    for line in outputs.get("show_ip_arp", "").splitlines():
        m = re.match(
            r"Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f\.]+)\s+ARPA\s+(\S+)",
            line,
            re.I,
        )
        if not m:
            continue
        ip_addr, mac, intf = m.group(1), m.group(2), m.group(3)
        iface = next((i for i in model["interfaces"] if i["name"] == intf), None)
        if not iface:
            continue
        # validar pertenece a esa red y no es la self-ip
        belongs = False
        for ipn in iface.get("ipv4", []):
            try:
                if (
                    ip_address(ip_addr) != ip_interface(ipn).ip
                    and ip_address(ip_addr) in ip_interface(ipn).network
                ):
                    belongs = True
                    break
            except Exception:
                pass
        if not belongs:
            continue
        role = (
            "pe"
            if (
                "wan" in (iface.get("desc", "").lower())
                or "entel" in (iface.get("desc", "").lower())
            )
            else "lan"
        )
        nid = f"nbr{neighbor_id_seq}"
        neighbor_id_seq += 1
        priv = "private" if is_private_ip(ip_addr) else "public"
        model["nodes"].append(
            {
                "id": nid,
                "label": f"{role.upper()} {ip_addr} ({priv})",
                "role": role,
                "vrf": iface.get("vrf", "global"),
            }
        )
        nets = []
        for ipn in iface.get("ipv4", []):
            try:
                nets.append(str(ip_interface(ipn).network))
            except Exception:
                pass
        model["edges"].append(
            {
                "a": f'rtr:{iface["name"]}',
                "b": nid,
                "label": ", ".join(sorted(set(nets))),
            }
        )

    # Rutas
    by_proto, default_nh, blackhole = parse_routes_by_proto(
        outputs.get("show_ip_route", "") or ""
    )
    model["routes"]["by_proto"] = by_proto
    model["routes"]["default_next_hop"] = default_nh
    model["routes"]["blackhole"] = blackhole

    # DEDUP PE default
    def find_node_by_ip(ip_str: str):
        for n in model["nodes"]:
            if ip_str and ip_str in (n.get("label", "")):
                return n
        return None

    def edge_exists(a_id: str, b_id: str, label: str) -> bool:
        for e in model["edges"]:
            if (
                e.get("a") == a_id
                and e.get("b") == b_id
                and e.get("label", "") == label
            ):
                return True
        return False

    if default_nh:
        pe_node = find_node_by_ip(default_nh)
        if pe_node is None:
            pe_node = {
                "id": "pe_default",
                "label": f"PE {default_nh} (private)",
                "role": "pe",
                "vrf": "global",
            }
            model["nodes"].append(pe_node)
        pe_id = pe_node["id"]
        for iface in model["interfaces"]:
            for ipn in iface.get("ipv4", []):
                try:
                    net = ip_interface(ipn).network
                    if ip_address(default_nh) in net:
                        a_id = f'rtr:{iface["name"]}'
                        lbl = str(net)
                        if not edge_exists(a_id, pe_id, lbl):
                            model["edges"].append({"a": a_id, "b": pe_id, "label": lbl})
                        break
                except Exception:
                    pass

    # Summary (conteos del summary)
    s = outputs.get("show_ip_route_sum", "")

    def count_pair(regex):
        m = re.search(regex, s, re.I)
        return (int(m.group(1)) + int(m.group(2))) if m else None

    model["routes"]["summary"] = {
        "connected": count_pair(r"connected\s+(\d+)\s+(\d+)"),
        "static": count_pair(r"static\s+(\d+)\s+(\d+)"),
        "eigrp": count_pair(r"eigrp\s+\d+\s+(\d+)\s+(\d+)"),
        "total": count_pair(r"Total\s+(\d+)\s+(\d+)"),
    }

    # Riesgos agregados al nodo
    for iface in model["interfaces"]:
        for r in iface.get("risk", []):
            if r not in model["nodes"][0]["risk"]:
                model["nodes"][0]["risk"].append(r)

    return model


def render_outputs(
    model_path, dot_path="topology.dot", mmd_path="topology.mmd", also_png=True
):
    import os

    renderer = os.path.join(os.path.dirname(__file__), "topology_render.py")
    if not os.path.exists(renderer):
        print("[!] topology_render.py no encontrado; omitiendo renderizado (solo JSON)")
        return
    print(f"[*] Ejecutando renderer: {renderer}")
    subprocess.run(
        [
            sys.executable,
            renderer,
            "--in",
            model_path,
            "--dot",
            dot_path,
            "--mmd",
            mmd_path,
        ],
        check=True,
    )
    if also_png and shutil.which("dot"):
        print("[*] Generando PNG con Graphviz")
        subprocess.run(["dot", "-Tpng", dot_path, "-o", "topology.png"], check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--enable", default="")
    ap.add_argument("--port", type=int, default=22)
    ap.add_argument("--device-type", default="cisco_xe")
    ap.add_argument("--out", default="topology_model.json")
    ap.add_argument("--render", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument(
        "--traceroute-file",
        default="",
        help="Si se indica, usa este archivo en vez de ejecutar traceroute",
    )
    ap.add_argument("--traceroute-port", type=int, default=22)
    ap.add_argument(
        "--traceroute-disable",
        action="store_true",
        help="No ejecutar traceroute automático",
    )
    args = ap.parse_args()

    # Traceroute primero
    tr_info = {"command": "", "hops": []}
    if args.traceroute_file:
        try:
            with open(args.traceroute_file, "r", encoding="utf-8") as f:
                tr_text = f.read()
            tr_info["command"] = f"file:{args.traceroute_file}"
            tr_info["hops"] = parse_traceroute(tr_text)
        except Exception as e:
            print(f"[!] No se pudo leer traceroute: {e}")
    elif not args.traceroute_disable:
        tr_res = run_traceroute_auto(
            args.host,
            port=args.traceroute_port,
            max_hops=64,
            timeout_s=2,
            queries=1,
            numeric=False,
        )
        tr_info["command"] = tr_res.get("command", "")
        tr_info["hops"] = tr_res.get("hops", [])

    # Probe SSH
    outs = probe(
        args.host,
        args.username,
        args.password,
        enable=args.enable,
        port=args.port,
        device_type=args.device_type,
        fast=args.fast,
    )

    # Modelo
    model = parse_model(
        outs,
        host_for_label=args.host,
        traceroute_hops=tr_info["hops"],
        traceroute_cmd=tr_info["command"],
    )

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2)
    print(f"[*] Modelo guardado en {args.out}")

    if args.render:
        render_outputs(args.out, "topology.dot", "topology.mmd", also_png=True)
        print(
            "[*] Render listo: topology.dot / topology.mmd (y topology.png si Graphviz está)"
        )


if __name__ == "__main__":
    main()
