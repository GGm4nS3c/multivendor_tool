CMD_SETS = {
    # Cisco
    "ios": [
        "terminal length 0",
        "terminal width 511",
        "show version",
        "show running-config",
        "show startup-config",
        "show logging",
    ],
    "ios_xe": [
        "terminal length 0",
        "terminal width 511",
        "show version",
        "show running-config",
        "show startup-config",
        "show logging",
    ],
    "nxos": [
        "terminal length 0",
        "show version",
        "show running-config",
        "show startup-config",
        "show logging logfile",
    ],
    "iosxr": [
        "terminal length 0",
        "show version",
        "show running-config",
        "show startup-config",
        "show logging",
    ],
    "asa": [
        "terminal pager 0",
        "show version",
        "show running-config",
        "show startup-config",
        "show logging",
    ],
    # Nokia SR OS / TiMOS (7705/7750/7x50)
    "nokia": [
        # Pager off
        "environment no more",
        # Version and configs
        "show version",
        # Full configuration display; fallbacks handled at runtime if needed
        "admin display-config",
        "show configuration",
        # Logs (may vary by setup; not critical if unsupported)
        "show log log-id 99",
    ],
}

# Huawei VRP
HUAWEI_PRE_CMDS = [
    # VRP 5/8 (moderno)
    "screen-length 0 temporary",
    # VRP 3.x (antiguo): variantes
    "screen-length 0",
    "screen-length disable",
    "terminal page 0",
]

# Preferencia para VRP antiguos (prioriza variantes legacy primero)
HUAWEI_PRE_CMDS_LEGACY = [
    "screen-length disable",
    "terminal page 0",
    "screen-length 0",
    "screen-length 0 temporary",
]
HUAWEI_CMDS = [
    "display version",
    "display current-configuration",
    "display saved-configuration",
    "display logbuffer",
    "display trapbuffer",
    "display history-command",
]

# HPE Comware
HP_PRE_CMDS = ["screen-length disable"]
HP_CMDS = [
    "display version",
    "display current-configuration",
    "display saved-configuration",
    "display logbuffer",
]

# Fortinet FortiOS
FORTI_PRE_CMDS = [
    "config global",
    "config system console",
    "set output standard",
    "end",
]
FORTI_CMDS = [
    "get system status",
    "show full-configuration",
    "execute log display",
]

DEVICE_TYPES = {
    # Cisco
    "ios": "cisco_ios",
    "ios_xe": "cisco_xe_noprep",
    "nxos": "cisco_nxos",
    "iosxr": "cisco_xr",
    "asa": "cisco_asa",
    # Others
    "huawei": "huawei",
    "hp": "hp_comware",
    "fortinet": "fortinet",
    # Nokia SR OS / TiMOS
    "nokia": "nokia_sros",
}

DEVICE_TYPES_TELNET = {
    # Cisco
    "ios": "cisco_ios_telnet",
    "nxos": "cisco_nxos_telnet",
    "iosxr": "cisco_xr_telnet",
    "asa": "cisco_asa_telnet",
    # Others
    "huawei": "huawei_telnet",
    "hp": "hp_comware_telnet",
    # Fortinet: soporte telnet depende del entorno; intentaremos si existe
    "fortinet": "fortinet_telnet",
    # Nokia SR OS / TiMOS
    "nokia": "nokia_sros_telnet",
}

PLATFORM_PATTERNS = [
    # Cisco
    (r"(?i)Cisco IOS XE Software|IOS-?XE", "ios_xe"),
    (r"(?i)Cisco IOS Software|IOS \(tm\)", "ios"),
    (r"(?i)NX-OS|Cisco Nexus Operating System", "nxos"),
    (r"(?i)IOS XR|XR Software", "iosxr"),
    (r"(?i)Adaptive Security Appliance|Cisco ASA|Firepower Threat Defense", "asa"),
    # Huawei
    (r"(?i)Huawei Versatile Routing Platform|VRP \(R\)|Huawei Technologies", "huawei"),
    # HPE Comware / H3C
    (r"(?i)Comware.*Software|H3C Comware|Hewlett Packard Enterprise Comware|HP Comware", "hp"),
    # Fortinet
    (r"(?i)FortiGate|FortiOS|Fortinet", "fortinet"),
    # Nokia SR OS / TiMOS
    (r"(?i)TiMOS|Nokia\s+77\d{2}\b|Nokia SR OS", "nokia"),
]

MODEL_HINTS = [
    (r"(?i)\bNexus\b|\bN[3579]K\b|\bN[39]K\b|\bN9K\b|\bN3K\b|\bN7K\b|\bN5K\b", "nxos"),
    (r"(?i)\bASR9\d{2,}\b|\bASR 9", "iosxr"),
    (r"(?i)\bASR1\d{3}\b|\bISR|C8\d{3}\b|C9\d{3}\b|CSR1000V\b|Catalyst 8\d{3}\b|Catalyst 9\d{3}\b", "ios"),
    (r"(?i)\bASA\b|\bFTD\b|Firepower", "asa"),
]

# Scan extras por plataforma
SCAN_EXTRAS = {
    # Rutas
    "route": {
        "ios": "show ip route",
        "nxos": "show ip route",
        "iosxr": "show route",
        "asa": "show route",
        "huawei": "display ip routing-table",
        "hp": "display ip routing-table",
        "fortinet": "get router info routing-table all",
        "nokia": "show router route-table",
    },
    # ARP
    "arp": {
        "ios": "show arp",
        "nxos": "show ip arp",
        "iosxr": "show arp",
        "asa": "show arp",
        "huawei": "display arp",
        "hp": "display arp",
        "fortinet": "get system arp",
        "nokia": "show router arp",
    },
}
