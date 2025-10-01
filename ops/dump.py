import json
import os
from typing import Dict

from ..core.utils import ensure_dir


def write_dump_files(outdir: str, host: str, platform: str, device_type: str, outputs: Dict[str, str]):
    dumps_dir = os.path.join(outdir, "dumps")
    ensure_dir(dumps_dir)

    conf_path = os.path.join(dumps_dir, f"{host}_configuracion.txt")
    log_path = os.path.join(dumps_dir, f"{host}_logs.txt")
    meta_path = os.path.join(dumps_dir, f"{host}_detected.json")

    if platform == "huawei":
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(outputs.get("display current-configuration", "") or "")
            f.write("\n\n===== SAVED CONFIG =====\n")
            f.write(outputs.get("display saved-configuration", "") or "")
            f.write("\n\n===== DISPLAY VERSION =====\n")
            f.write(outputs.get("display version", "") or "")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(outputs.get("display logbuffer", "") or "")
            f.write("\n\n===== TRAPBUFFER =====\n")
            f.write(outputs.get("display trapbuffer", "") or "")
            f.write("\n\n===== HISTORY COMMAND =====\n")
            f.write(outputs.get("display history-command", "") or "")

    elif platform == "hp":
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(outputs.get("display current-configuration", "") or "")
            f.write("\n\n===== SAVED CONFIG =====\n")
            f.write(outputs.get("display saved-configuration", "") or "")
            f.write("\n\n===== DISPLAY VERSION =====\n")
            f.write(outputs.get("display version", "") or "")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(outputs.get("display logbuffer", "") or "")

    elif platform == "fortinet":
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(outputs.get("show full-configuration", "") or "")
            f.write("\n\n===== GET SYSTEM STATUS =====\n")
            f.write(outputs.get("get system status", "") or "")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(outputs.get("execute log display", "") or "")

    elif platform == "nokia":
        with open(conf_path, "w", encoding="utf-8") as f:
            # Prefer admin display-config; fallback to show configuration
            cfg = outputs.get("admin display-config") or outputs.get("show configuration") or ""
            f.write(cfg)
            f.write("\n\n===== SHOW VERSION =====\n")
            f.write(outputs.get("show version", "") or "")
        with open(log_path, "w", encoding="utf-8") as f:
            # Best-effort logs
            f.write(outputs.get("show log log-id 99", "") or "")

    else:  # Cisco
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(outputs.get("show running-config", "") or "")
            f.write("\n\n===== STARTUP CONFIG =====\n")
            f.write(outputs.get("show startup-config", "") or "")
            f.write("\n\n===== SHOW VERSION =====\n")
            f.write(outputs.get("show version", "") or "")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(outputs.get("show logging", "") or outputs.get("show logging logfile", "") or "")

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "platform": platform,
                "device_type": device_type,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
