import json
import os
from typing import List, Dict, Any, Optional


def load_credentials(path: str | None = None) -> List[Dict[str, str]]:
    """Carga credenciales desde JSON (lista de objetos con username/password/secret)"""
    if not path:
        path = os.environ.get("MV_CREDENTIALS_FILE")
    if not path:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            out = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                out.append(
                    {
                        "username": item.get("username", ""),
                        "password": item.get("password", ""),
                        "secret": item.get("secret", ""),
                    }
                )
            return out
    except Exception:
        return []
    return []


# Defaults seguros (vacío) — requiere archivo de credenciales
CREDENTIAL_SETS: List[Dict[str, str]] = []


def _first_existing(paths: List[str]) -> Optional[str]:
    for p in paths:
        try:
            if p and os.path.exists(p):
                return p
        except Exception:
            continue
    return None


def load_run_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Carga configuración para 'mvtool run' desde JSON.
    Prioridades: argumento explícito -> MV_CONFIG_FILE/MVTOOL_CONFIG -> ./mvtool.json ./mvtool.config.json

    Ejemplo de archivo JSON:
    {
      "hosts_file": "Hosts/targets.txt",
      "outdir": "mv_results",
      "db": "mv_results/mvtool.db",
      "workers": 20,
      "retries": 2,
      "log_level": "INFO",
      "ssh_port": 22,
      "telnet_port": 23,
      "dump": false,
      "scan": true,
      "push": false,
      "allops": false,
      "syslog_ip": "192.0.2.10",
      "syslog_port": 514,
      "logging_source": "Loopback0",
      "ssh_legacy": false,
      "cred_backoff": 0,
      "prefer_telnet": false,
      "netconf_port": 830,
      "families_file": "families.txt",
      "credentials_file": "creds.json",
      "no_prompt": true,
      "huawei": false,
      "fortinet": false,
      "cisco": false,
      "fallback_telnet_on_auth": false
    }
    """
    try_paths = []
    if not path:
        env = os.environ.get("MV_CONFIG_FILE") or os.environ.get("MVTOOL_CONFIG")
        if env:
            try_paths.append(env)
        try_paths.extend(["mvtool.json", "mvtool.config.json"])
        path = _first_existing(try_paths)
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            # Permitir sección "run" opcional
            conf = data.get("run") if isinstance(data.get("run"), dict) else data
            if not isinstance(conf, dict):
                return {}
            # Resolver rutas relativas respecto del archivo de config
            base_dir = os.path.dirname(os.path.abspath(path))
            path_keys = [
                "hosts_file",
                "credentials_file",
                "families_file",
                "db",
                "outdir",
            ]
            for k in path_keys:
                v = conf.get(k)
                if isinstance(v, str) and v.strip():
                    vv = os.path.expandvars(os.path.expanduser(v))
                    if not os.path.isabs(vv):
                        vv = os.path.normpath(os.path.join(base_dir, vv))
                    conf[k] = vv
            return conf
    except Exception:
        return {}
    return {}
