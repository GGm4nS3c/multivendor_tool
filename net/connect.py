import re
from typing import Dict, Optional

from netmiko import ConnectHandler
try:
    from netmiko import SSHDetect
except Exception:
    from netmiko.ssh_autodetect import SSHDetect

try:
    from netmiko.exceptions import (
        NetMikoTimeoutException,
        NetMikoAuthenticationException,
    )
except Exception:
    from netmiko.ssh_exception import (
        NetMikoTimeoutException,
        NetMikoAuthenticationException,
    )

try:
    from paramiko.ssh_exception import SSHException, AuthenticationException
except Exception:
    SSHException = Exception
    AuthenticationException = Exception

from ..core.utils import sleep_min, sanitize_for_summary


def connect_with_retries(params: Dict, retries: int = 3, logger=None):
    last_exc = None
    for i in range(1, retries + 1):
        try:
            if logger:
                logger.debug(
                    f"Conectando a {params.get('host')}:{params.get('port', 22)} intento {i}/{retries}"
                )
            conn = ConnectHandler(**params)
            try:
                conn.set_keepalive(30)
            except Exception:
                pass
            return conn
        except Exception as e:
            last_exc = e
            msg = str(e)
            if logger:
                logger.warning(
                    f"Intento {i} fallido ({params.get('host')}): {sanitize_for_summary(msg)}"
                )

            # Limpiar kwargs no soportados
            if isinstance(params, dict):
                if isinstance(e, TypeError) and "unexpected keyword argument" in msg.lower():
                    cleaned = False
                    new_params = dict(params)
                    for k in ("look_for_keys", "allow_agent", "use_keys"):
                        if k in new_params:
                            new_params.pop(k, None)
                            cleaned = True
                    if cleaned:
                        if logger:
                            logger.debug(
                                f"Reintentando sin kwargs no soportados para {params.get('host')}"
                            )
                        params = new_params
                        continue

            transient_patterns = [
                "No existing session",
                "Bad file descriptor",
                "read_nonblocking",
                "Timed out",
                "Channel closed",
                "Error reading SSH protocol banner",
                "no acceptable ciphers",
                "negotiation failed",
            ]
            if i < retries and any(x.lower() in msg.lower() for x in transient_patterns):
                # Backoff progresivo
                sleep_min(max(5, 2 * i))
                continue
            raise
    raise last_exc


def guess_device_type_via_sshdetect(host: str, username: str, password: str, port: int = 22, timeout: int = 30) -> Optional[str]:
    try:
        return SSHDetect(
            device_type="autodetect",
            host=host,
            username=username,
            password=password,
            port=port,
            timeout=timeout,
        ).autodetect()
    except Exception:
        return None
