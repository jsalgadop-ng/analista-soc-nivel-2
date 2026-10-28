"""Columnas derivadas que facilitan las detecciones (IP externa, tipo de logon, bytes, etc.)."""

from __future__ import annotations

import ipaddress
import re

import pandas as pd

# Solo RFC1918, loopback y link-local se consideran internas. Ojo: ipaddress.is_private
# también marca como privadas las redes de documentación (TEST-NET 192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24), que en exports de laboratorio representan Internet.
_INTERNAL_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    )
]

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
PRIVILEGED_ACCOUNT_RE = re.compile(r"admin|adm_|_adm|root|svc|service|backup|sql|sa$", re.I)
SERVICE_ACCOUNT_RE = re.compile(r"svc|service|backup|sql", re.I)
WEB_SERVICE_ACCOUNT_RE = re.compile(r"iis apppool|w3wp|www-data|apache|nginx|network service", re.I)


def parse_ip(value) -> ipaddress._BaseAddress | None:
    if value is None or pd.isna(value):
        return None
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def is_external(value) -> bool:
    ip = parse_ip(value)
    if ip is None:
        return False
    return not any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def is_privileged_account(user: str) -> bool:
    return bool(user) and bool(PRIVILEGED_ACCOUNT_RE.search(user.split("\\")[-1]))


def is_service_account(user: str) -> bool:
    return bool(user) and bool(SERVICE_ACCOUNT_RE.search(user.split("\\")[-1]))


def short_user(user: str) -> str:
    return str(user).split("\\")[-1].lower()


def add_features(df: pd.DataFrame) -> pd.DataFrame:
    d = df.copy()
    d["eid"] = d["Event_ID"].fillna("").astype(str)
    d["desc"] = d["Event_Description"].fillna("").astype(str)
    d["cmd"] = d["Process_CommandLine"].fillna("").astype(str)
    d["user"] = d["User"].fillna("").astype(str)
    d["host"] = d["Hostname"].fillna("").astype(str)
    d["src_ip"] = d["Source_IP"].fillna("").astype(str)
    d["dest"] = d["Destination"].fillna("").astype(str)
    d["src_ext"] = d["src_ip"].map(is_external)

    d["logon_type"] = d["desc"].str.extract(r"LogonType\s*=\s*(\d+)", flags=re.I)[0]
    d["src_host"] = d["desc"].str.extract(r"source\s*=\s*([\w\-.]+)", flags=re.I)[0]

    dest_ip = d["dest"].str.extract(_IP_RE)[0]
    desc_ip = d["desc"].str.extract(_IP_RE)[0]
    d["dest_ip"] = dest_ip.fillna(desc_ip)
    d["dest_ext"] = d["dest_ip"].map(is_external)

    d["bytes_out"] = pd.to_numeric(
        d["cmd"].str.extract(r"bytes_out\s*=\s*(\d+)", flags=re.I)[0], errors="coerce"
    )
    d["uri"] = d["cmd"].where(d["cmd"].str.startswith("/"), "")
    d["uri"] = d["uri"].where(d["uri"] != "", d["cmd"].str.extract(r"uri\s*=\s*(\S+)", flags=re.I)[0].fillna(""))

    d["is_fail_logon"] = (d["eid"] == "4625") | d["desc"].str.contains(r"failed to log ?on", case=False)
    d["is_success_logon"] = (d["eid"] == "4624") | d["desc"].str.contains(
        r"successfully logged on", case=False
    )
    d["is_http"] = (d["eid"].str.upper() == "HTTP_ACCESS") | d["Log_Source"].fillna("").str.contains(
        r"iis|apache|nginx|waf|http", case=False
    )
    d["is_proxy"] = (d["eid"].str.upper() == "PROXY_ACCESS") | d["Log_Source"].fillna("").str.contains(
        r"proxy", case=False
    )
    d["is_process"] = d["eid"].isin(["4688", "4104", "4103", "1", "800"]) | d["desc"].str.contains(
        r"process (was )?created|new process|script block", case=False
    )
    # Ruta de archivo accedida (eventos de acceso a objetos / recursos compartidos).
    file_from_cmd = d["cmd"].str.extract(r"file access:\s*(.+)$", flags=re.I)[0]
    file_from_desc = d["desc"].str.extract(r"file share access:\s*(.+)$", flags=re.I)[0]
    d["file_path"] = file_from_cmd.fillna(file_from_desc).fillna("")
    return d


def bursts(times: pd.Series, gap_minutes: float) -> pd.Series:
    """Etiqueta grupos de eventos separados por más de `gap_minutes` (times ya ordenados)."""
    return (times.diff() > pd.Timedelta(minutes=gap_minutes)).cumsum()


def cadence(times: pd.Series) -> tuple[float, float] | None:
    """(intervalo medio en segundos, coeficiente de variación) o None si hay pocos eventos."""
    if len(times) < 4:
        return None
    deltas = times.sort_values().diff().dropna().dt.total_seconds()
    mean = deltas.mean()
    if mean <= 0:
        return None
    return float(mean), float(deltas.std(ddof=0) / mean)
