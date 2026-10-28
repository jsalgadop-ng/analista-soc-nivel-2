"""Carga y normalización del Excel exportado desde el SIEM."""

from __future__ import annotations

import hashlib
import io
import re
from dataclasses import dataclass, field

import pandas as pd

# Columnas canónicas que usa el motor de análisis.
CANONICAL_COLUMNS = [
    "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Destination",
    "Log_Source", "Event_Description", "Process_CommandLine", "Result", "Severity",
]
REQUIRED_COLUMNS = ["Timestamp", "Event_ID"]

# Alias aceptados (comparación sin mayúsculas, espacios ni guiones bajos).
_ALIASES = {
    "logid": "Log_ID", "id": "Log_ID", "eventrecordid": "Log_ID",
    "timestamp": "Timestamp", "time": "Timestamp", "date": "Timestamp", "fecha": "Timestamp",
    "timegenerated": "Timestamp", "datetime": "Timestamp",
    "hostname": "Hostname", "host": "Hostname", "computer": "Hostname", "equipo": "Hostname",
    "eventid": "Event_ID", "evento": "Event_ID",
    "user": "User", "usuario": "User", "account": "User", "username": "User",
    "sourceip": "Source_IP", "srcip": "Source_IP", "ipaddress": "Source_IP", "iporigen": "Source_IP",
    "destination": "Destination", "destino": "Destination", "dst": "Destination",
    "logsource": "Log_Source", "source": "Log_Source", "fuente": "Log_Source",
    "eventdescription": "Event_Description", "description": "Event_Description",
    "descripcion": "Event_Description", "message": "Event_Description",
    "processcommandline": "Process_CommandLine", "commandline": "Process_CommandLine",
    "process": "Process_CommandLine",
    "result": "Result", "resultado": "Result", "status": "Result",
    "severity": "Severity", "severidad": "Severity", "level": "Severity",
}


class LogLoadError(Exception):
    """El archivo no se pudo interpretar como un export de logs válido."""


@dataclass
class LoadedLogs:
    df: pd.DataFrame
    file_name: str
    sha256: str
    sheet: str
    warnings: list[str] = field(default_factory=list)


def _norm(name: str) -> str:
    return re.sub(r"[\s_\-]", "", str(name)).lower()


def _pick_sheet(xls: pd.ExcelFile) -> str:
    """Elige la hoja con más columnas reconocibles (los exports suelen tener una sola)."""
    best, best_hits = xls.sheet_names[0], -1
    for name in xls.sheet_names:
        cols = xls.parse(name, nrows=0).columns
        hits = sum(1 for c in cols if _norm(c) in _ALIASES)
        if hits > best_hits:
            best, best_hits = name, hits
    return best


def load_logs(data: bytes, file_name: str) -> LoadedLogs:
    """Lee un .xlsx (bytes) y devuelve un DataFrame con columnas canónicas y tipos limpios."""
    try:
        xls = pd.ExcelFile(io.BytesIO(data), engine="openpyxl")
    except Exception as exc:  # openpyxl lanza varios tipos según la corrupción
        raise LogLoadError(f"No se pudo abrir el archivo como Excel (.xlsx): {exc}") from exc

    sheet = _pick_sheet(xls)
    raw = xls.parse(sheet, dtype=str)
    warnings: list[str] = []

    rename = {}
    for col in raw.columns:
        target = _ALIASES.get(_norm(col))
        if target and target not in rename.values():
            rename[col] = target
    df = raw.rename(columns=rename)

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise LogLoadError(
            "Faltan columnas obligatorias: " + ", ".join(missing)
            + f". Columnas encontradas: {', '.join(map(str, raw.columns))}"
        )

    for col in CANONICAL_COLUMNS:
        if col not in df.columns:
            df[col] = None
            if col != "Log_ID":
                warnings.append(f"La columna '{col}' no existe en el archivo; se asume vacía.")
    extra = [c for c in df.columns if c not in CANONICAL_COLUMNS]
    df = df[CANONICAL_COLUMNS + extra]

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    bad_ts = int(df["Timestamp"].isna().sum())
    if bad_ts:
        warnings.append(f"{bad_ts} registros con fecha no interpretable fueron descartados.")
        df = df[df["Timestamp"].notna()]
    if df.empty:
        raise LogLoadError("El archivo no contiene registros con fecha válida.")

    for col in CANONICAL_COLUMNS:
        if col != "Timestamp":
            df[col] = df[col].astype("string").str.strip()
            df[col] = df[col].replace({"": pd.NA, "nan": pd.NA, "NaN": pd.NA, "None": pd.NA})
    # Event_ID puede venir como 4625.0 si Excel lo guardó como número.
    df["Event_ID"] = df["Event_ID"].str.replace(r"\.0$", "", regex=True)

    if df["Log_ID"].isna().all():
        df["Log_ID"] = [f"ROW-{i:05d}" for i in range(1, len(df) + 1)]
        warnings.append("El archivo no trae identificador de log; se generaron IDs ROW-xxxxx.")
    elif df["Log_ID"].duplicated().any():
        warnings.append("Hay Log_ID duplicados; las referencias a evidencias pueden ser ambiguas.")

    df = df.sort_values("Timestamp", kind="stable").reset_index(drop=True)
    return LoadedLogs(
        df=df,
        file_name=file_name,
        sha256=hashlib.sha256(data).hexdigest(),
        sheet=sheet,
        warnings=warnings,
    )
