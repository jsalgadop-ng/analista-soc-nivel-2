"""Motor de detección basado en reglas.

Cada detector recibe el DataFrame con columnas derivadas (ver features.py) y devuelve
hallazgos. Ningún detector produce un hallazgo sin Log_IDs que lo respalden.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import permutations

import pandas as pd

from .features import (
    WEB_SERVICE_ACCOUNT_RE, bursts, cadence, is_external, is_privileged_account,
    is_service_account,
)
from .knowledge import SENSITIVE_DATA_PATTERN, host_role, is_critical_host
from .models import Finding


@dataclass
class DetectionConfig:
    burst_gap_min: float = 10            # separación máxima entre intentos de una misma ráfaga
    bf_min_failures: int = 10            # fallos para considerar fuerza bruta (origen interno)
    bf_min_failures_external: int = 3    # umbral reducido si el origen es Internet
    spray_min_users: int = 5             # cuentas distintas para hablar de password spraying
    success_window_min: float = 60       # ventana para "éxito tras ataque"
    mass_access_min_files: int = 10
    mass_access_gap_min: float = 10
    exfil_min_bytes: int = 50 * 1024 ** 2
    exfil_min_uploads: int = 10
    business_start_hour: int = 7
    business_end_hour: int = 20
    correlation_gap_min: float = 90      # distancia temporal máxima para correlacionar hallazgos
    recurring_min_exec: int = 3


def _ids(rows: pd.DataFrame) -> list[str]:
    return rows["Log_ID"].astype(str).tolist()


def _fmt_t(ts: pd.Timestamp) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def _hm(ts: pd.Timestamp) -> str:
    return ts.strftime("%H:%M:%S")


def _mb(n: float) -> str:
    return f"{n / 1024 ** 2:,.1f} MB"


def _join(items, limit: int = 8) -> str:
    items = sorted({str(i) for i in items if str(i)})
    if len(items) > limit:
        return ", ".join(items[:limit]) + f" y {len(items) - limit} más"
    return ", ".join(items)


def _entities(rows: pd.DataFrame) -> dict:
    return {
        "users": {u for u in rows["user"] if u and u != "-"},
        "hosts": {h for h in rows["host"] if h},
        "ips": {i for i in rows["src_ip"] if i},
    }


def _finding(rows: pd.DataFrame, **kw) -> Finding:
    ent = _entities(rows)
    for key in ("users", "hosts", "ips"):
        kw.setdefault(key, ent[key])
    kw.setdefault("evidence_ids", _ids(rows))
    kw.setdefault("start", rows["Timestamp"].min())
    kw.setdefault("end", rows["Timestamp"].max())
    return Finding(**kw)


# --------------------------------------------------------------------------------------
# 1. Fuerza bruta / password spraying y éxito posterior
# --------------------------------------------------------------------------------------
def detect_credential_attacks(d: pd.DataFrame, cfg: DetectionConfig, consumed: set[str]) -> list[Finding]:
    out: list[Finding] = []
    fails = d[d["is_fail_logon"] & (d["src_ip"] != "")]
    for ip, g in fails.groupby("src_ip"):
        g = g.sort_values("Timestamp")
        external = is_external(ip)
        threshold = cfg.bf_min_failures_external if external else cfg.bf_min_failures
        for _, b in g.groupby(bursts(g["Timestamp"], cfg.burst_gap_min)):
            if len(b) < threshold:
                continue
            users = sorted(set(b["user"]) - {"", "-"})
            targets = sorted(set(b["host"]) - {""})
            rdp = (b["logon_type"] == "10").any()
            spray = len(users) >= cfg.spray_min_users
            t0, t1 = b["Timestamp"].min(), b["Timestamp"].max()
            minutes = max(1, round((t1 - t0).total_seconds() / 60))
            cad = cadence(b["Timestamp"])

            if spray:
                title = f"Password spraying desde {ip} contra {len(users)} cuentas"
                mitre = [("T1110.003", "Password Spraying")]
                base = 35
                technical = (
                    "Un mismo origen prueba pocas contraseñas contra muchas cuentas distintas para evitar el "
                    "bloqueo por intentos fallidos. Eventos 4625 con motivo 'bad password' indican que las "
                    "cuentas existen y que solo falla la contraseña."
                )
            else:
                title = f"Fuerza bruta {'RDP ' if rdp else ''}desde {ip} contra {_join(users)}"
                mitre = [("T1110.001", "Password Guessing")]
                base = 30
                technical = (
                    "Intentos repetidos de autenticación contra la misma cuenta desde un único origen. "
                    + ("LogonType=10 corresponde a inicio de sesión interactivo remoto (RDP). " if rdp else "")
                )
            if external and rdp:
                mitre.append(("T1133", "External Remote Services"))

            per_user = b.groupby("user").size()
            desc = (
                f"{len(b)} intentos fallidos de inicio de sesión entre {_hm(t0)} y {_hm(t1)} "
                f"(~{minutes} min) desde {ip} ({'Internet' if external else 'red interna'}) contra "
                f"{_join(targets)}. Cuentas objetivo ({len(users)}): {_join(users, 12)}; "
                f"entre {per_user.min()} y {per_user.max()} intentos por cuenta."
            )
            if cad:
                desc += f" Cadencia media de {cad[0]:.0f} s entre intentos."

            f = _finding(
                b, category="fuerza_bruta", title=title, description=desc, technical=technical,
                mitre=mitre, base_score=base, pivots={f"ip:{ip}"},
                iocs=[("IP origen", ip)],
            )
            if external:
                f.add(15, f"Origen externo (Internet): {ip}")
            crit = [h for h in targets if is_critical_host(h)]
            if crit:
                f.add(10, f"Dirigido a activo crítico: {_join(crit)} ({host_role(crit[0])})")
            if any(is_privileged_account(u) for u in users):
                f.add(10, "Incluye cuentas privilegiadas o de servicio: "
                          + _join(u for u in users if is_privileged_account(u)))
            if cad and cad[1] < 0.35:
                f.add(5, f"Cadencia regular (~{cad[0]:.0f} s, CV {cad[1]:.2f}): indica herramienta automatizada")
            out.append(f)

            # ¿Hubo inicio de sesión exitoso desde el mismo origen tras el ataque?
            window_end = t1 + pd.Timedelta(minutes=cfg.success_window_min)
            ok = d[d["is_success_logon"] & (d["src_ip"] == ip)
                   & (d["Timestamp"] >= t0) & (d["Timestamp"] <= window_end)]
            for user, s in ok.groupby("user"):
                prev_fails = b[b["user"] == user]
                rows = pd.concat([prev_fails, s]).sort_values("Timestamp")
                rdp_ok = (s["logon_type"] == "10").any()
                first = s.iloc[0]
                sf = _finding(
                    rows, category="inicio_sospechoso",
                    title=f"Inicio de sesión exitoso de {user} desde {ip} tras ataque de credenciales",
                    description=(
                        f"Tras {len(b)} intentos fallidos desde {ip}, la cuenta {user} inicia sesión con éxito "
                        f"en {first['host']} a las {_hm(first['Timestamp'])} (Log {first['Log_ID']}), "
                        f"{(first['Timestamp'] - t1).total_seconds() / 60:.0f} min después del último fallo. "
                        f"La cuenta acumulaba {len(prev_fails)} fallos previos desde ese origen."
                    ),
                    technical=(
                        "Un inicio de sesión correcto desde el mismo origen que acaba de ejecutar un ataque de "
                        "credenciales indica con alta probabilidad que la contraseña fue adivinada: la cuenta "
                        "debe considerarse comprometida (uso de cuentas válidas)."
                    ),
                    mitre=[("T1078", "Valid Accounts")] + ([("T1021.001", "Remote Desktop Protocol")] if rdp_ok else []),
                    base_score=45, pivots={f"ip:{ip}", f"user:{user}"},
                    iocs=[("IP origen", ip), ("Cuenta comprometida", user)],
                )
                if external:
                    sf.add(15, f"Sesión establecida desde Internet ({ip})")
                if len(prev_fails):
                    sf.add(15, f"La cuenta había sido objetivo directo del ataque ({len(prev_fails)} fallos previos)")
                if rdp_ok:
                    sf.add(5, "Acceso interactivo remoto (RDP, LogonType=10)")
                if is_privileged_account(user):
                    sf.add(10, f"Cuenta privilegiada: {user}")
                if is_critical_host(first["host"]):
                    sf.add(10, f"Sesión en activo crítico: {first['host']} ({host_role(first['host'])})")
                consumed.update(_ids(s))
                out.append(sf)
    return out


# --------------------------------------------------------------------------------------
# 2. Inicios de sesión sospechosos no cubiertos por el detector anterior
# --------------------------------------------------------------------------------------
def detect_suspicious_logons(d: pd.DataFrame, cfg: DetectionConfig, consumed: set[str]) -> list[Finding]:
    out: list[Finding] = []
    ok = d[d["is_success_logon"] & ~d["Log_ID"].isin(consumed)]

    for (ip, user), s in ok[ok["src_ext"]].groupby(["src_ip", "user"]):
        f = _finding(
            s, category="inicio_sospechoso",
            title=f"Inicio de sesión de {user} desde IP externa {ip}",
            description=f"{len(s)} inicios de sesión exitosos de {user} desde {ip} en {_join(s['host'])}.",
            technical="Los inicios de sesión directos desde Internet a sistemas internos no son habituales "
                      "y suelen indicar servicios expuestos o credenciales usadas por terceros.",
            mitre=[("T1078", "Valid Accounts"), ("T1133", "External Remote Services")],
            base_score=40, pivots={f"ip:{ip}", f"user:{user}"},
            iocs=[("IP origen", ip)],
        )
        f.add(15, f"Origen externo (Internet): {ip}")
        if is_privileged_account(user):
            f.add(10, f"Cuenta privilegiada: {user}")
        out.append(f)

    hours = ok["Timestamp"].dt.hour
    off = ok[(hours < cfg.business_start_hour) | (hours >= cfg.business_end_hour)
             | (ok["Timestamp"].dt.dayofweek >= 5)]
    off = off[~off["src_ext"]]
    for user, s in off.groupby("user"):
        if not user or user == "-":
            continue
        f = _finding(
            s, category="inicio_sospechoso",
            title=f"Inicios de sesión fuera de horario de {user}",
            description=(
                f"{len(s)} inicios de sesión de {user} fuera del horario laboral "
                f"({cfg.business_start_hour:02d}:00-{cfg.business_end_hour:02d}:00 L-V) en {_join(s['host'])}."
            ),
            technical="La actividad fuera de horario es un indicador débil por sí solo, pero relevante si "
                      "coincide con otras anomalías de la misma cuenta.",
            mitre=[("T1078", "Valid Accounts")], base_score=20, pivots={f"user:{user}"},
        )
        if is_privileged_account(user):
            f.add(15, f"Cuenta privilegiada: {user}")
        out.append(f)
    return out


# --------------------------------------------------------------------------------------
# 3. Escalamiento de privilegios
# --------------------------------------------------------------------------------------
_GROUP_CHANGE_EIDS = {"4728": "grupo global", "4732": "grupo local", "4756": "grupo universal"}


def detect_privilege_escalation(d: pd.DataFrame, cfg: DetectionConfig, consumed: set[str]) -> list[Finding]:
    out: list[Finding] = []
    priv = d[(d["eid"] == "4672") & d["src_ext"]]
    for (ip, user), s in priv.groupby(["src_ip", "user"]):
        first = s.iloc[0]
        prior = d[d["is_success_logon"] & (d["src_ip"] == ip) & (d["user"] == user)
                  & (d["Timestamp"] <= first["Timestamp"])
                  & (d["Timestamp"] >= first["Timestamp"] - pd.Timedelta(minutes=30))]
        f = _finding(
            s, category="escalamiento",
            title=f"Privilegios especiales asignados a {user} en sesión desde {ip}",
            description=(
                f"Evento 4672 (privilegios especiales asignados al nuevo inicio de sesión) para {user} en "
                f"{_join(s['host'])} a las {_hm(first['Timestamp'])}, con origen {ip} (Internet)."
                + (f" Ocurre {(first['Timestamp'] - prior.iloc[-1]['Timestamp']).total_seconds() / 60:.0f} min "
                   f"después del inicio de sesión {prior.iloc[-1]['Log_ID']} desde el mismo origen."
                   if len(prior) else "")
            ),
            technical=(
                "El evento 4672 se genera cuando una sesión obtiene privilegios sensibles (p. ej. "
                "SeDebugPrivilege, SeBackupPrivilege, SeTakeOwnership). Que una sesión con origen externo "
                "reciba estos privilegios implica control administrativo del equipo por parte de ese origen."
            ),
            mitre=[("T1078.002", "Valid Accounts: Domain Accounts"), ("T1068", "Privilege Escalation")],
            base_score=40, pivots={f"ip:{ip}", f"user:{user}"},
        )
        f.add(15, f"Sesión privilegiada con origen externo ({ip})")
        if len(prior):
            f.add(10, "Sucede inmediatamente tras un inicio de sesión sospechoso del mismo origen")
        crit = [h for h in s["host"] if is_critical_host(h)]
        if crit:
            f.add(10, f"Privilegios en activo crítico: {_join(crit)}")
        out.append(f)

    changes = d[d["eid"].isin(list(_GROUP_CHANGE_EIDS) + ["4720"])]
    for user, s in changes.groupby("user"):
        f = _finding(
            s, category="escalamiento",
            title=f"Cambios en cuentas o grupos privilegiados realizados por {user}",
            description=f"{len(s)} eventos de creación de cuenta o alta en grupos de seguridad por {user}: "
                        + "; ".join(s["desc"].head(5)),
            technical="Agregar cuentas a grupos privilegiados o crear cuentas nuevas es una técnica habitual "
                      "para consolidar acceso administrativo.",
            mitre=[("T1098", "Account Manipulation"), ("T1136", "Create Account")],
            base_score=45, pivots={f"user:{user}"},
        )
        out.append(f)
    return out


# --------------------------------------------------------------------------------------
# 4. Persistencia (antes que comandos, para no duplicar evidencias)
# --------------------------------------------------------------------------------------
_PERSIST_CMD_RE = re.compile(
    r"schtasks(\.exe)?\s+/create|reg(\.exe)?\s+add\s+.*\\run\b|new-service|sc(\.exe)?\s+create", re.I
)
_UNUSUAL_PATH_RE = re.compile(
    r"[a-z]:\\(programdata|users\\public|windows\\temp|temp|perflogs|users\\[^\\]+\\appdata)\\", re.I
)
_MASQUERADE_RE = re.compile(r"microsoft|windows|update|svchost|winupd|defender", re.I)


def detect_persistence(d: pd.DataFrame, cfg: DetectionConfig, consumed: set[str]) -> list[Finding]:
    out: list[Finding] = []
    persist = d[d["eid"].isin(["4698", "4697", "7045"]) | d["cmd"].str.contains(_PERSIST_CMD_RE)]

    # Binarios referenciados por la persistencia o ejecutados desde rutas inusuales con periodicidad.
    referenced = set()
    for text in persist["cmd"]:
        for m in re.finditer(r"([a-z]:\\[^\s;\"']+\.(?:exe|ps1|bat|dll|vbs))", text, re.I):
            referenced.add(m.group(1).lower())
    recurring_rows = []
    procs = d[(d["eid"] == "4688") & (d["cmd"] != "")]
    for (host, cmdline), g in procs.groupby(["host", "cmd"]):
        if len(g) < cfg.recurring_min_exec:
            continue
        exe = cmdline.strip('"').split(" ")[0].lower()
        if exe not in referenced and not _UNUSUAL_PATH_RE.search(cmdline):
            continue
        cad = cadence(g["Timestamp"])
        if exe in referenced or (cad and cad[1] < 0.25):
            recurring_rows.append(g)
    recurring = pd.concat(recurring_rows) if recurring_rows else d.iloc[0:0]

    allrows = pd.concat([persist, recurring]).drop_duplicates("Log_ID").sort_values("Timestamp")
    if allrows.empty:
        return out
    for host, g in allrows.groupby("host"):
        for _, b in g.groupby(bursts(g["Timestamp"], 180)):
            kinds, details, iocs, mitre = [], [], [], []
            tasks = b[b["eid"] == "4698"]
            services = b[b["eid"].isin(["7045", "4697"])]
            cmd_persist = b[b["cmd"].str.contains(_PERSIST_CMD_RE)]
            rec = b[b["Log_ID"].isin(recurring["Log_ID"])]
            if len(tasks) or len(cmd_persist):
                kinds.append("tarea programada / clave de inicio")
                mitre.append(("T1053.005", "Scheduled Task"))
                for _, r in pd.concat([tasks, cmd_persist]).iterrows():
                    details.append(f"{r['Log_ID']}: {r['cmd'] or r['desc']}")
                    m = re.search(r"TaskName=([^;]+)", r["cmd"])
                    if m:
                        iocs.append(("Tarea programada", m.group(1).strip()))
            if len(services):
                kinds.append("servicio instalado")
                mitre.append(("T1543.003", "Windows Service"))
                for _, r in services.iterrows():
                    details.append(f"{r['Log_ID']}: {r['cmd'] or r['desc']}")
                    m = re.search(r"ServiceName=([^;]+)", r["cmd"])
                    if m:
                        iocs.append(("Servicio", m.group(1).strip()))
            if len(rec):
                for cmdline, rg in rec.groupby("cmd"):
                    cad = cadence(rg["Timestamp"])
                    every = f" cada ~{cad[0] / 60:.0f} min" if cad else ""
                    kinds.append(f"ejecución periódica de {cmdline}")
                    details.append(f"{cmdline} ejecutado {len(rg)} veces{every} "
                                   f"({_hm(rg['Timestamp'].min())}-{_hm(rg['Timestamp'].max())})")
            for path in sorted({p for t in b["cmd"] for p in re.findall(r"[A-Za-z]:\\[^\s;\"']+\.\w{2,4}", t)}):
                iocs.append(("Archivo", path))

            f = _finding(
                b, category="persistencia",
                title=f"Mecanismos de persistencia en {host}: " + ", ".join(dict.fromkeys(kinds)),
                description=f"Se observan {len(b)} eventos de persistencia en {host} "
                            f"({host_role(host)}) por {_join(b['user'])}: " + " | ".join(details),
                technical=(
                    "Las tareas programadas (4698) y los servicios nuevos (7045) permiten que un binario o "
                    "script se ejecute automáticamente y sobreviva a reinicios. Ubicar los binarios en "
                    "C:\\ProgramData u otras rutas escribibles por usuarios, con nombres que imitan "
                    "componentes de Windows, es una técnica de enmascaramiento habitual."
                ),
                mitre=list(dict.fromkeys(mitre)) or [("T1547", "Boot or Logon Autostart Execution")],
                base_score=40, pivots={f"user:{u}" for u in _entities(b)["users"]},
                iocs=list(dict.fromkeys(iocs)),
            )
            texts = " ".join(b["cmd"])
            if _MASQUERADE_RE.search(texts) and _UNUSUAL_PATH_RE.search(texts):
                f.mitre.append(("T1036.005", "Masquerading: Match Legitimate Name or Location"))
                f.add(15, "Nombres que imitan componentes de Windows con binarios en rutas no estándar")
            if len(rec):
                f.add(10, f"El binario se ejecuta de forma periódica ({len(rec)} ejecuciones): persistencia activa")
            if len(set(kinds)) > 1:
                f.add(5, "Varios mecanismos de persistencia combinados (redundancia típica de un atacante)")
            if is_critical_host(host):
                f.add(10, f"Activo crítico: {host}")
            consumed.update(f.evidence_ids)
            out.append(f)
    return out


# --------------------------------------------------------------------------------------
# 5. Ataques a aplicaciones web
# --------------------------------------------------------------------------------------
_WEB_PATTERNS = [
    ("webshell", re.compile(r"\.(aspx?|php|jsp|ashx)\?.*\b(cmd|exec|command|c)=|/uploads?/.*\.(aspx?|php|jsp)", re.I),
     "Webshell en directorio de cargas con parámetro de comando"),
    ("sqli", re.compile(r"union(\s|%20)+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\d+\)", re.I), "Inyección SQL"),
    ("traversal", re.compile(r"\.\./|%2e%2e%2f", re.I), "Path traversal"),
    ("xss", re.compile(r"<script|%3cscript", re.I), "Cross-site scripting"),
    ("admin", re.compile(r"/admin|/manager|/wp-admin|/phpmyadmin", re.I), "Acceso a panel administrativo"),
    ("login_enum", re.compile(r"login\?.*user(name)?=", re.I), "Intentos de login con usuario fijado en la URL"),
    ("export", re.compile(r"/export|/dump|/backup", re.I), "Endpoint de exportación de datos"),
]
_WEB_STRONG = {"webshell", "sqli", "traversal", "xss"}


def detect_web_attacks(d: pd.DataFrame, cfg: DetectionConfig, consumed: set[str]) -> list[Finding]:
    out: list[Finding] = []
    web = d[d["is_http"] & (d["uri"] != "")]
    for ip, g in web.groupby("src_ip"):
        g = g.sort_values("Timestamp")
        for _, b in g.groupby(bursts(g["Timestamp"], 30)):
            hits: dict[str, pd.DataFrame] = {}
            for key, rx, _ in _WEB_PATTERNS:
                m = b[b["uri"].str.contains(rx)]
                if len(m):
                    hits[key] = m
            strong = _WEB_STRONG & hits.keys()
            if not strong and not (is_external(ip) and sum(len(v) for v in hits.values()) >= 10):
                continue
            hosts = sorted(set(b["host"]))
            t0, t1 = b["Timestamp"].min(), b["Timestamp"].max()
            status = b.groupby(["uri", "Result"]).size().reset_index(name="n")
            status_txt = "; ".join(
                f"{uri}: " + ", ".join(f"{r['Result']}×{r['n']}" for _, r in grp.iterrows())
                for uri, grp in status.groupby("uri")
            )
            # ¿El servidor web lanzó procesos (ejecución de comandos confirmada)?
            spawned = d[d["host"].isin(hosts) & d["is_process"]
                        & d["user"].str.contains(WEB_SERVICE_ACCOUNT_RE)
                        & (d["Timestamp"] >= t0) & (d["Timestamp"] <= t1 + pd.Timedelta(minutes=60))]
            rows = pd.concat([b, spawned]).sort_values("Timestamp")
            labels = [lbl for key, _, lbl in _WEB_PATTERNS if key in hits]
            mitre = [("T1190", "Exploit Public-Facing Application")]
            if "webshell" in hits:
                mitre.append(("T1505.003", "Web Shell"))
            if len(spawned):
                mitre += [("T1059.003", "Windows Command Shell"), ("T1033", "System Owner/User Discovery")]
            desc = (
                f"{len(b)} peticiones HTTP desde {ip} a {_join(hosts)} entre {_hm(t0)} y {_hm(t1)}. "
                f"Patrones: {', '.join(labels)}. Respuestas por recurso: {status_txt}."
            )
            if len(spawned):
                sp = spawned.iloc[0]
                desc += (f" A las {_hm(sp['Timestamp'])} la cuenta {sp['user']} del servidor web crea el proceso "
                         f"'{sp['cmd']}' (Log {sp['Log_ID']}).")
            f = _finding(
                rows, category="ataque_web",
                title=f"Explotación de aplicación web en {_join(hosts)} desde {ip}"
                      + (" con ejecución de comandos" if len(spawned) else ""),
                description=desc,
                technical=(
                    "Peticiones a un script en el directorio de cargas con un parámetro 'cmd' son la firma de "
                    "una webshell: un archivo subido por el atacante que ejecuta comandos del sistema. La "
                    "creación de cmd.exe por la identidad del application pool de IIS confirma que la "
                    "ejecución remota de código tuvo éxito. Las peticiones a /admin, login y exportación "
                    "muestran reconocimiento y búsqueda de datos."
                    if "webshell" in hits else
                    "Patrones de ataque en las URL solicitadas hacia la aplicación web."
                ),
                mitre=mitre, base_score=40,
                pivots={f"ip:{ip}"} | {f"user:{u}" for u in set(spawned["user"])},
                iocs=[("IP origen", ip)] + [("URI", u) for u in sorted(set(b["uri"]))],
            )
            if is_external(ip):
                f.add(15, f"Origen externo (Internet): {ip}")
            if strong:
                f.add(10, "Patrones de explotación inequívocos: " + ", ".join(
                    lbl for key, _, lbl in _WEB_PATTERNS if key in strong))
            if len(spawned):
                f.add(25, f"Ejecución remota de código confirmada: '{spawned.iloc[0]['cmd']}' "
                          f"bajo {spawned.iloc[0]['user']}")
            if "export" in hits and (hits["export"]["Result"] == "200").any():
                n200 = int((hits["export"]["Result"] == "200").sum())
                f.add(5, f"{n200} respuestas 200 en endpoint de exportación: posible extracción de datos")
            consumed.update(_ids(spawned))
            out.append(f)
    return out


# --------------------------------------------------------------------------------------
# 6. Comandos y procesos sospechosos
# --------------------------------------------------------------------------------------
@dataclass
class CommandRule:
    key: str
    pattern: re.Pattern
    name: str
    mitre: list[tuple[str, str]]
    category: str
    weight: int
    explanation: str


COMMAND_RULES = [
    CommandRule("encoded_ps", re.compile(r"powershell(\.exe)?\b.*\s-(e|ec|enc|encodedcommand)\b", re.I),
                "PowerShell con comando codificado en Base64",
                [("T1059.001", "PowerShell"), ("T1027", "Obfuscated Files or Information")], "comandos", 40,
                "-EncodedCommand oculta el script real a la inspección visual y a muchos controles; "
                "es poco habitual en administración legítima y muy común en malware."),
    CommandRule("ps_evasion", re.compile(
        r"-(w|windowstyle)\s+hidden|-executionpolicy\s+bypass|\biex\b|invoke-expression|downloadstring|"
        r"frombase64string", re.I),
                "PowerShell con evasión o descarga en memoria",
                [("T1059.001", "PowerShell"), ("T1140", "Deobfuscate/Decode Files")], "comandos", 35,
                "Ventanas ocultas, bypass de la política de ejecución o IEX son técnicas para ejecutar "
                "código sin dejar rastro en disco."),
    CommandRule("shadow_delete", re.compile(
        r"vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete|"
        r"bcdedit.*recoveryenabled\s+no", re.I),
                "Eliminación de copias de sombra (inhibición de recuperación)",
                [("T1490", "Inhibit System Recovery")], "comandos", 65,
                "Borrar las instantáneas de volumen impide restaurar archivos; es el paso previo típico al "
                "cifrado en ataques de ransomware."),
    CommandRule("cred_dump", re.compile(
        r"mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs(\.dll)?.*minidump|ntds\.dit", re.I),
                "Volcado de credenciales", [("T1003", "OS Credential Dumping")], "comandos", 65,
                "Extracción de hashes o contraseñas de la memoria de LSASS o de la base NTDS."),
    CommandRule("defense_evasion", re.compile(
        r"set-mppreference.*disable|wevtutil(\.exe)?\s+cl|clear-eventlog|auditpol.*/clear", re.I),
                "Desactivación de defensas o borrado de registros",
                [("T1562.001", "Disable or Modify Tools"), ("T1070.001", "Clear Windows Event Logs")],
                "comandos", 55, "Desactivar el antivirus o limpiar logs busca impedir la detección y la investigación."),
    CommandRule("lolbin_download", re.compile(
        r"certutil.*-urlcache|bitsadmin.*/transfer|mshta(\.exe)?\s+https?:|regsvr32.*/i:https?:|"
        r"invoke-webrequest|curl(\.exe)?\s+https?:|wget\s+https?:", re.I),
                "Descarga de herramientas con binarios del sistema", [("T1105", "Ingress Tool Transfer")],
                "comandos", 40, "Uso de utilidades legítimas (LOLBins) para traer herramientas al equipo."),
    CommandRule("discovery_priv", re.compile(
        r"get-localgroupmember|net(\.exe)?\s+(localgroup|group)\b.*admin|get-adgroupmember", re.I),
                "Enumeración de grupos privilegiados", [("T1069", "Permission Groups Discovery")], "comandos", 25,
                "Listar los miembros de Administrators permite al atacante identificar cuentas a comprometer."),
    CommandRule("discovery_share", re.compile(r"get-smbshare|net(\.exe)?\s+(view|share)\b", re.I),
                "Descubrimiento de recursos compartidos de red", [("T1135", "Network Share Discovery")],
                "comandos", 25, "Identificar carpetas compartidas es el paso previo a moverse o robar datos en ellas."),
    CommandRule("discovery_user", re.compile(
        r"\bwhoami\b|\bnltest\b|net(\.exe)?\s+user\b|\bsysteminfo\b|ipconfig\s+/all|\bquser\b", re.I),
                "Reconocimiento del sistema y del usuario",
                [("T1033", "System Owner/User Discovery"), ("T1082", "System Information Discovery")],
                "comandos", 20, "Comandos para saber con qué identidad y en qué equipo se está ejecutando."),
    CommandRule("archive_staging", re.compile(
        r"\b(tar|7z|7za|rar|winrar|zip)(\.exe)?\s+(.*\s)?(-a|a|-c|-r)\s|compress-archive", re.I),
                "Compresión de datos para su extracción (staging)",
                [("T1560.001", "Archive via Utility"), ("T1074.001", "Local Data Staging")], "exfiltracion", 35,
                "Empaquetar documentos en un único archivo comprimido facilita sacarlos de la red."),
    CommandRule("unusual_path_exec", re.compile(
        r"^\"?[a-z]:\\(programdata|users\\public|windows\\temp|temp|perflogs)\\\S*\.(exe|dll|ps1|bat|vbs)", re.I),
                "Ejecución de binario desde ruta inusual",
                [("T1036", "Masquerading"), ("T1204.002", "Malicious File")], "comandos", 30,
                "Los binarios legítimos residen en System32 o Program Files; ProgramData, Public y Temp "
                "son rutas escribibles por cualquier usuario usadas por malware."),
]


def detect_commands(d: pd.DataFrame, cfg: DetectionConfig, consumed: set[str]) -> list[Finding]:
    out: list[Finding] = []
    procs = d[d["is_process"] & ~d["Log_ID"].isin(consumed)]
    text = procs["cmd"] + " " + procs["desc"]
    matches = []
    for rule in COMMAND_RULES:
        target = procs["cmd"] if rule.key == "unusual_path_exec" else text
        hit = procs[target.str.contains(rule.pattern)]
        for _, r in hit.iterrows():
            matches.append({**r.to_dict(), "_rule": rule.key, "_cat": rule.category})
    if not matches:
        return out
    m = pd.DataFrame(matches).sort_values("Timestamp")
    rules = {r.key: r for r in COMMAND_RULES}

    for (user, host, cat), g in m.groupby(["user", "host", "_cat"]):
        for _, b in g.groupby(bursts(g["Timestamp"], 30)):
            rows = b.drop_duplicates("Log_ID")
            hit_rules = [rules[k] for k in dict.fromkeys(b["_rule"])]
            main = max(hit_rules, key=lambda r: r.weight)
            names = [r.name for r in hit_rules]
            lines = [f"{r['Log_ID']} {_hm(r['Timestamp'])}: {r['cmd'] or r['desc']}" for _, r in rows.iterrows()]
            mitre = list(dict.fromkeys(t for r in hit_rules for t in r.mitre))
            title = f"{main.name} en {host} ({user})"
            if len(hit_rules) > 1:
                title += f" + {len(hit_rules) - 1} técnica(s) más"
            f = _finding(
                rows, category=cat, title=title,
                description=f"{len(rows)} {'ejecución sospechosa' if len(rows) == 1 else 'ejecuciones sospechosas'} "
                            f"por {user} en {host} ({host_role(host)}) "
                            f"entre {_hm(rows['Timestamp'].min())} y {_hm(rows['Timestamp'].max())}: "
                            + " | ".join(lines),
                technical=" ".join(f"{r.name}: {r.explanation}" for r in hit_rules),
                mitre=mitre, base_score=main.weight, pivots={f"user:{user}"},
                iocs=[("Línea de comandos", c) for c in dict.fromkeys(rows["cmd"]) if c],
            )
            if len(hit_rules) > 1:
                f.add(min(15, 5 * (len(hit_rules) - 1)), "Varias técnicas encadenadas: " + "; ".join(names))
            ext_src = sorted({ip for ip in rows["src_ip"] if is_external(ip)})
            if ext_src:
                f.add(10, f"Ejecutado en una sesión con origen externo: {_join(ext_src)}")
                f.pivots |= {f"ip:{ip}" for ip in ext_src}
            if is_critical_host(host):
                f.add(10, f"Activo crítico: {host} ({host_role(host)})")
            if is_service_account(user):
                f.add(10, f"Cuenta de servicio usada para ejecución interactiva: {user}")
            elif is_privileged_account(user):
                f.add(10, f"Ejecutado con cuenta privilegiada: {user}")
            if cat == "exfiltracion":
                sens = [c for c in rows["cmd"] if SENSITIVE_DATA_PATTERN.search(c)]
                if sens:
                    f.add(10, "Los datos comprimidos provienen de rutas sensibles: " + "; ".join(sens))
                if any(_UNUSUAL_PATH_RE.search(c) or re.search(r"\\temp\\|\\public\\", c, re.I)
                       for c in rows["cmd"]):
                    f.add(5, "Archivo comprimido depositado en carpeta temporal o pública")
            out.append(f)
    return out


# --------------------------------------------------------------------------------------
# 7. Movimiento lateral (necesita los hallazgos previos para saber qué cuentas están comprometidas)
# --------------------------------------------------------------------------------------
def detect_lateral_movement(d: pd.DataFrame, cfg: DetectionConfig, prior: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    flagged_users: dict[str, pd.Timestamp] = {}
    for f in prior:
        if f.category in {"inicio_sospechoso", "escalamiento", "comandos", "ataque_web"}:
            for p in f.pivots:
                if p.startswith("user:"):
                    u = p[5:]
                    flagged_users[u] = min(flagged_users.get(u, f.start), f.start)
    if not flagged_users:
        return out

    net_logons = d[(d["is_success_logon"] | d["is_fail_logon"]) & d["logon_type"].isin(["3", "10"])
                   & ~d["src_ext"] & d["user"].isin(flagged_users)]
    net_logons = net_logons[net_logons["src_host"].fillna("") != net_logons["host"]]
    for (user, target), g in net_logons.groupby(["user", "host"]):
        g = g[g["Timestamp"] >= flagged_users[user]]
        if g.empty or not g["is_success_logon"].any():
            continue
        t0, t1 = g["Timestamp"].min(), g["Timestamp"].max()
        src_hosts = sorted(set(g["src_host"].dropna()))
        recon = d[(d["user"] == user) & d["cmd"].str.contains(rf"\\\\{re.escape(target)}\b", case=False)
                  & (d["Timestamp"] <= t0) & (d["Timestamp"] >= t0 - pd.Timedelta(minutes=60))]
        access = d[(d["user"] == user) & (d["host"] == target) & d["eid"].isin(["5140", "5145", "4663"])
                   & (d["Timestamp"] >= t0) & (d["Timestamp"] <= t1 + pd.Timedelta(minutes=30))]
        rows = pd.concat([recon, g, access]).drop_duplicates("Log_ID").sort_values("Timestamp")
        resources = [r["desc"] for _, r in access.iterrows()]
        src_txt = _join(src_hosts) or _join(g["src_ip"])
        desc = (
            f"La cuenta {user}, previamente implicada en actividad maliciosa, se autentica por red "
            f"(LogonType {_join(g['logon_type'])}) desde {src_txt} hacia {target} ({host_role(target)}): "
            f"{int(g['is_fail_logon'].sum())} fallo(s) y {int(g['is_success_logon'].sum())} éxito(s) entre "
            f"{_hm(t0)} y {_hm(t1)}."
        )
        if len(recon):
            desc += f" Antes ejecutó '{recon.iloc[-1]['cmd']}' ({recon.iloc[-1]['Log_ID']}) para enumerar {target}."
        if resources:
            desc += " Recursos accedidos a continuación: " + "; ".join(resources) + "."
        f = _finding(
            rows, category="movimiento_lateral",
            title=f"Movimiento lateral de {src_txt} a {target} con {user}",
            description=desc,
            technical=(
                "Un inicio de sesión de red (LogonType 3, SMB) desde un equipo ya comprometido hacia otro "
                "servidor, usando la misma cuenta, es la forma más común de propagación interna. El acceso "
                "inmediato a recursos compartidos (5140/5145) muestra el objetivo del salto."
            ),
            mitre=[("T1021.002", "SMB/Windows Admin Shares"), ("T1078", "Valid Accounts")]
                  + ([("T1039", "Data from Network Shared Drive")] if len(access) else []),
            base_score=45, pivots={f"user:{user}"},
            hosts={target, *src_hosts},
        )
        f.add(15, f"La cuenta {user} ya estaba comprometida o implicada en actividad maliciosa")
        if is_critical_host(target):
            f.add(10, f"Destino crítico: {target} ({host_role(target)})")
        sens = [r for r in resources if SENSITIVE_DATA_PATTERN.search(r)]
        if sens:
            f.add(15, "Acceso a información sensible tras el salto: " + "; ".join(sens))
        out.append(f)
    return out


# --------------------------------------------------------------------------------------
# 8. Recolección y exfiltración
# --------------------------------------------------------------------------------------
_SCRIPT_PROC_RE = re.compile(r"powershell|pwsh|cmd\.exe|certutil|curl|wget|python|wscript|cscript|rundll32|"
                             r"bitsadmin|mshta", re.I)


def detect_exfiltration(d: pd.DataFrame, cfg: DetectionConfig, prior: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    staging = [f for f in prior if f.category == "exfiltracion"]

    def staging_before(user: str, t: pd.Timestamp, minutes: float) -> list[Finding]:
        return [f for f in staging if f"user:{user}" in f.pivots
                and t - pd.Timedelta(minutes=minutes) <= f.end <= t]

    # a) Subidas voluminosas por proxy
    up = d[d["is_proxy"] & d["dest_ext"] & d["bytes_out"].notna()]
    for (user, dest), g in up.groupby(["user", "dest"]):
        g = g.sort_values("Timestamp")
        for _, b in g.groupby(bursts(g["Timestamp"], 15)):
            total = float(b["bytes_out"].sum())
            if total < cfg.exfil_min_bytes and len(b) < cfg.exfil_min_uploads:
                continue
            dest_ip = b["dest_ip"].iloc[0]
            t0, t1 = b["Timestamp"].min(), b["Timestamp"].max()
            cad = cadence(b["Timestamp"])
            f = _finding(
                b, category="exfiltracion",
                title=f"Exfiltración de {_mb(total)} a {dest} desde {_join(b['host'])} ({user})",
                description=(
                    f"{len(b)} peticiones HTTPS POST salientes de {user} desde {_join(b['host'])} "
                    f"({_join(b['src_ip'])}) hacia {dest} entre {_hm(t0)} y {_hm(t1)}; volumen total enviado "
                    f"{_mb(total)} (entre {_mb(b['bytes_out'].min())} y {_mb(b['bytes_out'].max())} por petición). "
                    f"URIs: {_join(b['uri'], 3)}. El proxy permitió todas las conexiones ({_join(b['Result'])})."
                ),
                technical=(
                    "Un volumen de subida sostenido hacia un único destino externo, dividido en fragmentos de "
                    "tamaño similar y numerados (/upload/session/N), es característico de exfiltración "
                    "automatizada sobre HTTPS para pasar desapercibida entre el tráfico web."
                ),
                mitre=[("T1567", "Exfiltration Over Web Service"), ("T1030", "Data Transfer Size Limits")],
                base_score=50, pivots={f"user:{user}", f"ip:{dest_ip}"},
                iocs=[("Destino de exfiltración", dest)],
            )
            f.add(10, f"Destino externo: {dest}")
            if total >= 1024 ** 3:
                f.add(25, f"Volumen muy elevado: {_mb(total)}")
            elif total >= 100 * 1024 ** 2:
                f.add(15, f"Volumen elevado: {_mb(total)}")
            prev = staging_before(user, t0, 60)
            if prev:
                f.add(15, "Precedido por compresión de datos del mismo usuario: "
                          + "; ".join(p.title for p in prev))
            if cad and cad[1] < 0.35:
                f.add(5, f"Envíos a intervalos regulares (~{cad[0]:.0f} s): transferencia automatizada")
            out.append(f)

    # b) Conexiones salientes a Internet iniciadas por intérpretes / LOLBins
    conns = d[d["dest_ext"] & ~d["is_proxy"] & ~d["is_http"]
              & (d["cmd"].str.contains(_SCRIPT_PROC_RE) | d["desc"].str.contains(_SCRIPT_PROC_RE))]
    for (user, host, dest_ip), g in conns.groupby(["user", "host", "dest_ip"]):
        t0 = g["Timestamp"].min()
        prev = staging_before(user, t0, 30)
        proc = _join(g["cmd"]) or "proceso de scripting"
        f = _finding(
            g, category="exfiltracion",
            title=f"Conexión saliente de {proc} desde {host} a {_join(g['dest'])}",
            description=(
                f"{len(g)} conexión(es) saliente(s) permitidas desde {host} ({_join(g['src_ip'])}) hacia "
                f"{_join(g['dest'])} a las {_hm(t0)}, iniciadas por {proc} con la cuenta {user}. "
                "El registro no incluye el volumen transferido, por lo que la salida de datos es probable pero "
                "no está confirmada por los logs."
            ),
            technical=(
                "PowerShell y otros intérpretes rara vez necesitan conectarse directamente a IPs de Internet. "
                "Una conexión así, justo después de comprimir datos, es compatible con la exfiltración del "
                "archivo o con un canal de mando y control (C2)."
            ),
            mitre=[("T1041", "Exfiltration Over C2 Channel"), ("T1071.001", "Web Protocols")],
            base_score=45, pivots={f"user:{user}", f"ip:{dest_ip}"},
            iocs=[("IP destino", dest_ip)],
        )
        f.add(10, f"Destino externo: {_join(g['dest'])}")
        if prev:
            f.add(20, "Inmediatamente después de compresión de datos: " + "; ".join(p.title for p in prev))
        if is_critical_host(host):
            f.add(10, f"Activo crítico: {host}")
        out.append(f)

    # c) Acceso masivo a archivos
    files = d[(d["file_path"] != "") & d["eid"].isin(["4663", "5145"])]
    for (user, share), g in files.groupby(["user", "dest"]):
        g = g.sort_values("Timestamp")
        for _, b in g.groupby(bursts(g["Timestamp"], cfg.mass_access_gap_min)):
            distinct = b["file_path"].nunique()
            if distinct < cfg.mass_access_min_files:
                continue
            t0, t1 = b["Timestamp"].min(), b["Timestamp"].max()
            minutes = max(1.0, (t1 - t0).total_seconds() / 60)
            paths = sorted(set(b["file_path"]))
            folder = re.sub(r"\\[^\\]+$", "", paths[0])
            follow = d[(d["user"] == user) & (d["host"] == b["host"].iloc[0]) & (d["dest"] == share)
                       & (d["Timestamp"] > t1) & (d["Timestamp"] <= t1 + pd.Timedelta(minutes=10))
                       & ~d["Log_ID"].isin(b["Log_ID"])]
            rows = pd.concat([b, follow]).sort_values("Timestamp")
            f = _finding(
                rows, category="exfiltracion",
                title=f"Acceso masivo a {distinct} archivos de {share or folder} por {user}",
                description=(
                    f"{user} accede desde {_join(b['src_ip'])} a {distinct} archivos distintos de {share} "
                    f"(carpeta {folder}) en {minutes:.0f} min ({distinct / minutes:.1f} archivos/min), entre "
                    f"{_hm(t0)} y {_hm(t1)}, de forma secuencial ({paths[0]} … {paths[-1]})."
                ),
                technical=(
                    "Leer en pocos minutos un gran número de archivos de forma secuencial no corresponde a uso "
                    "humano: es típico de herramientas que recolectan datos para robarlos o de ransomware "
                    "recorriendo el árbol de carpetas antes de cifrar."
                ),
                mitre=[("T1039", "Data from Network Shared Drive"), ("T1083", "File and Directory Discovery")],
                base_score=35, pivots={f"user:{user}"},
            )
            if SENSITIVE_DATA_PATTERN.search(share + folder):
                f.add(15, f"Información sensible: {share or folder}")
            if distinct / minutes >= 2:
                f.add(5, f"Ritmo de acceso automatizado ({distinct / minutes:.1f} archivos/min)")
            if is_service_account(user):
                f.add(10, f"Cuenta de servicio accediendo a datos de negocio: {user}")
            out.append(f)
    return out


# --------------------------------------------------------------------------------------
# 9. Otras anomalías: nombres que imitan activos legítimos y entidades de presencia acotada
# --------------------------------------------------------------------------------------
def _norm_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.split("\\")[-1].lower())


def _lookalike(a: str, b: str) -> bool:
    """True si a y b son nombres distintos pero equivalentes (DC01~DC-01, svc_backup~backupsvc)."""
    if a == b:
        return False
    na, nb = _norm_name(a), _norm_name(b)
    if len(na) < 3 or len(nb) < 3:
        return False
    if na == nb:
        return True
    for x, y in ((a, nb), (b, na)):
        tokens = [t for t in re.split(r"[_\-.\s]+", x.split("\\")[-1].lower()) if t]
        if 1 < len(tokens) <= 4 and any("".join(p) == y for p in permutations(tokens)):
            return True
    return False


def detect_anomalous_entities(d: pd.DataFrame, cfg: DetectionConfig, prior: list[Finding]) -> list[Finding]:
    known_pivots = {p.split(":", 1)[1] for f in prior for p in f.pivots}
    start, end = d["Timestamp"].min(), d["Timestamp"].max()
    span = end - start
    if span <= pd.Timedelta(minutes=30):
        return []

    candidates = {
        "Cuenta": d[(d["user"] != "") & (d["user"] != "-") & ~d["user"].str.contains(WEB_SERVICE_ACCOUNT_RE)],
        "Equipo": d[d["host"] != ""],
        "IP interna": d[(d["src_ip"] != "") & ~d["src_ext"]],
    }
    cols = {"Cuenta": "user", "Equipo": "host", "IP interna": "src_ip"}

    lookalikes: list[tuple[str, str, str, int, int]] = []
    bounded: list[tuple[str, str, pd.Timestamp, pd.Timestamp, int]] = []
    for kind, rows in candidates.items():
        col = cols[kind]
        counts = rows[col].value_counts()
        names = list(counts.index) if kind != "IP interna" else []
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                if _lookalike(a, b):
                    # La variante menos frecuente es la sospechosa.
                    odd, legit = (a, b) if counts[a] < counts[b] else (b, a)
                    lookalikes.append((kind, odd, legit, int(counts[odd]), int(counts[legit])))
        stats = rows.groupby(col)["Timestamp"].agg(["min", "max", "count"])
        for name, s in stats.iterrows():
            if name in known_pivots or s["count"] < 5:
                continue
            late = s["min"] > start + span * 0.10
            short = (s["max"] - s["min"]) < span * 0.70
            if late and short:
                bounded.append((kind, name, s["min"], s["max"], int(s["count"])))

    odd_names = {n for _, n, *_ in lookalikes} | {n for _, n, *_ in bounded}
    if not odd_names:
        return []
    rows = d[d["user"].isin(odd_names) | d["host"].isin(odd_names) | d["src_ip"].isin(odd_names)]
    together = rows[(rows[["user", "host", "src_ip"]].isin(list(odd_names)).sum(axis=1)) >= 2]
    privs = rows[(rows["eid"] == "4672") & rows["user"].isin(odd_names)]

    parts = []
    for kind, odd, legit, n_odd, n_legit in lookalikes:
        parts.append(f"{kind.lower()} '{odd}' ({n_odd} eventos) imita a '{legit}' ({n_legit} eventos)")
    for kind, name, t0, t1, n in bounded:
        if name not in {o for _, o, *_ in lookalikes}:
            parts.append(f"{kind.lower()} '{name}' solo aparece entre {_hm(t0)} y {_hm(t1)} ({n} eventos)")
    desc = ("Entidades fuera del patrón habitual del entorno: " + "; ".join(parts) + ". "
            f"{len(together)} eventos combinan dos o más de estas entidades entre sí.")
    if len(privs):
        desc += (f" Reciben privilegios especiales (4672): {_join(privs['user'])} en {_join(privs['host'])} "
                 f"({len(privs)} eventos).")
    desc += (" Puede tratarse de un sistema/cuenta no inventariado, de suplantación deliberada o de una "
             "inconsistencia de nomenclatura en la ingesta del SIEM: requiere validación con CMDB y AD.")

    f = _finding(
        rows, category="anomalia",
        title="Entidades no habituales y nombres que imitan activos legítimos",
        description=desc,
        technical=(
            "Los atacantes crean cuentas o equipos con nombres casi idénticos a los legítimos (p. ej. 'DC01' "
            "frente a 'DC-01', 'svc_backup' frente a 'backupsvc') para que su actividad pase por normal en "
            "revisiones rápidas. Entidades que aparecen a mitad de la captura y operan solo en una ventana "
            "acotada, interactuando entre sí, merecen verificación aunque sus acciones individuales parezcan benignas."
        ),
        mitre=[("T1036", "Masquerading"), ("T1136", "Create Account")],
        base_score=25,
        pivots={f"user:{n}" for n in odd_names if n in set(d["user"])},
        users={n for n in odd_names if n in set(d["user"])},
        hosts={n for n in odd_names if n in set(d["host"])},
        ips={n for n in odd_names if n in set(d["src_ip"])},
        iocs=[(k, n) for k, n, *_ in lookalikes] + [(k, n) for k, n, *_ in bounded
                                                    if n not in {o for _, o, *_ in lookalikes}],
    )
    crit = [(odd, legit) for k, odd, legit, *_ in lookalikes if k == "Equipo" and is_critical_host(legit)]
    if crit:
        f.add(15, "Nombre que imita a un activo crítico: " + ", ".join(f"{o} ~ {l}" for o, l in crit))
    acct = [(odd, legit) for k, odd, legit, *_ in lookalikes if k == "Cuenta"]
    if acct:
        f.add(10, "Cuenta con nombre que imita a otra existente: " + ", ".join(f"{o} ~ {l}" for o, l in acct))
    if len(privs):
        f.add(10, f"Las cuentas anómalas reciben privilegios especiales ({len(privs)} eventos 4672)")
    return [f]


# --------------------------------------------------------------------------------------
# 10. Ruido residual de autenticación (para documentar lo que NO es incidente)
# --------------------------------------------------------------------------------------
def detect_auth_noise(d: pd.DataFrame, cfg: DetectionConfig, prior: list[Finding]) -> list[Finding]:
    used = {i for f in prior for i in f.evidence_ids}
    rest = d[d["is_fail_logon"] & ~d["Log_ID"].isin(used)]
    if rest.empty:
        return []
    peak = 0
    for _, g in rest.groupby("src_ip"):
        g = g.sort_values("Timestamp")
        peak = max(peak, int(g.groupby(bursts(g["Timestamp"], cfg.burst_gap_min)).size().max()))
    top = rest["user"].value_counts().head(4)
    f = _finding(
        rest, category="fuerza_bruta",
        title="Fallos de autenticación internos dispersos (ruido de fondo)",
        description=(
            f"{len(rest)} inicios de sesión fallidos no asociados a ningún ataque, de {rest['user'].nunique()} "
            f"cuentas y {rest['src_ip'].nunique()} IPs internas. El máximo por origen en una ventana de "
            f"{cfg.burst_gap_min:.0f} min es {peak}, por debajo del umbral de fuerza bruta "
            f"({cfg.bf_min_failures}). Cuentas con más fallos: "
            + ", ".join(f"{u} ({n})" for u, n in top.items()) + "."
        ),
        technical="Errores de contraseña aislados son habituales en cualquier organización. Se documentan "
                  "para mostrar que fueron evaluados y descartados como ataque.",
        mitre=[], base_score=10,
    )
    return [f]


def run_detectors(d: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    consumed: set[str] = set()
    findings: list[Finding] = []
    findings += detect_credential_attacks(d, cfg, consumed)
    findings += detect_suspicious_logons(d, cfg, consumed)
    findings += detect_privilege_escalation(d, cfg, consumed)
    findings += detect_persistence(d, cfg, consumed)
    findings += detect_web_attacks(d, cfg, consumed)
    findings += detect_commands(d, cfg, consumed)
    findings += detect_lateral_movement(d, cfg, findings)
    findings += detect_exfiltration(d, cfg, findings)
    findings += detect_anomalous_entities(d, cfg, findings)
    findings += detect_auth_noise(d, cfg, findings)
    return findings
