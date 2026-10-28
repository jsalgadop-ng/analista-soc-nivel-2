"""Informe ejecutivo: versión breve y en lenguaje llano para la alta dirección.

Todo el contenido se deriva de los hallazgos del motor de reglas (nada se inventa): cada frase corresponde a un
tipo de hallazgo con evidencia en los logs. La IA, si se usa, solo reescribe el resumen a partir de esos mismos
hechos y sus cifras se comprueban contra ellos.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from fpdf.enums import MethodReturnValue

from .features import WEB_SERVICE_ACCOUNT_RE, is_external
from .knowledge import SENSITIVE_DATA_PATTERN, host_role, is_critical_host
from .models import Finding, Incident
from .pipeline import AnalysisResult
from .report import (ACCENT, GREY, LIGHT, NAVY, ReportMeta, _PDF, _rgb, limitations, md_escape)
from .risk import LEVEL_COLORS, LEVEL_DESCRIPTIONS, LEVELS

MAX_FRAGMENTS = 5            # hechos que se muestran por incidente (los de mayor prioridad)
MAX_KEY_POINTS = 5

# Prioridad al recortar los hechos de un incidente (menor = más importante).
_PRIORITY = {"exfiltracion": 0, "movimiento_lateral": 1, "ataque_web": 1, "comandos": 2, "persistencia": 2,
             "inicio_sospechoso": 3, "anomalia": 3, "escalamiento": 4, "fuerza_bruta": 4}


@dataclass
class ExecIncident:
    id: str
    level: str
    score: int
    headline: str
    what: str
    risk: str
    systems: str


@dataclass
class ExecContent:
    level: str
    situation: str
    figures: list[tuple[str, str]]
    summary: str
    key_points: list[str]
    incidents: list[ExecIncident]
    actions_now: list[str]
    actions_week: list[str]
    unknowns: list[str]
    ai_model: str | None = None
    ai_warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------------------
# Lenguaje llano
# --------------------------------------------------------------------------------------
def _user(u: str) -> str:
    return u.split("\\")[-1]


def _tech(f: Finding) -> set[str]:
    return {t for t, _ in f.mitre}


def _where(f: Finding) -> str:
    return ", ".join(sorted(f.hosts)) or "un equipo"


def _fragment(f: Finding) -> str | None:
    """Hecho observado, en una frase llana. Solo se emite lo que el tipo de hallazgo sustenta."""
    t, title, cat = _tech(f), f.title, f.category
    user = _user(sorted(f.users)[0]) if len(f.users) == 1 else None
    from_net = "desde Internet" if any(is_external(i) for i in f.ips) else "desde la red interna"
    if cat == "fuerza_bruta":
        if "T1110.003" in t:
            return f"se probaron contraseñas contra {len(f.users)} cuentas {from_net}"
        if "T1110.001" in t:
            return f"se probaron contraseñas repetidamente contra la cuenta {user or 'de un usuario'} {from_net}"
        return None
    if cat == "inicio_sospechoso":
        who = f"la cuenta {user}" if user else "una cuenta"
        if "tras ataque de credenciales" in title:
            return f"se logró iniciar sesión con {who} {from_net} tras intentos fallidos repetidos"
        if "fuera de horario" in title:
            return f"se inició sesión con {who} fuera del horario habitual"
        return f"se inició sesión con {who} {from_net}"
    if cat == "escalamiento":
        if title.startswith("Privilegios especiales"):
            return "esa sesión recibió privilegios especiales (control ampliado del equipo)"
        return "se modificaron cuentas o grupos con privilegios"
    if cat == "comandos":
        if "T1490" in t:
            return f"se borraron las copias de seguridad del sistema en {_where(f)}, lo que dificulta la recuperación"
        return f"se ejecutaron comandos ocultos o sospechosos en {_where(f)}"
    if cat == "persistencia":
        return f"se dejó un programa que se ejecuta solo en {_where(f)} para conservar el acceso"
    if cat == "movimiento_lateral":
        m = re.search(r" a (\S+) con ", title)
        return f"la intrusión saltó a otro servidor ({m.group(1)})" if m else "la intrusión saltó a otros equipos"
    if cat == "exfiltracion":
        if title.startswith("Exfiltración de"):
            size = re.search(r"Exfiltración de ([\d.,]+ ?\w+)", title)
            return (f"se enviaron {size.group(1)} de datos a una dirección de Internet" if size
                    else "se enviaron datos a una dirección de Internet")
        if title.startswith("Compresión"):
            return f"se comprimieron archivos en {_where(f)}, un paso habitual antes de sacarlos de la empresa"
        if title.startswith("Conexión saliente"):
            return f"{_where(f)} abrió una conexión hacia Internet (los registros no indican cuántos datos se enviaron)"
        m = re.search(r"Acceso masivo a (\d+) archivos de (.+?) por ", title)
        return (f"se accedió a {m.group(1)} archivos de {m.group(2)} en pocos minutos" if m
                else "se accedió a muchos archivos en poco tiempo")
    if cat == "ataque_web":
        return ("se explotó el sitio web expuesto a Internet y se ejecutaron comandos en el servidor"
                if "ejecución de comandos" in title else "se atacó el sitio web expuesto a Internet")
    if cat == "anomalia":
        return "hay cuentas o equipos con nombres que imitan a otros legítimos o que no estaban inventariados"
    return None


def _fragments(inc: Incident) -> list[str]:
    ordered = sorted(inc.findings, key=lambda f: f.start)
    pairs: list[tuple[int, int, str]] = []
    for n, f in enumerate(ordered):
        text = _fragment(f)
        if text and text not in [p[2] for p in pairs]:
            pairs.append((_PRIORITY.get(f.category, 5), n, text))
    keep = sorted(sorted(pairs)[:MAX_FRAGMENTS], key=lambda p: p[1])      # los más importantes, en orden cronológico
    extra = len(pairs) - MAX_FRAGMENTS
    return [p[2] for p in keep] + ([f"hay {extra} hecho{'s' if extra > 1 else ''} adicional{'es' if extra > 1 else ''} "
                                    "en el informe técnico"] if extra > 0 else [])


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " y " + items[-1]


def _kind(inc: Incident) -> str:
    cats = {f.category for f in inc.findings}
    mitre = set().union(*(_tech(f) for f in inc.findings))
    if "T1490" in mitre:
        return "ransomware"
    if "movimiento_lateral" in cats and "exfiltracion" in cats:
        return "intrusion"
    if "ataque_web" in cats:
        return "web"
    if "persistencia" in cats:
        return "persistencia"
    if "exfiltracion" in cats and any(f.title.startswith("Exfiltración") for f in inc.findings):
        return "fuga"
    if "fuerza_bruta" in cats and "inicio_sospechoso" in cats:
        return "cuenta"
    if cats == {"fuerza_bruta"}:
        return "contrasenas"
    if cats == {"anomalia"}:
        return "anomalia"
    return "otro"


_HEADLINE = {
    "ransomware": "Preparativos de un ataque de ransomware (secuestro de datos)",
    "intrusion": "Intrusión que se extendió a otro servidor, con posible robo de información",
    "web": "Ataque al sitio web de la empresa",
    "persistencia": "Acceso oculto dejado en un servidor",
    "fuga": "Salida de información hacia Internet",
    "cuenta": "Cuenta de usuario accedida tras un ataque de contraseñas",
    "contrasenas": "Intentos de adivinar contraseñas desde Internet",
    "anomalia": "Cuentas y equipos con nombres sospechosos",
    "otro": "Actividad sospechosa",
}

_RISK = {
    "ransomware": "Pérdida o cifrado de información y paralización de la operación si el ataque llega a completarse.",
    "intrusion": "Fuga de información confidencial y control de servidores internos por parte de terceros.",
    "web": "Un servidor expuesto a Internet bajo control ajeno, que puede servir de puerta de entrada a la red interna.",
    "persistencia": "El atacante puede conservar el acceso aunque se cambien contraseñas o se reinicien los equipos.",
    "fuga": "Fuga de información confidencial, con posibles consecuencias legales, contractuales y de reputación.",
    "cuenta": "Un tercero puede actuar con la identidad de un empleado y ver todo lo que esa persona puede ver.",
    "contrasenas": "Riesgo de que alguna contraseña sea adivinada y se tome una cuenta.",
    "anomalia": "Dificulta detectar actividad maliciosa; hay que verificar que esas cuentas y equipos son legítimos.",
    "otro": "Por determinar; requiere revisión del equipo de seguridad.",
}


def _systems(inc: Incident, limit: int = 4) -> str:
    hosts = sorted(inc.entities("hosts"), key=lambda h: (not is_critical_host(h), h))
    shown = [f"{h} ({host_role(h).split(' (')[0]})" for h in hosts[:limit]]
    extra = f" y {len(hosts) - limit} más" if len(hosts) > limit else ""
    return ", ".join(shown) + extra


_SENSITIVE_LABELS = [(r"finan|budget|presupuesto|payroll|nomina", "financiera"), (r"legal|contrat", "legal"),
                     (r"rrhh|\bhr\b", "de personal"), (r"confiden|secret", "confidencial")]


def _sensitive_label(text: str) -> str | None:
    if not SENSITIVE_DATA_PATTERN.search(text):
        return None
    return next((label for pattern, label in _SENSITIVE_LABELS if re.search(pattern, text, re.I)), "sensible")


def _incident(inc: Incident) -> ExecIncident:
    kind = _kind(inc)
    what = " ".join(f[0].upper() + f[1:] + "." for f in _fragments(inc)) or "Actividad sospechosa que requiere revisión."
    risk = _RISK[kind]
    label = _sensitive_label(" ".join(f.title + " " + f.description for f in inc.findings))
    if label and kind in ("intrusion", "fuga", "ransomware"):
        risk += f" Los registros mencionan información {label}."
    return ExecIncident(inc.id, inc.level, inc.score, _HEADLINE[kind], what, risk, _systems(inc))


# --------------------------------------------------------------------------------------
# Contenido
# --------------------------------------------------------------------------------------
def _key_points(r: AnalysisResult) -> list[str]:
    fs = [(i, f) for i in r.incidents for f in i.findings]
    pts: list[str] = []
    sent = [(i, re.search(r"Exfiltración de ([\d.,]+ ?\w+)", f.title)) for i, f in fs if f.title.startswith("Exfiltración de")]
    for i, m in sent:
        if m:
            pts.append(f"Hay indicios de salida de información: se registraron {m.group(1)} enviados a una dirección de "
                       f"Internet ({i.id}).")
    conn = sorted({i.id for i, f in fs if f.title.startswith("Conexión saliente")})
    if conn:
        pts.append(f"Tras comprimir archivos, un servidor abrió una conexión hacia Internet ({', '.join(conn)}); los registros "
                   "no permiten saber cuántos datos salieron.")
    bk = [(i, f) for i, f in fs if "T1490" in _tech(f)]
    if bk:
        pts.append("Se borraron copias de seguridad en " + ", ".join(sorted({h for _, f in bk for h in f.hosts})) +
                   ": es un paso típico antes de un ataque de ransomware.")
    accounts = sorted({_user(u) for _, f in fs if f.category == "inicio_sospechoso" and "tras ataque" in f.title
                       for u in f.users})
    if accounts:
        pts.append(f"Hay indicios de que {'las cuentas' if len(accounts) > 1 else 'la cuenta'} "
                   f"{_join(accounts)} {'fueron accedidas' if len(accounts) > 1 else 'fue accedida'} desde Internet tras "
                   "ataques de contraseñas.")
    web = sorted({h for _, f in fs if f.category == "ataque_web" for h in f.hosts})
    if web:
        pts.append(f"El servidor web {', '.join(web)}, expuesto a Internet, fue explotado para ejecutar comandos.")
    pers = sorted({h for _, f in fs if f.category == "persistencia" for h in f.hosts})
    if pers:
        pts.append(f"Se instaló un programa que se ejecuta solo en {', '.join(pers)} para conservar el acceso.")
    return pts[:MAX_KEY_POINTS]


def _actions(r: AnalysisResult) -> tuple[list[str], list[str]]:
    incs = r.incidents
    urgent = [i for i in incs if i.level in ("Crítico", "Alto")]
    cats = {f.category for i in incs for f in i.findings}
    mitre = {t for i in incs for f in i.findings for t in _tech(f)}
    now: list[str] = []
    if any(i.level == "Crítico" for i in incs):
        now.append("Activar hoy el plan de respuesta a incidentes y designar un responsable único del caso.")
    crit_hosts = sorted({h for i in incs if i.level == "Crítico" for h in i.entities("hosts")},
                        key=lambda h: (not is_critical_host(h), h))
    if crit_hosts:
        now.append(f"Decidir el aislamiento temporal de los {len(crit_hosts)} equipos implicados en incidentes críticos "
                   f"(prioridad: {', '.join(crit_hosts[:3])}). Puede causar interrupciones breves de servicio.")
    users = {u for i in urgent for u in i.entities("users") if not WEB_SERVICE_ACCOUNT_RE.search(u)}
    if users:
        now.append(f"Restablecer las contraseñas de las {len(users)} cuentas implicadas o atacadas y exigir verificación en dos pasos "
                   "en los accesos remotos.")
    if r.stats["external_ips"]:
        now.append(f"Bloquear en el cortafuegos las {len(r.stats['external_ips'])} direcciones de Internet implicadas.")
    if "exfiltracion" in cats:
        now.append("Consultar a Asesoría Legal y al responsable de protección de datos si procede notificar a la autoridad: "
                   "el RGPD exige hacerlo en 72 horas desde que se tiene conocimiento si hay datos personales.")
    if "T1490" in mitre:
        now.append("Comprobar que las copias de seguridad están íntegras y fuera de línea, antes de que pueda cifrarse "
                   "la información.")
    week = [
        "Ampliar la investigación con los equipos técnicos para confirmar qué información se vio afectada.",
        "Exigir verificación en dos pasos en todos los accesos remotos y no exponer el escritorio remoto (RDP) a Internet.",
        "Aprobar la implantación de monitorización avanzada de equipos (EDR) y copias de seguridad inmutables.",
    ]
    return now, week


def _unknowns(r: AnalysisResult) -> list[str]:
    s = r.stats
    out = [f"El análisis cubre solo los {s['events']} registros exportados ({s['start']:%d/%m/%Y %H:%M} – {s['end']:%H:%M}); "
           "no hay datos de antes ni de después."]
    gaps = []
    if any("ofuscado o redactado" in x for x in limitations(r)):
        gaps.append("algunos comandos aparecen ocultos en la exportación")
    if any(f.title.startswith("Conexión saliente") for i in r.incidents for f in i.findings):
        gaps.append("no siempre se sabe cuántos datos salieron hacia Internet")
    gaps.append("no hay datos de monitorización de equipos (EDR), DNS ni red")
    out.append("Limitaciones de los datos: " + "; ".join(gaps) + ". Por eso no se puede confirmar qué archivos concretos "
               "fueron vistos o copiados.")
    if any(i.related for i in r.incidents):
        out.append("Algunos incidentes podrían estar relacionados entre sí; los registros no permiten confirmarlo.")
    return out


def _summary(r: AnalysisResult, client: str) -> str:
    s, by = r.stats, r.stats["incidents_by_level"]
    if not r.incidents:
        return ("El análisis de los registros proporcionados no identificó actividad que supere los umbrales de "
                "detección. Se recomienda mantener la monitorización.")
    fs = [f for i in r.incidents for f in i.findings]
    cats = {f.category for f in fs}
    signs = []
    if any(f.category == "inicio_sospechoso" and "tras ataque" in f.title for f in fs):
        signs.append("cuentas accedidas desde Internet tras ataques de contraseñas")
    if cats & {"comandos", "movimiento_lateral", "persistencia"}:
        signs.append("actividad sospechosa dentro de servidores internos")
    if "ataque_web" in cats:
        signs.append("un servidor web expuesto a Internet atacado")
    if "exfiltracion" in cats:
        signs.append("información que pudo salir de la empresa")
    levels = " y ".join(f"{by[lvl]} de nivel {lvl.lower()}" for lvl in LEVELS if by[lvl])
    text = (f"Los registros de seguridad de {client} del {s['start']:%d/%m/%Y} (entre las {s['start']:%H:%M} y las "
            f"{s['end']:%H:%M}) indican {len(r.incidents)} incidentes independientes: {levels}.")
    if signs:
        text += f" Hay señales de {_join(signs)}."
    return text + " Se recomienda actuar de inmediato según las acciones indicadas más abajo."


def executive_content(r: AnalysisResult, meta: ReportMeta, narrative: dict | None = None) -> ExecContent:
    by = r.stats["incidents_by_level"]
    worst = r.incidents[0].level if r.incidents else "Bajo"
    hosts = {h for i in r.incidents for h in i.entities("hosts")}
    n_crit = by["Crítico"]
    situation = (f"{len(r.incidents)} incidentes de seguridad detectados" +
                 (f", {n_crit} de ellos críticos." if n_crit else ".") if r.incidents else
                 "Sin incidentes de seguridad detectados.")
    now, week = _actions(r)
    c = ExecContent(
        level=worst, situation=situation,
        figures=[(str(len(r.incidents)), "incidentes"), (str(n_crit), "críticos"),
                 (str(len(hosts)), "equipos implicados"), (str(len(r.stats["external_ips"])), "direcciones de Internet implicadas")],
        summary=_summary(r, meta.client), key_points=_key_points(r),
        incidents=[_incident(i) for i in r.incidents], actions_now=now, actions_week=week, unknowns=_unknowns(r))
    if narrative and narrative.get("resumen"):
        c.summary = re.sub(r"[*#`]", "", narrative["resumen"]).strip()
        c.ai_model = narrative.get("modelo", "IA")
        c.ai_warnings = unverified_numbers(c.summary, facts_text(c))
    return c


# --------------------------------------------------------------------------------------
# Apoyo a la IA: hechos de partida y comprobación de cifras
# --------------------------------------------------------------------------------------
def facts_text(c: ExecContent) -> str:
    """Los hechos (ya verificados por el motor) de los que debe partir la redacción de la IA."""
    lines = [f"SITUACIÓN: {c.situation} Nivel global: {c.level}."]
    lines += [f"CIFRA: {v} {k}" for v, k in c.figures]
    lines += [f"PUNTO CLAVE: {p}" for p in c.key_points]
    for i in c.incidents:
        lines.append(f"{i.id} [{i.level}] {i.headline}. {i.what} Riesgo: {i.risk} Sistemas: {i.systems}")
    lines += [f"ACCIÓN INMEDIATA: {a}" for a in c.actions_now]
    lines += [f"NO CONFIRMADO: {u}" for u in c.unknowns]
    return "\n".join(lines)


def unverified_numbers(text: str, facts: str) -> list[str]:
    """Cifras del texto de la IA que no aparecen en los hechos de partida (posibles invenciones)."""
    nums = lambda s: set(re.findall(r"\d+(?:[.,]\d+)?", s))
    return sorted(nums(text) - nums(facts))


# --------------------------------------------------------------------------------------
# Markdown (vista previa y descarga)
# --------------------------------------------------------------------------------------
def build_executive_markdown(r: AnalysisResult, meta: ReportMeta, narrative: dict | None = None) -> str:
    c, e = executive_content(r, meta, narrative), md_escape
    md = [f"# Informe ejecutivo — {e(meta.client)}",
          f"*Caso {e(meta.case_id)} · {meta.generated:%d/%m/%Y} · Elaborado por {e(meta.analyst)}*", "",
          f"**Nivel global: {c.level.upper()}** — {c.situation}", "",
          " · ".join(f"**{v}** {k}" for v, k in c.figures), "",
          "## Resumen", c.summary.replace("$", r"\$")]
    if c.ai_model:
        md.append(f"\n*Resumen redactado con asistencia de IA ({e(c.ai_model)}) a partir de los hallazgos del análisis.*")
    if c.key_points:
        md += ["", "## Lo más importante"] + [f"- {e(p)}" for p in c.key_points]
    md += ["", "## Qué ocurrió, en lenguaje claro",
           "*Cada afirmación se basa en los registros analizados; el detalle y las evidencias están en el informe técnico.*", ""]
    for i in c.incidents:
        md += [f"**{i.id} · {i.level.upper()} — {e(i.headline)}**  ", e(i.what) + "  ",
               f"*En riesgo:* {e(i.risk)}  ", f"*Sistemas:* {e(i.systems)}", ""]
    md += ["## Decisiones y acciones inmediatas (hoy)"] + [f"{n}. {e(a)}" for n, a in enumerate(c.actions_now, 1)]
    md += ["", "## Próximos pasos (esta semana)"] + [f"{n}. {e(a)}" for n, a in enumerate(c.actions_week, 1)]
    md += ["", "## Qué falta por confirmar"] + [f"- {e(u)}" for u in c.unknowns]
    md += ["", "*La criticidad es una estimación con reglas documentadas, no un dictamen forense. El detalle técnico, las "
               f"evidencias y el plan completo están en el Informe técnico del caso {e(meta.case_id)}.*"]
    return "\n".join(md)


# --------------------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------------------
def _band(pdf: _PDF, r: AnalysisResult, meta: ReportMeta, c: ExecContent) -> None:
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 34, "F")
    pdf.set_xy(15, 8)
    pdf.set_font("dv", "B", 8.5)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 5, "INFORME EJECUTIVO · INCIDENTE DE SEGURIDAD", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(15)
    pdf.set_font("dv", "B", 19)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 9, "Resumen para la alta dirección", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(15)
    pdf.set_font("dv", "", 8.5)
    pdf.set_text_color(200, 205, 218)
    pdf.cell(0, 5, f"{meta.client} · {meta.case_id} · {meta.generated:%d/%m/%Y} · {meta.analyst}",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(15)
    pdf.cell(0, 5, "CONFIDENCIAL — uso restringido a la dirección", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_y(40)


def _status(pdf: _PDF, c: ExecContent) -> None:
    y = pdf.get_y()
    color = _rgb(LEVEL_COLORS[c.level])
    pdf.set_fill_color(*color)
    pdf.rect(15, y, 3, 12.5, "F")
    pdf.set_xy(21, y)
    pdf.set_font("dv", "B", 8)
    pdf.set_text_color(*GREY)
    pdf.cell(0, 4, "NIVEL GLOBAL DE RIESGO", new_x="LMARGIN", new_y="NEXT")
    pdf.set_xy(21, y + 4)
    pdf.set_font("dv", "B", 15)
    pdf.set_text_color(*color)
    pdf.cell(36, 8, c.level.upper())
    pdf.set_xy(60, y + 5.2)
    pdf.set_font("dv", "", 8.5)
    pdf.set_text_color(*GREY)
    pdf.multi_cell(135, 4.2, LEVEL_DESCRIPTIONS[c.level], align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_y(y + 16)
    # cifras
    w, y0 = 180 / len(c.figures), pdf.get_y()
    for n, (value, label) in enumerate(c.figures):
        x = 15 + n * w
        pdf.set_fill_color(*LIGHT)
        pdf.rect(x, y0, w - 3, 15.5, "F")
        pdf.set_xy(x + 3, y0 + 1.5)
        pdf.set_font("dv", "B", 14)
        pdf.set_text_color(*NAVY)
        pdf.cell(w - 8, 7, value)
        pdf.set_xy(x + 3, y0 + 8.7)
        pdf.set_font("dv", "", 7.2)
        pdf.set_text_color(*GREY)
        pdf.multi_cell(w - 8, 3.3, label, align="L", new_x="RIGHT", new_y="TOP")
    pdf.set_text_color(0, 0, 0)
    pdf.set_xy(15, y0 + 17)


def _section(pdf: _PDF, title: str) -> None:
    if pdf.get_y() > 255:
        pdf.add_page()
    pdf.ln(2)
    pdf.set_font("dv", "B", 11.5)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 6, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*ACCENT)
    pdf.set_line_width(0.5)
    pdf.line(15, pdf.get_y(), 30, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(2.5)
    pdf.set_text_color(0, 0, 0)


def _lines(pdf: _PDF, text: str, size: float, style: str = "") -> int:
    pdf.set_font("dv", style, size)
    return len(pdf.multi_cell(0, 4, text, align="L", dry_run=True, output=MethodReturnValue.LINES))


def _incident_block(pdf: _PDF, i: ExecIncident) -> None:
    # Altura real del bloque, para no partirlo entre páginas ni dejar huecos innecesarios.
    height = (0.6 + 5.6 + _lines(pdf, i.what, 8.5) * 4.42 + 1.2 + _lines(pdf, f"En riesgo: {i.risk}", 8, "I") * 4.1
              + (_lines(pdf, f"Sistemas: {i.systems}", 8, "I") * 4.1 if i.systems else 0) + 1)
    if pdf.get_y() + height > pdf.page_break_trigger:
        pdf.add_page()
    pdf.ln(0.6)
    pdf.level_badge(i.level)
    pdf.set_font("dv", "B", 9.3)
    pdf.set_text_color(*NAVY)
    pdf.cell(0, 5.6, f"  {i.id} · {i.headline}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.set_x(15)
    pdf.para(i.what, size=8.5)
    pdf.set_font("dv", "I", 8)
    pdf.set_text_color(*GREY)
    pdf.multi_cell(0, 4.1, f"En riesgo: {i.risk}", align="L", new_x="LMARGIN", new_y="NEXT")
    if i.systems:
        pdf.multi_cell(0, 4.1, f"Sistemas: {i.systems}", align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)


def build_executive_pdf(r: AnalysisResult, meta: ReportMeta, narrative: dict | None = None) -> bytes:
    c = executive_content(r, meta, narrative)
    pdf = _PDF(meta)
    pdf.doc_title = "Informe ejecutivo de incidente de seguridad"
    pdf.set_title(f"Informe ejecutivo {meta.case_id}")
    pdf.set_author(meta.analyst)
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(True, margin=14)
    pdf.add_page()
    _band(pdf, r, meta, c)
    _status(pdf, c)

    _section(pdf, "Resumen")
    pdf.para(c.summary, size=9.2)
    if c.ai_model:
        pdf.para(f"Resumen redactado con asistencia de IA ({c.ai_model}) a partir de los hallazgos verificados del análisis.",
                 size=7.4, style="I", color=GREY)
    if c.key_points:
        _section(pdf, "Lo más importante")
        pdf.bullets(c.key_points, size=8.6)

    _section(pdf, "Qué ocurrió, en lenguaje claro")
    for inc in c.incidents:
        _incident_block(pdf, inc)

    _section(pdf, "Decisiones y acciones inmediatas (hoy)")
    pdf.bullets(c.actions_now, size=8.8, numbered=True)
    _section(pdf, "Próximos pasos (esta semana)")
    pdf.bullets(c.actions_week, size=8.8, numbered=True)

    _section(pdf, "Qué falta por confirmar")
    pdf.bullets(c.unknowns, size=8.4)
    pdf.para("La criticidad es una estimación con reglas documentadas, no un dictamen forense. El detalle técnico, las "
             f"evidencias (Log_ID) y el plan de acción completo figuran en el Informe técnico del caso {meta.case_id}.",
             size=7.8, style="I", color=GREY)
    return bytes(pdf.output())
