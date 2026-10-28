"""Informe técnico: contenido estructurado, vista previa Markdown y exportación a PDF."""

from __future__ import annotations

import io
import os
import re
from dataclasses import dataclass, field
from datetime import datetime

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from fpdf import FPDF, FontFace  # noqa: E402
from fpdf.enums import TableBordersLayout, TableCellFillMode, WrapMode  # noqa: E402

from .ai_assistant import CitationCheck, annotate_narrative, narrative_checks  # noqa: E402
from .knowledge import GENERAL_RECOMMENDATIONS, category_label  # noqa: E402
from .pipeline import AnalysisResult  # noqa: E402
from .risk import LEVEL_COLORS, LEVEL_DESCRIPTIONS, LEVELS, THRESHOLDS  # noqa: E402

EVIDENCE_ROWS_PER_INCIDENT = 30


@dataclass
class ReportMeta:
    analyst: str = "Analista SOC Nivel 2"
    organization: str = "Consultora de ciberseguridad — Estocolmo, Suecia"
    client: str = "Cliente"
    case_id: str = field(default_factory=lambda: f"CASO-{datetime.now():%Y%m%d-%H%M}")
    generated: datetime = field(default_factory=datetime.now)


# --------------------------------------------------------------------------------------
# Contenido (compartido entre la vista previa y el PDF)
# --------------------------------------------------------------------------------------
def key_figures(r: AnalysisResult) -> list[str]:
    s = r.stats
    by = s["incidents_by_level"]
    levels = ", ".join(f"{by[lvl]} {lvl.lower()}" for lvl in LEVELS if by[lvl])
    return [
        f"Registros analizados: {s['events']} eventos entre {s['start']:%d/%m/%Y %H:%M} y {s['end']:%H:%M}, "
        f"{s['hosts']} equipos, {s['users']} cuentas, {s['ips']} IPs de origen.",
        f"Incidentes identificados: {len(r.incidents)} ({levels or 'ninguno'}), a partir de {len(r.findings)} "
        f"hallazgos correlacionados.",
        f"Eventos implicados en hallazgos de riesgo medio o superior: {s['flagged_events']} "
        f"({s['flagged_events'] / max(1, s['events']):.0%} del total).",
        f"IPs externas observadas: {', '.join(s['external_ips']) or 'ninguna'}.",
    ]


def default_executive_summary(r: AnalysisResult) -> str:
    if not r.incidents:
        return ("El análisis de los registros proporcionados no identificó indicadores de compromiso que "
                "superen los umbrales de detección. Se recomienda mantener la monitorización.")
    crit = [i for i in r.incidents if i.level == "Crítico"]
    high = [i for i in r.incidents if i.level == "Alto"]
    parts = [
        f"El análisis de {r.stats['events']} registros del SIEM confirma que la organización sufrió "
        f"{'varios incidentes de seguridad independientes' if len(r.incidents) > 1 else 'un incidente de seguridad'} "
        f"durante el periodo analizado. Se identificaron {len(r.incidents)} incidentes: {len(crit)} de criticidad "
        f"crítica y {len(high)} de criticidad alta."
    ]
    if crit:
        parts.append("Los incidentes críticos son: " + "; ".join(f"{i.id} {i.title}" for i in crit) + ".")
    if high:
        parts.append("De criticidad alta: " + "; ".join(f"{i.id} {i.title}" for i in high) + ".")
    parts.append(
        "Se recomienda activar el procedimiento de respuesta a incidentes de inmediato: aislar los equipos "
        "comprometidos, bloquear las IPs externas implicadas, restablecer las credenciales afectadas y evaluar "
        "con el área legal la posible fuga de información."
    )
    return " ".join(parts)


def limitations(r: AnalysisResult) -> list[str]:
    df = r.df
    out = [
        f"El análisis se limita a los {len(df)} registros exportados ({r.stats['start']:%d/%m/%Y %H:%M} – "
        f"{r.stats['end']:%H:%M}). Actividad anterior o posterior, u otras fuentes no exportadas, no está cubierta.",
    ]
    redacted = df["Process_CommandLine"].fillna("").str.contains(r"redact", case=False)
    if redacted.any():
        out.append(f"{int(redacted.sum())} comandos tienen el contenido ofuscado o redactado en el export "
                   f"({', '.join(df.loc[redacted, 'Log_ID'].head(5))}); no es posible saber qué ejecutaron.")
    sources = sorted(df["Log_Source"].dropna().unique())
    out.append(f"Fuentes presentes: {', '.join(sources)}. No hay telemetría EDR, DNS ni captura de red, por lo que "
               "volúmenes y contenidos transferidos solo se conocen cuando el log los registra.")
    empty_dest = df["Destination"].isna().mean()
    if empty_dest > 0.2:
        out.append(f"El campo Destination está vacío en el {empty_dest:.0%} de los registros.")
    out.append("Las relaciones entre incidentes marcadas como 'posibles' no están confirmadas por los registros "
               "y deben verificarse con evidencia adicional.")
    return out


def all_iocs(r: AnalysisResult) -> list[tuple[str, str, str]]:
    seen: dict[tuple[str, str], str] = {}
    for inc in r.incidents:
        for kind, value in inc.iocs:
            seen.setdefault((kind, value), inc.id)
    return [(k, v, i) for (k, v), i in seen.items()]


def timeline_rows(r: AnalysisResult) -> list[tuple[str, str, str, str, str]]:
    rows = []
    for f in sorted((f for i in r.incidents for f in i.findings), key=lambda f: f.start):
        inc = r.incident_of(f)
        rows.append((f"{f.start:%H:%M:%S}", inc.id if inc else "-", f.id, f.level, f.title))
    return rows


def evidence_rows(r: AnalysisResult, ids: list[str], limit: int | None) -> tuple[pd.DataFrame, int]:
    rows = r.rows(ids).sort_values("Timestamp")
    total = len(rows)
    return (rows.head(limit) if limit else rows), total


def _detail(row) -> str:
    cmd = row["Process_CommandLine"]
    desc = row["Event_Description"] if pd.notna(row["Event_Description"]) else ""
    return f"{desc} | {cmd}" if pd.notna(cmd) and cmd else desc


def incident_ai(narrative: dict | None, inc_id: str) -> dict | None:
    if not narrative:
        return None
    return next((x for x in narrative.get("incidentes", []) if x.get("id") == inc_id), None)


# --------------------------------------------------------------------------------------
# Vista previa en Markdown
# --------------------------------------------------------------------------------------
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>#|$~])")


def md_escape(text) -> str:
    """Escapa texto procedente de los logs (rutas UNC, comodines, guiones bajos...) para Markdown."""
    return _MD_SPECIAL.sub(r"\\\1", str(text))


def _ai_md(text: str) -> str:
    """El texto de la IA ya es Markdown; solo se neutraliza '$' (fórmulas en algunos visores)."""
    return text.replace("$", r"\$")


def build_markdown(r: AnalysisResult, meta: ReportMeta, narrative: dict | None = None) -> str:
    e = md_escape
    md = ["# Informe técnico de incidente de seguridad\n",
          f"**Caso:** {e(meta.case_id)} · **Cliente:** {e(meta.client)} · **Analista:** {e(meta.analyst)} · "
          f"**Fecha:** {meta.generated:%d/%m/%Y %H:%M}\n",
          f"**Archivo analizado:** {e(r.logs.file_name)} · SHA-256 `{r.logs.sha256}`\n",
          "## 1. Resumen ejecutivo\n"]
    if narrative:
        check = narrative_checks(narrative, r)
        narrative = annotate_narrative(narrative, check, " ⚠️(no existe en los logs)")
        md.append(_ai_md(narrative["resumen_ejecutivo"]) + "\n")
        md.append(f"> Redactado con asistencia de IA ({narrative.get('modelo', '')}). {e(check.summary())}\n")
    else:
        md.append(e(default_executive_summary(r)) + "\n")
    md += [f"- {e(x)}" for x in key_figures(r)]

    md.append("\n## 2. Hallazgos identificados\n")
    md.append("| Incidente | Criticidad | Puntaje | Periodo | Título |\n|---|---|---|---|---|")
    for inc in r.incidents:
        md.append(f"| {inc.id} | {inc.level} | {inc.score} | {inc.start:%H:%M}–{inc.end:%H:%M} | {e(inc.title)} |")

    md.append("\n## 3. Análisis detallado de incidentes")
    for inc in r.incidents:
        md.append(f"\n### {inc.id} · {e(inc.title)}\n")
        md.append(f"**Criticidad: {inc.level} ({inc.score}/100).** Tácticas: {e(' → '.join(inc.tactics))}.\n")
        md.append("**Justificación:** " + "; ".join(
            e(x.reason) + (f" ({x.points:+d})" if n else "") for n, x in enumerate(inc.factors))
            + f" → {inc.score}/100.")
        ai = incident_ai(narrative, inc.id)
        if ai:
            md.append(f"\n**Secuencia del ataque (asistido por IA):** {_ai_md(ai['analisis'])}\n")
        for f in inc.findings:
            md.append(f"\n**{f.id} · {e(f.title)}** — {f.level} ({f.score})\n")
            md.append(f"- *Observado:* {e(f.description)}")
            md.append(f"- *Explicación técnica:* {e(f.technical)}")
            if f.mitre:
                md.append("- *MITRE ATT&CK:* " + e(", ".join(f"{t} {n}" for t, n in f.mitre)))
            md.append(f"- *Justificación del riesgo:* base {f.base_score}; "
                      + e("; ".join(f"{x.points:+d} {x.reason}" for x in f.factors) or "sin agravantes"))
            md.append(f"- *Evidencias:* {', '.join(f.evidence_ids[:20])}"
                      + (f" y {len(f.evidence_ids) - 20} más" if len(f.evidence_ids) > 20 else ""))
        md.append("\n**Posible impacto:**\n" + "\n".join(f"- {e(x)}" for x in inc.impact))
        if ai:
            md.append(f"- {_ai_md(ai['impacto'])}")
        md.append("\n**Plan de acción:**")
        for phase, steps in inc.plan.items():
            md.append(f"- **{phase.capitalize()}:** " + " ".join(f"({n}) {e(s)}" for n, s in enumerate(steps, 1)))
        if inc.related:
            md.append("\n**Relaciones posibles:** " + e("; ".join(inc.related)))

    n = 4
    if r.observations:
        md.append(f"\n## {n}. Observaciones evaluadas de bajo riesgo\n")
        for f in r.observations:
            md.append(f"- **{f.id} · {e(f.title)}** ({f.level}): {e(f.description)}")
        n += 1
    md.append(f"\n## {n}. Indicadores de compromiso (IoC)\n")
    md.append("| Tipo | Valor | Incidente |\n|---|---|---|")
    md += [f"| {e(k)} | `{v}` | {i} |" for k, v, i in all_iocs(r)]
    md.append(f"\n## {n + 1}. Recomendaciones generales de seguridad\n")
    if narrative:
        md += [f"{k}. {_ai_md(x)}" for k, x in enumerate(narrative["recomendaciones"], 1)]
    else:
        md += [f"{k}. {e(x)}" for k, x in enumerate(GENERAL_RECOMMENDATIONS, 1)]
    md.append(f"\n## {n + 2}. Limitaciones del análisis\n")
    md += [f"- {e(x)}" for x in limitations(r)]
    if narrative and narrative.get("limitaciones"):
        md.append(f"- {_ai_md(narrative['limitaciones'])}")
    return "\n".join(md)


# --------------------------------------------------------------------------------------
# Gráficos estáticos para el PDF (tema claro)
# --------------------------------------------------------------------------------------
_PDF_INK = "#1f2433"
_PDF_MUTED = "#6b7280"


def _png(fig) -> io.BytesIO:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    buf.seek(0)
    return buf


def _axes_style(ax):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color("#c3c2b7")
    ax.tick_params(colors=_PDF_MUTED, labelsize=8)


def chart_levels(r: AnalysisResult) -> io.BytesIO:
    fig, ax = plt.subplots(figsize=(4.2, 2.2))
    counts = [r.stats["incidents_by_level"][lvl] for lvl in LEVELS]
    bars = ax.barh(LEVELS, counts, color=[LEVEL_COLORS[lvl] for lvl in LEVELS], height=0.6)
    ax.invert_yaxis()
    ax.bar_label(bars, labels=[str(c) for c in counts], padding=3, color=_PDF_INK, fontsize=9)
    ax.set_xticks([])
    ax.spines["bottom"].set_visible(False)
    ax.set_title("Incidentes por criticidad", fontsize=9, color=_PDF_INK, loc="left")
    _axes_style(ax)
    return _png(fig)


def chart_timeline(r: AnalysisResult) -> io.BytesIO:
    incs = sorted(r.incidents, key=lambda i: i.start, reverse=True)
    fig, ax = plt.subplots(figsize=(7.5, 0.45 * len(incs) + 1.0))
    for n, inc in enumerate(incs):
        dur = max((inc.end - inc.start).total_seconds() / 86400, 2 / 1440)
        ax.barh(n, dur, left=matplotlib.dates.date2num(inc.start), height=0.5, color=LEVEL_COLORS[inc.level])
        ax.text(matplotlib.dates.date2num(inc.start + pd.Timedelta(seconds=dur * 86400)) + 0.002, n,
                f"{inc.level}", va="center", fontsize=7, color=_PDF_MUTED)
    ax.set_yticks(range(len(incs)), [i.id for i in incs])
    ax.xaxis_date()
    ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%H:%M"))
    ax.set_title("Línea de tiempo de incidentes", fontsize=9, color=_PDF_INK, loc="left")
    ax.grid(axis="x", color="#e1e0d9", linewidth=0.6)
    ax.set_axisbelow(True)
    _axes_style(ax)
    return _png(fig)


def chart_volume(r: AnalysisResult) -> io.BytesIO:
    flagged = r.flagged_ids()
    d = r.df.assign(bucket=r.df["Timestamp"].dt.floor("10min"), flag=r.df["Log_ID"].isin(flagged))
    g = d.groupby(["bucket", "flag"]).size().unstack(fill_value=0).reindex(columns=[False, True], fill_value=0)
    fig, ax = plt.subplots(figsize=(7.5, 2.4))
    x = matplotlib.dates.date2num(g.index)
    w = 8 / 1440
    ax.bar(x, g[False], width=w, color="#2a78d6", label="Eventos sin hallazgo")
    ax.bar(x, g[True], width=w, bottom=g[False], color="#eb6834", label="Eventos asociados a hallazgos")
    ax.xaxis_date()
    ax.xaxis.set_major_formatter(matplotlib.dates.DateFormatter("%H:%M"))
    ax.legend(fontsize=7, frameon=False, loc="upper right")
    ax.set_title("Volumen de eventos cada 10 minutos", fontsize=9, color=_PDF_INK, loc="left")
    ax.grid(axis="y", color="#e1e0d9", linewidth=0.6)
    ax.set_axisbelow(True)
    _axes_style(ax)
    return _png(fig)


# --------------------------------------------------------------------------------------
# PDF
# --------------------------------------------------------------------------------------
_FONT_DIR = os.path.join(os.path.dirname(matplotlib.__file__), "mpl-data", "fonts", "ttf")
NAVY = (21, 28, 46)
ACCENT = (235, 104, 52)
GREY = (107, 114, 128)
LIGHT = (244, 245, 248)


def _rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


class _PDF(FPDF):
    def __init__(self, meta: ReportMeta):
        super().__init__(format="A4")
        self.meta = meta
        self.doc_title = "Informe técnico de incidente de seguridad"
        self.set_auto_page_break(True, margin=18)
        self.set_margins(15, 16, 15)
        self.add_font("dv", "", os.path.join(_FONT_DIR, "DejaVuSans.ttf"))
        self.add_font("dv", "B", os.path.join(_FONT_DIR, "DejaVuSans-Bold.ttf"))
        self.add_font("dv", "I", os.path.join(_FONT_DIR, "DejaVuSans-Oblique.ttf"))
        self.add_font("dv", "BI", os.path.join(_FONT_DIR, "DejaVuSans-BoldOblique.ttf"))
        self.add_font("mono", "", os.path.join(_FONT_DIR, "DejaVuSansMono.ttf"))
        self.set_font("dv", size=9.5)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("dv", size=7.5)
        self.set_text_color(*GREY)
        self.cell(0, 5, f"{self.meta.case_id} · {self.doc_title}", align="L")
        self.cell(0, 5, "CONFIDENCIAL", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(225, 224, 217)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(4)
        self.set_text_color(0, 0, 0)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-12)
        self.set_font("dv", size=7.5)
        self.set_text_color(*GREY)
        self.cell(0, 5, f"Página {self.page_no()}/{{nb}}", align="C")

    # ---- bloques de texto ------------------------------------------------------------
    def h1(self, text: str):
        if self.get_y() > 240:
            self.add_page()
        self.start_section(text, level=0)
        self.ln(2)
        self.set_font("dv", "B", 15)
        self.set_text_color(*NAVY)
        self.multi_cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.6)
        self.line(15, self.get_y(), 40, self.get_y())
        self.set_line_width(0.2)
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def h2(self, text: str, color=NAVY, toc: bool = True):
        if self.get_y() > 250:
            self.add_page()
        if toc:
            self.start_section(text, level=1)
        self.ln(2)
        self.set_font("dv", "B", 11.5)
        self.set_text_color(*color)
        self.multi_cell(0, 6, text, align="L", new_x="LMARGIN", new_y="NEXT")
        self.ln(1)
        self.set_text_color(0, 0, 0)

    def h3(self, text: str):
        if self.get_y() > 262:
            self.add_page()
        self.ln(1)
        self.set_font("dv", "B", 9.5)
        self.set_text_color(*NAVY)
        self.multi_cell(0, 5, text, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)

    def para(self, text: str, size: float = 9.5, style: str = "", color=(0, 0, 0)):
        self.set_font("dv", style, size)
        self.set_text_color(*color)
        self.multi_cell(0, size * 0.52, text, align="L", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)
        self.ln(1.2)

    def bullets(self, items: list[str], size: float = 9.2, numbered: bool = False):
        self.set_font("dv", "", size)
        for n, item in enumerate(items, 1):
            mark = f"{n}." if numbered else "•"
            self.set_x(17)
            self.cell(6, size * 0.52, mark)
            self.multi_cell(0, size * 0.52, item, align="L", new_x="LMARGIN", new_y="NEXT")
            self.ln(0.6)
        self.ln(1)

    def level_badge(self, level: str, score: int | None = None):
        self.set_font("dv", "B", 8.5)
        text = f" {level.upper()}" + (f" · {score}/100 " if score is not None else " ")
        self.set_fill_color(*_rgb(LEVEL_COLORS[level]))
        self.set_text_color(*((31, 36, 51) if level == "Medio" else (255, 255, 255)))
        self.cell(self.get_string_width(text) + 2, 6, text, fill=True)
        self.set_text_color(0, 0, 0)

    def note_box(self, text: str, fill=LIGHT):
        self.set_fill_color(*fill)
        self.set_font("dv", "I", 8.5)
        self.multi_cell(0, 4.6, text, fill=True, align="L", new_x="LMARGIN", new_y="NEXT", padding=2)
        self.ln(2)

    def simple_table(self, headings: list[str], rows: list[list[str]], widths: list[float],
                     size: float = 7.8, wrap: WrapMode = WrapMode.WORD, colors: dict[int, dict] | None = None):
        self.set_font("dv", "", size)
        # Las filas sin franja heredan el color de relleno vigente: lo fijamos a blanco.
        self.set_fill_color(255, 255, 255)
        with self.table(
            col_widths=widths, width=sum(widths), align="LEFT", text_align="LEFT", line_height=size * 0.5,
            headings_style=FontFace(emphasis="BOLD", color=(255, 255, 255), fill_color=NAVY),
            cell_fill_color=LIGHT, cell_fill_mode=TableCellFillMode.ROWS,
            borders_layout=TableBordersLayout.NONE, padding=1.2, wrapmode=wrap,
        ) as table:
            head = table.row()
            for h in headings:
                head.cell(h)
            for row_idx, row in enumerate(rows):
                tr = table.row()
                for col_idx, value in enumerate(row):
                    style = (colors or {}).get(col_idx, {}).get(value)
                    tr.cell(str(value), style=style)
        self.ln(2)


def _level_styles() -> dict[str, FontFace]:
    return {
        lvl: FontFace(emphasis="BOLD", color=(31, 36, 51) if lvl == "Medio" else (255, 255, 255),
                      fill_color=_rgb(LEVEL_COLORS[lvl]))
        for lvl in LEVELS
    }


def _render_toc(pdf: _PDF, outline) -> None:
    pdf.set_font("dv", "B", 15)
    pdf.set_text_color(*NAVY)
    pdf.set_x(15)
    pdf.cell(0, 10, "Índice", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    for section in outline:
        indent = 6 * section.level
        pdf.set_font("dv", "B" if section.level == 0 else "", 9.5 if section.level == 0 else 8.8)
        pdf.set_text_color(0, 0, 0)
        name = section.name if len(section.name) < 95 else section.name[:92] + "…"
        pdf.set_x(15 + indent)
        link = pdf.add_link(page=section.page_number)
        pdf.cell(170 - indent, 5.6, name, link=link)
        pdf.cell(10, 5.6, str(section.page_number), align="R", new_x="LMARGIN", new_y="NEXT")


def _cover(pdf: _PDF, r: AnalysisResult, meta: ReportMeta) -> None:
    pdf.add_page()
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 297, "F")
    pdf.set_text_color(*ACCENT)
    pdf.set_font("dv", "B", 10)
    pdf.set_xy(20, 40)
    pdf.cell(0, 6, "INFORME TÉCNICO · RESPUESTA A INCIDENTES", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(20)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("dv", "B", 26)
    pdf.multi_cell(170, 12, "Investigación de incidente de seguridad", align="L", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(20)
    pdf.set_font("dv", "", 12)
    pdf.set_text_color(200, 205, 218)
    pdf.multi_cell(170, 7, f"Análisis de logs del SIEM de {meta.client}", new_x="LMARGIN", new_y="NEXT")

    worst = r.incidents[0].level if r.incidents else "Bajo"
    pdf.set_xy(20, 110)
    pdf.set_font("dv", "", 9)
    pdf.set_text_color(200, 205, 218)
    pdf.cell(0, 6, "CRITICIDAD GLOBAL", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(20)
    pdf.set_fill_color(*_rgb(LEVEL_COLORS[worst]))
    pdf.set_text_color(*((31, 36, 51) if worst == "Medio" else (255, 255, 255)))
    pdf.set_font("dv", "B", 16)
    pdf.cell(60, 12, worst.upper(), fill=True, align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_xy(20, 140)
    by = r.stats["incidents_by_level"]
    for lvl in LEVELS:
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("dv", "B", 22)
        pdf.set_x(20 + LEVELS.index(lvl) * 42)
        pdf.cell(40, 10, str(by[lvl]))
    pdf.ln(10)
    for lvl in LEVELS:
        pdf.set_font("dv", "", 8.5)
        pdf.set_text_color(200, 205, 218)
        pdf.set_x(20 + LEVELS.index(lvl) * 42)
        pdf.cell(40, 5, f"incidentes {lvl.lower()}")

    rows = [
        ("Caso", meta.case_id), ("Cliente", meta.client), ("Elaborado por", f"{meta.analyst}"),
        ("Organización", meta.organization), ("Fecha del informe", f"{meta.generated:%d/%m/%Y %H:%M}"),
        ("Archivo analizado", r.logs.file_name), ("SHA-256", r.logs.sha256),
        ("Periodo de los logs", f"{r.stats['start']:%d/%m/%Y %H:%M:%S} – {r.stats['end']:%d/%m/%Y %H:%M:%S}"),
        ("Clasificación", "CONFIDENCIAL — uso restringido al equipo de respuesta y dirección del cliente"),
    ]
    pdf.set_y(190)
    for k, v in rows:
        pdf.set_x(20)
        pdf.set_font("dv", "B", 8.5)
        pdf.set_text_color(*ACCENT)
        pdf.cell(38, 5.5, k.upper())
        pdf.set_font("mono" if k == "SHA-256" else "dv", "", 7.6 if k == "SHA-256" else 9)
        pdf.set_text_color(255, 255, 255)
        pdf.multi_cell(132, 5.5, v, new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)


def build_pdf(r: AnalysisResult, meta: ReportMeta, narrative: dict | None = None) -> bytes:
    pdf = _PDF(meta)
    pdf.set_title(f"Informe técnico {meta.case_id}")
    pdf.set_author(meta.analyst)
    pdf.set_subject("Investigación de incidente de seguridad")
    level_styles = _level_styles()
    check: CitationCheck | None = narrative_checks(narrative, r) if narrative else None
    if narrative:
        narrative = annotate_narrative(narrative, check, " [NO VERIFICADO: no existe en los logs]")

    _cover(pdf, r, meta)
    pdf.add_page()
    pdf.insert_toc_placeholder(_render_toc, pages=1, allow_extra_pages=True)

    # 1. Resumen ejecutivo (el marcador de índice ya abre una página nueva) ------------------
    pdf.h1("1. Resumen ejecutivo")
    if narrative:
        for p in narrative["resumen_ejecutivo"].split("\n"):
            if p.strip():
                pdf.para(p.strip())
        pdf.note_box(f"Redactado con asistencia de IA ({narrative.get('modelo', '')}) a partir exclusivamente de "
                     f"los registros y hallazgos de este análisis. Verificación de referencias: {check.summary()}")
    else:
        pdf.para(default_executive_summary(r))
    pdf.h3("Cifras clave")
    pdf.bullets(key_figures(r))
    y = pdf.get_y()
    pdf.image(chart_levels(r), x=15, y=y, w=85)
    pdf.set_xy(105, y + 2)
    pdf.set_font("dv", "", 8.2)
    for lvl in LEVELS:
        pdf.set_x(105)
        pdf.set_fill_color(*_rgb(LEVEL_COLORS[lvl]))
        pdf.cell(3, 3.5, "", fill=True)
        pdf.set_font("dv", "B", 8.2)
        pdf.cell(16, 3.5, f" {lvl}")
        pdf.set_font("dv", "", 8.2)
        pdf.multi_cell(74, 3.8, LEVEL_DESCRIPTIONS[lvl], new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
    pdf.set_y(max(pdf.get_y(), y + 46))

    # 2. Alcance y metodología -----------------------------------------------------------
    pdf.h1("2. Alcance y metodología")
    pdf.para(
        f"Se analizó el archivo {r.logs.file_name} (hoja '{r.logs.sheet}', {r.stats['events']} registros, "
        f"SHA-256 {r.logs.sha256}). La integridad del archivo puede verificarse recalculando este hash."
    )
    pdf.para(
        "El motor de análisis aplica reglas de detección deterministas sobre los registros (ataques de "
        "credenciales, inicios de sesión anómalos, escalamiento de privilegios, persistencia, comandos y procesos "
        "sospechosos, movimiento lateral, recolección y exfiltración, ataques web y entidades anómalas). Cada "
        "hallazgo se respalda con los Log_ID que lo originan. Los hallazgos se correlacionan en incidentes cuando "
        f"comparten la cuenta o la IP del actor y ocurren a menos de {r.config.correlation_gap_min:.0f} minutos; "
        "los vínculos más débiles se informan como relaciones posibles."
    )
    pdf.para(
        "Clasificación de riesgo: cada hallazgo parte de un puntaje base según la técnica y suma factores "
        "agravantes verificables (éxito del ataque, origen externo, activo crítico, cuenta privilegiada, datos "
        "sensibles, volumen de salida...). El incidente toma el puntaje de su hallazgo más grave más una "
        "bonificación por cadena multi-etapa y por patrones combinados conocidos."
    )
    pdf.simple_table(
        ["Nivel", "Puntaje", "Criterio"],
        [[lvl, f"≥ {t}" if t else f"< {THRESHOLDS[-2][0]}", LEVEL_DESCRIPTIONS[lvl]] for t, lvl in THRESHOLDS],
        [22, 20, 138], colors={0: level_styles},
    )

    # 3. Hallazgos identificados ---------------------------------------------------------
    pdf.h1("3. Hallazgos identificados")
    pdf.simple_table(
        ["ID", "Criticidad", "Pts", "Periodo", "Incidente"],
        [[i.id, i.level, str(i.score), f"{i.start:%H:%M}–{i.end:%H:%M}", i.title] for i in r.incidents],
        [16, 22, 10, 22, 110], colors={1: level_styles},
    )
    pdf.image(chart_timeline(r), x=15, w=180)
    pdf.ln(2)
    pdf.image(chart_volume(r), x=15, w=180)

    # 4. Detalle por incidente -----------------------------------------------------------
    pdf.add_page()
    pdf.h1("4. Análisis detallado de incidentes")
    for inc in r.incidents:
        pdf.h2(f"{inc.id} · {inc.title}")
        pdf.level_badge(inc.level, inc.score)
        pdf.set_font("dv", "", 8.5)
        pdf.set_text_color(*GREY)
        pdf.cell(0, 6, f"   {inc.start:%d/%m/%Y %H:%M:%S} – {inc.end:%H:%M:%S}", new_x="LMARGIN", new_y="NEXT")
        pdf.para("Tácticas: " + " → ".join(inc.tactics), size=8.4, color=GREY)

        ai = incident_ai(narrative, inc.id)
        if ai:
            pdf.h3("Secuencia del ataque (análisis asistido por IA)")
            pdf.para(ai["analisis"], size=9)

        pdf.h3("Hallazgos y explicación técnica")
        for f in inc.findings:
            pdf.set_font("dv", "B", 9)
            pdf.multi_cell(0, 4.8, f"{f.id} · {f.title}", new_x="LMARGIN", new_y="NEXT")
            pdf.level_badge(f.level, f.score)
            pdf.set_font("dv", "", 8)
            pdf.set_text_color(*GREY)
            pdf.cell(0, 6, "   " + category_label(f.category)
                     + (" · MITRE ATT&CK: " + ", ".join(t for t, _ in f.mitre) if f.mitre else ""),
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.para("Observado: " + f.description, size=8.8)
            pdf.para("Explicación técnica: " + f.technical, size=8.8, color=(55, 60, 75))
            if f.mitre:
                pdf.para("Técnicas: " + "; ".join(f"{t} {n}" for t, n in f.mitre), size=8.2, style="I",
                         color=GREY)

        pdf.h3("Criticidad y justificación")
        rows = [[f.id, f.level, str(f.base_score), "; ".join(f"{x.points:+d} {x.reason}" for x in f.factors) or "—",
                 str(f.score)] for f in inc.findings]
        pdf.simple_table(["Hallazgo", "Nivel", "Base", "Factores agravantes", "Total"], rows,
                         [16, 18, 11, 123, 12], size=7.4, colors={1: level_styles})
        pdf.para("Incidente: " + "; ".join(f"{x.reason} ({x.points:+d})" if n else x.reason
                                           for n, x in enumerate(inc.factors))
                 + f" → {inc.score}/100 ({inc.level}).", size=8.6, style="B")

        pdf.h3("Evidencias en los logs")
        ev, total = evidence_rows(r, inc.evidence_ids, EVIDENCE_ROWS_PER_INCIDENT)
        pdf.simple_table(
            ["Log_ID", "Hora", "Host", "Evento", "Usuario", "IP origen", "Detalle"],
            [[x["Log_ID"], f"{x['Timestamp']:%H:%M:%S}", x["Hostname"] or "", x["Event_ID"] or "",
              x["User"] or "", x["Source_IP"] or "", _detail(x)] for _, x in ev.iterrows()],
            [18, 13, 17, 17, 25, 21, 69], size=6.6, wrap=WrapMode.CHAR,
        )
        if total > len(ev):
            pdf.para(f"Se muestran {len(ev)} de {total} eventos de evidencia. Lista completa de Log_ID: "
                     + ", ".join(inc.evidence_ids), size=6.8, color=GREY)

        pdf.h3("Posible impacto en la organización")
        pdf.bullets(inc.impact + ([ai["impacto"]] if ai else []), size=8.8)

        pdf.h3("Plan de acción")
        for phase, title in (("investigar", "Investigar"), ("contener", "Contener"), ("remediar", "Remediar")):
            pdf.set_font("dv", "B", 8.8)
            pdf.set_text_color(*ACCENT)
            pdf.cell(0, 5, title, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)
            pdf.bullets(inc.plan[phase], size=8.6, numbered=True)
        if inc.related:
            pdf.note_box("Relaciones posibles: " + "; ".join(inc.related))
        pdf.ln(3)

    # 5. Línea de tiempo ------------------------------------------------------------------
    pdf.add_page()
    pdf.h1("5. Línea de tiempo consolidada")
    pdf.simple_table(["Hora", "Incidente", "Hallazgo", "Nivel", "Descripción"],
                     [list(x) for x in timeline_rows(r)], [16, 18, 16, 18, 112], size=7.6,
                     colors={3: level_styles})

    # 6. IoCs ----------------------------------------------------------------------------
    pdf.h1("6. Indicadores de compromiso (IoC)")
    pdf.simple_table(["Tipo", "Valor", "Incidente"], [list(x) for x in all_iocs(r)], [38, 124, 18],
                     size=7.6, wrap=WrapMode.CHAR)

    # 7. Observaciones de bajo riesgo -----------------------------------------------------
    if r.observations:
        pdf.h1("7. Observaciones evaluadas de bajo riesgo")
        for f in r.observations:
            pdf.h3(f"{f.id} · {f.title}")
            pdf.para(f.description, size=8.8)
            pdf.para(f.technical, size=8.6, color=GREY)

    # 8. Recomendaciones y limitaciones ----------------------------------------------------
    pdf.h1(("8" if r.observations else "7") + ". Recomendaciones generales de seguridad")
    pdf.bullets(narrative["recomendaciones"] if narrative else GENERAL_RECOMMENDATIONS, numbered=True)
    pdf.h1(("9" if r.observations else "8") + ". Limitaciones del análisis")
    pdf.bullets(limitations(r) + ([narrative["limitaciones"]] if narrative and narrative.get("limitaciones") else []))
    pdf.ln(4)
    pdf.note_box(
        "Rigor analítico: todas las conclusiones de este informe se sustentan en los registros del archivo "
        "indicado en la portada; cada hallazgo referencia los Log_ID que lo originan. "
        + ("Los apartados redactados con IA fueron verificados automáticamente contra el archivo. " if narrative else "")
    )
    return bytes(pdf.output())
