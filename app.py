"""SOC L2 Analyzer — aplicación web (Streamlit).

Ejecutar:  streamlit run app.py
"""

from __future__ import annotations

import hashlib
import html
import math
import queue
import threading
import time
from dataclasses import asdict
from pathlib import Path

import pandas as pd
import streamlit as st

from soc_analyzer import LogLoadError, load_logs, run_analysis
from soc_analyzer import charts
from soc_analyzer.ai_assistant import (
    DEFAULT_MODEL, MODELS, AIAssistant, AIError, annotate_invalid, narrative_checks, resolve_api_key,
    verify_citations,
)
from soc_analyzer.detections import DetectionConfig
from soc_analyzer.executive import build_executive_markdown, build_executive_pdf, executive_content, facts_text
from soc_analyzer.knowledge import CATEGORIES, category_label
from soc_analyzer.report import ReportMeta, build_markdown, build_pdf, md_escape as esc
from soc_analyzer.risk import LEVEL_COLORS, LEVEL_DESCRIPTIONS, LEVELS, THRESHOLDS, level_rank

APP_DIR = Path(__file__).parent
SAMPLE_FILE = APP_DIR / "Insumos" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
EVIDENCE_COLS = ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Destination",
                 "Event_Description", "Process_CommandLine", "Result", "Severity"]

st.set_page_config(page_title="SOC L2 Analyzer", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.block-container {padding-top: 3.5rem; max-width: 1400px;}
h1, h2, h3 {letter-spacing: -0.01em;}
.eyebrow {color:#9a5418; font-weight:700; font-size:0.78rem; letter-spacing:0.08em; text-transform:uppercase;}
.subtitle {color:#6e5a43; margin-top:-0.6rem; margin-bottom:1.2rem;}
.badge {display:inline-block; padding:2px 10px; border-radius:6px; font-weight:700; font-size:0.78rem;
        letter-spacing:0.03em; margin-right:6px; white-space:nowrap;}
.chip {display:inline-block; padding:1px 8px; border-radius:999px; border:1px solid #d8c7a3; color:#6e5a43;
       font-size:0.75rem; margin:0 4px 4px 0;}
.card {background:#fbf6ea; border:1px solid #d8c7a3; border-radius:12px; padding:16px 18px; margin-bottom:12px;}
.card h4 {margin:0 0 6px 0; font-size:1rem;}
.muted {color:#6e5a43; font-size:0.86rem;}
.factor {font-size:0.86rem; margin:2px 0;}
.factor b {color:#9a5418;}
div[data-testid="stMetric"] {background:#fbf6ea; border:1px solid #d8c7a3; border-radius:12px; padding:12px 16px;}
div[data-testid="stMetricValue"] {font-size:1.7rem;}
div[data-testid="stTab"] {padding:10px 12px; color:#6e5a43;}
div[data-testid="stTab"] p {font-size:0.95rem; white-space:nowrap; font-weight:600;}
div[data-testid="stTab"][aria-selected="true"], div[data-testid="stTab"][aria-selected="true"] p {color:#9a5418;}
div[data-testid="stTabs"] [role="tablist"] {gap:2px; margin-bottom:0.5rem;}
</style>
""", unsafe_allow_html=True)


# --------------------------------------------------------------------------------------
# Utilidades de presentación
# --------------------------------------------------------------------------------------
def badge(level: str, score: int | None = None) -> str:
    fg = "#2b2118" if level == "Medio" else "#ffffff"
    label = level.upper() + (f" · {score}" if score is not None else "")
    return f'<span class="badge" style="background:{LEVEL_COLORS[level]};color:{fg}">{label}</span>'


def chips(items) -> str:
    return "".join(f'<span class="chip">{html.escape(str(i))}</span>' for i in items)


def secret_api_key() -> str | None:
    try:
        return st.secrets.get("ANTHROPIC_API_KEY")
    except Exception:          # sin archivo de secretos
        return None


def evidence_df(result, ids: list[str]) -> pd.DataFrame:
    rows = result.rows(ids)[EVIDENCE_COLS].sort_values("Timestamp")
    text_cols = [c for c in EVIDENCE_COLS if c != "Timestamp"]
    return rows.astype({c: "object" for c in text_cols}).fillna({c: "" for c in text_cols})


def safe_ai_markdown(text: str) -> str:
    return text.replace("$", r"\$")


def run_with_progress(work, *, stages: tuple[str, str], prep_seconds: float, expected_chars: int,
                      live_text: bool = False):
    """Ejecuta una llamada a la IA en segundo plano mientras muestra una barra de progreso.

    ``work`` recibe una función ``emit(fragmento)`` que se invoca con cada trozo de texto generado.
    El avance es una estimación: mientras el modelo prepara la respuesta crece con el tiempo
    transcurrido (hasta el 55 %) y, cuando empieza a escribir, con el texto recibido (hasta el 95 %).
    Devuelve (valor retornado por ``work``, texto acumulado).
    """
    chunks: queue.SimpleQueue[str] = queue.SimpleQueue()
    out: dict = {}

    def target():
        try:
            out["value"] = work(chunks.put)
        except Exception as exc:          # se relanza en el hilo de Streamlit
            out["error"] = exc

    bar = st.progress(0.0, text=stages[0])
    live = st.empty() if live_text else None
    worker = threading.Thread(target=target, daemon=True)
    text, start = "", time.monotonic()
    worker.start()
    while worker.is_alive() or not chunks.empty():
        worker.join(0.25)
        new = ""
        while not chunks.empty():
            new += chunks.get()
        text += new
        if new and live is not None:
            live.markdown(safe_ai_markdown(text))
        elapsed = time.monotonic() - start
        if text:
            value, label = 0.55 + 0.40 * (1 - math.exp(-len(text) / expected_chars)), stages[1]
        else:
            value, label = 0.03 + 0.52 * (1 - math.exp(-elapsed / prep_seconds)), stages[0]
        bar.progress(value, text=f"{label} · {elapsed:.0f} s")
    bar.empty()
    if live is not None:
        live.empty()
    if "error" in out:
        raise out["error"]
    return out.get("value"), text


def header(eyebrow: str, title: str, subtitle: str) -> None:
    st.markdown(f'<div class="eyebrow">{eyebrow}</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<div class="subtitle">{subtitle}</div>', unsafe_allow_html=True)


# --------------------------------------------------------------------------------------
# Estado
# --------------------------------------------------------------------------------------
ss = st.session_state
ss.setdefault("logs", None)
ss.setdefault("result", None)
ss.setdefault("config", DetectionConfig())
ss.setdefault("chat", [])
ss.setdefault("narrative", None)
ss.setdefault("pdf", None)
ss.setdefault("exec_narrative", None)
ss.setdefault("exec_pdf", None)
ss.setdefault("meta", ReportMeta())


def analyze() -> None:
    ss.result = run_analysis(ss.logs, ss.config)
    ss.chat, ss.narrative, ss.pdf = [], None, None
    ss.exec_narrative, ss.exec_pdf = None, None


def set_logs(data: bytes, name: str) -> None:
    try:
        ss.logs = load_logs(data, name)
    except LogLoadError as exc:
        st.error(str(exc))
        return
    analyze()


# --------------------------------------------------------------------------------------
# Barra lateral
# --------------------------------------------------------------------------------------
PAGES = [
    "📂 Carga de datos",
    "🔍 Análisis de seguridad",
    "📊 Dashboard",
    "⚖️ Clasificación de riesgos",
    "🤖 Asistente IA",
    "📄 Informe técnico",
]
# Enlaces directos para demostraciones: ?demo=1 carga el archivo del reto, ?p=N abre la sección N (1-6).
if st.query_params.get("demo") == "1" and ss.logs is None and SAMPLE_FILE.exists():
    set_logs(SAMPLE_FILE.read_bytes(), SAMPLE_FILE.name)
_p = st.query_params.get("p", "1")
start_page = int(_p) - 1 if _p.isdigit() and 1 <= int(_p) <= len(PAGES) else 0

with st.sidebar:
    st.markdown("### 🛡️ SOC L2 Analyzer")
    st.caption("Investigación de incidentes a partir de logs del SIEM")

    if ss.result:
        r = ss.result
        st.divider()
        st.caption(f"**{r.logs.file_name}**  \n{r.stats['events']} eventos · {len(r.incidents)} incidentes")
        st.markdown(" ".join(badge(lvl) + f"{r.stats['incidents_by_level'][lvl]}" for lvl in LEVELS
                             if r.stats["incidents_by_level"][lvl]), unsafe_allow_html=True)

    st.divider()
    with st.expander("🤖 Configuración de IA", expanded=False):
        api_key_input = st.text_input("API key de Anthropic", type="password",
                                      help="También se toma de .streamlit/secrets.toml o de la variable de entorno "
                                           "ANTHROPIC_API_KEY.")
        model = st.selectbox("Modelo", list(MODELS), format_func=MODELS.get,
                             index=list(MODELS).index(DEFAULT_MODEL))
    api_key = resolve_api_key(api_key_input or secret_api_key())
    st.caption("IA: " + ("🟢 configurada" if api_key else "⚪ no configurada (modo solo reglas)"))

    with st.expander("⚙️ Parámetros de detección"):
        c = ss.config
        new = DetectionConfig(
            bf_min_failures=st.number_input("Fallos para fuerza bruta (origen interno)", 3, 100, c.bf_min_failures),
            bf_min_failures_external=st.number_input("Fallos para fuerza bruta (origen Internet)", 1, 50,
                                                     c.bf_min_failures_external),
            spray_min_users=st.number_input("Cuentas distintas para password spraying", 2, 50, c.spray_min_users),
            mass_access_min_files=st.number_input("Archivos para acceso masivo", 3, 500, c.mass_access_min_files),
            exfil_min_bytes=int(st.number_input("MB salientes para exfiltración", 1, 10000,
                                                c.exfil_min_bytes // 1024 ** 2)) * 1024 ** 2,
            correlation_gap_min=st.number_input("Ventana de correlación (min)", 5, 720, int(c.correlation_gap_min)),
            business_start_hour=st.number_input("Inicio horario laboral", 0, 23, c.business_start_hour),
            business_end_hour=st.number_input("Fin horario laboral", 1, 24, c.business_end_hour),
        )
        if asdict(new) != asdict(c):
            ss.config = new
            if ss.logs:
                analyze()
                st.rerun()


def require_result() -> bool:
    if ss.result is None:
        st.info("Primero cargue un archivo de logs en **📂 Carga de datos**.")
        return False
    return True


# --------------------------------------------------------------------------------------
# 1. Carga de datos
# --------------------------------------------------------------------------------------
def page_upload() -> None:
    header("Funcionalidad 01", "Carga de archivos", "Importe el Excel exportado del SIEM (.xlsx) para analizarlo.")
    col_up, col_sample = st.columns([3, 1])
    with col_up:
        up = st.file_uploader("Archivo de logs del SIEM", type=["xlsx"], label_visibility="collapsed")
        if up is not None and (ss.logs is None or ss.logs.sha256 != hashlib.sha256(up.getvalue()).hexdigest()):
            with st.spinner("Analizando registros…"):
                set_logs(up.getvalue(), up.name)
    with col_sample:
        if SAMPLE_FILE.exists() and st.button("Usar archivo del reto", width="stretch",
                                              help=SAMPLE_FILE.name):
            with st.spinner("Analizando registros…"):
                set_logs(SAMPLE_FILE.read_bytes(), SAMPLE_FILE.name)

    if not ss.logs:
        st.markdown(
            '<div class="card"><h4>Formato esperado</h4><div class="muted">Una hoja con columnas como '
            'Log_ID, Timestamp, Hostname, Event_ID, User, Source_IP, Destination, Log_Source, '
            'Event_Description, Process_CommandLine, Result y Severity. Se aceptan nombres equivalentes '
            '(p. ej. "Fecha", "Usuario", "IP origen"); solo Timestamp y Event_ID son obligatorias.</div></div>',
            unsafe_allow_html=True,
        )
        return

    logs, r = ss.logs, ss.result
    for w in logs.warnings:
        st.warning(w)
    df = logs.df
    m = st.columns(5)
    m[0].metric("Registros", f"{len(df):,}")
    m[1].metric("Equipos", df["Hostname"].nunique())
    m[2].metric("Cuentas", df["User"].nunique())
    m[3].metric("IPs de origen", df["Source_IP"].nunique())
    m[4].metric("Duración", f"{(df['Timestamp'].max() - df['Timestamp'].min()).total_seconds() / 3600:.1f} h")
    st.markdown(
        f'<div class="muted">Hoja <b>{html.escape(logs.sheet)}</b> · periodo {df["Timestamp"].min():%d/%m/%Y %H:%M:%S}'
        f' – {df["Timestamp"].max():%d/%m/%Y %H:%M:%S} · SHA-256 <code>{logs.sha256}</code> '
        f'(cadena de custodia)</div>', unsafe_allow_html=True)
    st.success(f"Análisis completado: {len(r.findings)} hallazgos correlacionados en {len(r.incidents)} incidentes. "
               "Continúe en **🔍 Análisis de seguridad**.")

    st.subheader("Visualización de registros")
    f1, f2, f3, f4 = st.columns([2, 1, 1, 1])
    q = f1.text_input("Buscar en todos los campos", placeholder="p. ej. powershell, 203.0.113.74, Finance")
    hosts = f2.multiselect("Equipo", sorted(df["Hostname"].dropna().unique()))
    eids = f3.multiselect("Event ID", sorted(df["Event_ID"].dropna().unique()))
    only_flagged = f4.toggle("Solo eventos con hallazgo", value=False)
    view = df
    if q:
        mask = view.astype(str).apply(lambda col: col.str.contains(q, case=False, regex=False)).any(axis=1)
        view = view[mask]
    if hosts:
        view = view[view["Hostname"].isin(hosts)]
    if eids:
        view = view[view["Event_ID"].isin(eids)]
    if only_flagged:
        view = view[view["Log_ID"].isin(r.flagged_ids())]
    st.caption(f"{len(view):,} de {len(df):,} registros")
    st.dataframe(view, hide_index=True, width="stretch", height=460,
                 column_config={"Timestamp": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss")})


# --------------------------------------------------------------------------------------
# 2. Análisis de seguridad
# --------------------------------------------------------------------------------------
COVERAGE = [
    ("Fuerza bruta", "Intentos de acceso no autorizados", {"fuerza_bruta"}),
    ("Inicios sospechosos", "Sesiones anómalas por origen, horario o patrón", {"inicio_sospechoso"}),
    ("Escalamiento", "Elevación de privilegios", {"escalamiento"}),
    ("Comandos y procesos", "Ejecución sospechosa en equipos", {"comandos", "persistencia"}),
    ("Movimiento lateral", "Saltos entre sistemas de la red", {"movimiento_lateral"}),
    ("Otras anomalías", "Exfiltración, ataques web, entidades anómalas", {"exfiltracion", "ataque_web", "anomalia"}),
]


def render_finding(r, f) -> None:
    st.markdown(
        f'{badge(f.level, f.score)} <b>{html.escape(f.id)} · {html.escape(f.title)}</b><br>'
        f'<span class="muted">{CATEGORIES[f.category]["icon"]} {category_label(f.category)} · '
        f'{f.start:%H:%M:%S} – {f.end:%H:%M:%S} · {len(f.evidence_ids)} eventos de evidencia</span>',
        unsafe_allow_html=True)
    st.markdown(f"**Observado.** {esc(f.description)}")
    st.markdown(f"**Explicación técnica.** {esc(f.technical)}")
    if f.mitre:
        st.markdown("**MITRE ATT&CK.** " + chips(f"{t} · {n}" for t, n in f.mitre), unsafe_allow_html=True)
    st.markdown("**Justificación del riesgo.** " + f"base {f.base_score}"
                + "".join(f'<div class="factor"><b>{x.points:+d}</b> {html.escape(x.reason)}</div>' for x in f.factors),
                unsafe_allow_html=True)
    st.dataframe(evidence_df(r, f.evidence_ids), hide_index=True, width="stretch",
                 height=min(38 * len(f.evidence_ids) + 40, 320))


def page_analysis() -> None:
    header("Funcionalidad 02", "Análisis de seguridad",
           "Eventos sospechosos identificados por el motor de reglas y correlacionados en incidentes.")
    if not require_result():
        return
    r = ss.result

    st.subheader("Cobertura de detección")
    cols = st.columns(6)
    for col, (name, desc, cats) in zip(cols, COVERAGE):
        fs = [f for f in r.findings if f.category in cats and f not in r.observations]
        worst = min((f.level for f in fs), key=level_rank, default=None)
        status = badge(worst) if worst else '<span class="chip">Sin evidencia en los logs</span>'
        col.markdown(f'<div class="card"><h4>{name}</h4><div class="muted">{desc}</div>'
                     f'<div style="margin-top:8px">{status}</div><div class="muted" style="margin-top:4px">'
                     f'{len(fs)} hallazgo(s){": " + ", ".join(f.id for f in fs) if fs else ""}</div></div>',
                     unsafe_allow_html=True)

    st.subheader(f"Incidentes correlacionados ({len(r.incidents)})")
    st.caption(f"Los hallazgos se agrupan cuando comparten la cuenta o la IP del actor y ocurren a menos de "
               f"{r.config.correlation_gap_min:.0f} min. Los vínculos más débiles se muestran como relaciones posibles.")
    for inc in r.incidents:
        with st.expander(f"{inc.id} · {inc.level.upper()} ({inc.score}) · {inc.title}",
                         expanded=inc is r.incidents[0]):
            st.markdown(
                f'{badge(inc.level, inc.score)} <span class="muted">{inc.start:%H:%M:%S} – {inc.end:%H:%M:%S} · '
                f'{len(inc.findings)} hallazgos · {len(inc.evidence_ids)} eventos</span><br>'
                f'<div style="margin-top:6px">{" → ".join(html.escape(t) for t in inc.tactics)}</div>',
                unsafe_allow_html=True)
            st.markdown("**Entidades:** " + chips(sorted(inc.entities("users")) + sorted(inc.entities("hosts"))
                                                  + sorted(inc.entities("ips"))), unsafe_allow_html=True)
            if inc.related:
                st.info("**Relaciones posibles (no confirmadas):** " + esc("; ".join(inc.related)))
            tabs = st.tabs([f.id for f in inc.findings] + ["Impacto y plan de acción"])
            for tab, f in zip(tabs, inc.findings):
                with tab:
                    render_finding(r, f)
            with tabs[-1]:
                st.markdown("**Posible impacto**\n" + "\n".join(f"- {esc(x)}" for x in inc.impact))
                c1, c2, c3 = st.columns(3)
                for col, phase in zip((c1, c2, c3), ("investigar", "contener", "remediar")):
                    col.markdown(f"**{phase.capitalize()}**\n" + "\n".join(
                        f"{n}. {esc(s)}" for n, s in enumerate(inc.plan[phase], 1)))

    if r.observations:
        st.subheader("Observaciones evaluadas de bajo riesgo")
        for f in r.observations:
            with st.expander(f"{f.id} · {f.title}"):
                render_finding(r, f)


# --------------------------------------------------------------------------------------
# 3. Dashboard
# --------------------------------------------------------------------------------------
def page_dashboard() -> None:
    header("Funcionalidad 03", "Dashboard", "Estadísticas y gráficos interactivos por criticidad.")
    if not require_result():
        return
    r = ss.result

    f1, f2, f3 = st.columns([1.2, 1.6, 2])
    levels = f1.multiselect("Criticidad", LEVELS, default=LEVELS)
    cats = f2.multiselect("Categoría", list(CATEGORIES), default=list(CATEGORIES), format_func=category_label)
    t0, t1 = r.stats["start"].to_pydatetime(), r.stats["end"].to_pydatetime()
    rng = f3.slider("Periodo", min_value=t0, max_value=t1, value=(t0, t1), format="HH:mm")
    lo, hi = pd.Timestamp(rng[0]), pd.Timestamp(rng[1])
    findings = [f for f in r.findings if f.level in levels and f.category in cats and f.end >= lo and f.start <= hi]
    incidents = [i for i in r.incidents if i.level in levels and any(f in findings for f in i.findings)]
    data = r.data[(r.data["Timestamp"] >= lo) & (r.data["Timestamp"] <= hi)]
    flagged = {i for f in findings for i in f.evidence_ids}

    compromised = sorted({u for f in findings if f.category == "inicio_sospechoso" for u in f.users})
    k = st.columns(6)
    k[0].metric("Eventos en el periodo", f"{len(data):,}")
    k[1].metric("Incidentes", len(incidents))
    k[2].metric("Críticos", sum(1 for i in incidents if i.level == "Crítico"))
    k[3].metric("Hallazgos", len(findings))
    k[4].metric("IPs externas", len({ip for ip in data.loc[data["src_ext"], "src_ip"]}
                                     | set(data.loc[data["dest_ext"], "dest_ip"].dropna())))
    k[5].metric("Cuentas comprometidas", len(compromised), help=", ".join(compromised) or None)

    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("##### Línea de tiempo de incidentes")
        if incidents:
            st.plotly_chart(charts.incident_timeline(incidents), width="stretch")
    with c2:
        st.markdown("##### Incidentes por criticidad")
        st.plotly_chart(charts.level_bars(incidents, "incidentes"), width="stretch")
        st.markdown("##### Hallazgos por criticidad")
        st.plotly_chart(charts.level_bars(findings, "hallazgos"), width="stretch")

    st.markdown("##### Mapa de la cadena de ataque (hallazgos por táctica y hora)")
    if findings:
        st.plotly_chart(charts.kill_chain(findings), width="stretch")

    st.markdown("##### Volumen de eventos y eventos implicados en hallazgos")
    st.plotly_chart(charts.event_volume(data, flagged), width="stretch")

    c3, c4 = st.columns(2)
    with c3:
        st.markdown("##### Principales IPs de origen")
        st.plotly_chart(charts.top_sources(data), width="stretch")
    with c4:
        st.markdown("##### Tipos de evento más frecuentes")
        st.plotly_chart(charts.event_types(data), width="stretch")

    c5, c6 = st.columns([3, 2])
    with c5:
        st.markdown("##### Actividad sospechosa por equipo y hora")
        st.plotly_chart(charts.host_heatmap(data, flagged), width="stretch")
    with c6:
        st.markdown("##### Hallazgos por táctica")
        if findings:
            st.plotly_chart(charts.tactic_bars(findings), width="stretch")

    with st.expander("Ver datos en tabla"):
        st.dataframe(pd.DataFrame([{
            "Hallazgo": f.id, "Incidente": (r.incident_of(f).id if r.incident_of(f) else "—"),
            "Criticidad": f.level, "Puntaje": f.score, "Categoría": category_label(f.category),
            "Inicio": f.start, "Fin": f.end, "Título": f.title, "Eventos": len(f.evidence_ids),
        } for f in findings]), hide_index=True, width="stretch")


# --------------------------------------------------------------------------------------
# 4. Clasificación de riesgos
# --------------------------------------------------------------------------------------
def page_risk() -> None:
    header("Funcionalidad 04", "Clasificación de riesgos",
           "Crítico, Alto, Medio o Bajo, con la justificación de cada puntaje.")
    if not require_result():
        return
    r = ss.result

    c1, c2 = st.columns([1, 1.4])
    with c1:
        st.markdown("##### Metodología")
        st.markdown(
            "Cada hallazgo parte de un **puntaje base** según la técnica observada y suma **factores agravantes** "
            "verificables en los logs (éxito del ataque, origen externo, activo crítico, cuenta privilegiada, "
            "datos sensibles, volumen de salida…). El incidente toma el puntaje de su hallazgo más grave, más una "
            "bonificación por **cadena multi-etapa** y por **patrones combinados** (p. ej. compresión + envío "
            "al exterior). El color nunca es la única señal: cada nivel se muestra con su etiqueta.")
        for t, lvl in THRESHOLDS:
            rng = f"≥ {t}" if t else f"< {THRESHOLDS[-2][0]}"
            st.markdown(f'{badge(lvl)} <b>{rng} pts</b> — <span class="muted">{LEVEL_DESCRIPTIONS[lvl]}</span>',
                        unsafe_allow_html=True)
    with c2:
        st.markdown("##### Puntaje de riesgo por hallazgo")
        st.plotly_chart(charts.risk_scores(r.findings), width="stretch")

    st.markdown("##### Clasificación de incidentes")
    for inc in r.incidents:
        st.markdown(
            f'<div class="card">{badge(inc.level, inc.score)}<b>{inc.id} · {html.escape(inc.title)}</b>'
            + "".join(f'<div class="factor"><b>{x.points:+d}</b> {html.escape(x.reason)}</div>'
                      if n else f'<div class="factor"><b>{x.points}</b> {html.escape(x.reason)}</div>'
                      for n, x in enumerate(inc.factors))
            + f'<div class="factor muted">= {inc.score}/100 → {inc.level}</div></div>',
            unsafe_allow_html=True)

    st.markdown("##### Detalle por hallazgo")
    st.dataframe(pd.DataFrame([{
        "Hallazgo": f.id, "Criticidad": f.level, "Puntaje": f.score, "Base": f.base_score,
        "Justificación": " | ".join(f"{x.points:+d} {x.reason}" for x in f.factors) or "Sin agravantes",
        "Título": f.title,
    } for f in sorted(r.findings, key=lambda f: -f.score)]), hide_index=True, width="stretch",
        column_config={"Puntaje": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%d")})


# --------------------------------------------------------------------------------------
# 5. Asistente IA
# --------------------------------------------------------------------------------------
SUGGESTIONS = [
    "Resume en orden cronológico qué ocurrió en la red y qué incidentes son independientes.",
    "¿Qué cuentas deben considerarse comprometidas y con qué evidencia?",
    "Las cuentas objetivo del password spraying, ¿muestran actividad sospechosa posterior?",
    "¿Qué datos pudieron salir de la organización, hacia dónde y en qué volumen?",
    "¿Hay algún evento sospechoso en los logs que el motor de reglas no haya cubierto?",
]


def page_ai() -> None:
    header("IA integrada", "Asistente de análisis",
           "Consulte los logs y los hallazgos en lenguaje natural. Cada respuesta cita Log_IDs verificables.")
    if not require_result():
        return
    if not api_key:
        st.warning("Configure una API key de Anthropic en la barra lateral (🤖 Configuración de IA) o en la variable "
                   "de entorno `ANTHROPIC_API_KEY`. El análisis por reglas funciona sin IA.")
        return
    r = ss.result
    st.caption(f"Modelo: {MODELS[model]}. La IA recibe solo los registros del archivo y los hallazgos del motor; "
               "las referencias a Log_IDs se comprueban automáticamente contra el archivo cargado.")

    for msg in ss.chat:
        with st.chat_message(msg["role"], avatar="🧑‍💻" if msg["role"] == "user" else "🛡️"):
            st.markdown(safe_ai_markdown(msg["display"]))
            if msg.get("check"):
                (st.success if msg["check_ok"] else st.warning)(msg["check"], icon="🔎")

    clicked = None
    if not ss.chat:
        st.markdown("**Preguntas sugeridas**")
        cols = st.columns(len(SUGGESTIONS))
        for col, s in zip(cols, SUGGESTIONS):
            if col.button(s, width="stretch"):
                clicked = s
    question = st.chat_input("Pregunte sobre los incidentes, cuentas, IPs o eventos…") or clicked
    if not question:
        if ss.chat and st.button("Borrar conversación"):
            ss.chat = []
            st.rerun()
        return

    with st.chat_message("user", avatar="🧑‍💻"):
        st.markdown(esc(question))
    history = [{"role": m["role"], "content": m["content"]} for m in ss.chat]
    with st.chat_message("assistant", avatar="🛡️"):
        assistant = AIAssistant(api_key, model)
        try:
            _, answer = run_with_progress(
                lambda emit: [emit(chunk) for chunk in assistant.chat(r, history, question)],
                stages=("Analizando los registros y hallazgos", "Redactando la respuesta"),
                prep_seconds=12, expected_chars=1500, live_text=True)
        except AIError as exc:
            st.error(str(exc))
            return
        check = verify_citations(answer, r)
        display = annotate_invalid(answer, check)
        st.markdown(safe_ai_markdown(display))
        (st.success if check.ok else st.warning)(check.summary(), icon="🔎")
    ss.chat += [
        {"role": "user", "content": question, "display": esc(question)},
        {"role": "assistant", "content": answer, "display": display, "check": check.summary(), "check_ok": check.ok},
    ]


# --------------------------------------------------------------------------------------
# 6. Informe técnico y exportación
# --------------------------------------------------------------------------------------
REPORT_TECH, REPORT_EXEC = "📘 Informe técnico", "📋 Informe ejecutivo"


def page_report() -> None:
    header("Funcionalidades 05 y 06", "Informe técnico",
           "Documento descargable en PDF: completo para el equipo de seguridad o breve para la alta dirección.")
    if not require_result():
        return
    r = ss.result
    meta: ReportMeta = ss.meta

    kind = st.segmented_control("Tipo de informe", [REPORT_TECH, REPORT_EXEC], default=REPORT_TECH, required=True,
                                key="report_kind", width="stretch")
    st.caption("Análisis completo con evidencias, explicación técnica y plan de acción de cada incidente (unas 25 páginas)."
               if kind == REPORT_TECH else
               "Resumen de 2 páginas en lenguaje no técnico para la alta dirección: qué pasó, qué está en riesgo y qué "
               "decisiones tomar.")

    with st.form("report_meta_form"):
        c1, c2, c3 = st.columns(3)
        analyst = c1.text_input("Analista", meta.analyst)
        client = c2.text_input("Cliente", meta.client)
        case_id = c3.text_input("ID del caso", meta.case_id)
        organization = st.text_input("Organización", meta.organization)
        if st.form_submit_button("Guardar datos del informe"):
            ss.meta = ReportMeta(analyst=analyst, client=client, case_id=case_id, organization=organization)
            ss.pdf, ss.exec_pdf = None, None
            st.rerun()

    if kind == REPORT_EXEC:
        _executive_report(r)
    else:
        _technical_report(r)


def _technical_report(r) -> None:
    st.markdown("##### Redacción asistida por IA")
    c1, c2 = st.columns([1, 2])
    with c1:
        if st.button("✨ Redactar con IA", disabled=not api_key, width="stretch",
                     help=None if api_key else "Configure la API key en la barra lateral"):
            assistant = AIAssistant(api_key, model)
            try:
                ss.narrative, _ = run_with_progress(
                    lambda emit: assistant.report_narrative(r, on_text=emit),
                    stages=("La IA está analizando los incidentes",
                            "La IA está redactando el resumen ejecutivo y el análisis de cada incidente"),
                    prep_seconds=60, expected_chars=13000)
                ss.pdf = None
            except AIError as exc:
                st.error(str(exc))
        if ss.narrative and st.button("Descartar texto de IA", width="stretch"):
            ss.narrative, ss.pdf = None, None
            st.rerun()
    with c2:
        if ss.narrative:
            check = narrative_checks(ss.narrative, r)
            (st.success if check.ok else st.warning)(
                f"Texto de IA incorporado ({ss.narrative.get('modelo', '')}). {check.summary()}", icon="🔎")
        else:
            st.info("Sin IA, el informe usa textos generados de forma determinista a partir de los hallazgos. "
                    "Con IA se añaden resumen ejecutivo, narrativa por incidente y recomendaciones, con verificación "
                    "automática de cada Log_ID citado.")

    st.markdown("##### Exportación")
    e1, e2, e3 = st.columns(3)
    if e1.button("📄 Generar PDF", type="primary", width="stretch"):
        with st.spinner("Generando PDF…"):
            ss.pdf = build_pdf(r, ss.meta, ss.narrative)
    if ss.pdf:
        e2.download_button("⬇️ Descargar informe PDF", ss.pdf, file_name=f"Informe_{ss.meta.case_id}.pdf",
                           mime="application/pdf", width="stretch")
    md = build_markdown(r, ss.meta, ss.narrative)
    e3.download_button("⬇️ Descargar Markdown", md.encode("utf-8"), file_name=f"Informe_{ss.meta.case_id}.md",
                       mime="text/markdown", width="stretch")

    st.markdown("##### Vista previa")
    with st.container(border=True):
        st.markdown(md)


def _executive_report(r) -> None:
    st.markdown("##### Redacción del resumen con IA")
    c1, c2 = st.columns([1, 2])
    with c1:
        if st.button("✨ Redactar resumen con IA", key="exec_ai", disabled=not api_key, width="stretch",
                     help=None if api_key else "Configure la API key en la barra lateral"):
            assistant = AIAssistant(api_key, model)
            facts = facts_text(executive_content(r, ss.meta))
            try:
                ss.exec_narrative, _ = run_with_progress(
                    lambda emit: assistant.executive_summary(facts, on_text=emit),
                    stages=("La IA está preparando el resumen para dirección", "La IA está redactando el resumen"),
                    prep_seconds=8, expected_chars=900, live_text=True)
                ss.exec_pdf = None
            except AIError as exc:
                st.error(str(exc))
        if ss.exec_narrative and st.button("Descartar texto de IA", key="exec_discard", width="stretch"):
            ss.exec_narrative, ss.exec_pdf = None, None
            st.rerun()
    with c2:
        content = executive_content(r, ss.meta, ss.exec_narrative)
        if not ss.exec_narrative:
            st.info("Sin IA, el resumen se genera de forma determinista a partir de los hallazgos. Con IA se redacta en "
                    "un estilo más natural usando solo esos mismos hechos, y se comprueba que no aparezcan cifras "
                    "ajenas a ellos.")
        elif content.ai_warnings:
            st.warning(f"Resumen redactado por {content.ai_model}, pero contiene cifras que no figuran en los hechos del "
                       f"análisis: {', '.join(content.ai_warnings)}. Revíselas antes de distribuir el informe.", icon="🔎")
        else:
            st.success(f"Resumen redactado por {content.ai_model}. Todas las cifras coinciden con los hechos "
                       "verificados del análisis.", icon="🔎")

    st.markdown("##### Exportación")
    e1, e2, e3 = st.columns(3)
    if e1.button("📄 Generar PDF ejecutivo", key="exec_pdf_btn", type="primary", width="stretch"):
        with st.spinner("Generando PDF…"):
            ss.exec_pdf = build_executive_pdf(r, ss.meta, ss.exec_narrative)
    if ss.exec_pdf:
        e2.download_button("⬇️ Descargar informe ejecutivo (PDF)", ss.exec_pdf,
                           file_name=f"Informe_Ejecutivo_{ss.meta.case_id}.pdf", mime="application/pdf",
                           key="exec_pdf_dl", width="stretch")
    md = build_executive_markdown(r, ss.meta, ss.exec_narrative)
    e3.download_button("⬇️ Descargar Markdown", md.encode("utf-8"),
                       file_name=f"Informe_Ejecutivo_{ss.meta.case_id}.md", mime="text/markdown",
                       key="exec_md_dl", width="stretch")

    st.markdown("##### Vista previa")
    with st.container(border=True):
        st.markdown(md)


# Navegación en pestañas superiores. Con on_change="rerun" solo se ejecuta la pestaña abierta.
ROUTES = dict(zip(PAGES, [page_upload, page_analysis, page_dashboard, page_risk, page_ai, page_report]))
tabs = st.tabs(PAGES, default=PAGES[start_page], key="nav", on_change="rerun")
for tab, name in zip(tabs, PAGES):
    with tab:
        if tab.open:
            ROUTES[name]()
