"""Gráficos interactivos (Plotly) para el dashboard."""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from .knowledge import CATEGORIES, CATEGORY_ORDER, category_label
from .models import Finding, Incident
from .risk import LEVEL_COLORS, LEVELS, THRESHOLDS

# Tema sepia. Serie 0/1 validadas sobre la superficie #f4ecd8 (CVD ΔE 18, visión normal ΔE 22).
SURFACE = "#f4ecd8"
INK = "#3b2f22"
INK_MUTED = "#6e5a43"
GRID = "#ded0b2"
SERIES = ["#9a5418", "#007d9e"]
FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"


def _style(fig: go.Figure, height: int = 340, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT, color=INK, size=12),
        showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, font=dict(color=INK_MUTED)),
        hoverlabel=dict(bgcolor="#fbf6ea", bordercolor=GRID, font=dict(family=FONT, color=INK)),
        modebar=dict(bgcolor="rgba(0,0,0,0)", color=INK_MUTED, activecolor=SERIES[0]),
        bargap=0.25,
    )
    fig.update_xaxes(gridcolor=GRID, linecolor=GRID, tickfont=dict(color=INK_MUTED), zeroline=False)
    fig.update_yaxes(gridcolor=GRID, linecolor=GRID, tickfont=dict(color=INK_MUTED), zeroline=False)
    return fig


def level_bars(items: list[Finding] | list[Incident], what: str) -> go.Figure:
    counts = {lvl: sum(1 for i in items if i.level == lvl) for lvl in LEVELS}
    fig = go.Figure(go.Bar(
        x=[counts[lvl] for lvl in LEVELS], y=LEVELS, orientation="h",
        marker=dict(color=[LEVEL_COLORS[lvl] for lvl in LEVELS], cornerradius=4),
        text=[f"{counts[lvl]}" for lvl in LEVELS], textposition="outside",
        textfont=dict(color=INK), cliponaxis=False,
        hovertemplate=f"%{{y}}: %{{x}} {what}<extra></extra>",
    ))
    fig.update_yaxes(autorange="reversed", showgrid=False)
    fig.update_xaxes(showgrid=False, showticklabels=False)
    return _style(fig, height=220, legend=False)


def event_volume(data: pd.DataFrame, flagged: set[str], freq: str = "10min") -> go.Figure:
    d = data.assign(bucket=data["Timestamp"].dt.floor(freq),
                    flag=data["Log_ID"].isin(flagged))
    g = d.groupby(["bucket", "flag"]).size().unstack(fill_value=0).reindex(columns=[False, True], fill_value=0)
    fig = go.Figure()
    fig.add_bar(x=g.index, y=g[False], name="Eventos sin hallazgo", marker=dict(color=SERIES[0]),
                hovertemplate="%{x|%H:%M}: %{y} eventos sin hallazgo<extra></extra>")
    fig.add_bar(x=g.index, y=g[True], name="Eventos asociados a hallazgos", marker=dict(color=SERIES[1]),
                hovertemplate="%{x|%H:%M}: %{y} eventos con hallazgo<extra></extra>")
    fig.update_layout(barmode="stack")
    fig.update_xaxes(tickformat="%H:%M", showgrid=False)
    fig.update_yaxes(title=dict(text="Eventos", font=dict(color=INK_MUTED)))
    return _style(fig)


def incident_timeline(incidents: list[Incident]) -> go.Figure:
    fig = go.Figure()
    seen = set()
    for inc in sorted(incidents, key=lambda i: i.start, reverse=True):
        end = max(inc.end, inc.start + pd.Timedelta(minutes=2))
        fig.add_trace(go.Scatter(
            x=[inc.start, end], y=[inc.id, inc.id], mode="lines+markers",
            line=dict(color=LEVEL_COLORS[inc.level], width=10),
            marker=dict(size=10, color=LEVEL_COLORS[inc.level], line=dict(color=SURFACE, width=2)),
            name=inc.level, legendgroup=inc.level, showlegend=inc.level not in seen,
            hovertemplate=(f"<b>{inc.id} · {inc.level}</b><br>{inc.title}<br>"
                           f"{inc.start:%H:%M:%S} – {inc.end:%H:%M:%S}<extra></extra>"),
        ))
        seen.add(inc.level)
    fig.update_xaxes(tickformat="%H:%M")
    fig.update_yaxes(showgrid=False)
    return _style(fig, height=max(240, 46 * len(incidents) + 60))


def kill_chain(findings: list[Finding]) -> go.Figure:
    cats = [c for c in CATEGORY_ORDER if any(f.category == c for f in findings)]
    fig = go.Figure()
    for lvl in LEVELS:
        fs = [f for f in findings if f.level == lvl]
        if not fs:
            continue
        fig.add_trace(go.Scatter(
            x=[f.start for f in fs], y=[category_label(f.category) for f in fs], mode="markers+text",
            text=[f.id for f in fs], textfont=dict(color=INK_MUTED, size=10),
            # Etiquetas alternadas arriba/abajo para que hallazgos cercanos no se solapen.
            textposition=["top center" if int(f.id[2:]) % 2 else "bottom center" for f in fs],
            marker=dict(size=[10 + min(20, len(f.evidence_ids) ** 0.5 * 2) for f in fs],
                        color=LEVEL_COLORS[lvl], line=dict(color=SURFACE, width=2)),
            name=lvl,
            customdata=[[f.id, f.title, f.score, len(f.evidence_ids)] for f in fs],
            hovertemplate="<b>%{customdata[0]}</b> · " + lvl + " (%{customdata[2]} pts)<br>%{customdata[1]}"
                          "<br>%{x|%H:%M:%S} · %{customdata[3]} eventos de evidencia<extra></extra>",
        ))
    fig.update_yaxes(categoryorder="array", categoryarray=[category_label(c) for c in reversed(cats)])
    fig.update_xaxes(tickformat="%H:%M")
    return _style(fig, height=max(300, 52 * len(cats) + 80))


def top_sources(data: pd.DataFrame, n: int = 10) -> go.Figure:
    counts = data[data["src_ip"] != ""].groupby(["src_ip", "src_ext"]).size().reset_index(name="n")
    counts = counts.sort_values("n", ascending=False).head(n).iloc[::-1]
    fig = go.Figure()
    for ext, name, color in ((False, "IP interna", SERIES[0]), (True, "IP externa (Internet)", SERIES[1])):
        c = counts[counts["src_ext"] == ext]
        fig.add_bar(x=c["n"], y=c["src_ip"], orientation="h", name=name, marker=dict(color=color, cornerradius=4),
                    hovertemplate="%{y}: %{x} eventos<extra>" + name + "</extra>")
    fig.update_yaxes(categoryorder="array", categoryarray=list(counts["src_ip"]), showgrid=False)
    return _style(fig)


def event_types(data: pd.DataFrame, n: int = 12) -> go.Figure:
    g = (data.groupby("eid").agg(n=("Log_ID", "size"), desc=("desc", lambda s: s.mode().iat[0]))
         .sort_values("n", ascending=False).head(n).iloc[::-1])
    fig = go.Figure(go.Bar(
        x=g["n"], y=[f"{e}" for e in g.index], orientation="h", marker=dict(color=SERIES[0], cornerradius=4),
        customdata=g["desc"], hovertemplate="Event ID %{y}: %{x}<br>%{customdata}<extra></extra>",
    ))
    fig.update_yaxes(type="category", showgrid=False)
    return _style(fig, legend=False)


def host_heatmap(data: pd.DataFrame, flagged: set[str]) -> go.Figure:
    d = data[data["Log_ID"].isin(flagged)]
    if d.empty:
        d = data
    pivot = (d.assign(hour=d["Timestamp"].dt.strftime("%H:00"))
             .groupby(["host", "hour"]).size().unstack(fill_value=0))
    fig = go.Figure(go.Heatmap(
        z=pivot.values, x=list(pivot.columns), y=list(pivot.index),
        colorscale=[[0, "#efe4cc"], [0.001, "#e3c9a0"], [0.5, "#b9814a"], [1, "#6b3a12"]],
        xgap=2, ygap=2, colorbar=dict(title=dict(text="Eventos", font=dict(color=INK_MUTED)),
                                      tickfont=dict(color=INK_MUTED)),
        hovertemplate="%{y} · %{x}: %{z} eventos con hallazgo<extra></extra>",
    ))
    fig.update_xaxes(showgrid=False)
    fig.update_yaxes(showgrid=False)
    return _style(fig, height=max(280, 28 * len(pivot) + 80), legend=False)


def tactic_bars(findings: list[Finding]) -> go.Figure:
    order = list(dict.fromkeys(CATEGORIES[c]["tactic"] for c in CATEGORY_ORDER))
    counts = pd.Series([CATEGORIES[f.category]["tactic"] for f in findings]).value_counts()
    tactics = [t for t in order if t in counts]
    fig = go.Figure(go.Bar(
        x=[int(counts[t]) for t in tactics], y=tactics, orientation="h",
        marker=dict(color=SERIES[0], cornerradius=4),
        text=[int(counts[t]) for t in tactics], textposition="outside", textfont=dict(color=INK), cliponaxis=False,
        hovertemplate="%{y}: %{x} hallazgos<extra></extra>",
    ))
    fig.update_yaxes(autorange="reversed", showgrid=False)
    fig.update_xaxes(showticklabels=False, showgrid=False)
    return _style(fig, height=max(220, 36 * len(tactics) + 40), legend=False)


def risk_scores(findings: list[Finding]) -> go.Figure:
    fs = sorted(findings, key=lambda f: f.score)
    fig = go.Figure(go.Bar(
        x=[f.score for f in fs], y=[f.id for f in fs], orientation="h",
        marker=dict(color=[LEVEL_COLORS[f.level] for f in fs], cornerradius=4),
        text=[f"{f.score} · {f.level}" for f in fs], textposition="outside", textfont=dict(color=INK),
        cliponaxis=False, customdata=[f.title for f in fs],
        hovertemplate="<b>%{y}</b> · %{x} pts<br>%{customdata}<extra></extra>",
    ))
    for threshold, lvl in THRESHOLDS[:-1]:
        fig.add_vline(x=threshold, line=dict(color=GRID, width=1, dash="dot"),
                      annotation=dict(text=f"{lvl} ≥{threshold}", font=dict(color=INK_MUTED, size=10),
                                      yanchor="bottom", y=1.0))
    fig.update_xaxes(range=[0, 112], showgrid=False, title=dict(text="Puntaje de riesgo (0-100)",
                                                                  font=dict(color=INK_MUTED)))
    fig.update_yaxes(type="category", showgrid=False)
    fig = _style(fig, height=max(300, 28 * len(fs) + 80), legend=False)
    fig.update_layout(margin=dict(t=34))   # espacio para las etiquetas de umbral
    return fig
