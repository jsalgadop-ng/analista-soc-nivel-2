"""Correlación de hallazgos en incidentes.

Dos hallazgos pertenecen al mismo incidente si comparten una entidad pivote (cuenta
o IP del actor) y ocurren a menos de `gap` minutos uno del otro. Compartir solo un
equipo o una cuenta objetivo NO basta para fusionarlos: esos vínculos se informan
como "relación posible, no confirmada" para no afirmar más de lo que prueban los logs.
"""

from __future__ import annotations

import pandas as pd

from .knowledge import CATEGORIES, CATEGORY_ORDER, IMPACT, PLAYBOOKS, category_label, fill, host_role
from .features import is_external
from .models import Finding, Incident, RiskFactor
from .risk import CHAIN_BONUS_MAX, CHAIN_BONUS_PER_EXTRA_TACTIC, level_rank


def _interval_gap(a: Finding, b: Finding) -> pd.Timedelta:
    if a.end < b.start:
        return b.start - a.end
    if b.end < a.start:
        return a.start - b.end
    return pd.Timedelta(0)


def group_findings(findings: list[Finding], gap_minutes: float) -> list[list[Finding]]:
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    limit = pd.Timedelta(minutes=gap_minutes)
    for i, a in enumerate(findings):
        for j in range(i + 1, len(findings)):
            b = findings[j]
            if a.pivots & b.pivots and _interval_gap(a, b) <= limit:
                parent[find(i)] = find(j)

    groups: dict[int, list[Finding]] = {}
    for i, f in enumerate(findings):
        groups.setdefault(find(i), []).append(f)
    return sorted(groups.values(), key=lambda g: min(f.start for f in g))


def _title(cats: set[str], findings: list[Finding]) -> str:
    mitre = {t for f in findings for t, _ in f.mitre}
    if "T1490" in mitre:
        base = "Actividad precursora de ransomware"
    elif "movimiento_lateral" in cats and "exfiltracion" in cats:
        base = "Intrusión con movimiento lateral y exfiltración de datos"
    elif "ataque_web" in cats:
        base = "Explotación de aplicación web" + (" (webshell)" if "T1505.003" in mitre else "")
    elif "persistencia" in cats:
        base = "Implantación de mecanismos de persistencia"
    elif "exfiltracion" in cats and any(f.title.startswith("Exfiltración") for f in findings):
        base = "Exfiltración de datos"
    elif "fuerza_bruta" in cats and "inicio_sospechoso" in cats:
        base = "Compromiso de cuenta por ataque de credenciales"
    elif cats == {"fuerza_bruta"}:
        base = findings[0].title if len(findings) == 1 else "Ataque de credenciales"
    elif cats == {"anomalia"}:
        base = "Entidades anómalas y posible suplantación de nombres"
    else:
        base = " → ".join(category_label(c) for c in CATEGORY_ORDER if c in cats)
    return base


def _external_ips(findings: list[Finding]) -> tuple[list[str], list[str]]:
    """(IPs externas de origen, IPs externas de destino) observadas en los hallazgos."""
    sources = {i for f in findings for i in f.ips if is_external(i)}
    pivots = {p[3:] for f in findings for p in f.pivots if p.startswith("ip:") and is_external(p[3:])}
    return sorted(sources), sorted(pivots - sources)


def _actor(findings: list[Finding]) -> str:
    sources, dests = _external_ips(findings)
    users = sorted({p[5:] for f in findings for p in f.pivots if p.startswith("user:")})
    parts = []
    if sources:
        parts.append("origen " + ", ".join(sources[:2]))
    if dests:
        parts.append("destino " + ", ".join(dests[:2]))
    if users and len(users) <= 2:
        parts.append("cuenta " + ", ".join(users))
    return " — " + "; ".join(parts) if parts else ""


def build_incidents(findings: list[Finding], gap_minutes: float) -> list[Incident]:
    incidents: list[Incident] = []
    for n, group in enumerate(group_findings(findings, gap_minutes), start=1):
        group.sort(key=lambda f: f.start)
        cats = {f.category for f in group}
        top = max(group, key=lambda f: f.score)
        factors = [RiskFactor(top.score, f"Hallazgo más grave: {top.id} ({top.level}, {top.score} pts)")]

        tactics = list(dict.fromkeys(CATEGORIES[f.category]["tactic"] for f in group))
        if len(tactics) > 1:
            bonus = min(CHAIN_BONUS_MAX, CHAIN_BONUS_PER_EXTRA_TACTIC * (len(tactics) - 1))
            factors.append(RiskFactor(bonus, f"Cadena de ataque multi-etapa ({len(tactics)} tácticas: "
                                             + ", ".join(tactics) + ")"))
        mitre = {t for f in group for t, _ in f.mitre}
        if {"T1560.001"} & mitre and any(f.category == "exfiltracion" and ("T1041" in {t for t, _ in f.mitre}
                                         or "T1567" in {t for t, _ in f.mitre}) for f in group):
            factors.append(RiskFactor(10, "Patrón completo de exfiltración: compresión seguida de envío al exterior"))
        if "T1490" in mitre and "T1039" in mitre:
            factors.append(RiskFactor(10, "Patrón precursor de ransomware: acceso masivo a datos + borrado de copias de sombra"))
        score = min(100, sum(f.points for f in factors))

        users = {u for f in group for u in f.users}
        hosts = {h for f in group for h in f.hosts}
        src_ips, dest_ips = _external_ips(group)
        ctx = {
            "users": ", ".join(sorted(users)),
            "hosts": ", ".join(sorted(hosts)),
            "ext_ips": ", ".join(src_ips),
            "dest_ips": ", ".join(dest_ips),
            "entities": ", ".join(v for _, v in group[0].iocs) if cats == {"anomalia"} else "",
        }
        ordered_cats = [c for c in CATEGORY_ORDER if c in cats]
        impact = [x for c in ordered_cats if c in IMPACT and (x := fill(IMPACT[c], ctx))]
        crit_assets = [f"{h}: {host_role(h)}" for h in sorted(hosts)]
        if crit_assets:
            impact.append("Activos implicados — " + "; ".join(crit_assets) + ".")
        plan: dict[str, list[str]] = {"investigar": [], "contener": [], "remediar": []}
        for c in ordered_cats:
            for phase, steps in PLAYBOOKS.get(c, {}).items():
                for s in steps:
                    s = fill(s, ctx)
                    if s and s not in plan[phase]:
                        plan[phase].append(s)

        incidents.append(Incident(
            id=f"INC-{n:02d}",
            title=_title(cats, group) + _actor(group),
            findings=group, score=score, factors=factors, tactics=tactics,
            impact=impact, plan=plan,
        ))

    _link_related(incidents)
    return incidents


def _link_related(incidents: list[Incident]) -> None:
    """Relaciones posibles (no confirmadas) por cuentas o equipos compartidos."""
    for a in incidents:
        for b in incidents:
            if a is b:
                continue
            shared_users = a.entities("users") & b.entities("users")
            shared_hosts = a.entities("hosts") & b.entities("hosts")
            if not (shared_users or shared_hosts):
                continue
            # Evitamos relaciones triviales con hallazgos de ruido de fondo.
            if a.level == "Bajo" or b.level == "Bajo":
                continue
            parts = []
            if shared_users:
                parts.append("cuentas " + ", ".join(sorted(shared_users)))
            if shared_hosts:
                parts.append("equipos " + ", ".join(sorted(shared_hosts)))
            a.related.append(f"{b.id} comparte {' y '.join(parts)} (relación posible, no confirmada por los logs)")


def sort_incidents(incidents: list[Incident]) -> list[Incident]:
    return sorted(incidents, key=lambda i: (level_rank(i.level), -i.score, i.start))
