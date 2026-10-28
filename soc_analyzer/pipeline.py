"""Orquestación: logs → características → hallazgos → incidentes → estadísticas."""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .correlation import build_incidents, sort_incidents
from .detections import DetectionConfig, run_detectors
from .features import add_features
from .loader import LoadedLogs
from .models import Finding, Incident
from .risk import LEVELS


@dataclass
class AnalysisResult:
    logs: LoadedLogs
    data: pd.DataFrame                  # logs con columnas derivadas
    findings: list[Finding]
    incidents: list[Incident]           # ordenados por criticidad
    observations: list[Finding]         # hallazgos de bajo riesgo evaluados y descartados
    config: DetectionConfig
    stats: dict = field(default_factory=dict)

    @property
    def df(self) -> pd.DataFrame:
        return self.logs.df

    def finding(self, fid: str) -> Finding | None:
        return next((f for f in self.findings if f.id == fid), None)

    def incident_of(self, finding: Finding) -> Incident | None:
        return next((i for i in self.incidents if finding in i.findings), None)

    def rows(self, ids: list[str]) -> pd.DataFrame:
        return self.df[self.df["Log_ID"].isin(ids)]

    def flagged_ids(self) -> set[str]:
        return {i for f in self.findings if f.level != "Bajo" for i in f.evidence_ids}


def run_analysis(logs: LoadedLogs, config: DetectionConfig | None = None) -> AnalysisResult:
    cfg = config or DetectionConfig()
    data = add_features(logs.df)
    findings = run_detectors(data, cfg)
    findings.sort(key=lambda f: f.start)
    for n, f in enumerate(findings, start=1):
        f.id = f"H-{n:02d}"
    # Los hallazgos de nivel Bajo sin entidad pivote (ruido evaluado y descartado) se informan
    # como observaciones, no como incidentes.
    observations = [f for f in findings if f.level == "Bajo" and not f.pivots]
    incidents = sort_incidents(build_incidents(
        [f for f in findings if f not in observations], cfg.correlation_gap_min))

    df = logs.df
    flagged = {i for f in findings if f.level != "Bajo" for i in f.evidence_ids}
    stats = {
        "events": len(df),
        "start": df["Timestamp"].min(),
        "end": df["Timestamp"].max(),
        "hosts": int(df["Hostname"].nunique()),
        "users": int(df["User"].nunique()),
        "ips": int(df["Source_IP"].nunique()),
        "external_ips": sorted({i for i in data.loc[data["src_ext"], "src_ip"]}
                               | {i for i in data.loc[data["dest_ext"], "dest_ip"].dropna()}),
        "flagged_events": len(flagged),
        "findings_by_level": {lvl: sum(1 for f in findings if f.level == lvl) for lvl in LEVELS},
        "incidents_by_level": {lvl: sum(1 for i in incidents if i.level == lvl) for lvl in LEVELS},
    }
    return AnalysisResult(logs=logs, data=data, findings=findings, incidents=incidents,
                          observations=observations, config=cfg, stats=stats)
