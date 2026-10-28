"""Estructuras de datos del análisis: hallazgos, factores de riesgo e incidentes."""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .risk import level_for_score


@dataclass
class RiskFactor:
    points: int
    reason: str


@dataclass
class Finding:
    """Un hallazgo concreto, siempre respaldado por Log_IDs del archivo cargado."""

    category: str
    title: str
    description: str          # qué se observó (hechos y cifras)
    technical: str            # explicación técnica
    mitre: list[tuple[str, str]]
    evidence_ids: list[str]
    start: pd.Timestamp
    end: pd.Timestamp
    base_score: int
    factors: list[RiskFactor] = field(default_factory=list)
    # Entidades que permiten correlacionar con otros hallazgos (p. ej. "user:CORP\\admin").
    pivots: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    iocs: list[tuple[str, str]] = field(default_factory=list)   # (tipo, valor)
    id: str = ""

    @property
    def score(self) -> int:
        return max(0, min(100, self.base_score + sum(f.points for f in self.factors)))

    @property
    def level(self) -> str:
        return level_for_score(self.score)

    def add(self, points: int, reason: str) -> None:
        self.factors.append(RiskFactor(points, reason))


@dataclass
class Incident:
    id: str
    title: str
    findings: list[Finding]
    score: int
    factors: list[RiskFactor]
    tactics: list[str]
    impact: list[str]
    plan: dict[str, list[str]]      # investigar / contener / remediar
    related: list[str] = field(default_factory=list)   # relaciones posibles, no confirmadas

    @property
    def level(self) -> str:
        return level_for_score(self.score)

    @property
    def start(self) -> pd.Timestamp:
        return min(f.start for f in self.findings)

    @property
    def end(self) -> pd.Timestamp:
        return max(f.end for f in self.findings)

    @property
    def evidence_ids(self) -> list[str]:
        seen: dict[str, None] = {}
        for f in self.findings:
            for i in f.evidence_ids:
                seen.setdefault(i, None)
        return list(seen)

    def entities(self, kind: str) -> set[str]:
        out: set[str] = set()
        for f in self.findings:
            out |= getattr(f, kind)
        return out

    @property
    def iocs(self) -> list[tuple[str, str]]:
        seen: dict[tuple[str, str], None] = {}
        for f in self.findings:
            for ioc in f.iocs:
                seen.setdefault(ioc, None)
        return list(seen)
