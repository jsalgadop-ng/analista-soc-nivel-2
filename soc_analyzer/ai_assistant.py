"""Asistente de IA (Claude) para apoyar el análisis y la redacción del informe.

Garantías de rigor:
  * El modelo recibe los logs reales y los hallazgos del motor de reglas como único contexto.
  * Se le exige citar Log_IDs entre corchetes en cada afirmación factual.
  * Toda cita se verifica contra el archivo cargado; las inexistentes se marcan en la interfaz y
    el informe, de modo que ninguna conclusión de la IA entra al PDF sin trazabilidad.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import anthropic

from .knowledge import category_label
from .pipeline import AnalysisResult

MODELS = {
    "claude-opus-5-5": "Claude Opus 5.5 (máxima calidad)",
    "claude-sonnet-5-5": "Claude Sonnet 5.5 (rápido)",
    "claude-haiku-5-5": "Claude Haiku 5.5 (económico)",
}
DEFAULT_MODEL = "claude-opus-5-5"
# Haiku no admite reintento automático en otro modelo si un clasificador declina la petición.
_FALLBACK_MODELS = {"claude-opus-5-5", "claude-sonnet-5-5"}
_FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_FULL_LOG_ROWS = 2500

SYSTEM_INSTRUCTIONS = """Eres un analista SOC de nivel 2 de una consultora de ciberseguridad en Estocolmo. \
Apoyas la investigación de un posible incidente a partir de logs exportados del SIEM de un cliente.

Reglas de rigor analítico (obligatorias):
1. Usa EXCLUSIVAMENTE la información de los registros y de los hallazgos incluidos abajo. No inventes \
eventos, IPs, usuarios, archivos, volúmenes ni horarios.
2. Cada afirmación factual debe citar el o los Log_ID que la sustentan, entre corchetes y separados por \
comas, por ejemplo [EVT-00123, EVT-00130]. No uses rangos. Dentro de corchetes escribe solo Log_IDs o \
identificadores de hallazgo (H-xx) o incidente (INC-xx).
3. Distingue con claridad: HECHO (visible en los logs), INFERENCIA (deducción razonable) e HIPÓTESIS \
(posible pero no demostrada). Si algo no puede determinarse con los logs, dilo explícitamente: \
"no hay evidencia en los registros".
4. Los niveles de criticidad los calcula el motor de reglas con una metodología documentada. No los \
cambies; si consideras que alguno debería revisarse, indícalo como observación justificada.
5. Responde siempre en español, con tono profesional y conciso, apto para un informe técnico.
6. El cliente aporta los logs para su propia defensa: tu trabajo es explicar, priorizar y recomendar \
medidas defensivas, no generar herramientas ofensivas."""


class AIError(Exception):
    pass


@dataclass
class CitationCheck:
    valid: list[str]
    invalid: list[str]

    @property
    def ok(self) -> bool:
        return not self.invalid

    def summary(self) -> str:
        total = len(self.valid) + len(self.invalid)
        if not total:
            return "Sin referencias a logs."
        if self.ok:
            return f"{total} referencias verificadas: todas existen en el archivo cargado."
        return (f"{len(self.valid)}/{total} referencias verificadas. No existen en el archivo: "
                + ", ".join(self.invalid))


def verify_citations(text: str, result: AnalysisResult) -> CitationCheck:
    log_ids = set(result.df["Log_ID"].astype(str))
    known = {f.id for f in result.findings} | {i.id for i in result.incidents}
    hosts = set(result.df["Hostname"].dropna().astype(str))
    valid, invalid = [], []
    for group in re.findall(r"\[([^\[\]]+)\]", text):
        for token in re.findall(r"[A-Za-z][A-Za-z0-9_]*-\d+", group):
            if token in hosts:
                continue
            target = valid if token in log_ids or token in known else invalid
            if token not in target:
                target.append(token)
    return CitationCheck(valid, invalid)


def annotate_invalid(text: str, check: CitationCheck, marker: str = " ⚠️(no existe en los logs)") -> str:
    for token in check.invalid:
        text = re.sub(rf"\b{re.escape(token)}\b", f"{token}{marker}", text)
    return text


def annotate_narrative(narrative: dict, check: CitationCheck, marker: str) -> dict:
    """Copia de la narrativa con las referencias inexistentes marcadas en todos sus textos."""
    if check.ok:
        return narrative
    out = dict(narrative)
    out["resumen_ejecutivo"] = annotate_invalid(narrative["resumen_ejecutivo"], check, marker)
    out["limitaciones"] = annotate_invalid(narrative.get("limitaciones", ""), check, marker)
    out["recomendaciones"] = [annotate_invalid(x, check, marker) for x in narrative.get("recomendaciones", [])]
    out["incidentes"] = [{**i, "analisis": annotate_invalid(i["analisis"], check, marker),
                          "impacto": annotate_invalid(i["impacto"], check, marker)}
                         for i in narrative.get("incidentes", [])]
    return out


def resolve_api_key(user_key: str | None) -> str | None:
    return (user_key or "").strip() or os.environ.get("ANTHROPIC_API_KEY") or None


# --------------------------------------------------------------------------------------
# Contexto
# --------------------------------------------------------------------------------------
def _finding_payload(f) -> dict:
    return {
        "id": f.id,
        "categoria": category_label(f.category),
        "titulo": f.title,
        "nivel": f.level,
        "puntaje": f.score,
        "justificacion": [f"+{x.points} {x.reason}" for x in f.factors],
        "descripcion": f.description,
        "mitre": [f"{t} {n}" for t, n in f.mitre],
        "inicio": str(f.start), "fin": str(f.end),
        "evidencias": f.evidence_ids if len(f.evidence_ids) <= 60
        else f.evidence_ids[:60] + [f"... ({len(f.evidence_ids) - 60} más)"],
    }


def build_context(result: AnalysisResult) -> str:
    df = result.df
    s = result.stats
    incidents = [{
        "id": i.id, "titulo": i.title, "nivel": i.level, "puntaje": i.score,
        "justificacion": [f"{x.points} {x.reason}" for x in i.factors],
        "tacticas": i.tactics, "hallazgos": [f.id for f in i.findings],
        "relaciones_posibles": i.related,
    } for i in result.incidents]
    payload = {
        "archivo": result.logs.file_name,
        "sha256": result.logs.sha256,
        "eventos": s["events"],
        "periodo": f"{s['start']} a {s['end']}",
        "ips_externas_observadas": s["external_ips"],
        "incidentes": incidents,
        "hallazgos": [_finding_payload(f) for f in result.findings],
    }
    cols = ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP", "Destination",
            "Log_Source", "Event_Description", "Process_CommandLine", "Result", "Severity"]
    if len(df) <= MAX_FULL_LOG_ROWS:
        logs = df[cols]
        note = f"Se incluyen los {len(df)} registros completos."
    else:
        logs = df[df["Log_ID"].isin(result.flagged_ids())][cols]
        note = (f"El archivo tiene {len(df)} registros; por tamaño se incluyen solo los {len(logs)} "
                "registros asociados a hallazgos. Indica esta limitación si afecta a una respuesta.")
    csv = logs.assign(Timestamp=logs["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")).to_csv(index=False)
    return (
        "## Resultado del motor de reglas (JSON)\n"
        + json.dumps(payload, ensure_ascii=False, indent=1, default=str)
        + f"\n\n## Registros del SIEM (CSV)\n{note}\n" + csv
    )


# --------------------------------------------------------------------------------------
# Cliente
# --------------------------------------------------------------------------------------
REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "resumen_ejecutivo": {"type": "string"},
        "incidentes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "analisis": {"type": "string"},
                    "impacto": {"type": "string"},
                },
                "required": ["id", "analisis", "impacto"],
                "additionalProperties": False,
            },
        },
        "recomendaciones": {"type": "array", "items": {"type": "string"}},
        "limitaciones": {"type": "string"},
    },
    "required": ["resumen_ejecutivo", "incidentes", "recomendaciones", "limitaciones"],
    "additionalProperties": False,
}

REPORT_PROMPT = """Redacta las secciones narrativas del informe técnico de seguridad para el cliente.

- resumen_ejecutivo: 2-3 párrafos para dirección (sin jerga excesiva): qué ocurrió, cuántos incidentes \
y de qué gravedad, qué activos y datos están en riesgo y qué decisiones urgentes se recomiendan. Cita Log_IDs \
clave entre corchetes.
- incidentes: para CADA incidente de la lista (usa su id exacto), "analisis" reconstruye la secuencia \
cronológica del ataque citando Log_IDs, indicando qué es hecho, inferencia o hipótesis; "impacto" describe \
el posible impacto en la organización basado en los activos y datos implicados.
- recomendaciones: 6-10 recomendaciones generales de seguridad priorizadas y derivadas de lo observado.
- limitaciones: qué no puede determinarse con estos logs (fuentes ausentes, campos vacíos, etc.).

Revisa también si los logs contienen algún indicio relevante que el motor de reglas no haya cubierto; \
si lo hay, menciónalo en el resumen como observación adicional citando sus Log_IDs."""


EXECUTIVE_SYSTEM = """Eres un analista de ciberseguridad que explica incidentes a la alta dirección de una empresa, \
personas sin conocimientos técnicos. Reglas:
1. Usa EXCLUSIVAMENTE los hechos del bloque HECHOS. No añadas datos, cifras, fechas, nombres ni causas que no \
estén allí. Si algo no está confirmado, dilo.
2. Lenguaje de negocio, sin jerga: nada de direcciones IP, identificadores de log, códigos de evento ni siglas \
técnicas sin explicar. Habla de riesgo para la empresa y de decisiones.
3. Refleja el grado de certeza de los hechos: usa "los registros indican" o "hay indicios de" cuando se trate de \
indicios. No afirmes que un atacante "controló", "robó" o "tomó" algo si los hechos solo muestran indicios.
4. Texto plano en español, sin viñetas, sin títulos y sin formato Markdown.
5. Tu trabajo es defensivo: explicar, priorizar y recomendar decisiones."""

EXECUTIVE_PROMPT = """HECHOS (ya verificados por el motor de análisis a partir de los logs):
{facts}

Redacta el resumen para la alta dirección: máximo 130 palabras, uno o dos párrafos. Debe decir qué ocurrió en \
conjunto, qué está en riesgo para el negocio, qué parte no está confirmada y qué decisiones urgentes deben tomarse. \
No cites Log_IDs ni direcciones IP. Usa solo las cifras que aparecen en HECHOS."""


class AIAssistant:
    def __init__(self, api_key: str | None, model: str = DEFAULT_MODEL):
        self.model = model
        self.client = anthropic.Anthropic(api_key=api_key, max_retries=3)

    def _system(self, result: AnalysisResult) -> list[dict]:
        return [
            {"type": "text", "text": SYSTEM_INSTRUCTIONS},
            # El contexto de logs es idéntico entre preguntas: se cachea para abaratar el chat.
            {"type": "text", "text": build_context(result), "cache_control": {"type": "ephemeral"}},
        ]

    def _stream(self, **kwargs):
        if self.model in _FALLBACK_MODELS:
            kwargs.update(betas=[_FALLBACK_BETA], fallbacks="default")
        return self.client.beta.messages.stream(model=self.model, **kwargs)

    @staticmethod
    def _check_stop(message) -> None:
        if message.stop_reason == "refusal":
            raise AIError("El modelo declinó responder a esta petición. Reformule la pregunta "
                          "centrándose en el análisis defensivo de los registros.")

    def chat(self, result: AnalysisResult, history: list[dict], question: str) -> Iterator[str]:
        """Genera la respuesta en streaming (fragmentos de texto)."""
        messages = [*history, {"role": "user", "content": question}]
        try:
            with self._stream(
                max_tokens=16000,
                system=self._system(result),
                messages=messages,
                output_config={"effort": "medium"},
            ) as stream:
                yield from stream.text_stream
                final = stream.get_final_message()
            self._check_stop(final)
            if final.stop_reason == "max_tokens":
                yield "\n\n_(Respuesta truncada por longitud.)_"
        except anthropic.APIError as exc:
            raise AIError(describe_api_error(exc)) from exc

    def report_narrative(self, result: AnalysisResult, on_text: Callable[[str], None] | None = None) -> dict:
        """Redacta la narrativa del informe; ``on_text`` recibe cada fragmento generado (para mostrar avance)."""
        try:
            with self._stream(
                max_tokens=32000,
                system=self._system(result),
                messages=[{"role": "user", "content": REPORT_PROMPT}],
                output_config={"effort": "high", "format": {"type": "json_schema", "schema": REPORT_SCHEMA}},
            ) as stream:
                for chunk in stream.text_stream:
                    if on_text:
                        on_text(chunk)
                final = stream.get_final_message()
        except anthropic.APIError as exc:
            raise AIError(describe_api_error(exc)) from exc
        self._check_stop(final)
        if final.stop_reason == "max_tokens":
            raise AIError("La respuesta del modelo se truncó; vuelva a intentarlo.")
        text = next((b.text for b in final.content if b.type == "text"), "")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AIError("La IA devolvió un formato inesperado; vuelva a intentarlo.") from exc
        known = {i.id for i in result.incidents}
        data["incidentes"] = [i for i in data.get("incidentes", []) if i.get("id") in known]
        data["modelo"] = final.model
        return data


    def executive_summary(self, facts: str, on_text: Callable[[str], None] | None = None) -> dict:
        """Resumen para dirección redactado a partir de hechos ya verificados (sin necesidad de enviar los logs)."""
        try:
            with self._stream(
                max_tokens=4000,
                system=[{"type": "text", "text": EXECUTIVE_SYSTEM}],
                messages=[{"role": "user", "content": EXECUTIVE_PROMPT.format(facts=facts)}],
                output_config={"effort": "medium"},
            ) as stream:
                for chunk in stream.text_stream:
                    if on_text:
                        on_text(chunk)
                final = stream.get_final_message()
        except anthropic.APIError as exc:
            raise AIError(describe_api_error(exc)) from exc
        self._check_stop(final)
        if final.stop_reason == "max_tokens":
            raise AIError("La respuesta del modelo se truncó; vuelva a intentarlo.")
        text = "".join(b.text for b in final.content if b.type == "text").strip()
        if not text:
            raise AIError("La IA no devolvió texto; vuelva a intentarlo.")
        return {"resumen": text, "modelo": final.model}


def describe_api_error(exc: anthropic.APIError) -> str:
    if isinstance(exc, anthropic.AuthenticationError):
        return "La API key de Anthropic no es válida."
    if isinstance(exc, anthropic.PermissionDeniedError):
        return "La API key no tiene permisos para este modelo."
    if isinstance(exc, anthropic.NotFoundError):
        return "Modelo no disponible para esta cuenta."
    if isinstance(exc, anthropic.RateLimitError):
        return "Límite de uso de la API alcanzado; espere un momento y reintente."
    if isinstance(exc, anthropic.APIConnectionError):
        return "No hay conexión con la API de Anthropic (revise red/proxy)."
    if isinstance(exc, anthropic.APIStatusError):
        return f"Error de la API ({exc.status_code}): {exc.message}"
    return f"Error de la API: {exc}"


def narrative_checks(narrative: dict, result: AnalysisResult) -> CitationCheck:
    text = json.dumps(narrative, ensure_ascii=False)
    return verify_citations(text, result)
