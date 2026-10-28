"""Metodología de clasificación de riesgo.

Cada hallazgo parte de un puntaje base según la técnica observada y suma factores
agravantes explícitos (éxito del ataque, activo crítico, origen externo, salida de
datos...). El puntaje final (0-100) se traduce a un nivel. Así cada clasificación
queda justificada por una lista de factores verificables en los logs.
"""

LEVELS = ["Crítico", "Alto", "Medio", "Bajo"]

# Umbrales inferiores de cada nivel.
THRESHOLDS = [(80, "Crítico"), (60, "Alto"), (35, "Medio"), (0, "Bajo")]

# Validado con el validador de paletas sobre el fondo sepia #f4ecd8 (CVD ΔE ≥ 11, visión normal ΔE ≥ 18).
# Siempre se muestran junto a la etiqueta del nivel: el color nunca es la única señal.
LEVEL_COLORS = {
    "Crítico": "#9e1739",
    "Alto": "#e35a12",
    "Medio": "#d8a900",
    "Bajo": "#2a78d6",
}

LEVEL_DESCRIPTIONS = {
    "Crítico": "Compromiso confirmado o pérdida/destrucción de datos en curso. Respuesta inmediata.",
    "Alto": "Actividad maliciosa con alta probabilidad de éxito o sobre activos críticos. Respuesta en horas.",
    "Medio": "Actividad sospechosa que requiere validación y seguimiento. Respuesta en el día.",
    "Bajo": "Comportamiento atípico de bajo impacto o compatible con ruido operativo. Monitorear.",
}

# Bonificación de incidente por cadena multi-etapa (varias tácticas ATT&CK encadenadas).
CHAIN_BONUS_PER_EXTRA_TACTIC = 4
CHAIN_BONUS_MAX = 12


def level_for_score(score: int) -> str:
    for threshold, level in THRESHOLDS:
        if score >= threshold:
            return level
    return "Bajo"


def level_rank(level: str) -> int:
    """0 = Crítico ... 3 = Bajo (útil para ordenar)."""
    return LEVELS.index(level) if level in LEVELS else len(LEVELS)
