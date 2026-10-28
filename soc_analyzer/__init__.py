"""SOC Analyzer: análisis de logs de SIEM, correlación de incidentes e informe técnico."""

import warnings

# Las reglas usan grupos en sus regex solo para agrupar alternativas, no para extraer.
warnings.filterwarnings("ignore", message="This pattern is interpreted as a regular expression")

from .loader import load_logs, LogLoadError  # noqa: E402
from .pipeline import run_analysis, AnalysisResult  # noqa: E402

__all__ = ["load_logs", "LogLoadError", "run_analysis", "AnalysisResult"]
