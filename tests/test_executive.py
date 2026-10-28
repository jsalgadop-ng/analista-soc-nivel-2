"""Pruebas del informe ejecutivo (lenguaje llano para la alta dirección)."""

import io
import re
from pathlib import Path

import pandas as pd
import pytest

from soc_analyzer import load_logs, run_analysis
from soc_analyzer.executive import (build_executive_markdown, build_executive_pdf, executive_content, facts_text,
                                    unverified_numbers)
from soc_analyzer.report import ReportMeta

SAMPLE = Path(__file__).parents[1] / "Insumos" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


@pytest.fixture(scope="module")
def result():
    if not SAMPLE.exists():
        pytest.skip("archivo del reto no disponible")
    return run_analysis(load_logs(SAMPLE.read_bytes(), SAMPLE.name))


def _all_text(c) -> str:
    parts = [c.situation, c.summary, *c.key_points, *c.actions_now, *c.actions_week, *c.unknowns]
    parts += [t for i in c.incidents for t in (i.headline, i.what, i.risk, i.systems)]
    return "\n".join(parts)


def test_un_bloque_por_incidente_con_su_nivel(result):
    c = executive_content(result, ReportMeta())
    assert [(i.id, i.level) for i in c.incidents] == [(i.id, i.level) for i in result.incidents]
    assert c.level == "Crítico" and c.figures[0] == ("7", "incidentes") and c.figures[1] == ("5", "críticos")


def test_sin_jerga_tecnica_ni_identificadores_de_log(result):
    text = _all_text(executive_content(result, ReportMeta()))
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", text), "no debe haber direcciones IP"
    assert not re.search(r"EVT-\d+|\bH-\d+\b|\bT1\d{3}\b|Base64|vssadmin|4624|4625", text)


def test_los_hechos_clave_estan_sustentados_en_los_hallazgos(result):
    c = executive_content(result, ReportMeta())
    text = _all_text(c)
    assert "241.6 MB" in text                                   # Exfiltración de 241.6 MB (H-16)
    assert "copias de seguridad" in text                        # T1490 (H-13)
    assert "WEB-01" in text and "FS-SRV01" in text
    inc = {i.id: i for i in c.incidents}
    assert "ransomware" in inc["INC-04"].headline.lower()
    assert "8 cuentas" in inc["INC-01"].what                    # password spraying contra 8 cuentas (H-02)


def test_lo_no_confirmado_se_declara(result):
    c = executive_content(result, ReportMeta())
    assert any("no siempre se sabe cuántos datos" in u for u in c.unknowns)
    assert any("no hay datos de antes ni de después" in u for u in c.unknowns)


def test_pdf_y_markdown_ejecutivos(result):
    m = ReportMeta(client="Cliente S.A.")
    pdf = build_executive_pdf(result, m)
    assert pdf.startswith(b"%PDF")
    md = build_executive_markdown(result, m)
    assert md.startswith("# Informe ejecutivo") and "INC-03" in md and "Decisiones y acciones inmediatas" in md


def test_pdf_ejecutivo_es_breve(result):
    fitz = pytest.importorskip("fitz")   # PyMuPDF solo se usa para contar páginas
    assert len(fitz.open(stream=build_executive_pdf(result, ReportMeta()), filetype="pdf")) == 2


def test_cifras_inventadas_por_la_ia_se_detectan(result):
    facts = facts_text(executive_content(result, ReportMeta()))
    assert unverified_numbers("Se enviaron 241.6 MB y hay 7 incidentes.", facts) == []
    assert unverified_numbers("Se enviaron 500 MB en 3 incidentes.", facts) == ["3", "500"]   # hay 7, no 3


def test_resumen_de_ia_se_incorpora_y_se_verifica(result):
    ok = executive_content(result, ReportMeta(), {"resumen": "Hay 7 incidentes, 5 críticos.", "modelo": "m"})
    assert ok.summary.startswith("Hay 7") and ok.ai_model == "m" and ok.ai_warnings == []
    bad = executive_content(result, ReportMeta(), {"resumen": "Se filtraron 9999 registros.", "modelo": "m"})
    assert bad.ai_warnings == ["9999"]


def test_sin_incidentes_el_informe_sigue_generandose():
    rows = [{"Log_ID": f"E{i}", "Timestamp": f"2026-01-05 09:{i % 60:02d}:00", "Hostname": "WS-01", "Event_ID": 4624,
             "User": "CORP\\ana", "Source_IP": "10.0.0.5", "Event_Description": "An account was successfully logged on"}
            for i in range(60)]
    buf = io.BytesIO()
    pd.DataFrame(rows).to_excel(buf, index=False)
    r = run_analysis(load_logs(buf.getvalue(), "benigno.xlsx"))
    c = executive_content(r, ReportMeta())
    assert c.incidents == [] and c.level == "Bajo" and "no identificó" in c.summary
    assert build_executive_pdf(r, ReportMeta()).startswith(b"%PDF")
