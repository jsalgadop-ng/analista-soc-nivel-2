"""Pruebas del motor de análisis sobre el archivo del reto y sobre datos sintéticos."""

import io
from pathlib import Path

import pandas as pd
import pytest

from soc_analyzer import LogLoadError, load_logs, run_analysis
from soc_analyzer.ai_assistant import verify_citations
from soc_analyzer.features import is_external
from soc_analyzer.report import ReportMeta, build_markdown, build_pdf

SAMPLE = Path(__file__).parents[1] / "Insumos" / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"


def _xlsx(rows: list[dict]) -> bytes:
    buf = io.BytesIO()
    pd.DataFrame(rows).to_excel(buf, index=False)
    return buf.getvalue()


@pytest.fixture(scope="module")
def result():
    if not SAMPLE.exists():
        pytest.skip("archivo del reto no disponible")
    return run_analysis(load_logs(SAMPLE.read_bytes(), SAMPLE.name))


def _incident_with(result, text):
    return next(i for i in result.incidents if text in i.title)


def test_detecta_los_siete_incidentes(result):
    assert len(result.incidents) == 7
    levels = [i.level for i in result.incidents]
    assert levels.count("Crítico") == 5 and levels.count("Alto") == 2


def test_password_spraying_y_cuenta_comprometida(result):
    inc = _incident_with(result, "ataque de credenciales")
    titles = " ".join(f.title for f in inc.findings)
    assert "Password spraying desde 203.0.113.74 contra 8 cuentas" in titles
    assert "CORP\\mgarcia" in titles
    assert "EVT-00123" in inc.evidence_ids          # logon exitoso tras el spraying


def test_intrusion_rdp_con_movimiento_lateral_y_exfiltracion(result):
    inc = _incident_with(result, "movimiento lateral")
    cats = {f.category for f in inc.findings}
    assert {"fuerza_bruta", "inicio_sospechoso", "escalamiento", "comandos",
            "movimiento_lateral", "exfiltracion"} <= cats
    assert {"EVT-00188", "EVT-00225", "EVT-00231", "EVT-00232", "EVT-00235"} <= set(inc.evidence_ids)


def test_ransomware_insider_persistencia_webshell_y_anomalias(result):
    assert "EVT-00314" in _incident_with(result, "ransomware").evidence_ids     # vssadmin delete shadows
    exf = _incident_with(result, "Exfiltración de datos")
    assert any("241.6 MB" in f.title for f in exf.findings)
    assert "EVT-00524" in _incident_with(result, "persistencia").evidence_ids   # servicio WinUpdateHelper
    assert "EVT-00599" in _incident_with(result, "webshell").evidence_ids       # cmd.exe /c whoami bajo IIS
    anomalies = _incident_with(result, "suplantación")
    assert {"DC01"} <= anomalies.entities("hosts") and "CORP\\svc_backup" in anomalies.entities("users")


def test_ruido_no_es_incidente(result):
    assert [f.title for f in result.observations] == ["Fallos de autenticación internos dispersos (ruido de fondo)"]


def test_toda_evidencia_existe_en_el_archivo(result):
    ids = set(result.df["Log_ID"])
    for f in result.findings:
        assert f.evidence_ids and set(f.evidence_ids) <= ids
        assert f.factors or f.level == "Bajo"


def test_verificacion_de_citas(result):
    check = verify_citations("Ver [EVT-00188, EVT-99999] y [INC-01] en [DC-01]", result)
    assert check.valid == ["EVT-00188", "INC-01"] and check.invalid == ["EVT-99999"]


def test_informe_pdf_y_markdown(result):
    pdf = build_pdf(result, ReportMeta(client="Test"))
    assert pdf.startswith(b"%PDF") and len(pdf) > 50_000
    md = build_markdown(result, ReportMeta())
    assert "\\\\\\\\FS-SRV01\\\\Finance" in md                   # rutas UNC escapadas para Markdown


def test_ips_de_documentacion_se_tratan_como_externas():
    assert is_external("203.0.113.74") and is_external("8.8.8.8")
    assert not is_external("10.10.1.22") and not is_external("192.168.1.5") and not is_external("")


def test_datos_benignos_no_generan_incidentes():
    rows = [{"Log_ID": f"E{i}", "Timestamp": f"2026-01-05 09:{i % 60:02d}:00", "Hostname": "WS-01",
             "Event_ID": 4624, "User": "CORP\\ana", "Source_IP": "10.0.0.5",
             "Event_Description": "An account was successfully logged on"} for i in range(60)]
    r = run_analysis(load_logs(_xlsx(rows), "benigno.xlsx"))
    assert r.incidents == []


def test_columnas_obligatorias():
    with pytest.raises(LogLoadError):
        load_logs(_xlsx([{"Foo": 1}]), "malo.xlsx")
