@echo off
REM Instala dependencias (solo la primera vez) y abre la aplicacion en el navegador.
cd /d "%~dp0"
python -m pip install -q -r requirements.txt
python -m streamlit run app.py
